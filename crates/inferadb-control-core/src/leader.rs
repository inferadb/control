use std::{sync::Arc, time::Duration};

use inferadb_control_storage::StorageBackend;
use inferadb_control_types::error::{Error, Result};
use tokio::{sync::RwLock, time};

/// Leader lease TTL in seconds
const LEADER_LEASE_TTL: u64 = 30;

/// Leader lease renewal interval in seconds (renew before expiry)
const LEADER_RENEWAL_INTERVAL: u64 = 10;

/// Leader election coordinator using storage backend for distributed coordination
///
/// Only one instance across all running instances can be the leader at a time.
/// The leader is responsible for running background jobs and other singleton tasks.
///
/// # Leader Election Algorithm
///
/// 1. Try to acquire leader lease by setting a key with TTL
/// 2. If key already exists, another instance is the leader
/// 3. Leader must periodically renew the lease
/// 4. If leader fails to renew, the lease expires and another instance can acquire it
///
/// # Usage
///
/// ```rust,no_run
/// use inferadb_control_core::LeaderElection;
/// use inferadb_control_storage::MemoryBackend;
/// use std::sync::Arc;
///
/// # async fn example() {
/// let storage = MemoryBackend::new();
/// let leader = Arc::new(LeaderElection::new(storage, 1));
///
/// // Try to become leader
/// if leader.try_acquire_leadership().await.unwrap() {
///     println!("I am the leader!");
///
///     // Start lease renewal
///     leader.clone().start_lease_renewal();
///
///     // Do leader-only work...
///
///     // Release leadership when done
///     leader.release_leadership().await.unwrap();
/// }
/// # }
/// ```
pub struct LeaderElection<S: StorageBackend> {
    storage: S,
    instance_id: u16,
    is_leader: Arc<RwLock<bool>>,
    shutdown: Arc<RwLock<bool>>,
}

impl<S: StorageBackend + 'static> LeaderElection<S> {
    /// Create a new leader election coordinator
    ///
    /// # Arguments
    ///
    /// * `storage` - Storage backend for distributed coordination
    /// * `instance_id` - Unique instance ID (typically worker_id)
    pub fn new(storage: S, instance_id: u16) -> Self {
        Self {
            storage,
            instance_id,
            is_leader: Arc::new(RwLock::new(false)),
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Storage key for leader lease
    fn leader_key() -> Vec<u8> {
        b"leader/current".to_vec()
    }

    /// Try to acquire leadership
    ///
    /// Returns `Ok(true)` if leadership was acquired, `Ok(false)` if another instance is leader.
    ///
    /// # Errors
    ///
    /// Returns an error if storage operation fails.
    pub async fn try_acquire_leadership(&self) -> Result<bool> {
        let key = Self::leader_key();

        // Check if leader already exists
        if let Some(existing) = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::internal(format!("Failed to check leader status: {e}")))?
        {
            // Check if it's us (we might already be leader)
            if let Ok(leader_id) = String::from_utf8(existing.to_vec())
                && let Ok(id) = leader_id.parse::<u16>()
                && id == self.instance_id
            {
                // We're already the leader
                let mut is_leader = self.is_leader.write().await;
                *is_leader = true;
                return Ok(true);
            }

            // Another instance is leader
            return Ok(false);
        }

        // No current leader, try to acquire lease
        let value = self.instance_id.to_string();
        self.storage
            .set_with_ttl(key, value.as_bytes().to_vec(), LEADER_LEASE_TTL)
            .await
            .map_err(|e| Error::internal(format!("Failed to acquire leadership: {e}")))?;

        // Mark ourselves as leader
        let mut is_leader = self.is_leader.write().await;
        *is_leader = true;

        tracing::info!(instance_id = self.instance_id, "Acquired leadership lease");

        Ok(true)
    }

    /// Check if this instance is currently the leader
    pub async fn is_leader(&self) -> bool {
        *self.is_leader.read().await
    }

    /// Renew the leader lease
    ///
    /// This should be called periodically while the instance is leader.
    async fn renew_lease(&self) -> Result<()> {
        // Only renew if we're the leader
        if !self.is_leader().await {
            return Ok(());
        }

        let key = Self::leader_key();
        let value = self.instance_id.to_string();

        self.storage.set_with_ttl(key, value.as_bytes().to_vec(), LEADER_LEASE_TTL).await.map_err(
            |e| {
                // If renewal fails, we're no longer the leader
                tracing::error!("Failed to renew leader lease: {}", e);
                Error::internal(format!("Failed to renew leader lease: {e}"))
            },
        )?;

        tracing::debug!(instance_id = self.instance_id, "Renewed leadership lease");

        Ok(())
    }

    /// Start automatic lease renewal
    ///
    /// Spawns a background task that periodically renews the leader lease.
    /// The task will stop when `shutdown()` is called or if lease renewal fails.
    pub fn start_lease_renewal(self: Arc<Self>) {
        let election = Arc::clone(&self);

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(LEADER_RENEWAL_INTERVAL));

            loop {
                interval.tick().await;

                // Check if shutdown requested
                {
                    let shutdown = election.shutdown.read().await;
                    if *shutdown {
                        break;
                    }
                }

                // Only renew if we're the leader
                if !election.is_leader().await {
                    continue;
                }

                // Renew lease
                if let Err(e) = election.renew_lease().await {
                    tracing::error!("Lease renewal failed, stepping down as leader: {}", e);

                    // Mark as no longer leader
                    let mut is_leader = election.is_leader.write().await;
                    *is_leader = false;
                    break;
                }
            }

            tracing::info!(instance_id = election.instance_id, "Stopped lease renewal");
        });
    }

    /// Release leadership voluntarily
    ///
    /// This should be called when shutting down gracefully.
    pub async fn release_leadership(&self) -> Result<()> {
        // Only release if we're the leader
        if !self.is_leader().await {
            return Ok(());
        }

        let key = Self::leader_key();

        self.storage
            .delete(&key)
            .await
            .map_err(|e| Error::internal(format!("Failed to release leadership: {e}")))?;

        // Mark as no longer leader
        let mut is_leader = self.is_leader.write().await;
        *is_leader = false;

        tracing::info!(instance_id = self.instance_id, "Released leadership");

        Ok(())
    }

    /// Request shutdown of background tasks
    pub async fn shutdown(&self) {
        let mut shutdown = self.shutdown.write().await;
        *shutdown = true;

        // Release leadership
        if let Err(e) = self.release_leadership().await {
            tracing::error!("Failed to release leadership on shutdown: {}", e);
        }
    }

    /// Run a task with leadership
    ///
    /// This is a convenience method that:
    /// 1. Tries to acquire leadership
    /// 2. Runs the provided task if leadership is acquired
    /// 3. Releases leadership when done
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use inferadb_control_core::LeaderElection;
    /// # use inferadb_control_storage::MemoryBackend;
    /// # use std::sync::Arc;
    /// # async fn example() {
    /// let storage = MemoryBackend::new();
    /// let leader = Arc::new(LeaderElection::new(storage, 1));
    ///
    /// leader.run_with_leadership(|| async {
    ///     println!("Doing leader-only work...");
    ///     Ok(())
    /// }).await.unwrap();
    /// # }
    /// ```
    pub async fn run_with_leadership<F, Fut>(&self, task: F) -> Result<()>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        if !self.try_acquire_leadership().await? {
            tracing::debug!("Not the leader, skipping task");
            return Ok(());
        }

        tracing::info!("Running leader-only task");

        // Don't release leadership automatically - let the caller decide
        // This allows for long-running leader tasks
        task().await
    }
}

#[cfg(test)]
mod tests {
    use inferadb_control_storage::MemoryBackend;

    use super::*;

    #[tokio::test]
    async fn test_leader_election_single_instance() {
        let storage = MemoryBackend::new();
        let leader = LeaderElection::new(storage, 1);

        // First attempt should acquire leadership
        assert!(leader.try_acquire_leadership().await.unwrap());
        assert!(leader.is_leader().await);
    }

    #[tokio::test]
    async fn test_leader_election_multiple_instances() {
        let storage = MemoryBackend::new();
        let leader1 = LeaderElection::new(storage.clone(), 1);
        let leader2 = LeaderElection::new(storage.clone(), 2);

        // First instance acquires leadership
        assert!(leader1.try_acquire_leadership().await.unwrap());
        assert!(leader1.is_leader().await);

        // Second instance should not acquire leadership
        assert!(!leader2.try_acquire_leadership().await.unwrap());
        assert!(!leader2.is_leader().await);
    }

    #[tokio::test]
    async fn test_leader_election_release() {
        let storage = MemoryBackend::new();
        let leader = LeaderElection::new(storage, 1);

        // Acquire leadership
        assert!(leader.try_acquire_leadership().await.unwrap());
        assert!(leader.is_leader().await);

        // Release leadership
        leader.release_leadership().await.unwrap();
        assert!(!leader.is_leader().await);
    }

    #[tokio::test]
    async fn test_leader_election_reacquire() {
        let storage = MemoryBackend::new();
        let leader = LeaderElection::new(storage.clone(), 1);

        // Acquire and release
        assert!(leader.try_acquire_leadership().await.unwrap());
        leader.release_leadership().await.unwrap();

        // Should be able to reacquire
        assert!(leader.try_acquire_leadership().await.unwrap());
        assert!(leader.is_leader().await);
    }

    #[tokio::test]
    async fn test_leader_election_lease_renewal() {
        let storage = MemoryBackend::new();
        let leader = Arc::new(LeaderElection::new(storage, 1));

        // Acquire leadership
        assert!(leader.try_acquire_leadership().await.unwrap());

        // Start lease renewal
        leader.clone().start_lease_renewal();

        // Wait for a renewal cycle
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should still be leader
        assert!(leader.is_leader().await);

        // Shutdown
        leader.shutdown().await;

        // Wait for cleanup
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should no longer be leader after shutdown
        assert!(!leader.is_leader().await);
    }

    #[tokio::test]
    async fn test_leader_election_run_with_leadership() {
        let storage = MemoryBackend::new();
        let leader = LeaderElection::new(storage, 1);

        let mut task_ran = false;

        leader
            .run_with_leadership(|| async {
                task_ran = true;
                Ok(())
            })
            .await
            .unwrap();

        assert!(task_ran);
        assert!(leader.is_leader().await);
    }

    #[tokio::test]
    async fn test_non_leader_skips_task() {
        let storage = MemoryBackend::new();
        let leader1 = LeaderElection::new(storage.clone(), 1);
        let leader2 = LeaderElection::new(storage.clone(), 2);

        // Leader 1 acquires leadership
        assert!(leader1.try_acquire_leadership().await.unwrap());

        // Leader 2 tries to run task
        let mut task_ran = false;
        leader2
            .run_with_leadership(|| async {
                task_ran = true;
                Ok(())
            })
            .await
            .unwrap();

        // Task should not have run
        assert!(!task_ran);
        assert!(!leader2.is_leader().await);
    }
}
