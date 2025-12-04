use std::{sync::Arc, time::Duration};

use inferadb_management_storage::StorageBackend;
use inferadb_management_types::error::Result;
use tokio::{task::JoinHandle, time};

use crate::{
    leader::LeaderElection,
    repository::{AuditLogRepository, UserSessionRepository, VaultRefreshTokenRepository},
};

/// Background job scheduler
///
/// Runs periodic cleanup and maintenance tasks. Jobs only run on the leader instance
/// to avoid duplicate work in multi-instance deployments.
///
/// # Jobs
///
/// - **Expired session cleanup** (daily): Remove expired user sessions
/// - **Expired token cleanup** (daily): Remove expired verification and reset tokens
/// - **Expired refresh token cleanup** (daily): Remove old used/expired refresh tokens
/// - **Expired authorization code cleanup** (hourly): Clean up old authorization codes
/// - **Audit log retention** (daily): Remove audit logs older than 90 days
///
/// # Usage
///
/// ```rust,no_run
/// use inferadb_management_core::BackgroundJobs;
/// use inferadb_management_core::LeaderElection;
/// use inferadb_management_storage::MemoryBackend;
/// use std::sync::Arc;
///
/// # async fn example() {
/// let storage = MemoryBackend::new();
/// let leader = Arc::new(LeaderElection::new(storage.clone(), 1));
///
/// let jobs = BackgroundJobs::new(storage, leader);
/// jobs.start().await;
///
/// // Jobs will run in background...
///
/// jobs.stop().await;
/// # }
/// ```
pub struct BackgroundJobs<S: StorageBackend> {
    storage: S,
    leader: Arc<LeaderElection<S>>,
    shutdown: Arc<tokio::sync::RwLock<bool>>,
    handles: Arc<tokio::sync::Mutex<Vec<JoinHandle<()>>>>,
}

impl<S: StorageBackend + Clone + Send + Sync + 'static> BackgroundJobs<S> {
    /// Create a new background job scheduler
    ///
    /// # Arguments
    ///
    /// * `storage` - Storage backend
    /// * `leader` - Leader election coordinator
    pub fn new(storage: S, leader: Arc<LeaderElection<S>>) -> Self {
        Self {
            storage,
            leader,
            shutdown: Arc::new(tokio::sync::RwLock::new(false)),
            handles: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    /// Start all background jobs
    ///
    /// Spawns background tasks for each job. Jobs will only execute when this instance is the
    /// leader.
    pub async fn start(&self) {
        let mut handles = self.handles.lock().await;

        // Session cleanup (daily at 2 AM)
        handles.push(self.spawn_daily_job("session_cleanup", 2, 0, |storage, _leader| {
            Box::pin(async move { Self::cleanup_expired_sessions(storage).await })
        }));

        // Token cleanup (daily at 3 AM)
        handles.push(self.spawn_daily_job("token_cleanup", 3, 0, |storage, _leader| {
            Box::pin(async move { Self::cleanup_expired_tokens(storage).await })
        }));

        // Refresh token cleanup (daily at 4 AM)
        handles.push(self.spawn_daily_job("refresh_token_cleanup", 4, 0, |storage, _leader| {
            Box::pin(async move { Self::cleanup_expired_refresh_tokens(storage).await })
        }));

        // Authorization code cleanup (hourly)
        handles.push(self.spawn_hourly_job("authz_code_cleanup", |storage, _leader| {
            Box::pin(async move { Self::cleanup_expired_authorization_codes(storage).await })
        }));

        // Audit log retention cleanup (daily at 5 AM)
        handles.push(self.spawn_daily_job("audit_log_cleanup", 5, 0, |storage, _leader| {
            Box::pin(async move { Self::cleanup_old_audit_logs(storage).await })
        }));

        tracing::info!("Background jobs started");
    }

    /// Stop all background jobs
    pub async fn stop(&self) {
        // Signal shutdown
        {
            let mut shutdown = self.shutdown.write().await;
            *shutdown = true;
        }

        // Wait for all jobs to complete
        let mut handles = self.handles.lock().await;
        for handle in handles.drain(..) {
            handle.abort();
        }

        tracing::info!("Background jobs stopped");
    }

    /// Spawn a job that runs daily at a specific time
    fn spawn_daily_job<F, Fut>(
        &self,
        name: &'static str,
        hour: u32,
        minute: u32,
        task: F,
    ) -> JoinHandle<()>
    where
        F: Fn(S, Arc<LeaderElection<S>>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let storage = self.storage.clone();
        let leader = Arc::clone(&self.leader);
        let shutdown = Arc::clone(&self.shutdown);

        tokio::spawn(async move {
            // Calculate initial delay to next scheduled time
            let now = chrono::Utc::now();
            let target_time = now
                .date_naive()
                .and_hms_opt(hour, minute, 0)
                .unwrap()
                .and_local_timezone(chrono::Utc)
                .unwrap();

            let target_time = if target_time <= now {
                // If target time has passed today, schedule for tomorrow
                target_time + chrono::Duration::days(1)
            } else {
                target_time
            };

            let initial_delay = (target_time - now).num_seconds().max(0) as u64;

            // Wait for initial delay
            tokio::time::sleep(Duration::from_secs(initial_delay)).await;

            // Run daily
            let mut interval = time::interval(Duration::from_secs(24 * 60 * 60));

            loop {
                interval.tick().await;

                // Check shutdown
                if *shutdown.read().await {
                    break;
                }

                // Only run if we're the leader
                if !leader.is_leader().await {
                    tracing::debug!(job = name, "Skipping job (not leader)");
                    continue;
                }

                tracing::info!(job = name, "Running daily job");

                if let Err(e) = task(storage.clone(), Arc::clone(&leader)).await {
                    tracing::error!(job = name, error = %e, "Daily job failed");
                }
            }

            tracing::debug!(job = name, "Daily job stopped");
        })
    }

    /// Spawn a job that runs hourly
    fn spawn_hourly_job<F, Fut>(&self, name: &'static str, task: F) -> JoinHandle<()>
    where
        F: Fn(S, Arc<LeaderElection<S>>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let storage = self.storage.clone();
        let leader = Arc::clone(&self.leader);
        let shutdown = Arc::clone(&self.shutdown);

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60 * 60));

            loop {
                interval.tick().await;

                // Check shutdown
                if *shutdown.read().await {
                    break;
                }

                // Only run if we're the leader
                if !leader.is_leader().await {
                    tracing::debug!(job = name, "Skipping job (not leader)");
                    continue;
                }

                tracing::info!(job = name, "Running hourly job");

                if let Err(e) = task(storage.clone(), Arc::clone(&leader)).await {
                    tracing::error!(job = name, error = %e, "Hourly job failed");
                }
            }

            tracing::debug!(job = name, "Hourly job stopped");
        })
    }

    /// Cleanup expired user sessions
    async fn cleanup_expired_sessions(storage: S) -> Result<()> {
        let repo = UserSessionRepository::new(storage);
        let cleaned = repo.cleanup_expired().await?;

        tracing::info!(count = cleaned, "Cleaned up expired sessions");

        Ok(())
    }

    /// Cleanup expired email verification and password reset tokens
    async fn cleanup_expired_tokens(_storage: S) -> Result<()> {
        // Token cleanup is handled by TTL on the storage layer
        // This is a placeholder for future detailed cleanup if needed
        tracing::debug!("Token cleanup skipped (TTL-based expiry in storage layer)");
        Ok(())
    }

    /// Cleanup old used/expired refresh tokens
    async fn cleanup_expired_refresh_tokens(storage: S) -> Result<()> {
        let repo = VaultRefreshTokenRepository::new(storage);

        // Use the existing cleanup method
        let cleaned = repo.delete_expired().await?;

        tracing::info!(count = cleaned, "Cleaned up old refresh tokens");

        Ok(())
    }

    /// Cleanup expired authorization codes
    ///
    /// Authorization codes have 10-minute TTL and are cleaned up automatically by storage layer TTL
    async fn cleanup_expired_authorization_codes(_storage: S) -> Result<()> {
        // Authorization code cleanup is handled by TTL on the storage layer
        tracing::debug!("Authorization code cleanup skipped (TTL-based expiry in storage layer)");
        Ok(())
    }

    /// Cleanup old audit logs (90-day retention)
    ///
    /// Deletes audit logs older than 90 days to comply with retention policy
    async fn cleanup_old_audit_logs(storage: S) -> Result<()> {
        let repo = AuditLogRepository::new(storage);

        // Calculate cutoff date (90 days ago)
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(90);

        let deleted = repo.delete_older_than(cutoff_date).await?;

        if deleted > 0 {
            tracing::info!(
                count = deleted,
                cutoff_date = %cutoff_date.format("%Y-%m-%d"),
                "Cleaned up old audit logs"
            );
        } else {
            tracing::debug!("No old audit logs to clean up");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use inferadb_management_storage::MemoryBackend;

    use super::*;

    #[tokio::test]
    async fn test_background_jobs_start_stop() {
        let storage = MemoryBackend::new();
        let leader = Arc::new(LeaderElection::new(storage.clone(), 1));

        // Acquire leadership
        leader.try_acquire_leadership().await.unwrap();

        let jobs = BackgroundJobs::new(storage, leader);

        jobs.start().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        jobs.stop().await;
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let storage = MemoryBackend::new();

        // This just tests the function doesn't error
        let result = BackgroundJobs::<MemoryBackend>::cleanup_expired_sessions(storage).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_token_cleanup() {
        let storage = MemoryBackend::new();

        let result = BackgroundJobs::<MemoryBackend>::cleanup_expired_tokens(storage).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_refresh_token_cleanup() {
        let storage = MemoryBackend::new();

        let result = BackgroundJobs::<MemoryBackend>::cleanup_expired_refresh_tokens(storage).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_authorization_code_cleanup() {
        let storage = MemoryBackend::new();

        let result =
            BackgroundJobs::<MemoryBackend>::cleanup_expired_authorization_codes(storage).await;
        assert!(result.is_ok());
    }
}
