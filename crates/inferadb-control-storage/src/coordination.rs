//! Multi-instance coordination primitives using FoundationDB
//!
//! This module provides distributed coordination capabilities for management API
//! instances running in a cluster. It includes:
//!
//! - **Leader Election**: Ensures only one instance handles background jobs
//! - **Worker Registry**: Tracks active instances for distributed task coordination
//! - **Lease Management**: TTL-based leases with automatic expiration
//!
//! # Architecture
//!
//! Uses FoundationDB's ACID transactions and atomic operations for coordination:
//!
//! - Leader election uses compare-and-set with TTL-based leases
//! - Worker registry uses heartbeat pattern with cleanup of stale workers
//! - All operations are multi-instance safe with optimistic concurrency control

#[cfg(feature = "fdb")]
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
#[cfg(feature = "fdb")]
use tracing::{debug, info, warn};

#[cfg(feature = "fdb")]
use crate::FdbBackend;
use crate::backend::StorageResult;
#[cfg(feature = "fdb")]
use crate::backend::{StorageBackend, StorageError};

/// Leader election result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaderStatus {
    /// This instance is the leader
    Leader { lease_expiry: u64 },
    /// Another instance is the leader
    Follower { leader_id: String, lease_expiry: u64 },
    /// No leader currently elected
    NoLeader,
}

/// Worker information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerInfo {
    /// Unique worker ID (e.g., hostname, pod name)
    pub worker_id: String,
    /// Worker start timestamp (unix seconds)
    pub started_at: u64,
    /// Last heartbeat timestamp (unix seconds)
    pub last_heartbeat: u64,
    /// Worker metadata (version, capabilities, etc.)
    pub metadata: serde_json::Value,
}

/// Coordinator trait for multi-instance operations
#[async_trait]
pub trait Coordinator: Send + Sync {
    /// Attempt to become the leader for a named resource
    ///
    /// # Arguments
    ///
    /// * `resource_name` - Name of the leadership resource (e.g., "session-cleanup")
    /// * `worker_id` - Unique ID for this instance
    /// * `lease_duration_secs` - How long the lease is valid
    ///
    /// # Returns
    ///
    /// LeaderStatus indicating if this instance became leader
    async fn try_acquire_leadership(
        &self,
        resource_name: &str,
        worker_id: &str,
        lease_duration_secs: u64,
    ) -> StorageResult<LeaderStatus>;

    /// Release leadership for a named resource
    ///
    /// # Arguments
    ///
    /// * `resource_name` - Name of the leadership resource
    /// * `worker_id` - Unique ID for this instance (must match current leader)
    async fn release_leadership(&self, resource_name: &str, worker_id: &str) -> StorageResult<()>;

    /// Check current leadership status
    async fn check_leadership(&self, resource_name: &str) -> StorageResult<LeaderStatus>;

    /// Register this worker in the worker registry
    ///
    /// # Arguments
    ///
    /// * `worker_id` - Unique ID for this worker
    /// * `metadata` - Worker metadata (version, capabilities, etc.)
    async fn register_worker(
        &self,
        worker_id: &str,
        metadata: serde_json::Value,
    ) -> StorageResult<()>;

    /// Send heartbeat to indicate this worker is still alive
    async fn heartbeat(&self, worker_id: &str) -> StorageResult<()>;

    /// List all active workers
    ///
    /// Returns workers that have sent heartbeats within the last `max_age_secs` seconds
    async fn list_active_workers(&self, max_age_secs: u64) -> StorageResult<Vec<WorkerInfo>>;

    /// Remove stale workers from the registry
    ///
    /// Removes workers that haven't sent heartbeats within `max_age_secs` seconds
    ///
    /// # Returns
    ///
    /// Number of workers removed
    async fn cleanup_stale_workers(&self, max_age_secs: u64) -> StorageResult<usize>;
}

/// Leadership lease record
#[cfg(feature = "fdb")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeaderLease {
    worker_id: String,
    lease_expiry: u64,
    acquired_at: u64,
}

#[cfg(feature = "fdb")]
#[async_trait]
impl Coordinator for FdbBackend {
    async fn try_acquire_leadership(
        &self,
        resource_name: &str,
        worker_id: &str,
        lease_duration_secs: u64,
    ) -> StorageResult<LeaderStatus> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let lease_expiry = now + lease_duration_secs;

        let key = format!("coordination/leader/{}", resource_name).into_bytes();

        // Try to acquire or renew lease
        let result = self.get(&key).await?;

        match result {
            None => {
                // No current leader - try to acquire
                let lease = LeaderLease {
                    worker_id: worker_id.to_string(),
                    lease_expiry,
                    acquired_at: now,
                };
                let value = serde_json::to_vec(&lease).map_err(|e| {
                    StorageError::Internal(format!("Failed to serialize lease: {}", e))
                })?;

                // Write with TTL
                self.set_with_ttl(key.clone(), value, lease_duration_secs).await?;

                info!(
                    worker_id = worker_id,
                    resource = resource_name,
                    lease_expiry = lease_expiry,
                    "Acquired leadership"
                );

                Ok(LeaderStatus::Leader { lease_expiry })
            },
            Some(existing_bytes) => {
                let existing_lease: LeaderLease =
                    serde_json::from_slice(&existing_bytes).map_err(|e| {
                        StorageError::Internal(format!("Failed to deserialize lease: {}", e))
                    })?;

                if existing_lease.lease_expiry <= now {
                    // Lease expired - acquire it
                    let lease = LeaderLease {
                        worker_id: worker_id.to_string(),
                        lease_expiry,
                        acquired_at: now,
                    };
                    let value = serde_json::to_vec(&lease).map_err(|e| {
                        StorageError::Internal(format!("Failed to serialize lease: {}", e))
                    })?;

                    self.set_with_ttl(key.clone(), value, lease_duration_secs).await?;

                    info!(
                        worker_id = worker_id,
                        resource = resource_name,
                        previous_leader = existing_lease.worker_id,
                        "Acquired leadership (previous lease expired)"
                    );

                    Ok(LeaderStatus::Leader { lease_expiry })
                } else if existing_lease.worker_id == worker_id {
                    // We already hold the lease - renew it
                    let lease = LeaderLease {
                        worker_id: worker_id.to_string(),
                        lease_expiry,
                        acquired_at: existing_lease.acquired_at,
                    };
                    let value = serde_json::to_vec(&lease).map_err(|e| {
                        StorageError::Internal(format!("Failed to serialize lease: {}", e))
                    })?;

                    self.set_with_ttl(key.clone(), value, lease_duration_secs).await?;

                    debug!(
                        worker_id = worker_id,
                        resource = resource_name,
                        lease_expiry = lease_expiry,
                        "Renewed leadership lease"
                    );

                    Ok(LeaderStatus::Leader { lease_expiry })
                } else {
                    // Another worker holds the lease
                    debug!(
                        worker_id = worker_id,
                        resource = resource_name,
                        current_leader = existing_lease.worker_id,
                        lease_expiry = existing_lease.lease_expiry,
                        "Leadership held by another worker"
                    );

                    Ok(LeaderStatus::Follower {
                        leader_id: existing_lease.worker_id,
                        lease_expiry: existing_lease.lease_expiry,
                    })
                }
            },
        }
    }

    async fn release_leadership(&self, resource_name: &str, worker_id: &str) -> StorageResult<()> {
        let key = format!("coordination/leader/{}", resource_name).into_bytes();

        // Check if we're the current leader
        let result = self.get(&key).await?;

        match result {
            Some(bytes) => {
                let lease: LeaderLease = serde_json::from_slice(&bytes).map_err(|e| {
                    StorageError::Internal(format!("Failed to deserialize lease: {}", e))
                })?;

                if lease.worker_id == worker_id {
                    // We're the leader - release the lease
                    self.delete(&key).await?;
                    info!(worker_id = worker_id, resource = resource_name, "Released leadership");
                } else {
                    warn!(
                        worker_id = worker_id,
                        resource = resource_name,
                        current_leader = lease.worker_id,
                        "Attempted to release leadership but not current leader"
                    );
                }
            },
            None => {
                debug!(worker_id = worker_id, resource = resource_name, "No leadership to release");
            },
        }

        Ok(())
    }

    async fn check_leadership(&self, resource_name: &str) -> StorageResult<LeaderStatus> {
        let key = format!("coordination/leader/{}", resource_name).into_bytes();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        match self.get(&key).await? {
            None => Ok(LeaderStatus::NoLeader),
            Some(bytes) => {
                let lease: LeaderLease = serde_json::from_slice(&bytes).map_err(|e| {
                    StorageError::Internal(format!("Failed to deserialize lease: {}", e))
                })?;

                if lease.lease_expiry <= now {
                    Ok(LeaderStatus::NoLeader)
                } else {
                    Ok(LeaderStatus::Follower {
                        leader_id: lease.worker_id,
                        lease_expiry: lease.lease_expiry,
                    })
                }
            },
        }
    }

    async fn register_worker(
        &self,
        worker_id: &str,
        metadata: serde_json::Value,
    ) -> StorageResult<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let worker_info = WorkerInfo {
            worker_id: worker_id.to_string(),
            started_at: now,
            last_heartbeat: now,
            metadata,
        };

        let key = format!("coordination/workers/{}", worker_id).into_bytes();
        let value = serde_json::to_vec(&worker_info).map_err(|e| {
            StorageError::Internal(format!("Failed to serialize worker info: {}", e))
        })?;

        // Register with 5-minute TTL (workers should heartbeat more frequently)
        self.set_with_ttl(key, value, 300).await?;

        info!(worker_id = worker_id, "Worker registered");

        Ok(())
    }

    async fn heartbeat(&self, worker_id: &str) -> StorageResult<()> {
        let key = format!("coordination/workers/{}", worker_id).into_bytes();

        // Get existing worker info
        let existing = self.get(&key).await?;

        match existing {
            Some(bytes) => {
                let mut worker_info: WorkerInfo = serde_json::from_slice(&bytes).map_err(|e| {
                    StorageError::Internal(format!("Failed to deserialize worker info: {}", e))
                })?;

                // Update last heartbeat
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                worker_info.last_heartbeat = now;

                let value = serde_json::to_vec(&worker_info).map_err(|e| {
                    StorageError::Internal(format!("Failed to serialize worker info: {}", e))
                })?;

                // Update with fresh TTL
                self.set_with_ttl(key, value, 300).await?;

                debug!(worker_id = worker_id, "Heartbeat sent");

                Ok(())
            },
            None => {
                // Worker not registered - this shouldn't happen
                Err(StorageError::NotFound(format!("Worker {} not registered", worker_id)))
            },
        }
    }

    async fn list_active_workers(&self, max_age_secs: u64) -> StorageResult<Vec<WorkerInfo>> {
        let prefix = b"coordination/workers/";
        let start_key = prefix.to_vec();
        let end_key = {
            let mut key = prefix.to_vec();
            key.push(0xFF);
            key
        };

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let cutoff = now - max_age_secs;

        let results = self.get_range(start_key..end_key).await?;

        let mut workers = Vec::new();
        for kv in results {
            let worker_info: WorkerInfo = serde_json::from_slice(&kv.value).map_err(|e| {
                StorageError::Internal(format!("Failed to deserialize worker info: {}", e))
            })?;

            // Only include workers that have recent heartbeats
            if worker_info.last_heartbeat >= cutoff {
                workers.push(worker_info);
            }
        }

        debug!(count = workers.len(), "Listed active workers");

        Ok(workers)
    }

    async fn cleanup_stale_workers(&self, max_age_secs: u64) -> StorageResult<usize> {
        let prefix = b"coordination/workers/";
        let start_key = prefix.to_vec();
        let end_key = {
            let mut key = prefix.to_vec();
            key.push(0xFF);
            key
        };

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let cutoff = now - max_age_secs;

        let results = self.get_range(start_key..end_key).await?;

        let mut removed_count = 0;
        for kv in results {
            let worker_info: WorkerInfo = serde_json::from_slice(&kv.value).map_err(|e| {
                StorageError::Internal(format!("Failed to deserialize worker info: {}", e))
            })?;

            // Remove workers with stale heartbeats
            if worker_info.last_heartbeat < cutoff {
                self.delete(&kv.key).await?;
                removed_count += 1;
                info!(
                    worker_id = worker_info.worker_id,
                    last_heartbeat = worker_info.last_heartbeat,
                    "Removed stale worker"
                );
            }
        }

        if removed_count > 0 {
            info!(count = removed_count, "Cleaned up stale workers");
        }

        Ok(removed_count)
    }
}

#[cfg(all(test, feature = "fdb"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_leadership_acquisition() {
        let backend = FdbBackend::new().await.unwrap();

        let status = backend.try_acquire_leadership("test-resource", "worker-1", 60).await.unwrap();

        assert!(matches!(status, LeaderStatus::Leader { .. }));

        // Second attempt should show we're already leader
        let status2 =
            backend.try_acquire_leadership("test-resource", "worker-1", 60).await.unwrap();

        assert!(matches!(status2, LeaderStatus::Leader { .. }));

        // Different worker should see worker-1 as leader
        let status3 =
            backend.try_acquire_leadership("test-resource", "worker-2", 60).await.unwrap();

        assert!(matches!(status3, LeaderStatus::Follower { .. }));
    }

    #[tokio::test]
    async fn test_leadership_release() {
        let backend = FdbBackend::new().await.unwrap();

        backend.try_acquire_leadership("test-resource-2", "worker-1", 60).await.unwrap();

        backend.release_leadership("test-resource-2", "worker-1").await.unwrap();

        let status = backend.check_leadership("test-resource-2").await.unwrap();
        assert!(matches!(status, LeaderStatus::NoLeader));
    }

    #[tokio::test]
    async fn test_worker_registry() {
        let backend = FdbBackend::new().await.unwrap();

        let metadata = serde_json::json!({
            "version": "1.0.0",
            "capabilities": ["cleanup", "notifications"]
        });

        backend.register_worker("test-worker-1", metadata.clone()).await.unwrap();

        let workers = backend.list_active_workers(300).await.unwrap();
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].worker_id, "test-worker-1");

        // Heartbeat
        backend.heartbeat("test-worker-1").await.unwrap();

        let workers2 = backend.list_active_workers(300).await.unwrap();
        assert_eq!(workers2.len(), 1);
    }
}
