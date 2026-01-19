//! Multi-instance coordination primitives
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
//! Uses the storage backend's ACID transactions and atomic operations for coordination:
//!
//! - Leader election uses compare-and-set with TTL-based leases
//! - Worker registry uses heartbeat pattern with cleanup of stale workers
//! - All operations are multi-instance safe with optimistic concurrency control

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::backend::StorageResult;

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
