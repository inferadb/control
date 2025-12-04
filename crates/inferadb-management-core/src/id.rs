use std::{
    sync::{Arc, Once},
    time::Duration,
};

use chrono::Utc;
use idgenerator::IdGeneratorOptions;
use inferadb_management_storage::StorageBackend;
use inferadb_management_types::error::{Error, Result};
use tokio::{sync::RwLock, time};

/// Custom epoch for Snowflake IDs: 2024-01-01T00:00:00Z (in milliseconds)
const CUSTOM_EPOCH: i64 = 1704067200000;

/// Worker heartbeat TTL in seconds
const WORKER_HEARTBEAT_TTL: u64 = 30;

/// Worker heartbeat interval in seconds
const WORKER_HEARTBEAT_INTERVAL: u64 = 10;

static INIT: Once = Once::new();
static mut WORKER_ID: u16 = 0;

/// Worker ID registration manager for multi-instance coordination
pub struct WorkerRegistry<S: StorageBackend> {
    storage: S,
    worker_id: u16,
    shutdown: Arc<RwLock<bool>>,
}

impl<S: StorageBackend + 'static> WorkerRegistry<S> {
    /// Create a new worker registry
    pub fn new(storage: S, worker_id: u16) -> Self {
        Self { storage, worker_id, shutdown: Arc::new(RwLock::new(false)) }
    }

    /// Generate storage key for worker registration
    fn worker_key(worker_id: u16) -> Vec<u8> {
        format!("workers/active/{}", worker_id).into_bytes()
    }

    /// Register this worker and check for collisions
    ///
    /// Returns Ok(()) if registration succeeds, Err if worker ID is already in use
    pub async fn register(&self) -> Result<()> {
        let key = Self::worker_key(self.worker_id);

        // Check if worker ID is already registered
        if (self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to check worker registration: {}", e)))?)
        .is_some()
        {
            return Err(Error::Config(format!(
                "Worker ID {} is already in use by another instance",
                self.worker_id
            )));
        }

        // Register this worker with TTL
        let timestamp = Utc::now().to_rfc3339();
        self.storage
            .set_with_ttl(key, timestamp.as_bytes().to_vec(), WORKER_HEARTBEAT_TTL)
            .await
            .map_err(|e| Error::Internal(format!("Failed to register worker: {}", e)))?;

        Ok(())
    }

    /// Update the worker heartbeat
    async fn heartbeat(&self) -> Result<()> {
        let key = Self::worker_key(self.worker_id);
        let timestamp = Utc::now().to_rfc3339();

        self.storage
            .set_with_ttl(key, timestamp.as_bytes().to_vec(), WORKER_HEARTBEAT_TTL)
            .await
            .map_err(|e| Error::Internal(format!("Failed to update worker heartbeat: {}", e)))?;

        Ok(())
    }

    /// Start the heartbeat task
    ///
    /// This spawns a background task that periodically updates the worker registration
    pub fn start_heartbeat(self: Arc<Self>) {
        let registry = Arc::clone(&self);

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(WORKER_HEARTBEAT_INTERVAL));

            loop {
                interval.tick().await;

                // Check if shutdown requested
                {
                    let shutdown = registry.shutdown.read().await;
                    if *shutdown {
                        break;
                    }
                }

                // Update heartbeat
                if let Err(e) = registry.heartbeat().await {
                    tracing::error!("Failed to update worker heartbeat: {}", e);
                }
            }

            // Cleanup on shutdown
            if let Err(e) = registry.cleanup().await {
                tracing::error!("Failed to cleanup worker registration: {}", e);
            }
        });
    }

    /// Request shutdown of the heartbeat task
    pub async fn shutdown(&self) {
        let mut shutdown = self.shutdown.write().await;
        *shutdown = true;
    }

    /// Remove this worker's registration
    async fn cleanup(&self) -> Result<()> {
        let key = Self::worker_key(self.worker_id);

        self.storage.delete(&key).await.map_err(|e| {
            Error::Internal(format!("Failed to cleanup worker registration: {}", e))
        })?;

        Ok(())
    }
}

/// Snowflake ID generator with custom epoch and worker ID management
pub struct IdGenerator;

impl IdGenerator {
    /// Initialize the global ID generator with the specified worker ID
    ///
    /// This must be called once at application startup before generating any IDs.
    ///
    /// # Arguments
    ///
    /// * `worker_id` - Worker ID (0-1023) for this instance
    ///
    /// # Errors
    ///
    /// Returns an error if worker_id is out of range or initialization fails
    pub fn init(worker_id: u16) -> Result<()> {
        if worker_id > 1023 {
            return Err(Error::Config(format!(
                "Worker ID must be between 0 and 1023, got {}",
                worker_id
            )));
        }

        let options = IdGeneratorOptions::new()
            .worker_id(worker_id.into())
            .worker_id_bit_len(10)
            .base_time(CUSTOM_EPOCH);

        INIT.call_once(|| {
            unsafe {
                WORKER_ID = worker_id;
            }
            idgenerator::IdInstance::init(options).expect("Failed to initialize ID generator");
        });

        Ok(())
    }

    /// Generate a new unique ID
    ///
    /// # Returns
    ///
    /// A unique 64-bit Snowflake ID
    ///
    /// # Panics
    ///
    /// Panics if `init()` has not been called first
    pub fn next_id() -> i64 {
        idgenerator::IdInstance::next_id()
    }

    /// Get the worker ID for this generator
    pub fn worker_id() -> u16 {
        unsafe { WORKER_ID }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use inferadb_management_storage::MemoryBackend;

    use super::*;

    #[test]
    fn test_id_generation() {
        // Initialize with worker ID 0, but may already be initialized by other tests
        let _ = IdGenerator::init(0);

        // Generate multiple IDs to verify they're unique and positive
        let id1 = IdGenerator::next_id();
        let id2 = IdGenerator::next_id();
        let id3 = IdGenerator::next_id();

        // All IDs should be positive
        assert!(id1 > 0, "id1 ({}) should be positive", id1);
        assert!(id2 > 0, "id2 ({}) should be positive", id2);
        assert!(id3 > 0, "id3 ({}) should be positive", id3);

        // All IDs should be unique (the core requirement)
        assert_ne!(id1, id2, "id1 and id2 should be different");
        assert_ne!(id2, id3, "id2 and id3 should be different");
        assert_ne!(id1, id3, "id1 and id3 should be different");
    }

    #[test]
    fn test_worker_id_validation() {
        // Invalid worker ID (out of range)
        assert!(IdGenerator::init(1024).is_err());

        // Valid worker IDs - but may already be initialized by other tests
        // so we just verify it doesn't panic
        let _ = IdGenerator::init(1023);
    }

    #[test]
    fn test_id_uniqueness() {
        // May already be initialized by other tests, which is fine
        let _ = IdGenerator::init(1);
        let mut ids = HashSet::new();

        for _ in 0..1000 {
            let id = IdGenerator::next_id();
            assert!(ids.insert(id), "Duplicate ID generated: {}", id);
        }
    }

    #[tokio::test]
    async fn test_worker_registry_registration() {
        let storage = MemoryBackend::new();
        let registry = WorkerRegistry::new(storage, 1);

        // First registration should succeed
        assert!(registry.register().await.is_ok());
    }

    #[tokio::test]
    async fn test_worker_registry_collision_detection() {
        let storage = MemoryBackend::new();
        let registry1 = WorkerRegistry::new(storage.clone(), 1);
        let registry2 = WorkerRegistry::new(storage.clone(), 1);

        // First registration succeeds
        registry1.register().await.unwrap();

        // Second registration with same worker ID should fail
        let result = registry2.register().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already in use"));
    }

    #[tokio::test]
    async fn test_worker_registry_cleanup() {
        let storage = MemoryBackend::new();
        let registry = WorkerRegistry::new(storage.clone(), 2);

        // Register
        registry.register().await.unwrap();

        // Verify registration exists
        let key = WorkerRegistry::<MemoryBackend>::worker_key(2);
        assert!(storage.get(&key).await.unwrap().is_some());

        // Cleanup
        registry.cleanup().await.unwrap();

        // Verify registration is removed
        assert!(storage.get(&key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_worker_registry_heartbeat() {
        let storage = MemoryBackend::new();
        let registry = Arc::new(WorkerRegistry::new(storage.clone(), 3));

        // Register
        registry.register().await.unwrap();

        // Start heartbeat
        registry.clone().start_heartbeat();

        // Wait a bit for heartbeat to run
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify registration still exists
        let key = WorkerRegistry::<MemoryBackend>::worker_key(3);
        assert!(storage.get(&key).await.unwrap().is_some());

        // Request shutdown
        registry.shutdown().await;

        // Wait for cleanup
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
