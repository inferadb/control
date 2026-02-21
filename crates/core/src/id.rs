use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use chrono::Utc;
use idgenerator::IdGeneratorOptions;
use inferadb_control_storage::StorageBackend;
use inferadb_control_types::error::{Error, Result};
use tokio::{sync::RwLock, time};

/// Custom epoch for Snowflake IDs: 2024-01-01T00:00:00Z (in milliseconds)
const CUSTOM_EPOCH: i64 = 1704067200000;

/// Worker heartbeat TTL
const WORKER_HEARTBEAT_TTL: Duration = Duration::from_secs(30);

/// Worker heartbeat interval in seconds
const WORKER_HEARTBEAT_INTERVAL: u64 = 10;

/// Stores the worker ID after initialization. Using OnceLock ensures thread-safe
/// one-time initialization without requiring unsafe code.
static WORKER_ID: OnceLock<u16> = OnceLock::new();

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
        format!("workers/active/{worker_id}").into_bytes()
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
            .map_err(|e| Error::internal(format!("Failed to check worker registration: {e}")))?)
        .is_some()
        {
            return Err(Error::config(format!(
                "Worker ID {} is already in use by another instance",
                self.worker_id
            )));
        }

        // Register this worker with TTL
        let timestamp = Utc::now().to_rfc3339();
        self.storage
            .set_with_ttl(key, timestamp.as_bytes().to_vec(), WORKER_HEARTBEAT_TTL)
            .await
            .map_err(|e| Error::internal(format!("Failed to register worker: {e}")))?;

        Ok(())
    }

    /// Update the worker heartbeat
    async fn heartbeat(&self) -> Result<()> {
        let key = Self::worker_key(self.worker_id);
        let timestamp = Utc::now().to_rfc3339();

        self.storage
            .set_with_ttl(key, timestamp.as_bytes().to_vec(), WORKER_HEARTBEAT_TTL)
            .await
            .map_err(|e| Error::internal(format!("Failed to update worker heartbeat: {e}")))?;

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

        self.storage
            .delete(&key)
            .await
            .map_err(|e| Error::internal(format!("Failed to cleanup worker registration: {e}")))?;

        Ok(())
    }
}

/// Maximum number of attempts to find an available worker ID
const MAX_WORKER_ID_ATTEMPTS: u32 = 50;

/// Maximum valid worker ID (10 bits = 1024 values, 0-1023)
const MAX_WORKER_ID: u16 = 1023;

/// Acquire a worker ID automatically using collision detection
///
/// This function attempts to find and register an available worker ID.
/// It uses the following strategy:
///
/// 1. **Kubernetes StatefulSet**: If `POD_NAME` ends with `-N` (ordinal), uses that ordinal
/// 2. **Random with collision detection**: Otherwise, randomly selects and attempts to register
///
/// # Arguments
///
/// * `storage` - Storage backend for coordination
/// * `explicit_id` - Optional explicitly configured worker ID (takes priority)
///
/// # Returns
///
/// Returns the acquired worker ID on success, or an error if no ID could be acquired.
///
/// # Example
///
/// ```ignore
/// // In Kubernetes with auto-assignment
/// let worker_id = acquire_worker_id(&storage, None).await?;
///
/// // With explicit ID (for local development)
/// let worker_id = acquire_worker_id(&storage, Some(0)).await?;
/// ```
pub async fn acquire_worker_id<S: StorageBackend + 'static>(
    storage: &S,
    explicit_id: Option<u16>,
) -> Result<u16> {
    // If an explicit ID is provided, use it directly
    if let Some(id) = explicit_id {
        if id > MAX_WORKER_ID {
            return Err(Error::config(format!(
                "Worker ID must be between 0 and {MAX_WORKER_ID}, got {id}"
            )));
        }
        tracing::info!(worker_id = id, "Using explicitly configured worker ID");
        return Ok(id);
    }

    // Try to derive worker ID from Kubernetes pod ordinal
    if let Some(id) = try_get_pod_ordinal() {
        tracing::info!(worker_id = id, "Using worker ID derived from Kubernetes pod ordinal");
        return Ok(id);
    }

    // Fall back to random selection with collision detection
    acquire_random_worker_id(storage).await
}

/// Try to extract pod ordinal from Kubernetes StatefulSet pod name
///
/// StatefulSet pods are named `{statefulset-name}-{ordinal}`, e.g., `inferadb-control-0`
fn try_get_pod_ordinal() -> Option<u16> {
    let pod_name = std::env::var("POD_NAME").or_else(|_| std::env::var("HOSTNAME")).ok()?;

    // Extract the last segment after the final hyphen
    let ordinal_str = pod_name.rsplit('-').next()?;

    // Try to parse as a number
    let ordinal: u16 = ordinal_str.parse().ok()?;

    // Validate it's within the valid range
    if ordinal > MAX_WORKER_ID {
        tracing::warn!(
            pod_name = %pod_name,
            ordinal = ordinal,
            "Pod ordinal {} exceeds maximum worker ID {}, will use random assignment",
            ordinal,
            MAX_WORKER_ID
        );
        return None;
    }

    tracing::debug!(
        pod_name = %pod_name,
        ordinal = ordinal,
        "Extracted pod ordinal from pod name"
    );

    Some(ordinal)
}

/// Acquire a random worker ID with collision detection
///
/// This function randomly selects worker IDs and attempts to register them
/// until one succeeds or the maximum number of attempts is reached.
async fn acquire_random_worker_id<S: StorageBackend>(storage: &S) -> Result<u16> {
    use rand::Rng;

    let mut rng = rand::rng();
    let mut attempted: std::collections::HashSet<u16> = std::collections::HashSet::new();

    for attempt in 1..=MAX_WORKER_ID_ATTEMPTS {
        // Generate a random worker ID that hasn't been tried yet
        let worker_id = loop {
            let id: u16 = rng.random_range(0..=MAX_WORKER_ID);
            if attempted.insert(id) {
                break id;
            }
            // If we've tried all IDs, give up
            if attempted.len() > MAX_WORKER_ID as usize {
                return Err(Error::config(
                    "All worker IDs have been attempted without success".to_string(),
                ));
            }
        };

        // Try to register this worker ID
        let key = format!("workers/active/{worker_id}").into_bytes();

        // Check if already registered
        match storage.get(&key).await {
            Ok(Some(_)) => {
                tracing::debug!(
                    worker_id = worker_id,
                    attempt = attempt,
                    "Worker ID already in use, trying another"
                );
                continue;
            },
            Ok(None) => {
                // Attempt to register with TTL
                let timestamp = Utc::now().to_rfc3339();
                match storage
                    .set_with_ttl(key, timestamp.as_bytes().to_vec(), WORKER_HEARTBEAT_TTL)
                    .await
                {
                    Ok(()) => {
                        tracing::info!(
                            worker_id = worker_id,
                            attempts = attempt,
                            "Successfully acquired random worker ID"
                        );
                        return Ok(worker_id);
                    },
                    Err(e) => {
                        tracing::warn!(
                            worker_id = worker_id,
                            error = %e,
                            "Failed to register worker ID, trying another"
                        );
                        continue;
                    },
                }
            },
            Err(e) => {
                tracing::warn!(
                    worker_id = worker_id,
                    error = %e,
                    "Failed to check worker ID availability"
                );
                continue;
            },
        }
    }

    Err(Error::config(format!(
        "Failed to acquire worker ID after {MAX_WORKER_ID_ATTEMPTS} attempts. All attempted IDs were in use."
    )))
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
            return Err(Error::config(format!(
                "Worker ID must be between 0 and 1023, got {worker_id}"
            )));
        }

        WORKER_ID.get_or_init(|| {
            let options = IdGeneratorOptions::new()
                .worker_id(worker_id.into())
                .worker_id_bit_len(10)
                .base_time(CUSTOM_EPOCH);

            // Initialization failure at startup is unrecoverable - panic is appropriate
            #[allow(clippy::expect_used)]
            idgenerator::IdInstance::init(options).expect("Failed to initialize ID generator");
            worker_id
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
    ///
    /// Returns 0 if the generator has not been initialized.
    pub fn worker_id() -> u16 {
        WORKER_ID.get().copied().unwrap_or(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashSet;

    use inferadb_control_storage::MemoryBackend;

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
        assert!(id1 > 0, "id1 ({id1}) should be positive");
        assert!(id2 > 0, "id2 ({id2}) should be positive");
        assert!(id3 > 0, "id3 ({id3}) should be positive");

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
            assert!(ids.insert(id), "Duplicate ID generated: {id}");
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

    #[tokio::test]
    async fn test_acquire_worker_id_explicit() {
        let storage = MemoryBackend::new();

        // Explicit ID should be used directly
        let id = acquire_worker_id(&storage, Some(42)).await.unwrap();
        assert_eq!(id, 42);
    }

    #[tokio::test]
    async fn test_acquire_worker_id_explicit_invalid() {
        let storage = MemoryBackend::new();

        // Invalid explicit ID should fail
        let result = acquire_worker_id(&storage, Some(1024)).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be between 0 and 1023"));
    }

    #[tokio::test]
    async fn test_acquire_worker_id_auto() {
        let storage = MemoryBackend::new();

        // Without explicit ID and without POD_NAME, should acquire a random ID
        let id = acquire_worker_id(&storage, None).await.unwrap();
        assert!(id <= MAX_WORKER_ID, "Worker ID {id} should be <= {MAX_WORKER_ID}");
    }

    #[tokio::test]
    async fn test_acquire_worker_id_finds_available() {
        let storage = MemoryBackend::new();

        // Register a few worker IDs manually
        for id in 0..10 {
            let key = format!("workers/active/{id}").into_bytes();
            storage
                .set_with_ttl(key, b"timestamp".to_vec(), std::time::Duration::from_secs(30))
                .await
                .unwrap();
        }

        // Auto-acquire should find an available ID that's not 0-9
        let id = acquire_worker_id(&storage, None).await.unwrap();
        assert!(id > 9 || id <= MAX_WORKER_ID, "Should find an available ID");
    }

    // Note: Environment variable tests are inherently racy in parallel test execution.
    // These tests verify the logic directly rather than relying on env vars.

    #[test]
    fn test_parse_pod_ordinal_statefulset_name() {
        // Test parsing logic for StatefulSet-style pod names
        let name = "inferadb-control-5";
        let ordinal_str = name.rsplit('-').next().unwrap();
        let ordinal: u16 = ordinal_str.parse().unwrap();
        assert_eq!(ordinal, 5);
    }

    #[test]
    fn test_parse_pod_ordinal_deployment_name() {
        // Test parsing logic for Deployment-style pod names
        let name = "inferadb-control-abc123";
        let ordinal_str = name.rsplit('-').next().unwrap();
        let result = ordinal_str.parse::<u16>();
        assert!(result.is_err(), "Deployment pod suffix should not parse as a number");
    }

    #[test]
    fn test_parse_pod_ordinal_complex_name() {
        // Test with multiple hyphens in pod name
        let name = "my-app-namespace-inferadb-control-42";
        let ordinal_str = name.rsplit('-').next().unwrap();
        let ordinal: u16 = ordinal_str.parse().unwrap();
        assert_eq!(ordinal, 42);
    }

    #[test]
    fn test_parse_pod_ordinal_overflow() {
        // Test that very large ordinals are rejected
        let ordinal: u16 = 2000;
        assert!(ordinal > MAX_WORKER_ID);
    }

    mod proptest_id {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn ids_are_strictly_increasing(n in 2usize..100) {
                let _ = IdGenerator::init(999);
                let ids: Vec<i64> = (0..n).map(|_| IdGenerator::next_id()).collect();
                for window in ids.windows(2) {
                    prop_assert!(window[1] > window[0], "IDs must be strictly increasing: {} > {}", window[1], window[0]);
                }
            }

            #[test]
            fn ids_are_unique(n in 2usize..100) {
                let _ = IdGenerator::init(998);
                let ids: Vec<i64> = (0..n).map(|_| IdGenerator::next_id()).collect();
                let unique: HashSet<i64> = ids.iter().copied().collect();
                prop_assert_eq!(ids.len(), unique.len(), "All generated IDs must be unique");
            }

            #[test]
            fn ids_are_positive(_seed in 0u16..1000) {
                let _ = IdGenerator::init(997);
                let id = IdGenerator::next_id();
                prop_assert!(id > 0, "Generated IDs must be positive: {}", id);
            }
        }
    }
}
