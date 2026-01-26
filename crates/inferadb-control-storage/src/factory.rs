use std::{ops::RangeBounds, sync::Arc};

use async_trait::async_trait;
use bon::Builder;
use bytes::Bytes;
use inferadb_storage::{
    KeyValue, StorageBackend, StorageResult, Transaction,
    auth::{
        MemorySigningKeyStore, PublicSigningKeyStore, SigningKeyMetrics, SigningKeyMetricsSnapshot,
    },
};
use inferadb_storage_ledger::{LedgerBackend, LedgerBackendConfig, auth::LedgerSigningKeyStore};

use crate::MemoryBackend;

/// Storage backend type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageBackendType {
    /// In-memory storage (for development and testing)
    Memory,
    /// Ledger storage (production backend)
    Ledger,
}

/// Ledger-specific configuration
#[derive(Debug, Clone, Builder)]
#[builder(on(String, into))]
pub struct LedgerConfig {
    /// Ledger server endpoint (e.g., "http://localhost:50051")
    pub endpoint: String,
    /// Client ID for idempotency tracking
    pub client_id: String,
    /// Namespace ID for data scoping
    pub namespace_id: i64,
    /// Optional vault ID for finer-grained scoping
    pub vault_id: Option<i64>,
}

/// Storage backend configuration
#[derive(Debug, Clone, Builder)]
pub struct StorageConfig {
    /// Backend type
    pub backend_type: StorageBackendType,
    /// Ledger configuration (only used for Ledger backend)
    pub ledger: Option<LedgerConfig>,
}

impl StorageConfig {
    /// Create a new in-memory storage configuration
    pub fn memory() -> Self {
        Self { backend_type: StorageBackendType::Memory, ledger: None }
    }

    /// Create a new Ledger storage configuration
    pub fn ledger(config: LedgerConfig) -> Self {
        Self { backend_type: StorageBackendType::Ledger, ledger: Some(config) }
    }
}

/// Backend enum wrapper that implements StorageBackend
#[derive(Clone)]
pub enum Backend {
    /// In-memory backend with shared signing key store
    Memory {
        /// The underlying memory storage backend
        storage: MemoryBackend,
        /// Shared signing key store for memory testing
        signing_keys: Arc<MemorySigningKeyStore>,
    },
    /// Ledger backend for production
    Ledger {
        /// The underlying Ledger storage backend
        backend: LedgerBackend,
        /// Metrics collector for signing key operations
        signing_key_metrics: SigningKeyMetrics,
    },
}

impl Backend {
    /// Creates a new in-memory backend.
    ///
    /// The memory backend is primarily for testing and includes a shared
    /// signing key store for consistency across handler calls.
    #[must_use]
    pub fn memory() -> Self {
        Backend::Memory {
            storage: MemoryBackend::new(),
            signing_keys: Arc::new(MemorySigningKeyStore::new()),
        }
    }

    /// Returns a reference to the underlying `MemoryBackend` if this is a memory backend.
    ///
    /// This is useful in tests where you need to access the raw storage backend
    /// for creating repository instances that share the same data store.
    ///
    /// # Returns
    ///
    /// `Some(&MemoryBackend)` for memory backends, `None` for other backends.
    #[must_use]
    pub fn as_memory(&self) -> Option<&MemoryBackend> {
        match self {
            Backend::Memory { storage, .. } => Some(storage),
            Backend::Ledger { .. } => None,
        }
    }

    /// Returns a signing key store for managing public signing keys.
    ///
    /// For `Ledger` backends, this returns a `LedgerSigningKeyStore` that
    /// writes keys directly to the Ledger with metrics instrumentation.
    ///
    /// For `Memory` backends, this returns the shared `MemorySigningKeyStore`
    /// instance to ensure consistency across handler calls.
    #[must_use]
    pub fn signing_key_store(&self) -> Arc<dyn PublicSigningKeyStore> {
        match self {
            Backend::Memory { signing_keys, .. } => {
                Arc::clone(signing_keys) as Arc<dyn PublicSigningKeyStore>
            },
            Backend::Ledger { backend, signing_key_metrics } => Arc::new(
                LedgerSigningKeyStore::new(backend.client_arc())
                    .with_metrics(signing_key_metrics.clone()),
            ),
        }
    }

    /// Returns a snapshot of signing key operation metrics.
    ///
    /// For `Ledger` backends, returns current metrics including operation
    /// counts, latencies, and error rates.
    ///
    /// For `Memory` backends, returns `None` since metrics aren't tracked.
    #[must_use]
    pub fn signing_key_metrics(&self) -> Option<SigningKeyMetricsSnapshot> {
        match self {
            Backend::Memory { .. } => None,
            Backend::Ledger { signing_key_metrics, .. } => Some(signing_key_metrics.snapshot()),
        }
    }
}

#[async_trait]
impl StorageBackend for Backend {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        match self {
            Backend::Memory { storage: b, .. } => b.get(key).await,
            Backend::Ledger { backend: b, .. } => b.get(key).await,
        }
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        match self {
            Backend::Memory { storage: b, .. } => b.set(key, value).await,
            Backend::Ledger { backend: b, .. } => b.set(key, value).await,
        }
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        match self {
            Backend::Memory { storage: b, .. } => b.delete(key).await,
            Backend::Ledger { backend: b, .. } => b.delete(key).await,
        }
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        match self {
            Backend::Memory { storage: b, .. } => b.get_range(range).await,
            Backend::Ledger { backend: b, .. } => b.get_range(range).await,
        }
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        match self {
            Backend::Memory { storage: b, .. } => b.clear_range(range).await,
            Backend::Ledger { backend: b, .. } => b.clear_range(range).await,
        }
    }

    async fn set_with_ttl(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        match self {
            Backend::Memory { storage: b, .. } => b.set_with_ttl(key, value, ttl_seconds).await,
            Backend::Ledger { backend: b, .. } => b.set_with_ttl(key, value, ttl_seconds).await,
        }
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        match self {
            Backend::Memory { storage: b, .. } => b.transaction().await,
            Backend::Ledger { backend: b, .. } => b.transaction().await,
        }
    }

    async fn health_check(&self) -> StorageResult<()> {
        match self {
            Backend::Memory { storage: b, .. } => b.health_check().await,
            Backend::Ledger { backend: b, .. } => b.health_check().await,
        }
    }
}

/// Create a storage backend based on configuration
///
/// # Arguments
///
/// * `config` - Storage backend configuration
///
/// # Returns
///
/// A backend enum wrapping the concrete implementation
///
/// # Errors
///
/// Returns an error if the backend cannot be created
pub async fn create_storage_backend(config: &StorageConfig) -> StorageResult<Backend> {
    match config.backend_type {
        StorageBackendType::Memory => {
            let storage = MemoryBackend::new();
            let signing_keys = Arc::new(MemorySigningKeyStore::new());
            Ok(Backend::Memory { storage, signing_keys })
        },
        StorageBackendType::Ledger => {
            let ledger_config = config.ledger.as_ref().ok_or_else(|| {
                inferadb_storage::StorageError::Internal(
                    "Ledger configuration required for Ledger backend".to_string(),
                )
            })?;
            let backend_config = LedgerBackendConfig::builder()
                .endpoints(vec![&ledger_config.endpoint])
                .client_id(&ledger_config.client_id)
                .namespace_id(ledger_config.namespace_id)
                .maybe_vault_id(ledger_config.vault_id)
                .build()
                .map_err(|e| {
                    inferadb_storage::StorageError::Internal(format!("Ledger config error: {e}"))
                })?;
            let backend = LedgerBackend::new(backend_config).await.map_err(|e| {
                inferadb_storage::StorageError::Internal(format!("Ledger connection error: {e}"))
            })?;
            Ok(Backend::Ledger { backend, signing_key_metrics: SigningKeyMetrics::new() })
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_memory_backend() {
        let config = StorageConfig::memory();
        let backend = create_storage_backend(&config).await.unwrap();

        // Test basic operations
        backend.set(b"test".to_vec(), b"value".to_vec()).await.unwrap();
        let value = backend.get(b"test").await.unwrap();
        assert!(value.is_some());
    }
}
