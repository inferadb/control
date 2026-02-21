use std::{ops::RangeBounds, sync::Arc, time::Duration};

use async_trait::async_trait;
use bon::Builder;
use bytes::Bytes;
use inferadb_common_storage::{
    KeyValue, StorageBackend, StorageResult, Transaction, VaultId,
    auth::{
        MemorySigningKeyStore, PublicSigningKeyStore, SigningKeyMetrics, SigningKeyMetricsSnapshot,
    },
    health::{HealthProbe, HealthStatus},
};
use inferadb_common_storage_ledger::{
    ClientConfig, LedgerBackend, LedgerBackendConfig, ServerSource, auth::LedgerSigningKeyStore,
};

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

/// Delegates a method call to the inner storage backend of each `Backend` variant.
///
/// Eliminates the repetitive `match self { Memory { storage: b, .. } => ..., Ledger { backend: b,
/// .. } => ... }` pattern across all `StorageBackend` trait methods. Each variant destructures to
/// extract only the storage field (`storage` for Memory, `backend` for Ledger), ignoring extra
/// fields like `signing_keys` and `signing_key_metrics`.
macro_rules! delegate_storage {
    ($self:ident, $method:ident ( $($arg:expr),* )) => {
        match $self {
            Backend::Memory { storage: __backend, .. } => __backend.$method($($arg),*).await,
            Backend::Ledger { backend: __backend, .. } => __backend.$method($($arg),*).await,
        }
    };
}

#[async_trait]
impl StorageBackend for Backend {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        delegate_storage!(self, get(key))
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        delegate_storage!(self, set(key, value))
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        delegate_storage!(self, delete(key))
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        delegate_storage!(self, get_range(range))
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        delegate_storage!(self, clear_range(range))
    }

    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()> {
        delegate_storage!(self, set_with_ttl(key, value, ttl))
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        delegate_storage!(self, transaction())
    }

    async fn compare_and_set(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        delegate_storage!(self, compare_and_set(key, expected, new_value))
    }

    async fn health_check(&self, probe: HealthProbe) -> StorageResult<HealthStatus> {
        delegate_storage!(self, health_check(probe))
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
                inferadb_common_storage::StorageError::internal(
                    "Ledger configuration required for Ledger backend",
                )
            })?;
            let client_config = ClientConfig::builder()
                .servers(ServerSource::from_static([&ledger_config.endpoint]))
                .client_id(&ledger_config.client_id)
                .build()
                .map_err(|e| {
                    inferadb_common_storage::StorageError::internal(format!(
                        "Ledger client config error: {e}"
                    ))
                })?;
            let backend_config = LedgerBackendConfig::builder()
                .client(client_config)
                .namespace_id(ledger_config.namespace_id)
                .maybe_vault_id(ledger_config.vault_id.map(VaultId::from))
                .build()
                .map_err(|e| {
                    inferadb_common_storage::StorageError::internal(format!(
                        "Ledger backend config error: {e}"
                    ))
                })?;
            let backend = LedgerBackend::new(backend_config).await.map_err(|e| {
                inferadb_common_storage::StorageError::internal(format!(
                    "Ledger connection error: {e}"
                ))
            })?;
            Ok(Backend::Ledger { backend, signing_key_metrics: SigningKeyMetrics::new() })
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
