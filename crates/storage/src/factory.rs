use std::sync::Arc;

use bon::Builder;
use inferadb_common_storage::{
    DynBackend, StorageResult, VaultSlug,
    auth::{
        MemorySigningKeyStore, PublicSigningKeyStore, SigningKeyMetrics, SigningKeyMetricsSnapshot,
    },
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
    /// Organization for data scoping
    pub organization: u64,
    /// Optional vault for finer-grained scoping
    pub vault: Option<u64>,
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

/// Result of creating a storage backend, including the signing key store.
pub struct StorageBundle {
    /// The storage backend (trait object)
    pub storage: DynBackend,
    /// Signing key store for the backend
    pub signing_keys: Arc<dyn PublicSigningKeyStore>,
    /// Signing key metrics (only available for Ledger backends)
    pub signing_key_metrics: Option<SigningKeyMetrics>,
}

impl StorageBundle {
    /// Returns a snapshot of signing key operation metrics.
    ///
    /// For `Ledger` backends, returns current metrics including operation
    /// counts, latencies, and error rates.
    ///
    /// For `Memory` backends, returns `None` since metrics aren't tracked.
    #[must_use]
    pub fn signing_key_metrics_snapshot(&self) -> Option<SigningKeyMetricsSnapshot> {
        self.signing_key_metrics.as_ref().map(SigningKeyMetrics::snapshot)
    }
}

/// Create a storage backend and signing key store based on configuration.
///
/// # Errors
///
/// Returns an error if the backend cannot be created.
pub async fn create_storage_backend(config: &StorageConfig) -> StorageResult<StorageBundle> {
    match config.backend_type {
        StorageBackendType::Memory => {
            let storage: DynBackend = Arc::new(MemoryBackend::new());
            let signing_keys: Arc<dyn PublicSigningKeyStore> =
                Arc::new(MemorySigningKeyStore::new());
            Ok(StorageBundle { storage, signing_keys, signing_key_metrics: None })
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
                .organization(ledger_config.organization)
                .maybe_vault(ledger_config.vault.map(VaultSlug::from))
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

            let signing_key_metrics = SigningKeyMetrics::new();
            let signing_keys: Arc<dyn PublicSigningKeyStore> = Arc::new(
                LedgerSigningKeyStore::new(backend.client_arc())
                    .with_metrics(signing_key_metrics.clone()),
            );
            let storage: DynBackend = Arc::new(backend);

            Ok(StorageBundle {
                storage,
                signing_keys,
                signing_key_metrics: Some(signing_key_metrics),
            })
        },
    }
}

/// Create a memory-backed [`StorageBundle`] for testing.
///
/// This is a convenience function that creates a `MemoryBackend` with a shared
/// `MemorySigningKeyStore`, suitable for unit and integration tests.
#[must_use]
pub fn memory_storage() -> StorageBundle {
    let storage: DynBackend = Arc::new(MemoryBackend::new());
    let signing_keys: Arc<dyn PublicSigningKeyStore> = Arc::new(MemorySigningKeyStore::new());
    StorageBundle { storage, signing_keys, signing_key_metrics: None }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_common_storage::StorageBackend;

    use super::*;

    #[tokio::test]
    async fn test_create_memory_backend() {
        let config = StorageConfig::memory();
        let bundle = create_storage_backend(&config).await.unwrap();

        // Test basic operations
        bundle.storage.set(b"test".to_vec(), b"value".to_vec()).await.unwrap();
        let value = bundle.storage.get(b"test").await.unwrap();
        assert!(value.is_some());
    }

    #[tokio::test]
    async fn test_memory_storage_helper() {
        let bundle = memory_storage();

        bundle.storage.set(b"key".to_vec(), b"val".to_vec()).await.unwrap();
        let value = bundle.storage.get(b"key").await.unwrap();
        assert!(value.is_some());
        assert!(bundle.signing_key_metrics.is_none());
    }
}
