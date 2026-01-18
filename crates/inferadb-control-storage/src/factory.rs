use std::ops::RangeBounds;

use async_trait::async_trait;
use bytes::Bytes;
use inferadb_storage::{KeyValue, StorageBackend, StorageResult, Transaction};
#[cfg(feature = "ledger")]
use inferadb_storage_ledger::{LedgerBackend, LedgerBackendConfig};

#[cfg(feature = "fdb")]
use crate::FdbBackend;
use crate::MemoryBackend;

/// Storage backend type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageBackendType {
    /// In-memory storage (for development and testing)
    Memory,
    /// FoundationDB storage (for production, legacy)
    FoundationDB,
    /// Ledger storage (target production backend)
    Ledger,
}

/// Ledger-specific configuration
#[cfg(feature = "ledger")]
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Backend type
    pub backend_type: StorageBackendType,
    /// FDB cluster file path (only used for FoundationDB backend)
    pub fdb_cluster_file: Option<String>,
    /// Ledger configuration (only used for Ledger backend)
    #[cfg(feature = "ledger")]
    pub ledger: Option<LedgerConfig>,
}

impl StorageConfig {
    /// Create a new in-memory storage configuration
    pub fn memory() -> Self {
        Self {
            backend_type: StorageBackendType::Memory,
            fdb_cluster_file: None,
            #[cfg(feature = "ledger")]
            ledger: None,
        }
    }

    /// Create a new FoundationDB storage configuration
    pub fn foundationdb(cluster_file: Option<String>) -> Self {
        Self {
            backend_type: StorageBackendType::FoundationDB,
            fdb_cluster_file: cluster_file,
            #[cfg(feature = "ledger")]
            ledger: None,
        }
    }

    /// Create a new Ledger storage configuration
    #[cfg(feature = "ledger")]
    pub fn ledger(config: LedgerConfig) -> Self {
        Self {
            backend_type: StorageBackendType::Ledger,
            fdb_cluster_file: None,
            ledger: Some(config),
        }
    }
}

/// Backend enum wrapper that implements StorageBackend
#[derive(Clone)]
pub enum Backend {
    Memory(MemoryBackend),
    #[cfg(feature = "fdb")]
    FoundationDB(FdbBackend),
    #[cfg(feature = "ledger")]
    Ledger(LedgerBackend),
}

impl Backend {
    /// Get the FDB database handle if using FoundationDB backend.
    ///
    /// Returns `None` if using a non-FDB backend (e.g., Memory).
    /// This is used for FDB-based cross-service communication like
    /// JWKS storage and cache invalidation.
    #[cfg(feature = "fdb")]
    pub fn fdb_database(&self) -> Option<std::sync::Arc<foundationdb::Database>> {
        match self {
            Backend::FoundationDB(b) => Some(b.database()),
            _ => None,
        }
    }

    /// Get the FDB database handle if using FoundationDB backend.
    ///
    /// Returns `None` if using a non-FDB backend (e.g., Memory).
    #[cfg(not(feature = "fdb"))]
    pub fn fdb_database(&self) -> Option<std::sync::Arc<()>> {
        None
    }
}

#[async_trait]
impl StorageBackend for Backend {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        match self {
            Backend::Memory(b) => b.get(key).await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.get(key).await,
            #[cfg(feature = "ledger")]
            Backend::Ledger(b) => b.get(key).await,
        }
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        match self {
            Backend::Memory(b) => b.set(key, value).await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.set(key, value).await,
            #[cfg(feature = "ledger")]
            Backend::Ledger(b) => b.set(key, value).await,
        }
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        match self {
            Backend::Memory(b) => b.delete(key).await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.delete(key).await,
            #[cfg(feature = "ledger")]
            Backend::Ledger(b) => b.delete(key).await,
        }
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        match self {
            Backend::Memory(b) => b.get_range(range).await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.get_range(range).await,
            #[cfg(feature = "ledger")]
            Backend::Ledger(b) => b.get_range(range).await,
        }
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        match self {
            Backend::Memory(b) => b.clear_range(range).await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.clear_range(range).await,
            #[cfg(feature = "ledger")]
            Backend::Ledger(b) => b.clear_range(range).await,
        }
    }

    async fn set_with_ttl(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        match self {
            Backend::Memory(b) => b.set_with_ttl(key, value, ttl_seconds).await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.set_with_ttl(key, value, ttl_seconds).await,
            #[cfg(feature = "ledger")]
            Backend::Ledger(b) => b.set_with_ttl(key, value, ttl_seconds).await,
        }
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        match self {
            Backend::Memory(b) => b.transaction().await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.transaction().await,
            #[cfg(feature = "ledger")]
            Backend::Ledger(b) => b.transaction().await,
        }
    }

    async fn health_check(&self) -> StorageResult<()> {
        match self {
            Backend::Memory(b) => b.health_check().await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.health_check().await,
            #[cfg(feature = "ledger")]
            Backend::Ledger(b) => b.health_check().await,
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
            let backend = MemoryBackend::new();
            Ok(Backend::Memory(backend))
        },
        #[cfg(feature = "fdb")]
        StorageBackendType::FoundationDB => {
            let backend = FdbBackend::with_cluster_file(config.fdb_cluster_file.clone()).await?;
            Ok(Backend::FoundationDB(backend))
        },
        #[cfg(not(feature = "fdb"))]
        StorageBackendType::FoundationDB => Err(inferadb_storage::StorageError::Internal(
            "FoundationDB support not compiled. Enable the 'fdb' feature.".to_string(),
        )),
        #[cfg(feature = "ledger")]
        StorageBackendType::Ledger => {
            let ledger_config = config.ledger.as_ref().ok_or_else(|| {
                inferadb_storage::StorageError::Internal(
                    "Ledger configuration required for Ledger backend".to_string(),
                )
            })?;
            let backend_config = LedgerBackendConfig::builder()
                .with_endpoint(&ledger_config.endpoint)
                .with_client_id(&ledger_config.client_id)
                .with_namespace_id(ledger_config.namespace_id);
            let backend_config = if let Some(vault_id) = ledger_config.vault_id {
                backend_config.with_vault_id(vault_id)
            } else {
                backend_config
            };
            let backend_config = backend_config.build().map_err(|e| {
                inferadb_storage::StorageError::Internal(format!("Ledger config error: {}", e))
            })?;
            let backend = LedgerBackend::new(backend_config).await.map_err(|e| {
                inferadb_storage::StorageError::Internal(format!("Ledger connection error: {}", e))
            })?;
            Ok(Backend::Ledger(backend))
        },
        #[cfg(not(feature = "ledger"))]
        StorageBackendType::Ledger => Err(inferadb_storage::StorageError::Internal(
            "Ledger support not compiled. Enable the 'ledger' feature.".to_string(),
        )),
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

    #[tokio::test]
    #[cfg(feature = "fdb")]
    async fn test_create_fdb_backend_requires_fdb() {
        let config = StorageConfig::foundationdb(None);
        let result = create_storage_backend(&config).await;

        // FDB backend is fully implemented, but requires FDB to be running
        // In dev environments without FDB, this should fail with a connection error
        assert!(result.is_err());
    }
}
