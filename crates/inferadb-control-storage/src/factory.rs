use std::ops::RangeBounds;

use async_trait::async_trait;
use bytes::Bytes;
use inferadb_storage::{KeyValue, StorageBackend, StorageResult, Transaction};
use inferadb_storage_ledger::{LedgerBackend, LedgerBackendConfig};

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
    Memory(MemoryBackend),
    Ledger(LedgerBackend),
}

#[async_trait]
impl StorageBackend for Backend {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        match self {
            Backend::Memory(b) => b.get(key).await,
            Backend::Ledger(b) => b.get(key).await,
        }
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        match self {
            Backend::Memory(b) => b.set(key, value).await,
            Backend::Ledger(b) => b.set(key, value).await,
        }
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        match self {
            Backend::Memory(b) => b.delete(key).await,
            Backend::Ledger(b) => b.delete(key).await,
        }
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        match self {
            Backend::Memory(b) => b.get_range(range).await,
            Backend::Ledger(b) => b.get_range(range).await,
        }
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        match self {
            Backend::Memory(b) => b.clear_range(range).await,
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
            Backend::Ledger(b) => b.set_with_ttl(key, value, ttl_seconds).await,
        }
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        match self {
            Backend::Memory(b) => b.transaction().await,
            Backend::Ledger(b) => b.transaction().await,
        }
    }

    async fn health_check(&self) -> StorageResult<()> {
        match self {
            Backend::Memory(b) => b.health_check().await,
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
                inferadb_storage::StorageError::Internal(format!("Ledger config error: {e}"))
            })?;
            let backend = LedgerBackend::new(backend_config).await.map_err(|e| {
                inferadb_storage::StorageError::Internal(format!("Ledger connection error: {e}"))
            })?;
            Ok(Backend::Ledger(backend))
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
