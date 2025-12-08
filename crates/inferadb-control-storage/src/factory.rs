use std::ops::RangeBounds;

use async_trait::async_trait;
use bytes::Bytes;

#[cfg(feature = "fdb")]
use crate::FdbBackend;
use crate::{
    MemoryBackend,
    backend::{KeyValue, StorageBackend, StorageResult, Transaction},
};

/// Storage backend type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageBackendType {
    /// In-memory storage (for development and testing)
    Memory,
    /// FoundationDB storage (for production)
    FoundationDB,
}

/// Storage backend configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Backend type
    pub backend_type: StorageBackendType,
    /// FDB cluster file path (only used for FoundationDB backend)
    pub fdb_cluster_file: Option<String>,
}

impl StorageConfig {
    /// Create a new in-memory storage configuration
    pub fn memory() -> Self {
        Self { backend_type: StorageBackendType::Memory, fdb_cluster_file: None }
    }

    /// Create a new FoundationDB storage configuration
    pub fn foundationdb(cluster_file: Option<String>) -> Self {
        Self { backend_type: StorageBackendType::FoundationDB, fdb_cluster_file: cluster_file }
    }
}

/// Backend enum wrapper that implements StorageBackend
#[derive(Clone)]
pub enum Backend {
    Memory(MemoryBackend),
    #[cfg(feature = "fdb")]
    FoundationDB(FdbBackend),
}

#[async_trait]
impl StorageBackend for Backend {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        match self {
            Backend::Memory(b) => b.get(key).await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.get(key).await,
        }
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        match self {
            Backend::Memory(b) => b.set(key, value).await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.set(key, value).await,
        }
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        match self {
            Backend::Memory(b) => b.delete(key).await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.delete(key).await,
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
        }
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        match self {
            Backend::Memory(b) => b.transaction().await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.transaction().await,
        }
    }

    async fn health_check(&self) -> StorageResult<()> {
        match self {
            Backend::Memory(b) => b.health_check().await,
            #[cfg(feature = "fdb")]
            Backend::FoundationDB(b) => b.health_check().await,
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
        StorageBackendType::FoundationDB => {
            use crate::backend::StorageError;
            Err(StorageError::Internal(
                "FoundationDB support not compiled. Enable the 'fdb' feature.".to_string(),
            ))
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
