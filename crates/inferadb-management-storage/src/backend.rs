use std::ops::RangeBounds;

use async_trait::async_trait;
use bytes::Bytes;

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;

/// Storage operation errors
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Key not found
    #[error("Key not found: {0}")]
    NotFound(String),

    /// Transaction conflict (optimistic locking failure)
    #[error("Transaction conflict")]
    Conflict,

    /// Connection or network error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Internal storage backend error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Operation timeout
    #[error("Operation timeout")]
    Timeout,
}

/// Key-value pair
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyValue {
    pub key: Bytes,
    pub value: Bytes,
}

/// Transaction handle for atomic operations
#[async_trait]
pub trait Transaction: Send {
    /// Get a value within the transaction
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>>;

    /// Set a value within the transaction
    fn set(&mut self, key: Vec<u8>, value: Vec<u8>);

    /// Delete a key within the transaction
    fn delete(&mut self, key: Vec<u8>);

    /// Commit the transaction
    async fn commit(self: Box<Self>) -> StorageResult<()>;
}

/// Storage backend abstraction
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Get a value by key
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>>;

    /// Set a key-value pair
    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()>;

    /// Delete a key
    async fn delete(&self, key: &[u8]) -> StorageResult<()>;

    /// Get a range of key-value pairs
    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send;

    /// Clear a range of keys
    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send;

    /// Set a key with TTL (time-to-live) in seconds
    /// Not all backends may support TTL natively
    async fn set_with_ttl(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> StorageResult<()>;

    /// Begin a new transaction
    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>>;

    /// Check if the backend is healthy and can accept requests
    async fn health_check(&self) -> StorageResult<()>;
}
