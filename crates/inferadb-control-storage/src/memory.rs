//! In-memory storage backend re-export.
//!
//! This module re-exports [`MemoryBackend`] from the shared
//! [`inferadb_storage`] crate. The implementation provides:
//!
//! - Thread-safe concurrent access via RwLock
//! - Ordered key-value storage with range queries
//! - Basic TTL support with background cleanup
//! - MVCC-like transaction semantics
//!
//! # Example
//!
//! ```ignore
//! use inferadb_control_storage::StorageBackend;
//!
//! #[tokio::main]
//! async fn main() {
//!     let backend = MemoryBackend::new();
//!     backend.set(b"key".to_vec(), b"value".to_vec()).await.unwrap();
//! }
//! ```

// Re-export MemoryBackend from the shared crate
pub use inferadb_storage::MemoryBackend;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::backend::StorageBackend;

    #[tokio::test]
    async fn test_basic_operations() {
        let backend = MemoryBackend::new();

        // Set and get
        backend.set(b"key1".to_vec(), b"value1".to_vec()).await.unwrap();
        let value = backend.get(b"key1").await.unwrap();
        assert_eq!(value, Some(Bytes::from("value1")));

        // Delete
        backend.delete(b"key1").await.unwrap();
        let value = backend.get(b"key1").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_range_operations() {
        let backend = MemoryBackend::new();

        backend.set(b"a".to_vec(), b"1".to_vec()).await.unwrap();
        backend.set(b"b".to_vec(), b"2".to_vec()).await.unwrap();
        backend.set(b"c".to_vec(), b"3".to_vec()).await.unwrap();

        let range = backend.get_range(b"a".to_vec()..b"c".to_vec()).await.unwrap();
        assert_eq!(range.len(), 2);
        assert_eq!(range[0].key, Bytes::from("a"));
        assert_eq!(range[1].key, Bytes::from("b"));
    }

    #[tokio::test]
    async fn test_ttl() {
        let backend = MemoryBackend::new();

        backend.set_with_ttl(b"temp".to_vec(), b"value".to_vec(), 1).await.unwrap();

        // Should exist immediately
        let value = backend.get(b"temp").await.unwrap();
        assert!(value.is_some());

        // Wait for expiry
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should be gone
        let value = backend.get(b"temp").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_transaction() {
        let backend = MemoryBackend::new();

        backend.set(b"key1".to_vec(), b"value1".to_vec()).await.unwrap();

        let mut txn = backend.transaction().await.unwrap();

        // Read within transaction
        let value = txn.get(b"key1").await.unwrap();
        assert_eq!(value, Some(Bytes::from("value1")));

        // Write within transaction
        txn.set(b"key2".to_vec(), b"value2".to_vec());

        // Delete within transaction
        txn.delete(b"key1".to_vec());

        // Commit transaction
        txn.commit().await.unwrap();

        // Verify changes
        let value1 = backend.get(b"key1").await.unwrap();
        assert_eq!(value1, None);

        let value2 = backend.get(b"key2").await.unwrap();
        assert_eq!(value2, Some(Bytes::from("value2")));
    }

    #[tokio::test]
    async fn test_health_check() {
        let backend = MemoryBackend::new();
        assert!(backend.health_check().await.is_ok());
    }
}
