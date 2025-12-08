use std::{
    collections::BTreeMap,
    ops::{Bound, RangeBounds},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use tokio::time::sleep;

use crate::backend::{KeyValue, StorageBackend, StorageResult, Transaction};

/// In-memory storage backend using BTreeMap
///
/// This backend provides:
/// - Thread-safe concurrent access via RwLock
/// - Ordered key-value storage with range queries
/// - Basic TTL support with background cleanup
/// - MVCC-like transaction semantics
#[derive(Clone)]
pub struct MemoryBackend {
    data: Arc<RwLock<BTreeMap<Vec<u8>, Bytes>>>,
    ttl_data: Arc<RwLock<BTreeMap<Vec<u8>, Instant>>>,
}

impl MemoryBackend {
    /// Create a new in-memory storage backend
    pub fn new() -> Self {
        let backend = Self {
            data: Arc::new(RwLock::new(BTreeMap::new())),
            ttl_data: Arc::new(RwLock::new(BTreeMap::new())),
        };

        // Start background TTL cleanup task
        let backend_clone = backend.clone();
        tokio::spawn(async move {
            backend_clone.cleanup_expired_keys().await;
        });

        backend
    }

    /// Background task to clean up expired keys
    async fn cleanup_expired_keys(&self) {
        loop {
            sleep(Duration::from_secs(1)).await;

            let now = Instant::now();
            let mut expired_keys = Vec::new();

            // Find expired keys
            {
                let ttl_guard = self.ttl_data.read();
                for (key, expiry) in ttl_guard.iter() {
                    if *expiry <= now {
                        expired_keys.push(key.clone());
                    }
                }
            }

            // Remove expired keys
            if !expired_keys.is_empty() {
                let mut data_guard = self.data.write();
                let mut ttl_guard = self.ttl_data.write();
                for key in expired_keys {
                    data_guard.remove(&key);
                    ttl_guard.remove(&key);
                }
            }
        }
    }

    /// Check if a key has expired
    fn is_expired(&self, key: &[u8]) -> bool {
        let ttl_guard = self.ttl_data.read();
        if let Some(expiry) = ttl_guard.get(key) {
            return *expiry <= Instant::now();
        }
        false
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageBackend for MemoryBackend {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        // Check if key is expired
        if self.is_expired(key) {
            return Ok(None);
        }

        let data = self.data.read();

        Ok(data.get(key).cloned())
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        let mut data = self.data.write();

        data.insert(key.clone(), Bytes::from(value));

        // Remove TTL if exists
        {
            let mut ttl_guard = self.ttl_data.write();
            ttl_guard.remove(&key);
        }

        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        let mut data = self.data.write();

        data.remove(key);

        // Remove TTL if exists
        {
            let mut ttl_guard = self.ttl_data.write();
            ttl_guard.remove(key);
        }

        Ok(())
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        let data = self.data.read();

        let start = match range.start_bound() {
            Bound::Included(b) => Bound::Included(b.as_slice()),
            Bound::Excluded(b) => Bound::Excluded(b.as_slice()),
            Bound::Unbounded => Bound::Unbounded,
        };

        let end = match range.end_bound() {
            Bound::Included(b) => Bound::Included(b.as_slice()),
            Bound::Excluded(b) => Bound::Excluded(b.as_slice()),
            Bound::Unbounded => Bound::Unbounded,
        };

        let results: Vec<KeyValue> = data
            .range::<[u8], _>((start, end))
            .filter(|(key, _)| !self.is_expired(key))
            .map(|(k, v)| KeyValue { key: Bytes::copy_from_slice(k), value: v.clone() })
            .collect();

        Ok(results)
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        let mut data = self.data.write();

        let keys_to_remove: Vec<Vec<u8>> = data.range(range).map(|(k, _)| k.clone()).collect();

        for key in keys_to_remove {
            data.remove(&key);
            let mut ttl_guard = self.ttl_data.write();
            ttl_guard.remove(&key);
        }

        Ok(())
    }

    async fn set_with_ttl(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let mut data = self.data.write();

        let mut ttl_data = self.ttl_data.write();

        let expiry = Instant::now() + Duration::from_secs(ttl_seconds);

        data.insert(key.clone(), Bytes::from(value));
        ttl_data.insert(key, expiry);

        Ok(())
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        Ok(Box::new(MemoryTransaction::new(self.clone())))
    }

    async fn health_check(&self) -> StorageResult<()> {
        // Try to acquire read lock
        let _unused = self.data.read();
        Ok(())
    }
}

/// In-memory transaction implementation
struct MemoryTransaction {
    backend: MemoryBackend,
    pending_writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl MemoryTransaction {
    fn new(backend: MemoryBackend) -> Self {
        Self { backend, pending_writes: BTreeMap::new() }
    }
}

#[async_trait]
impl Transaction for MemoryTransaction {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        // Check pending writes first
        if let Some(value) = self.pending_writes.get(key) {
            return Ok(value.as_ref().map(|v| Bytes::copy_from_slice(v)));
        }

        // Otherwise, read from backend
        self.backend.get(key).await
    }

    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.pending_writes.insert(key, Some(value));
    }

    fn delete(&mut self, key: Vec<u8>) {
        self.pending_writes.insert(key, None);
    }

    async fn commit(self: Box<Self>) -> StorageResult<()> {
        let mut data = self.backend.data.write();

        // Apply all pending writes
        for (key, value) in self.pending_writes {
            match value {
                Some(v) => {
                    data.insert(key, Bytes::from(v));
                },
                None => {
                    data.remove(&key);
                },
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
