//! FoundationDB storage backend for Management API
//!
//! Provides production-ready persistent storage using FoundationDB.
//! Implements the StorageBackend trait with full support for:
//! - ACID transactions
//! - Range queries
//! - TTL-based expiration
//! - Multi-version concurrency control (MVCC)

use std::{
    collections::BTreeMap,
    ops::{Bound, RangeBounds},
    sync::{Arc, Once},
};

use async_trait::async_trait;
use bytes::Bytes;
use foundationdb::{Database, FdbBindingError, RangeOption, tuple::Subspace};
use futures::StreamExt;
use parking_lot::Mutex;
use tokio::time::{Duration, interval};
use tracing::{debug, warn};

use crate::backend::{KeyValue, StorageBackend, StorageError, StorageResult, Transaction};

// Global initialization flag for FDB network
// The FDB client library requires that select_api_version (called by boot())
// is only called once per process
static FDB_INIT: Once = Once::new();

/// FoundationDB storage backend
#[derive(Clone)]
pub struct FdbBackend {
    db: Arc<Database>,
    // Subspaces for organizing data
    data_subspace: Subspace,
    ttl_subspace: Subspace,
}

impl FdbBackend {
    /// Create a new FoundationDB backend with default cluster file
    pub async fn new() -> StorageResult<Self> {
        Self::with_cluster_file(None).await
    }

    /// Create a new FoundationDB backend with a specific cluster file
    ///
    /// # Arguments
    ///
    /// * `cluster_file` - Optional path to the FDB cluster file
    ///
    /// # Errors
    ///
    /// Returns an error if FDB initialization or connection fails
    pub async fn with_cluster_file(cluster_file: Option<String>) -> StorageResult<Self> {
        // Initialize FDB API - only once per process
        // The FDB client library requires that select_api_version (called by boot())
        // is only called once per process. Using Once ensures thread-safe initialization.
        FDB_INIT.call_once(|| {
            let _network = unsafe { foundationdb::boot() };
            // The network handle is intentionally leaked here as it needs to live
            // for the entire process lifetime
            std::mem::forget(_network);
        });

        // Create database handle
        let db = if let Some(path) = cluster_file {
            Database::from_path(&path).map_err(|e| {
                StorageError::Connection(format!("Failed to open cluster file: {}", e))
            })?
        } else {
            Database::default().map_err(|e| {
                StorageError::Connection(format!("Failed to open default cluster: {}", e))
            })?
        };

        // Create subspaces for organizing data
        let data_subspace = Subspace::from_bytes(b"data");
        let ttl_subspace = Subspace::from_bytes(b"ttl");

        debug!("FoundationDB backend initialized for Management API");

        let backend = Self { db: Arc::new(db), data_subspace, ttl_subspace };

        // Start background TTL cleanup task
        backend.start_ttl_cleanup();

        Ok(backend)
    }

    /// Start background task to clean up expired TTL entries
    fn start_ttl_cleanup(&self) {
        let backend = self.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(60)); // Run every minute
            loop {
                ticker.tick().await;
                if let Err(e) = backend.cleanup_expired_keys().await {
                    warn!("TTL cleanup failed: {}", e);
                }
            }
        });
    }

    /// Clean up expired TTL entries
    async fn cleanup_expired_keys(&self) -> StorageResult<()> {
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let db = Arc::clone(&self.db);
        let ttl_subspace = self.ttl_subspace.clone();
        let data_subspace = self.data_subspace.clone();

        db.run({
            let ttl_subspace = ttl_subspace.clone();
            let data_subspace = data_subspace.clone();
            move |trx, _maybe_committed| {
                let ttl_subspace = ttl_subspace.clone();
                let data_subspace = data_subspace.clone();
                async move {
                    // Find all TTL entries that have expired
                    let start = ttl_subspace.pack(&(0u64,));
                    let end = ttl_subspace.pack(&(now,));

                    let range_opt = RangeOption::from((start.as_slice(), end.as_slice()));
                    // Use get_ranges to iterate through all expired keys
                    let mut range_stream = trx.get_ranges(range_opt, false);

                    while let Some(result) = range_stream.next().await {
                        let kvs = result.map_err(|e| {
                            FdbBindingError::new_custom_error(Box::new(std::io::Error::other(
                                format!("FDB get_ranges failed: {}", e),
                            )))
                        })?;

                        for kv in kvs.iter() {
                            // Extract the original key from the TTL index
                            // TTL key format: ttl_subspace/{expiry_timestamp}/{original_key}
                            let ttl_key = kv.key();

                            // Unpack to get past the subspace and timestamp
                            if let Ok(unpacked) = foundationdb::tuple::unpack::<(u64, Vec<u8>)>(
                                &ttl_key[ttl_subspace.bytes().len()..],
                            ) {
                                let original_key_bytes = unpacked.1;

                                // Reconstruct the full data key
                                let data_key = data_subspace.pack(&original_key_bytes);

                                // Delete both the data and TTL index entries
                                trx.clear(&data_key);
                                trx.clear(ttl_key);
                            }
                        }
                    }

                    Ok(())
                }
            }
        })
        .await
        .map_err(|e| StorageError::Internal(format!("TTL cleanup failed: {}", e)))?;

        Ok(())
    }

    /// Convert range bounds to FDB byte range
    fn range_to_bytes<R>(&self, range: R) -> (Vec<u8>, Vec<u8>)
    where
        R: RangeBounds<Vec<u8>>,
    {
        let start = match range.start_bound() {
            Bound::Included(k) => self.data_subspace.pack(k),
            Bound::Excluded(k) => {
                let mut key = self.data_subspace.pack(k);
                key.push(0x00);
                key
            },
            Bound::Unbounded => self.data_subspace.bytes().to_vec(),
        };

        let end = match range.end_bound() {
            Bound::Included(k) => {
                let mut key = self.data_subspace.pack(k);
                key.push(0xff);
                key
            },
            Bound::Excluded(k) => self.data_subspace.pack(k),
            Bound::Unbounded => {
                let mut key = self.data_subspace.bytes().to_vec();
                key.push(0xff);
                key
            },
        };

        (start, end)
    }
}

#[async_trait]
impl StorageBackend for FdbBackend {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        let db = Arc::clone(&self.db);
        let data_key = self.data_subspace.pack(&key.to_vec());

        let result = db
            .run({
                let data_key = data_key.clone();
                move |trx, _maybe_committed| {
                    let data_key = data_key.clone();
                    async move {
                        trx.get(&data_key, false).await.map_err(|e| {
                            FdbBindingError::new_custom_error(Box::new(std::io::Error::other(
                                format!("FDB get failed: {}", e),
                            )))
                        })
                    }
                }
            })
            .await
            .map_err(|e| StorageError::Internal(format!("FDB get failed: {}", e)))?;

        Ok(result.map(|v| Bytes::from(v.to_vec())))
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        let db = Arc::clone(&self.db);
        let data_key = self.data_subspace.pack(&key);

        db.run({
            let data_key = data_key.clone();
            let value = value.clone();
            move |trx, _maybe_committed| {
                let data_key = data_key.clone();
                let value = value.clone();
                async move {
                    trx.set(&data_key, &value);
                    Ok(())
                }
            }
        })
        .await
        .map_err(|e| StorageError::Internal(format!("FDB set failed: {}", e)))?;

        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        let db = Arc::clone(&self.db);
        let data_key = self.data_subspace.pack(&key.to_vec());

        db.run({
            let data_key = data_key.clone();
            move |trx, _maybe_committed| {
                let data_key = data_key.clone();
                async move {
                    trx.clear(&data_key);
                    Ok(())
                }
            }
        })
        .await
        .map_err(|e| StorageError::Internal(format!("FDB delete failed: {}", e)))?;

        Ok(())
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        let (start, end) = self.range_to_bytes(range);
        let db = Arc::clone(&self.db);
        let data_subspace = self.data_subspace.clone();

        // Use get_ranges (plural) to iterate through all pages of results
        // The single get_range only returns the first batch
        let all_kvs = db
            .run({
                let start = start.clone();
                let end = end.clone();
                move |trx, _maybe_committed| {
                    let start = start.clone();
                    let end = end.clone();
                    async move {
                        let range_opt = RangeOption::from((start.as_slice(), end.as_slice()));
                        // Use get_ranges which returns a Stream and iterate to collect all results
                        let mut range_stream = trx.get_ranges(range_opt, false);
                        let mut all_results = Vec::new();

                        while let Some(result) = range_stream.next().await {
                            match result {
                                Ok(values) => {
                                    // Each batch contains multiple key-value pairs
                                    for kv in values.iter() {
                                        all_results.push((kv.key().to_vec(), kv.value().to_vec()));
                                    }
                                },
                                Err(e) => {
                                    return Err(FdbBindingError::new_custom_error(Box::new(
                                        std::io::Error::other(format!(
                                            "FDB get_ranges failed: {}",
                                            e
                                        )),
                                    )));
                                },
                            }
                        }

                        Ok(all_results)
                    }
                }
            })
            .await
            .map_err(|e| StorageError::Internal(format!("FDB get_range failed: {}", e)))?;

        // Convert FDB key-values to our KeyValue type, removing subspace prefix
        let subspace_len = data_subspace.bytes().len();
        let result = all_kvs
            .into_iter()
            .filter_map(|(full_key, value)| {
                if full_key.len() > subspace_len {
                    // Unpack the key to remove subspace prefix
                    if let Ok(unpacked) =
                        foundationdb::tuple::unpack::<Vec<u8>>(&full_key[subspace_len..])
                    {
                        Some(KeyValue { key: Bytes::from(unpacked), value: Bytes::from(value) })
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        Ok(result)
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        let (start, end) = self.range_to_bytes(range);
        let db = Arc::clone(&self.db);

        db.run({
            let start = start.clone();
            let end = end.clone();
            move |trx, _maybe_committed| {
                let start = start.clone();
                let end = end.clone();
                async move {
                    trx.clear_range(&start, &end);
                    Ok(())
                }
            }
        })
        .await
        .map_err(|e| StorageError::Internal(format!("FDB clear_range failed: {}", e)))?;

        Ok(())
    }

    async fn set_with_ttl(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let expiry =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                + ttl_seconds;

        let db = Arc::clone(&self.db);
        let data_key = self.data_subspace.pack(&key);
        let ttl_key = self.ttl_subspace.pack(&(expiry, key.clone()));

        db.run({
            let data_key = data_key.clone();
            let ttl_key = ttl_key.clone();
            let value = value.clone();
            move |trx, _maybe_committed| {
                let data_key = data_key.clone();
                let ttl_key = ttl_key.clone();
                let value = value.clone();
                async move {
                    // Set the data
                    trx.set(&data_key, &value);
                    // Set the TTL index entry (empty value)
                    trx.set(&ttl_key, &[]);
                    Ok(())
                }
            }
        })
        .await
        .map_err(|e| StorageError::Internal(format!("FDB set_with_ttl failed: {}", e)))?;

        Ok(())
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        Ok(Box::new(FdbTransaction {
            backend: self.clone(),
            pending_writes: Arc::new(Mutex::new(BTreeMap::new())),
        }))
    }

    async fn health_check(&self) -> StorageResult<()> {
        // Perform a simple read/write test to verify FDB connectivity
        let test_key = b"__health_check__".to_vec();
        let test_value = b"ok".to_vec();

        self.set(test_key.clone(), test_value.clone()).await?;
        let result = self.get(&test_key).await?;

        if result.as_deref() != Some(test_value.as_slice()) {
            return Err(StorageError::Internal("Health check failed: value mismatch".to_string()));
        }

        self.delete(&test_key).await?;

        debug!("FDB health check passed");
        Ok(())
    }
}

/// Type alias for pending writes map
type PendingWrites = Arc<Mutex<BTreeMap<Vec<u8>, Option<Vec<u8>>>>>;

/// FDB transaction implementation
struct FdbTransaction {
    backend: FdbBackend,
    pending_writes: PendingWrites,
}

#[async_trait]
impl Transaction for FdbTransaction {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        // Check pending writes first
        {
            let pending = self.pending_writes.lock();
            if let Some(value_opt) = pending.get(key) {
                return Ok(value_opt.as_ref().map(|v| Bytes::from(v.clone())));
            }
        }

        // If not in pending writes, read from backend
        self.backend.get(key).await
    }

    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let mut pending = self.pending_writes.lock();
        pending.insert(key, Some(value));
    }

    fn delete(&mut self, key: Vec<u8>) {
        let mut pending = self.pending_writes.lock();
        pending.insert(key, None);
    }

    async fn commit(self: Box<Self>) -> StorageResult<()> {
        let pending = {
            let pending = self.pending_writes.lock();
            pending.clone()
        };

        if pending.is_empty() {
            return Ok(());
        }

        let db = Arc::clone(&self.backend.db);
        let data_subspace = self.backend.data_subspace.clone();

        db.run({
            let data_subspace = data_subspace.clone();
            let pending = pending.clone();
            move |trx, _maybe_committed| {
                let data_subspace = data_subspace.clone();
                let pending = pending.clone();
                async move {
                    for (key, value_opt) in pending.iter() {
                        let data_key = data_subspace.pack(key);
                        match value_opt {
                            Some(value) => trx.set(&data_key, value),
                            None => trx.clear(&data_key),
                        }
                    }
                    Ok(())
                }
            }
        })
        .await
        .map_err(|e| {
            if e.to_string().contains("conflict") {
                StorageError::Conflict
            } else {
                StorageError::Internal(format!("Transaction commit failed: {}", e))
            }
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_backend() -> StorageResult<FdbBackend> {
        // Use default cluster file for tests
        FdbBackend::new().await
    }

    #[tokio::test]
    #[ignore] // Requires running FDB instance
    async fn test_basic_operations() -> StorageResult<()> {
        let backend = create_test_backend().await?;

        // Test set and get
        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();

        backend.set(key.clone(), value.clone()).await?;
        let result = backend.get(&key).await?;
        assert_eq!(result.as_deref(), Some(value.as_slice()));

        // Test delete
        backend.delete(&key).await?;
        let result = backend.get(&key).await?;
        assert_eq!(result, None);

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires running FDB instance
    async fn test_range_operations() -> StorageResult<()> {
        let backend = create_test_backend().await?;

        // Set up test data
        backend.set(b"key1".to_vec(), b"value1".to_vec()).await?;
        backend.set(b"key2".to_vec(), b"value2".to_vec()).await?;
        backend.set(b"key3".to_vec(), b"value3".to_vec()).await?;

        // Test get_range
        let range = backend.get_range(b"key1".to_vec()..b"key3".to_vec()).await?;
        assert_eq!(range.len(), 2);

        // Test clear_range
        backend.clear_range(b"key1".to_vec()..b"key4".to_vec()).await?;
        let range = backend.get_range(b"key1".to_vec()..b"key4".to_vec()).await?;
        assert_eq!(range.len(), 0);

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires running FDB instance
    async fn test_transaction() -> StorageResult<()> {
        let backend = create_test_backend().await?;

        let key1 = b"txn_key1".to_vec();
        let key2 = b"txn_key2".to_vec();
        let value1 = b"txn_value1".to_vec();
        let value2 = b"txn_value2".to_vec();

        // Start a transaction
        let mut txn = backend.transaction().await?;
        txn.set(key1.clone(), value1.clone());
        txn.set(key2.clone(), value2.clone());

        // Values shouldn't be visible yet
        let result = backend.get(&key1).await?;
        assert_eq!(result, None);

        // Commit transaction
        txn.commit().await?;

        // Now values should be visible
        let result1 = backend.get(&key1).await?;
        let result2 = backend.get(&key2).await?;
        assert_eq!(result1.as_deref(), Some(value1.as_slice()));
        assert_eq!(result2.as_deref(), Some(value2.as_slice()));

        // Cleanup
        backend.delete(&key1).await?;
        backend.delete(&key2).await?;

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires running FDB instance
    async fn test_health_check() -> StorageResult<()> {
        let backend = create_test_backend().await?;
        backend.health_check().await?;
        Ok(())
    }
}
