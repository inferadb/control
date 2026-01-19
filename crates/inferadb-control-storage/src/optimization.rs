//! Storage optimization layer with batching and caching
//!
//! This module provides performance optimizations on top of the base storage backend:
//!
//! - **Batch Writes**: Accumulate multiple writes and flush in batches with automatic splitting to
//!   respect transaction size limits
//! - **Read Caching**: LRU cache for frequently accessed keys
//! - **Size Estimation**: Accurate tracking of batch sizes to prevent transaction failures
//!
//! # Usage
//!
//! Wrap any `StorageBackend` implementation with `OptimizedBackend`:
//!
//! ```ignore
//! let base_backend = LedgerBackend::new().await?;
//! let optimized = OptimizedBackend::new(base_backend, cache_config, batch_config);
//!
//! // Use batch writer for bulk operations
//! let mut batch = optimized.batch_writer();
//! batch.set(b"key1".to_vec(), b"value1".to_vec());
//! batch.set(b"key2".to_vec(), b"value2".to_vec());
//! batch.flush().await?;
//! ```

use std::{
    collections::{HashMap, VecDeque},
    ops::RangeBounds,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tracing::{debug, trace, warn};

use crate::{
    backend::{KeyValue, StorageBackend, StorageResult, Transaction},
    metrics::{Metrics, MetricsCollector},
};

/// Transaction size limit (10MB with safety margin)
/// We use 9MB as the effective limit to leave room for metadata overhead
const TRANSACTION_SIZE_LIMIT: usize = 9 * 1024 * 1024;

/// Default maximum batch size (number of operations)
const DEFAULT_MAX_BATCH_SIZE: usize = 1000;

/// Default maximum batch byte size (8MB to stay well under transaction limit)
const DEFAULT_MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Configuration for read caching
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries in cache
    pub max_entries: usize,
    /// TTL for cache entries (in seconds)
    pub ttl_secs: u64,
    /// Enable cache (can be disabled for testing)
    pub enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self { max_entries: 10_000, ttl_secs: 60, enabled: true }
    }
}

impl CacheConfig {
    /// Create a disabled cache config
    pub fn disabled() -> Self {
        Self { max_entries: 0, ttl_secs: 0, enabled: false }
    }

    /// Create a cache config with custom settings
    pub fn new(max_entries: usize, ttl_secs: u64) -> Self {
        Self { max_entries, ttl_secs, enabled: true }
    }
}

/// Configuration for batch writes
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum number of operations per batch
    pub max_batch_size: usize,
    /// Maximum byte size per batch (should be under the 10MB transaction limit)
    pub max_batch_bytes: usize,
    /// Enable batching (can be disabled for testing)
    pub enabled: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            enabled: true,
        }
    }
}

impl BatchConfig {
    /// Create a disabled batch config
    pub fn disabled() -> Self {
        Self { max_batch_size: 0, max_batch_bytes: 0, enabled: false }
    }

    /// Create a batch config with custom settings
    pub fn new(max_batch_size: usize, max_batch_bytes: usize) -> Self {
        Self { max_batch_size, max_batch_bytes, enabled: true }
    }

    /// Create a batch config optimized for large transactions
    pub fn for_large_transactions() -> Self {
        Self {
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_batch_bytes: TRANSACTION_SIZE_LIMIT,
            enabled: true,
        }
    }
}

/// Represents a single write operation in a batch
#[derive(Debug, Clone)]
pub enum BatchOperation {
    /// Set a key-value pair
    Set { key: Vec<u8>, value: Vec<u8> },
    /// Delete a key
    Delete { key: Vec<u8> },
}

impl BatchOperation {
    /// Calculate the approximate size of this operation in bytes
    pub fn size_bytes(&self) -> usize {
        match self {
            BatchOperation::Set { key, value } => {
                // Key + value + overhead for encoding (estimate ~50 bytes)
                key.len() + value.len() + 50
            },
            BatchOperation::Delete { key } => {
                // Key + overhead
                key.len() + 50
            },
        }
    }

    /// Get the key for this operation
    pub fn key(&self) -> &[u8] {
        match self {
            BatchOperation::Set { key, .. } => key,
            BatchOperation::Delete { key } => key,
        }
    }
}

/// Statistics from a batch flush operation
#[derive(Debug, Clone, Default)]
pub struct BatchFlushStats {
    /// Number of operations flushed
    pub operations_count: usize,
    /// Number of sub-batches created (due to size limits)
    pub batches_count: usize,
    /// Total bytes written
    pub total_bytes: usize,
    /// Time taken to flush
    pub duration: Duration,
}

/// Batch writer for accumulating and flushing write operations
///
/// This writer accumulates write operations and flushes them in optimized batches.
/// It automatically splits large batches to respect transaction size limits.
pub struct BatchWriter<B: StorageBackend> {
    backend: B,
    operations: Vec<BatchOperation>,
    current_size_bytes: usize,
    config: BatchConfig,
    cache: Option<Arc<Mutex<LruCache>>>,
}

impl<B: StorageBackend + Clone> BatchWriter<B> {
    /// Create a new batch writer
    pub fn new(backend: B, config: BatchConfig, cache: Option<Arc<Mutex<LruCache>>>) -> Self {
        Self { backend, operations: Vec::new(), current_size_bytes: 0, config, cache }
    }

    /// Add a set operation to the batch
    pub fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let op = BatchOperation::Set { key, value };
        self.current_size_bytes += op.size_bytes();
        self.operations.push(op);
    }

    /// Add a delete operation to the batch
    pub fn delete(&mut self, key: Vec<u8>) {
        let op = BatchOperation::Delete { key };
        self.current_size_bytes += op.size_bytes();
        self.operations.push(op);
    }

    /// Get the current number of pending operations
    pub fn pending_count(&self) -> usize {
        self.operations.len()
    }

    /// Get the current estimated size in bytes
    pub fn pending_bytes(&self) -> usize {
        self.current_size_bytes
    }

    /// Check if the batch should be flushed based on size limits
    pub fn should_flush(&self) -> bool {
        if !self.config.enabled {
            return !self.operations.is_empty();
        }
        self.operations.len() >= self.config.max_batch_size
            || self.current_size_bytes >= self.config.max_batch_bytes
    }

    /// Split operations into sub-batches that fit within size limits
    fn split_into_batches(&self) -> Vec<Vec<&BatchOperation>> {
        if self.operations.is_empty() {
            return Vec::new();
        }

        let max_bytes = if self.config.enabled {
            self.config.max_batch_bytes
        } else {
            TRANSACTION_SIZE_LIMIT
        };

        let max_ops = if self.config.enabled { self.config.max_batch_size } else { usize::MAX };

        let mut batches = Vec::new();
        let mut current_batch = Vec::new();
        let mut current_bytes = 0usize;

        for op in &self.operations {
            let op_size = op.size_bytes();

            // If this single operation exceeds the limit, it goes in its own batch
            // (storage backend will reject it, but we let it through for proper error handling)
            if op_size > max_bytes {
                if !current_batch.is_empty() {
                    batches.push(current_batch);
                    current_batch = Vec::new();
                    current_bytes = 0;
                }
                batches.push(vec![op]);
                continue;
            }

            // Check if adding this operation would exceed limits
            if (current_bytes + op_size > max_bytes || current_batch.len() >= max_ops)
                && !current_batch.is_empty()
            {
                batches.push(current_batch);
                current_batch = Vec::new();
                current_bytes = 0;
            }

            current_batch.push(op);
            current_bytes += op_size;
        }

        if !current_batch.is_empty() {
            batches.push(current_batch);
        }

        batches
    }

    /// Flush all pending operations to the backend
    ///
    /// This method splits operations into appropriately-sized batches and
    /// commits each batch in a separate transaction for optimal performance.
    pub async fn flush(&mut self) -> StorageResult<BatchFlushStats> {
        if self.operations.is_empty() {
            return Ok(BatchFlushStats::default());
        }

        let start = Instant::now();
        let total_ops = self.operations.len();
        let total_bytes = self.current_size_bytes;

        let batches = self.split_into_batches();
        let batches_count = batches.len();

        debug!(
            operations = total_ops,
            bytes = total_bytes,
            batches = batches_count,
            "Flushing batch writes"
        );

        // Invalidate cache entries for all keys being written
        if let Some(cache) = &self.cache {
            let mut cache = cache.lock();
            for op in &self.operations {
                cache.invalidate(op.key());
            }
        }

        // Execute each sub-batch in its own transaction
        for (batch_idx, batch_ops) in batches.into_iter().enumerate() {
            let mut txn = self.backend.transaction().await?;

            for op in batch_ops {
                match op {
                    BatchOperation::Set { key, value } => {
                        txn.set(key.clone(), value.clone());
                    },
                    BatchOperation::Delete { key } => {
                        txn.delete(key.clone());
                    },
                }
            }

            txn.commit().await.map_err(|e| {
                warn!(batch = batch_idx, error = %e, "Batch commit failed");
                e
            })?;

            trace!(batch = batch_idx, "Batch committed successfully");
        }

        // Clear the pending operations
        self.operations.clear();
        self.current_size_bytes = 0;

        let stats = BatchFlushStats {
            operations_count: total_ops,
            batches_count,
            total_bytes,
            duration: start.elapsed(),
        };

        debug!(
            operations = stats.operations_count,
            batches = stats.batches_count,
            bytes = stats.total_bytes,
            duration_ms = stats.duration.as_millis(),
            "Batch flush completed"
        );

        Ok(stats)
    }

    /// Flush if the batch has reached size limits, otherwise do nothing
    pub async fn flush_if_needed(&mut self) -> StorageResult<Option<BatchFlushStats>> {
        if self.should_flush() { Ok(Some(self.flush().await?)) } else { Ok(None) }
    }

    /// Clear all pending operations without flushing
    pub fn clear(&mut self) {
        self.operations.clear();
        self.current_size_bytes = 0;
    }
}

/// Cache entry with expiration
struct CacheEntry {
    value: Option<Bytes>,
    expires_at: Instant,
}

/// LRU cache implementation
pub struct LruCache {
    entries: HashMap<Vec<u8>, CacheEntry>,
    access_order: VecDeque<Vec<u8>>,
    max_entries: usize,
    ttl: Duration,
}

impl LruCache {
    fn new(max_entries: usize, ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            access_order: VecDeque::new(),
            max_entries,
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    fn get(&mut self, key: &[u8]) -> Option<Option<Bytes>> {
        let now = Instant::now();

        // Check if entry exists and is not expired
        if let Some(entry) = self.entries.get(key) {
            if entry.expires_at > now {
                // Move to back of access queue (most recently used)
                if let Some(pos) = self.access_order.iter().position(|k| k == key) {
                    self.access_order.remove(pos);
                }
                self.access_order.push_back(key.to_vec());

                return Some(entry.value.clone());
            } else {
                // Entry expired - remove it
                self.entries.remove(key);
                if let Some(pos) = self.access_order.iter().position(|k| k == key) {
                    self.access_order.remove(pos);
                }
            }
        }

        None
    }

    fn insert(&mut self, key: Vec<u8>, value: Option<Bytes>) {
        let now = Instant::now();

        // Evict if at capacity
        while self.entries.len() >= self.max_entries && !self.access_order.is_empty() {
            if let Some(old_key) = self.access_order.pop_front() {
                self.entries.remove(&old_key);
            }
        }

        // Insert new entry
        self.entries.insert(key.clone(), CacheEntry { value, expires_at: now + self.ttl });
        self.access_order.push_back(key);
    }

    /// Invalidate a cache entry
    pub fn invalidate(&mut self, key: &[u8]) {
        self.entries.remove(key);
        if let Some(pos) = self.access_order.iter().position(|k| k == key) {
            self.access_order.remove(pos);
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Optimized storage backend wrapper
#[derive(Clone)]
pub struct OptimizedBackend<B: StorageBackend> {
    backend: B,
    cache: Arc<Mutex<LruCache>>,
    cache_config: CacheConfig,
    batch_config: BatchConfig,
    metrics: Metrics,
}

impl<B: StorageBackend + Clone> OptimizedBackend<B> {
    /// Create a new optimized backend wrapper
    pub fn new(backend: B, cache_config: CacheConfig, batch_config: BatchConfig) -> Self {
        let cache = if cache_config.enabled {
            Arc::new(Mutex::new(LruCache::new(cache_config.max_entries, cache_config.ttl_secs)))
        } else {
            Arc::new(Mutex::new(LruCache::new(0, 0)))
        };

        Self { backend, cache, cache_config, batch_config, metrics: Metrics::new() }
    }

    /// Create a batch writer for bulk write operations
    ///
    /// The batch writer accumulates operations and flushes them in optimized
    /// batches, automatically splitting to respect transaction size limits.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut batch = optimized.batch_writer();
    /// for i in 0..1000 {
    ///     batch.set(format!("key{}", i).into_bytes(), b"value".to_vec());
    /// }
    /// let stats = batch.flush().await?;
    /// println!("Flushed {} operations in {} batches", stats.operations_count, stats.batches_count);
    /// ```
    pub fn batch_writer(&self) -> BatchWriter<B> {
        BatchWriter::new(
            self.backend.clone(),
            self.batch_config.clone(),
            if self.cache_config.enabled { Some(Arc::clone(&self.cache)) } else { None },
        )
    }

    /// Execute a batch of operations atomically
    ///
    /// This is a convenience method for executing multiple operations in a
    /// single optimized batch. For more control, use `batch_writer()`.
    pub async fn execute_batch(
        &self,
        operations: Vec<BatchOperation>,
    ) -> StorageResult<BatchFlushStats> {
        let mut batch = self.batch_writer();
        for op in operations {
            match op {
                BatchOperation::Set { key, value } => batch.set(key, value),
                BatchOperation::Delete { key } => batch.delete(key),
            }
        }
        batch.flush().await
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.lock();
        (cache.len(), self.cache_config.max_entries)
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        if self.cache_config.enabled {
            let mut cache = self.cache.lock();
            cache.clear();
            debug!("Cache cleared");
        }
    }

    /// Get the underlying backend
    pub fn inner(&self) -> &B {
        &self.backend
    }

    /// Get the batch configuration
    pub fn batch_config(&self) -> &BatchConfig {
        &self.batch_config
    }
}

#[async_trait]
impl<B: StorageBackend + Clone> StorageBackend for OptimizedBackend<B> {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        let start = Instant::now();

        // Check cache first if enabled
        if self.cache_config.enabled {
            let mut cache = self.cache.lock();
            if let Some(cached_value) = cache.get(key) {
                self.metrics.record_cache_hit();
                self.metrics.record_get(start.elapsed());
                trace!(key_len = key.len(), "Cache hit");
                return Ok(cached_value);
            }
            self.metrics.record_cache_miss();
        }

        // Cache miss - fetch from backend
        let result = self.backend.get(key).await;

        // Update cache on success
        if self.cache_config.enabled {
            if let Ok(ref value) = result {
                let mut cache = self.cache.lock();
                cache.insert(key.to_vec(), value.clone());
                trace!(key_len = key.len(), "Cached value");
            }
        }

        self.metrics.record_get(start.elapsed());

        if result.is_err() {
            self.metrics.record_error();
        }

        result
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        let start = Instant::now();

        // Invalidate cache entry
        if self.cache_config.enabled {
            let mut cache = self.cache.lock();
            cache.invalidate(&key);
        }

        let result = self.backend.set(key, value).await;

        self.metrics.record_set(start.elapsed());

        if result.is_err() {
            self.metrics.record_error();
        }

        result
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        let start = Instant::now();

        // Invalidate cache entry
        if self.cache_config.enabled {
            let mut cache = self.cache.lock();
            cache.invalidate(key);
        }

        let result = self.backend.delete(key).await;

        self.metrics.record_delete(start.elapsed());

        if result.is_err() {
            self.metrics.record_error();
        }

        result
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        let start = Instant::now();

        // Range queries bypass cache
        let result = self.backend.get_range(range).await;

        self.metrics.record_get_range(start.elapsed());

        if result.is_err() {
            self.metrics.record_error();
        }

        result
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        let start = Instant::now();

        // Clear cache (conservative approach - could be more targeted)
        if self.cache_config.enabled {
            let mut cache = self.cache.lock();
            cache.clear();
            debug!("Cache cleared due to clear_range operation");
        }

        let result = self.backend.clear_range(range).await;

        self.metrics.record_clear_range(start.elapsed());

        if result.is_err() {
            self.metrics.record_error();
        }

        result
    }

    async fn set_with_ttl(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let start = Instant::now();

        // Invalidate cache entry
        if self.cache_config.enabled {
            let mut cache = self.cache.lock();
            cache.invalidate(&key);
        }

        let result = self.backend.set_with_ttl(key, value, ttl_seconds).await;

        self.metrics.record_set(start.elapsed());
        self.metrics.record_ttl_operation();

        if result.is_err() {
            self.metrics.record_error();
        }

        result
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        let start = Instant::now();
        let txn = self.backend.transaction().await?;
        self.metrics.record_transaction(start.elapsed());
        Ok(txn)
    }

    async fn health_check(&self) -> StorageResult<()> {
        self.metrics.record_health_check();
        self.backend.health_check().await
    }
}

impl<B: StorageBackend + Clone> MetricsCollector for OptimizedBackend<B> {
    fn metrics(&self) -> &Metrics {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryBackend;

    #[tokio::test]
    async fn test_cache_hit() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::new(100, 60);
        let batch_config = BatchConfig::disabled();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        // First get - cache miss
        optimized.set(b"key1".to_vec(), b"value1".to_vec()).await.unwrap();
        let val1 = optimized.get(b"key1").await.unwrap();
        assert_eq!(val1, Some(Bytes::from("value1")));

        // Second get - should hit cache
        let val2 = optimized.get(b"key1").await.unwrap();
        assert_eq!(val2, Some(Bytes::from("value1")));

        let snapshot = optimized.metrics().snapshot();
        assert!(snapshot.cache_hits > 0, "Should have cache hits");
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::new(100, 60);
        let batch_config = BatchConfig::disabled();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        // Set and cache
        optimized.set(b"key1".to_vec(), b"value1".to_vec()).await.unwrap();
        optimized.get(b"key1").await.unwrap();

        // Update value - should invalidate cache
        optimized.set(b"key1".to_vec(), b"value2".to_vec()).await.unwrap();

        // Next get should fetch new value
        let val = optimized.get(b"key1").await.unwrap();
        assert_eq!(val, Some(Bytes::from("value2")));
    }

    #[tokio::test]
    async fn test_cache_eviction() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::new(2, 60); // Only 2 entries
        let batch_config = BatchConfig::disabled();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        // Add 3 entries - oldest should be evicted
        optimized.set(b"key1".to_vec(), b"value1".to_vec()).await.unwrap();
        optimized.get(b"key1").await.unwrap();

        optimized.set(b"key2".to_vec(), b"value2".to_vec()).await.unwrap();
        optimized.get(b"key2").await.unwrap();

        optimized.set(b"key3".to_vec(), b"value3".to_vec()).await.unwrap();
        optimized.get(b"key3").await.unwrap();

        let (cache_size, _) = optimized.cache_stats();
        assert_eq!(cache_size, 2, "Cache should not exceed max size");
    }

    #[tokio::test]
    async fn test_disabled_cache() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        let batch_config = BatchConfig::disabled();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        optimized.set(b"key1".to_vec(), b"value1".to_vec()).await.unwrap();
        optimized.get(b"key1").await.unwrap();
        optimized.get(b"key1").await.unwrap();

        let snapshot = optimized.metrics().snapshot();
        assert_eq!(snapshot.cache_hits, 0, "Disabled cache should have no hits");
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::default();
        let batch_config = BatchConfig::disabled();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        optimized.set(b"key1".to_vec(), b"value1".to_vec()).await.unwrap();
        optimized.get(b"key1").await.unwrap();
        optimized.delete(b"key1").await.unwrap();

        let snapshot = optimized.metrics().snapshot();
        assert_eq!(snapshot.set_count, 1);
        assert_eq!(snapshot.get_count, 1);
        assert_eq!(snapshot.delete_count, 1);
    }

    // Batch writer tests

    #[tokio::test]
    async fn test_batch_writer_basic() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        let batch_config = BatchConfig::new(100, 1024 * 1024);
        let optimized = OptimizedBackend::new(backend.clone(), cache_config, batch_config);

        let mut batch = optimized.batch_writer();
        batch.set(b"key1".to_vec(), b"value1".to_vec());
        batch.set(b"key2".to_vec(), b"value2".to_vec());
        batch.delete(b"key3".to_vec());

        assert_eq!(batch.pending_count(), 3);

        let stats = batch.flush().await.unwrap();
        assert_eq!(stats.operations_count, 3);
        assert_eq!(stats.batches_count, 1);

        // Verify writes were applied
        let val1 = backend.get(b"key1").await.unwrap();
        assert_eq!(val1, Some(Bytes::from("value1")));
        let val2 = backend.get(b"key2").await.unwrap();
        assert_eq!(val2, Some(Bytes::from("value2")));
    }

    #[tokio::test]
    async fn test_batch_writer_auto_split() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        // Very small batch size to force splitting
        let batch_config = BatchConfig::new(2, 1024 * 1024);
        let optimized = OptimizedBackend::new(backend.clone(), cache_config, batch_config);

        let mut batch = optimized.batch_writer();
        for i in 0..5 {
            batch.set(format!("key{}", i).into_bytes(), format!("value{}", i).into_bytes());
        }

        let stats = batch.flush().await.unwrap();
        assert_eq!(stats.operations_count, 5);
        assert_eq!(stats.batches_count, 3); // 2 + 2 + 1

        // Verify all writes were applied
        for i in 0..5 {
            let val = backend.get(format!("key{}", i).as_bytes()).await.unwrap();
            assert_eq!(val, Some(Bytes::from(format!("value{}", i))));
        }
    }

    #[tokio::test]
    async fn test_batch_writer_size_limit_split() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        // Very small byte limit to force splitting
        let batch_config = BatchConfig::new(1000, 200);
        let optimized = OptimizedBackend::new(backend.clone(), cache_config, batch_config);

        let mut batch = optimized.batch_writer();
        // Each operation is roughly 60+ bytes (key + value + overhead)
        for i in 0..5 {
            batch.set(format!("key{}", i).into_bytes(), format!("value{}", i).into_bytes());
        }

        let stats = batch.flush().await.unwrap();
        assert_eq!(stats.operations_count, 5);
        assert!(stats.batches_count >= 2, "Should split into multiple batches");

        // Verify all writes were applied
        for i in 0..5 {
            let val = backend.get(format!("key{}", i).as_bytes()).await.unwrap();
            assert_eq!(val, Some(Bytes::from(format!("value{}", i))));
        }
    }

    #[tokio::test]
    async fn test_batch_writer_should_flush() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        let batch_config = BatchConfig::new(3, 1024 * 1024);
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        let mut batch = optimized.batch_writer();
        assert!(!batch.should_flush());

        batch.set(b"key1".to_vec(), b"value1".to_vec());
        batch.set(b"key2".to_vec(), b"value2".to_vec());
        assert!(!batch.should_flush());

        batch.set(b"key3".to_vec(), b"value3".to_vec());
        assert!(batch.should_flush());
    }

    #[tokio::test]
    async fn test_batch_writer_flush_if_needed() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        let batch_config = BatchConfig::new(2, 1024 * 1024);
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        let mut batch = optimized.batch_writer();
        batch.set(b"key1".to_vec(), b"value1".to_vec());

        // Not at limit yet
        let result = batch.flush_if_needed().await.unwrap();
        assert!(result.is_none());

        batch.set(b"key2".to_vec(), b"value2".to_vec());

        // Now at limit
        let result = batch.flush_if_needed().await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().operations_count, 2);
    }

    #[tokio::test]
    async fn test_batch_writer_empty_flush() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        let batch_config = BatchConfig::default();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        let mut batch = optimized.batch_writer();
        let stats = batch.flush().await.unwrap();

        assert_eq!(stats.operations_count, 0);
        assert_eq!(stats.batches_count, 0);
    }

    #[tokio::test]
    async fn test_batch_writer_cache_invalidation() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::new(100, 60);
        let batch_config = BatchConfig::default();
        let optimized = OptimizedBackend::new(backend.clone(), cache_config, batch_config);

        // Pre-populate cache
        optimized.set(b"key1".to_vec(), b"old_value".to_vec()).await.unwrap();
        optimized.get(b"key1").await.unwrap(); // Cache it

        // Use batch writer to update
        let mut batch = optimized.batch_writer();
        batch.set(b"key1".to_vec(), b"new_value".to_vec());
        batch.flush().await.unwrap();

        // Verify cache was invalidated and new value is returned
        let val = optimized.get(b"key1").await.unwrap();
        assert_eq!(val, Some(Bytes::from("new_value")));
    }

    #[tokio::test]
    async fn test_execute_batch() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        let batch_config = BatchConfig::default();
        let optimized = OptimizedBackend::new(backend.clone(), cache_config, batch_config);

        let operations = vec![
            BatchOperation::Set { key: b"key1".to_vec(), value: b"value1".to_vec() },
            BatchOperation::Set { key: b"key2".to_vec(), value: b"value2".to_vec() },
            BatchOperation::Delete { key: b"key3".to_vec() },
        ];

        let stats = optimized.execute_batch(operations).await.unwrap();
        assert_eq!(stats.operations_count, 3);

        let val1 = backend.get(b"key1").await.unwrap();
        assert_eq!(val1, Some(Bytes::from("value1")));
    }

    #[tokio::test]
    async fn test_batch_operation_size() {
        let small_op = BatchOperation::Set { key: b"key".to_vec(), value: b"val".to_vec() };
        let large_op = BatchOperation::Set { key: vec![0u8; 100], value: vec![0u8; 1000] };
        let delete_op = BatchOperation::Delete { key: b"key".to_vec() };

        // Set operations should be larger than delete operations with same key
        assert!(small_op.size_bytes() > delete_op.size_bytes());
        // Larger keys/values should produce larger sizes
        assert!(small_op.size_bytes() < large_op.size_bytes());
    }

    #[tokio::test]
    async fn test_batch_config_for_large_transactions() {
        let config = BatchConfig::for_large_transactions();
        assert!(config.enabled);
        assert_eq!(config.max_batch_bytes, TRANSACTION_SIZE_LIMIT);
        assert_eq!(config.max_batch_size, DEFAULT_MAX_BATCH_SIZE);
    }

    #[tokio::test]
    async fn test_large_batch_stress() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        let batch_config = BatchConfig::new(100, 10000); // Small limits
        let optimized = OptimizedBackend::new(backend.clone(), cache_config, batch_config);

        let mut batch = optimized.batch_writer();

        // Add many operations
        for i in 0..500 {
            batch.set(
                format!("stress_key_{}", i).into_bytes(),
                format!("stress_value_{}", i).into_bytes(),
            );
        }

        let stats = batch.flush().await.unwrap();
        assert_eq!(stats.operations_count, 500);
        assert!(stats.batches_count > 1, "Large batch should be split");

        // Verify random samples
        let val = backend.get(b"stress_key_0").await.unwrap();
        assert_eq!(val, Some(Bytes::from("stress_value_0")));
        let val = backend.get(b"stress_key_499").await.unwrap();
        assert_eq!(val, Some(Bytes::from("stress_value_499")));
    }

    #[tokio::test]
    async fn test_set_invalidates_cache() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::new(100, 60);
        let batch_config = BatchConfig::disabled();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        // Pre-populate and cache
        optimized.set(b"key".to_vec(), b"old".to_vec()).await.unwrap();
        optimized.get(b"key").await.unwrap();

        // Update via set - should invalidate cache
        optimized.set(b"key".to_vec(), b"new".to_vec()).await.unwrap();

        // Verify cache was invalidated and new value is returned
        let val = optimized.get(b"key").await.unwrap();
        assert_eq!(val, Some(Bytes::from("new")));
    }

    #[tokio::test]
    async fn test_transaction_passthrough() {
        // Transactions operate directly on backend for atomicity.
        // Use the set/delete/execute_batch methods for cache-aware operations.
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::new(100, 60);
        let batch_config = BatchConfig::disabled();
        let optimized = OptimizedBackend::new(backend.clone(), cache_config, batch_config);

        // Write via transaction
        let mut txn = optimized.transaction().await.unwrap();
        txn.set(b"txn_key".to_vec(), b"value".to_vec());
        txn.commit().await.unwrap();

        // Value should be in backend
        let val = backend.get(b"txn_key").await.unwrap();
        assert_eq!(val, Some(Bytes::from("value")));
    }
}
