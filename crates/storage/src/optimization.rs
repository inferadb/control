//! Storage optimization layer with batching and caching
//!
//! This module provides performance optimizations on top of the base storage backend:
//!
//! - **Batch Writes**: Accumulate multiple writes and flush in batches with automatic splitting to
//!   respect transaction size limits
//! - **Read Caching**: Concurrent cache (via `moka`) for frequently accessed keys with TinyLFU
//!   eviction and built-in TTL
//! - **Cache Invalidation**: Automatic cache invalidation on batch writes
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
    ops::RangeBounds,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bon::Builder;
use bytes::Bytes;
// Re-export shared batch types from inferadb-storage
pub use inferadb_common_storage::batch::{
    BatchConfig, BatchFlushStats, BatchOperation, DEFAULT_MAX_BATCH_BYTES, DEFAULT_MAX_BATCH_SIZE,
    TRANSACTION_SIZE_LIMIT,
};
use inferadb_common_storage::health::{HealthProbe, HealthStatus};
use moka::sync::Cache;
use tracing::{debug, trace};

use crate::{
    backend::{KeyValue, StorageBackend, StorageResult, Transaction},
    metrics::{Metrics, MetricsCollector},
};

/// Configuration for read caching
#[derive(Debug, Clone, Builder)]
pub struct CacheConfig {
    /// Maximum number of entries in cache
    #[builder(default = 10_000)]
    pub max_entries: usize,
    /// TTL for cache entries (in seconds)
    #[builder(default = 60)]
    pub ttl_secs: u64,
    /// Enable cache (can be disabled for testing)
    #[builder(default = true)]
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

/// Type alias for the moka-backed cache
type MokaCache = Cache<Vec<u8>, Option<Bytes>>;

/// Build a moka cache from configuration
fn build_cache(config: &CacheConfig) -> MokaCache {
    Cache::builder()
        .max_capacity(config.max_entries as u64)
        .time_to_live(Duration::from_secs(config.ttl_secs))
        .build()
}

/// Batch writer with cache invalidation support
///
/// This wraps the shared `inferadb_common_storage::BatchWriter` and adds cache invalidation
/// on flush. This ensures cache consistency when using batch operations.
pub struct BatchWriter<B: StorageBackend> {
    inner: inferadb_common_storage::BatchWriter<B>,
    cache: Option<MokaCache>,
}

impl<B: StorageBackend + Clone> BatchWriter<B> {
    /// Create a new batch writer with optional cache
    pub fn new(backend: B, config: BatchConfig, cache: Option<MokaCache>) -> Self {
        Self { inner: inferadb_common_storage::BatchWriter::new(backend, config), cache }
    }

    /// Add a set operation to the batch
    pub fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.inner.set(key, value);
    }

    /// Add a delete operation to the batch
    pub fn delete(&mut self, key: Vec<u8>) {
        self.inner.delete(key);
    }

    /// Get the current number of pending operations
    pub fn pending_count(&self) -> usize {
        self.inner.pending_count()
    }

    /// Get the current estimated size in bytes
    pub fn pending_bytes(&self) -> usize {
        self.inner.pending_bytes()
    }

    /// Check if the batch should be flushed based on size limits
    pub fn should_flush(&self) -> bool {
        self.inner.should_flush()
    }

    /// Flush all pending operations to the backend
    ///
    /// This method invalidates cache entries for all keys being written
    /// before delegating to the underlying batch writer.
    pub async fn flush(&mut self) -> StorageResult<BatchFlushStats> {
        // Invalidate cache entries for all keys being written
        if let Some(cache) = &self.cache {
            for op in self.inner.pending_operations() {
                cache.invalidate(op.key());
            }
        }

        self.inner.flush().await.into_result()
    }

    /// Flush if the batch has reached size limits, otherwise do nothing
    pub async fn flush_if_needed(&mut self) -> StorageResult<Option<BatchFlushStats>> {
        if self.should_flush() { Ok(Some(self.flush().await?)) } else { Ok(None) }
    }

    /// Clear all pending operations without flushing
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

/// Optimized storage backend wrapper
#[derive(Clone)]
pub struct OptimizedBackend<B: StorageBackend> {
    backend: B,
    cache: Option<MokaCache>,
    cache_config: CacheConfig,
    batch_config: BatchConfig,
    metrics: Metrics,
}

impl<B: StorageBackend + Clone> OptimizedBackend<B> {
    /// Create a new optimized backend wrapper
    pub fn new(backend: B, cache_config: CacheConfig, batch_config: BatchConfig) -> Self {
        let cache = if cache_config.enabled { Some(build_cache(&cache_config)) } else { None };
        Self { backend, cache, cache_config, batch_config, metrics: Metrics::new() }
    }

    /// Create a batch writer for bulk write operations
    ///
    /// The batch writer accumulates operations and flushes them in optimized
    /// batches, automatically splitting to respect transaction size limits.
    /// Cache entries are automatically invalidated on flush.
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
        BatchWriter::new(self.backend.clone(), self.batch_config.clone(), self.cache.clone())
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
        let count = self.cache.as_ref().map_or(0, |c| c.entry_count() as usize);
        (count, self.cache_config.max_entries)
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        if let Some(cache) = &self.cache {
            cache.invalidate_all();
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

        // Check cache first
        if let Some(cache) = &self.cache {
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
        if let Some(cache) = &self.cache
            && let Ok(ref value) = result
        {
            cache.insert(key.to_vec(), value.clone());
            trace!(key_len = key.len(), "Cached value");
        }

        self.metrics.record_get(start.elapsed());

        if result.is_err() {
            self.metrics.record_error();
        }

        result
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        let start = Instant::now();

        if let Some(cache) = &self.cache {
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

        if let Some(cache) = &self.cache {
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

        // Clear entire cache (conservative approach — could be more targeted)
        if let Some(cache) = &self.cache {
            cache.invalidate_all();
            debug!("Cache cleared due to clear_range operation");
        }

        let result = self.backend.clear_range(range).await;

        self.metrics.record_clear_range(start.elapsed());

        if result.is_err() {
            self.metrics.record_error();
        }

        result
    }

    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()> {
        let start = Instant::now();

        if let Some(cache) = &self.cache {
            cache.invalidate(&key);
        }

        let result = self.backend.set_with_ttl(key, value, ttl).await;

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

    async fn compare_and_set(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        let start = Instant::now();

        if let Some(cache) = &self.cache {
            cache.invalidate(key);
        }

        let result = self.backend.compare_and_set(key, expected, new_value).await;

        self.metrics.record_set(start.elapsed());

        if result.is_err() {
            self.metrics.record_error();
        }

        result
    }

    async fn health_check(&self, probe: HealthProbe) -> StorageResult<HealthStatus> {
        self.metrics.record_health_check();
        self.backend.health_check(probe).await
    }
}

impl<B: StorageBackend + Clone> MetricsCollector for OptimizedBackend<B> {
    fn metrics(&self) -> &Metrics {
        &self.metrics
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        optimized.set(b"key1".to_vec(), b"value1".to_vec()).await.expect("set failed");
        let val1 = optimized.get(b"key1").await.expect("get failed");
        assert_eq!(val1, Some(Bytes::from("value1")));

        // Second get - should hit cache
        let val2 = optimized.get(b"key1").await.expect("get failed");
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
        optimized.set(b"key1".to_vec(), b"value1".to_vec()).await.expect("set failed");
        optimized.get(b"key1").await.expect("get failed");

        // Update value - should invalidate cache
        optimized.set(b"key1".to_vec(), b"value2".to_vec()).await.expect("set failed");

        // Next get should fetch new value
        let val = optimized.get(b"key1").await.expect("get failed");
        assert_eq!(val, Some(Bytes::from("value2")));
    }

    #[tokio::test]
    async fn test_cache_eviction() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::new(2, 60); // Only 2 entries
        let batch_config = BatchConfig::disabled();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        // Add 3 entries — moka enforces max_capacity asynchronously, so we
        // just verify the cache never grows unboundedly.
        optimized.set(b"key1".to_vec(), b"value1".to_vec()).await.expect("set failed");
        optimized.get(b"key1").await.expect("get failed");

        optimized.set(b"key2".to_vec(), b"value2".to_vec()).await.expect("set failed");
        optimized.get(b"key2").await.expect("get failed");

        optimized.set(b"key3".to_vec(), b"value3".to_vec()).await.expect("set failed");
        optimized.get(b"key3").await.expect("get failed");

        // Run pending maintenance tasks to enforce eviction
        optimized.cache.as_ref().expect("cache should be enabled").run_pending_tasks();

        let (cache_size, _) = optimized.cache_stats();
        assert!(cache_size <= 2, "Cache should not exceed max size, got {cache_size}");
    }

    #[tokio::test]
    async fn test_disabled_cache() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        let batch_config = BatchConfig::disabled();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        optimized.set(b"key1".to_vec(), b"value1".to_vec()).await.expect("set failed");
        optimized.get(b"key1").await.expect("get failed");
        optimized.get(b"key1").await.expect("get failed");

        let snapshot = optimized.metrics().snapshot();
        assert_eq!(snapshot.cache_hits, 0, "Disabled cache should have no hits");
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::default();
        let batch_config = BatchConfig::disabled();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        optimized.set(b"key1".to_vec(), b"value1".to_vec()).await.expect("set failed");
        optimized.get(b"key1").await.expect("get failed");
        optimized.delete(b"key1").await.expect("delete failed");

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
        let batch_config = BatchConfig::builder()
            .max_batch_size(100)
            .max_batch_bytes(1024 * 1024)
            .build()
            .unwrap();
        let optimized = OptimizedBackend::new(backend.clone(), cache_config, batch_config);

        let mut batch = optimized.batch_writer();
        batch.set(b"key1".to_vec(), b"value1".to_vec());
        batch.set(b"key2".to_vec(), b"value2".to_vec());
        batch.delete(b"key3".to_vec());

        assert_eq!(batch.pending_count(), 3);

        let stats = batch.flush().await.expect("flush failed");
        assert_eq!(stats.operations_count, 3);
        assert_eq!(stats.batches_count, 1);

        // Verify writes were applied
        let val1 = backend.get(b"key1").await.expect("get failed");
        assert_eq!(val1, Some(Bytes::from("value1")));
        let val2 = backend.get(b"key2").await.expect("get failed");
        assert_eq!(val2, Some(Bytes::from("value2")));
    }

    #[tokio::test]
    async fn test_batch_writer_auto_split() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        // Very small batch size to force splitting
        let batch_config =
            BatchConfig::builder().max_batch_size(2).max_batch_bytes(1024 * 1024).build().unwrap();
        let optimized = OptimizedBackend::new(backend.clone(), cache_config, batch_config);

        let mut batch = optimized.batch_writer();
        for i in 0..5 {
            batch.set(format!("key{i}").into_bytes(), format!("value{i}").into_bytes());
        }

        let stats = batch.flush().await.expect("flush failed");
        assert_eq!(stats.operations_count, 5);
        assert_eq!(stats.batches_count, 3); // 2 + 2 + 1

        // Verify all writes were applied
        for i in 0..5 {
            let val = backend.get(format!("key{i}").as_bytes()).await.expect("get failed");
            assert_eq!(val, Some(Bytes::from(format!("value{i}"))));
        }
    }

    #[tokio::test]
    async fn test_batch_writer_size_limit_split() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        // Very small byte limit to force splitting
        let batch_config =
            BatchConfig::builder().max_batch_size(1000).max_batch_bytes(200).build().unwrap();
        let optimized = OptimizedBackend::new(backend.clone(), cache_config, batch_config);

        let mut batch = optimized.batch_writer();
        // Each operation is roughly 60+ bytes (key + value + overhead)
        for i in 0..5 {
            batch.set(format!("key{i}").into_bytes(), format!("value{i}").into_bytes());
        }

        let stats = batch.flush().await.expect("flush failed");
        assert_eq!(stats.operations_count, 5);
        assert!(stats.batches_count >= 2, "Should split into multiple batches");

        // Verify all writes were applied
        for i in 0..5 {
            let val = backend.get(format!("key{i}").as_bytes()).await.expect("get failed");
            assert_eq!(val, Some(Bytes::from(format!("value{i}"))));
        }
    }

    #[tokio::test]
    async fn test_batch_writer_should_flush() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        let batch_config =
            BatchConfig::builder().max_batch_size(3).max_batch_bytes(1024 * 1024).build().unwrap();
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
        let batch_config =
            BatchConfig::builder().max_batch_size(2).max_batch_bytes(1024 * 1024).build().unwrap();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        let mut batch = optimized.batch_writer();
        batch.set(b"key1".to_vec(), b"value1".to_vec());

        // Not at limit yet
        let result = batch.flush_if_needed().await.expect("flush failed");
        assert!(result.is_none());

        batch.set(b"key2".to_vec(), b"value2".to_vec());

        // Now at limit
        let result = batch.flush_if_needed().await.expect("flush failed");
        assert!(result.is_some());
        assert_eq!(result.expect("expected stats").operations_count, 2);
    }

    #[tokio::test]
    async fn test_batch_writer_empty_flush() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        let batch_config = BatchConfig::default();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        let mut batch = optimized.batch_writer();
        let stats = batch.flush().await.expect("flush failed");

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
        optimized.set(b"key1".to_vec(), b"old_value".to_vec()).await.expect("set failed");
        optimized.get(b"key1").await.expect("get failed"); // Cache it

        // Use batch writer to update
        let mut batch = optimized.batch_writer();
        batch.set(b"key1".to_vec(), b"new_value".to_vec());
        batch.flush().await.expect("flush failed");

        // Verify cache was invalidated and new value is returned
        let val = optimized.get(b"key1").await.expect("get failed");
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

        let stats = optimized.execute_batch(operations).await.expect("execute failed");
        assert_eq!(stats.operations_count, 3);

        let val1 = backend.get(b"key1").await.expect("get failed");
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
        assert!(config.enabled());
        assert_eq!(config.max_batch_bytes(), TRANSACTION_SIZE_LIMIT);
        assert_eq!(config.max_batch_size(), DEFAULT_MAX_BATCH_SIZE);
    }

    #[tokio::test]
    async fn test_large_batch_stress() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::disabled();
        let batch_config =
            BatchConfig::builder().max_batch_size(100).max_batch_bytes(10000).build().unwrap(); // Small limits
        let optimized = OptimizedBackend::new(backend.clone(), cache_config, batch_config);

        let mut batch = optimized.batch_writer();

        // Add many operations
        for i in 0..500 {
            batch.set(
                format!("stress_key_{i}").into_bytes(),
                format!("stress_value_{i}").into_bytes(),
            );
        }

        let stats = batch.flush().await.expect("flush failed");
        assert_eq!(stats.operations_count, 500);
        assert!(stats.batches_count > 1, "Large batch should be split");

        // Verify random samples
        let val = backend.get(b"stress_key_0").await.expect("get failed");
        assert_eq!(val, Some(Bytes::from("stress_value_0")));
        let val = backend.get(b"stress_key_499").await.expect("get failed");
        assert_eq!(val, Some(Bytes::from("stress_value_499")));
    }

    #[tokio::test]
    async fn test_set_invalidates_cache() {
        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::new(100, 60);
        let batch_config = BatchConfig::disabled();
        let optimized = OptimizedBackend::new(backend, cache_config, batch_config);

        // Pre-populate and cache
        optimized.set(b"key".to_vec(), b"old".to_vec()).await.expect("set failed");
        optimized.get(b"key").await.expect("get failed");

        // Update via set - should invalidate cache
        optimized.set(b"key".to_vec(), b"new".to_vec()).await.expect("set failed");

        // Verify cache was invalidated and new value is returned
        let val = optimized.get(b"key").await.expect("get failed");
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
        let mut txn = optimized.transaction().await.expect("txn failed");
        txn.set(b"txn_key".to_vec(), b"value".to_vec());
        txn.commit().await.expect("commit failed");

        // Value should be in backend
        let val = backend.get(b"txn_key").await.expect("get failed");
        assert_eq!(val, Some(Bytes::from("value")));
    }

    #[tokio::test]
    async fn test_concurrent_cache_access() {
        use std::sync::Arc;

        let backend = MemoryBackend::new();
        let cache_config = CacheConfig::new(1_000, 60);
        let batch_config = BatchConfig::disabled();
        let optimized = Arc::new(OptimizedBackend::new(backend, cache_config, batch_config));

        // Pre-populate some keys
        for i in 0..100 {
            optimized
                .set(format!("conc_key_{i}").into_bytes(), format!("value_{i}").into_bytes())
                .await
                .expect("set failed");
        }

        // Spawn 10 tasks each doing 100 reads
        let mut handles = Vec::new();
        for task_id in 0..10 {
            let opt = Arc::clone(&optimized);
            handles.push(tokio::spawn(async move {
                for i in 0..100 {
                    let key = format!("conc_key_{}", (task_id * 10 + i) % 100);
                    let val = opt.get(key.as_bytes()).await.expect("concurrent get failed");
                    assert!(val.is_some(), "Expected value for {key}");
                }
            }));
        }

        for handle in handles {
            handle.await.expect("task panicked");
        }

        let snapshot = optimized.metrics().snapshot();
        assert!(snapshot.cache_hits > 0, "Should have cache hits from concurrent access");
    }
}
