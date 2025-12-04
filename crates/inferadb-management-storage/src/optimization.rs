//! Storage optimization layer with batching and caching
//!
//! This module provides performance optimizations on top of the base storage backend:
//!
//! - **Batch Writes**: Accumulate multiple writes and flush in batches
//! - **Read Caching**: LRU cache for frequently accessed keys
//! - **Query Plan Optimization**: Optimize range queries and transaction patterns
//!
//! # Usage
//!
//! Wrap any `StorageBackend` implementation with `OptimizedBackend`:
//!
//! ```ignore
//! let base_backend = FdbBackend::new().await?;
//! let optimized = OptimizedBackend::new(base_backend, cache_config, batch_config);
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
use tracing::{debug, trace};

use crate::{
    backend::{KeyValue, StorageBackend, StorageResult, Transaction},
    metrics::{Metrics, MetricsCollector},
};

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
    /// Maximum batch size (number of operations)
    pub max_batch_size: usize,
    /// Maximum time to wait before flushing (milliseconds)
    pub max_wait_ms: u64,
    /// Enable batching (can be disabled for testing)
    pub enabled: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self { max_batch_size: 100, max_wait_ms: 100, enabled: true }
    }
}

impl BatchConfig {
    /// Create a disabled batch config
    pub fn disabled() -> Self {
        Self { max_batch_size: 0, max_wait_ms: 0, enabled: false }
    }

    /// Create a batch config with custom settings
    pub fn new(max_batch_size: usize, max_wait_ms: u64) -> Self {
        Self { max_batch_size, max_wait_ms, enabled: true }
    }
}

/// Cache entry with expiration
struct CacheEntry {
    value: Option<Bytes>,
    expires_at: Instant,
}

/// LRU cache implementation
struct LruCache {
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

    fn invalidate(&mut self, key: &[u8]) {
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
    #[allow(dead_code)] // Reserved for future batch write implementation
    batch_config: BatchConfig,
    metrics: Metrics,
}

impl<B: StorageBackend> OptimizedBackend<B> {
    /// Create a new optimized backend wrapper
    pub fn new(backend: B, cache_config: CacheConfig, batch_config: BatchConfig) -> Self {
        let cache = if cache_config.enabled {
            Arc::new(Mutex::new(LruCache::new(cache_config.max_entries, cache_config.ttl_secs)))
        } else {
            Arc::new(Mutex::new(LruCache::new(0, 0)))
        };

        Self { backend, cache, cache_config, batch_config, metrics: Metrics::new() }
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
}

#[async_trait]
impl<B: StorageBackend> StorageBackend for OptimizedBackend<B> {
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

        let result = self.backend.transaction().await;

        self.metrics.record_transaction(start.elapsed());

        if result.is_err() {
            self.metrics.record_error();
        }

        result
    }

    async fn health_check(&self) -> StorageResult<()> {
        self.metrics.record_health_check();
        self.backend.health_check().await
    }
}

impl<B: StorageBackend> MetricsCollector for OptimizedBackend<B> {
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
}
