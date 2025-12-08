//! Storage metrics collection and monitoring
//!
//! This module provides comprehensive metrics for storage backends, particularly
//! FoundationDB-specific telemetry including:
//!
//! - Operation latencies (get, set, delete, range queries, transactions)
//! - Operation counts and throughput
//! - Error rates by type
//! - Transaction conflict rates
//! - Cache hit/miss rates
//! - Connection pool utilization
//!
//! Metrics are designed to be exported to Prometheus or other monitoring systems.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tracing::warn;

/// Metrics snapshot for export
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    /// Total GET operations
    pub get_count: u64,
    /// Total SET operations
    pub set_count: u64,
    /// Total DELETE operations
    pub delete_count: u64,
    /// Total GET_RANGE operations
    pub get_range_count: u64,
    /// Total CLEAR_RANGE operations
    pub clear_range_count: u64,
    /// Total TRANSACTION operations
    pub transaction_count: u64,

    /// Total GET latency in microseconds
    pub get_latency_us: u64,
    /// Total SET latency in microseconds
    pub set_latency_us: u64,
    /// Total DELETE latency in microseconds
    pub delete_latency_us: u64,
    /// Total GET_RANGE latency in microseconds
    pub get_range_latency_us: u64,
    /// Total TRANSACTION latency in microseconds
    pub transaction_latency_us: u64,

    /// Total errors
    pub error_count: u64,
    /// Transaction conflicts
    pub conflict_count: u64,
    /// Timeout errors
    pub timeout_count: u64,

    /// Cache hits (if caching enabled)
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,

    /// TTL operations count
    pub ttl_operations: u64,
    /// Health check count
    pub health_check_count: u64,
}

impl MetricsSnapshot {
    /// Calculate average GET latency in microseconds
    pub fn avg_get_latency_us(&self) -> f64 {
        if self.get_count == 0 { 0.0 } else { self.get_latency_us as f64 / self.get_count as f64 }
    }

    /// Calculate average SET latency in microseconds
    pub fn avg_set_latency_us(&self) -> f64 {
        if self.set_count == 0 { 0.0 } else { self.set_latency_us as f64 / self.set_count as f64 }
    }

    /// Calculate average DELETE latency in microseconds
    pub fn avg_delete_latency_us(&self) -> f64 {
        if self.delete_count == 0 {
            0.0
        } else {
            self.delete_latency_us as f64 / self.delete_count as f64
        }
    }

    /// Calculate average GET_RANGE latency in microseconds
    pub fn avg_get_range_latency_us(&self) -> f64 {
        if self.get_range_count == 0 {
            0.0
        } else {
            self.get_range_latency_us as f64 / self.get_range_count as f64
        }
    }

    /// Calculate average TRANSACTION latency in microseconds
    pub fn avg_transaction_latency_us(&self) -> f64 {
        if self.transaction_count == 0 {
            0.0
        } else {
            self.transaction_latency_us as f64 / self.transaction_count as f64
        }
    }

    /// Calculate cache hit rate (0.0 - 1.0)
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 { 0.0 } else { self.cache_hits as f64 / total as f64 }
    }

    /// Calculate error rate (0.0 - 1.0)
    pub fn error_rate(&self) -> f64 {
        let total_ops = self.get_count
            + self.set_count
            + self.delete_count
            + self.get_range_count
            + self.clear_range_count
            + self.transaction_count;

        if total_ops == 0 { 0.0 } else { self.error_count as f64 / total_ops as f64 }
    }

    /// Calculate conflict rate (0.0 - 1.0)
    pub fn conflict_rate(&self) -> f64 {
        if self.transaction_count == 0 {
            0.0
        } else {
            self.conflict_count as f64 / self.transaction_count as f64
        }
    }

    /// Total operations count
    pub fn total_operations(&self) -> u64 {
        self.get_count
            + self.set_count
            + self.delete_count
            + self.get_range_count
            + self.clear_range_count
            + self.transaction_count
    }
}

/// Metrics collector for storage operations
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

struct MetricsInner {
    // Operation counts
    get_count: AtomicU64,
    set_count: AtomicU64,
    delete_count: AtomicU64,
    get_range_count: AtomicU64,
    clear_range_count: AtomicU64,
    transaction_count: AtomicU64,

    // Latencies (cumulative microseconds)
    get_latency_us: AtomicU64,
    set_latency_us: AtomicU64,
    delete_latency_us: AtomicU64,
    get_range_latency_us: AtomicU64,
    transaction_latency_us: AtomicU64,

    // Errors
    error_count: AtomicU64,
    conflict_count: AtomicU64,
    timeout_count: AtomicU64,

    // Cache
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,

    // Other
    ttl_operations: AtomicU64,
    health_check_count: AtomicU64,
}

impl Metrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                get_count: AtomicU64::new(0),
                set_count: AtomicU64::new(0),
                delete_count: AtomicU64::new(0),
                get_range_count: AtomicU64::new(0),
                clear_range_count: AtomicU64::new(0),
                transaction_count: AtomicU64::new(0),
                get_latency_us: AtomicU64::new(0),
                set_latency_us: AtomicU64::new(0),
                delete_latency_us: AtomicU64::new(0),
                get_range_latency_us: AtomicU64::new(0),
                transaction_latency_us: AtomicU64::new(0),
                error_count: AtomicU64::new(0),
                conflict_count: AtomicU64::new(0),
                timeout_count: AtomicU64::new(0),
                cache_hits: AtomicU64::new(0),
                cache_misses: AtomicU64::new(0),
                ttl_operations: AtomicU64::new(0),
                health_check_count: AtomicU64::new(0),
            }),
        }
    }

    /// Record a GET operation
    pub fn record_get(&self, duration: Duration) {
        self.inner.get_count.fetch_add(1, Ordering::Relaxed);
        self.inner.get_latency_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record a SET operation
    pub fn record_set(&self, duration: Duration) {
        self.inner.set_count.fetch_add(1, Ordering::Relaxed);
        self.inner.set_latency_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record a DELETE operation
    pub fn record_delete(&self, duration: Duration) {
        self.inner.delete_count.fetch_add(1, Ordering::Relaxed);
        self.inner.delete_latency_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record a GET_RANGE operation
    pub fn record_get_range(&self, duration: Duration) {
        self.inner.get_range_count.fetch_add(1, Ordering::Relaxed);
        self.inner.get_range_latency_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record a CLEAR_RANGE operation
    pub fn record_clear_range(&self, duration: Duration) {
        self.inner.clear_range_count.fetch_add(1, Ordering::Relaxed);
        // Reuse get_range latency bucket for now
        self.inner.get_range_latency_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record a TRANSACTION operation
    pub fn record_transaction(&self, duration: Duration) {
        self.inner.transaction_count.fetch_add(1, Ordering::Relaxed);
        self.inner.transaction_latency_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record an error
    pub fn record_error(&self) {
        self.inner.error_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a transaction conflict
    pub fn record_conflict(&self) {
        self.inner.conflict_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a timeout error
    pub fn record_timeout(&self) {
        self.inner.timeout_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache hit
    pub fn record_cache_hit(&self) {
        self.inner.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss
    pub fn record_cache_miss(&self) {
        self.inner.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a TTL operation
    pub fn record_ttl_operation(&self) {
        self.inner.ttl_operations.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a health check
    pub fn record_health_check(&self) {
        self.inner.health_check_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of current metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            get_count: self.inner.get_count.load(Ordering::Relaxed),
            set_count: self.inner.set_count.load(Ordering::Relaxed),
            delete_count: self.inner.delete_count.load(Ordering::Relaxed),
            get_range_count: self.inner.get_range_count.load(Ordering::Relaxed),
            clear_range_count: self.inner.clear_range_count.load(Ordering::Relaxed),
            transaction_count: self.inner.transaction_count.load(Ordering::Relaxed),
            get_latency_us: self.inner.get_latency_us.load(Ordering::Relaxed),
            set_latency_us: self.inner.set_latency_us.load(Ordering::Relaxed),
            delete_latency_us: self.inner.delete_latency_us.load(Ordering::Relaxed),
            get_range_latency_us: self.inner.get_range_latency_us.load(Ordering::Relaxed),
            transaction_latency_us: self.inner.transaction_latency_us.load(Ordering::Relaxed),
            error_count: self.inner.error_count.load(Ordering::Relaxed),
            conflict_count: self.inner.conflict_count.load(Ordering::Relaxed),
            timeout_count: self.inner.timeout_count.load(Ordering::Relaxed),
            cache_hits: self.inner.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.inner.cache_misses.load(Ordering::Relaxed),
            ttl_operations: self.inner.ttl_operations.load(Ordering::Relaxed),
            health_check_count: self.inner.health_check_count.load(Ordering::Relaxed),
        }
    }

    /// Reset all metrics to zero
    pub fn reset(&self) {
        self.inner.get_count.store(0, Ordering::Relaxed);
        self.inner.set_count.store(0, Ordering::Relaxed);
        self.inner.delete_count.store(0, Ordering::Relaxed);
        self.inner.get_range_count.store(0, Ordering::Relaxed);
        self.inner.clear_range_count.store(0, Ordering::Relaxed);
        self.inner.transaction_count.store(0, Ordering::Relaxed);
        self.inner.get_latency_us.store(0, Ordering::Relaxed);
        self.inner.set_latency_us.store(0, Ordering::Relaxed);
        self.inner.delete_latency_us.store(0, Ordering::Relaxed);
        self.inner.get_range_latency_us.store(0, Ordering::Relaxed);
        self.inner.transaction_latency_us.store(0, Ordering::Relaxed);
        self.inner.error_count.store(0, Ordering::Relaxed);
        self.inner.conflict_count.store(0, Ordering::Relaxed);
        self.inner.timeout_count.store(0, Ordering::Relaxed);
        self.inner.cache_hits.store(0, Ordering::Relaxed);
        self.inner.cache_misses.store(0, Ordering::Relaxed);
        self.inner.ttl_operations.store(0, Ordering::Relaxed);
        self.inner.health_check_count.store(0, Ordering::Relaxed);
    }

    /// Log current metrics at INFO level
    pub fn log_metrics(&self) {
        let snapshot = self.snapshot();

        if snapshot.total_operations() == 0 {
            return;
        }

        tracing::info!(
            get_count = snapshot.get_count,
            set_count = snapshot.set_count,
            delete_count = snapshot.delete_count,
            get_range_count = snapshot.get_range_count,
            transaction_count = snapshot.transaction_count,
            avg_get_latency_us = snapshot.avg_get_latency_us(),
            avg_set_latency_us = snapshot.avg_set_latency_us(),
            avg_delete_latency_us = snapshot.avg_delete_latency_us(),
            avg_transaction_latency_us = snapshot.avg_transaction_latency_us(),
            error_count = snapshot.error_count,
            error_rate = snapshot.error_rate(),
            conflict_count = snapshot.conflict_count,
            conflict_rate = snapshot.conflict_rate(),
            cache_hit_rate = snapshot.cache_hit_rate(),
            "Storage metrics snapshot"
        );

        // Warn if error rate is high
        if snapshot.error_rate() > 0.05 {
            warn!(
                error_rate = snapshot.error_rate(),
                error_count = snapshot.error_count,
                total_ops = snapshot.total_operations(),
                "High storage error rate detected"
            );
        }

        // Warn if conflict rate is high
        if snapshot.conflict_rate() > 0.10 {
            warn!(
                conflict_rate = snapshot.conflict_rate(),
                conflict_count = snapshot.conflict_count,
                transaction_count = snapshot.transaction_count,
                "High transaction conflict rate detected"
            );
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for collecting metrics from storage backends
pub trait MetricsCollector {
    /// Get metrics instance
    fn metrics(&self) -> &Metrics;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_recording() {
        let metrics = Metrics::new();

        metrics.record_get(Duration::from_micros(100));
        metrics.record_set(Duration::from_micros(200));
        metrics.record_delete(Duration::from_micros(150));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_count, 1);
        assert_eq!(snapshot.set_count, 1);
        assert_eq!(snapshot.delete_count, 1);
        assert_eq!(snapshot.get_latency_us, 100);
        assert_eq!(snapshot.set_latency_us, 200);
        assert_eq!(snapshot.delete_latency_us, 150);
    }

    #[test]
    fn test_average_latency() {
        let metrics = Metrics::new();

        metrics.record_get(Duration::from_micros(100));
        metrics.record_get(Duration::from_micros(200));
        metrics.record_get(Duration::from_micros(300));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_count, 3);
        assert_eq!(snapshot.avg_get_latency_us(), 200.0);
    }

    #[test]
    fn test_cache_hit_rate() {
        let metrics = Metrics::new();

        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_miss();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.cache_hit_rate(), 0.75);
    }

    #[test]
    fn test_error_rate() {
        let metrics = Metrics::new();

        // Record 4 operations total
        metrics.record_get(Duration::from_micros(100));
        metrics.record_get(Duration::from_micros(100));
        metrics.record_get(Duration::from_micros(100));
        metrics.record_set(Duration::from_micros(100));
        // Record 1 error
        metrics.record_error();

        // Error rate = errors / total_ops = 1/4 = 0.25
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.error_rate(), 0.25);
    }

    #[test]
    fn test_conflict_rate() {
        let metrics = Metrics::new();

        metrics.record_transaction(Duration::from_micros(1000));
        metrics.record_transaction(Duration::from_micros(1000));
        metrics.record_transaction(Duration::from_micros(1000));
        metrics.record_transaction(Duration::from_micros(1000));
        metrics.record_conflict();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.conflict_rate(), 0.25);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = Metrics::new();

        metrics.record_get(Duration::from_micros(100));
        metrics.record_set(Duration::from_micros(200));
        metrics.record_error();

        metrics.reset();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_count, 0);
        assert_eq!(snapshot.set_count, 0);
        assert_eq!(snapshot.error_count, 0);
    }
}
