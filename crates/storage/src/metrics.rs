//! Storage metrics collection and monitoring
//!
//! This module re-exports metrics types from `inferadb-storage` for use in
//! Control's storage layer. See [`inferadb_common_storage::metrics`] for full documentation.
//!
//! # Re-exported Types
//!
//! - [`Metrics`] - Metrics collector with atomic counters
//! - [`MetricsSnapshot`] - Point-in-time snapshot of metrics
//! - [`MetricsCollector`] - Trait for backends that collect metrics

pub use inferadb_common_storage::metrics::{Metrics, MetricsCollector, MetricsSnapshot};
