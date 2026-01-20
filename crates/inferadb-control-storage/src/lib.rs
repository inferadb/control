#![deny(unsafe_code)]

pub mod backend;
pub mod coordination;
pub mod factory;
pub mod memory;
pub mod metrics;
pub mod optimization;

pub use backend::{KeyValue, StorageBackend, StorageError, StorageResult, Transaction};
pub use coordination::{Coordinator, LeaderStatus, WorkerInfo};
pub use factory::{
    Backend, LedgerConfig, StorageBackendType, StorageConfig, create_storage_backend,
};
pub use memory::MemoryBackend;
pub use metrics::{Metrics, MetricsCollector, MetricsSnapshot};
pub use optimization::{
    BatchConfig, BatchFlushStats, BatchOperation, BatchWriter, CacheConfig, LruCache,
    OptimizedBackend,
};
