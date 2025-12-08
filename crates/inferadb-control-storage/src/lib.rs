pub mod backend;
pub mod coordination;
pub mod factory;
#[cfg(feature = "fdb")]
pub mod fdb;
pub mod memory;
pub mod metrics;
pub mod optimization;

pub use backend::{KeyValue, StorageBackend, StorageError, StorageResult, Transaction};
pub use coordination::{Coordinator, LeaderStatus, WorkerInfo};
pub use factory::{Backend, StorageBackendType, StorageConfig, create_storage_backend};
#[cfg(feature = "fdb")]
pub use fdb::FdbBackend;
pub use memory::MemoryBackend;
pub use metrics::{Metrics, MetricsCollector};
pub use optimization::{BatchConfig, CacheConfig, OptimizedBackend};
