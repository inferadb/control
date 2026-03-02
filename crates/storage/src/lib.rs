#![deny(unsafe_code)]

pub mod backend;
pub mod buffered;
pub mod coordination;
pub mod factory;
pub mod memory;

pub use backend::{KeyValue, StorageBackend, StorageError, StorageResult, Transaction};
pub use buffered::BufferedBackend;
pub use coordination::{Coordinator, LeaderStatus, WorkerInfo};
pub use factory::{
    LedgerConfig, StorageBackendType, StorageBundle, StorageConfig, create_storage_backend,
    memory_storage,
};
pub use inferadb_common_storage::{
    DynBackend,
    auth::{MemorySigningKeyStore, PublicSigningKey, PublicSigningKeyStore},
    to_storage_range,
};
pub use memory::MemoryBackend;
