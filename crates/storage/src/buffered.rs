//! Buffered storage backend re-export.
//!
//! The implementation lives in [`inferadb_common_storage::buffered`]; this
//! module re-exports it so that existing `inferadb_control_storage::BufferedBackend`
//! imports continue to work without changes.

pub use inferadb_common_storage::BufferedBackend;
