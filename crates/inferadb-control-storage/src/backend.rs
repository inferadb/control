//! Storage backend re-exports from shared crate.
//!
//! This module re-exports the core storage traits and types from
//! [`inferadb_storage`], ensuring Control uses the same interfaces
//! as other InferaDB services.
//!
//! # Types
//!
//! - [`StorageBackend`] - Core trait for key-value storage operations
//! - [`Transaction`] - Trait for atomic multi-operation commits
//! - [`StorageError`] - Canonical error types for storage operations
//! - [`StorageResult`] - Result type alias for storage operations
//! - [`KeyValue`] - Key-value pair for range query results

// Re-export all storage types from the shared crate
pub use inferadb_storage::{KeyValue, StorageBackend, StorageError, StorageResult, Transaction};
