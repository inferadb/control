//! # InferaDB Control Types
//!
//! Shared type definitions for InferaDB Control.
//!
//! This crate provides all core types used across the Control ecosystem,
//! ensuring a single source of truth and preventing circular dependencies.
//!
//! ## Builder Patterns
//!
//! All entity types in this crate use the [`bon`](https://docs.rs/bon) crate for builder
//! pattern generation. There are two patterns used:
//!
//! ### Derived Builders (Struct-level)
//!
//! Types without validation use `#[derive(bon::Builder)]` directly on the struct.
//! Optional fields get `.maybe_*()` methods for passing `Option<T>` values:
//!
//! ```ignore
//! use inferadb_control_types::entities::AuditLog;
//! use inferadb_control_types::entities::{AuditEventType, AuditResourceType};
//!
//! // Required fields use direct setters, optional fields use maybe_* methods
//! let log = AuditLog::builder()
//!     .event_type(AuditEventType::UserLogin)
//!     .maybe_organization(Some(123))
//!     .maybe_user_id(Some(456))
//!     .build();
//! ```
//!
//! ### Fallible Builders (Constructor-level)
//!
//! Types with validation use `#[builder]` on the `new()` function. These return
//! `Result<Self>` and require `.build()?.unwrap()` or error handling:
//!
//! ```ignore
//! use inferadb_control_types::entities::User;
//!
//! // Fallible builder returns Result
//! let user = User::builder()
//!     .id(12345)
//!     .name("alice".to_string())
//!     .maybe_password_hash(Some("hash".to_string()))
//!     .build()
//!     .expect("valid user");
//! ```
//!
//! ### Common Patterns
//!
//! - **Required fields**: Call `.field(value)` - build fails at compile time if missing
//! - **Optional fields**: Either omit (defaults to `None`) or use `.maybe_field(Some(value))`
//! - **String fields**: Pass `&str` directly when `#[builder(on(String, into))]` is set
//! - **Default values**: Some fields like `id` and `created_at` have defaults via
//!   `#[builder(default = expr)]`

#![deny(unsafe_code)]

// ============================================================================
// Re-exports from upstream crates
// ============================================================================
pub use inferadb_ledger_types::{OrganizationSlug, VaultSlug};

// ============================================================================
// ID Generation
// ============================================================================

pub mod id;

pub use id::IdGenerator;

// ============================================================================
// Error Types
// ============================================================================

pub mod error;

pub use error::{Error, Result};

// ============================================================================
// Request/Response Types
// ============================================================================

pub mod dto;

pub use dto::ErrorResponse;
