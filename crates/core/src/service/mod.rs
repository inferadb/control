//! Ledger SDK service wrappers.
//!
//! Thin wrappers around [`inferadb_ledger_sdk::LedgerClient`] operations that
//! handle error mapping from gRPC status codes to [`inferadb_control_types::Error`].
//! Service methods return Ledger SDK types directly (per PRD Decision 14) —
//! no conversion to Control-specific entity types.

pub mod error;

pub use error::{SdkResultExt, sdk_error_to_control};

pub mod app;
pub mod credential;
pub mod email;
pub mod invitation;
pub mod membership;
pub mod onboarding;
pub mod organization;
pub mod session;
pub mod team;
pub mod user;
pub mod vault;
