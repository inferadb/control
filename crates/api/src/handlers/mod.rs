//! HTTP handler modules for the Control API.
//!
//! Each submodule corresponds to a resource domain (organizations, vaults,
//! schemas, etc.) and contains request/response types plus handler functions.
//! Shared helpers live in [`common`]. Application state and error mapping
//! live in [`state`].

pub mod audit_logs;
pub mod auth;
pub mod clients;
pub mod common;
pub mod email_auth;
pub mod emails;
pub mod health;
pub mod metrics;
pub mod mfa_auth;
pub mod organizations;
pub mod schemas;
pub mod state;
pub mod teams;
pub mod tokens;
pub mod users;
pub mod vaults;

pub use health::{healthz_handler, livez_handler, readyz_handler, startupz_handler};
pub use metrics::{init_exporter, metrics_handler};
pub use state::{ApiError, AppState};
