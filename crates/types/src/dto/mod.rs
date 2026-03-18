//! Request/Response DTOs.
//!
//! Most handler-specific request/response types are now defined locally
//! in their handler files. This module retains shared types used across
//! the API layer.

pub mod auth;

pub use auth::ErrorResponse;
