//! Shared request/response DTOs.
//!
//! Handler-specific types live in their respective handler modules.
//! This module contains types shared across multiple handlers.

pub mod auth;

pub use auth::ErrorResponse;
