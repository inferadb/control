//! # InferaDB Control Constants
//!
//! Zero-dependency crate containing constants used across the Control codebase.
//!
//! This crate centralizes:
//! - Authentication constants (JWT issuer/audience, session cookies)
//! - Token duration constants (TTLs, expiry times)
//! - Business limit constants (max sessions, passkeys, organizations)
//! - Rate limit category identifiers

pub mod auth;
pub mod duration;
pub mod limits;
pub mod ratelimit;

// Re-export commonly used constants at crate root
pub use auth::{REQUIRED_AUDIENCE, REQUIRED_ISSUER, SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME};
pub use duration::{
    AUTHORIZATION_CODE_TTL_SECONDS, CLIENT_REFRESH_TOKEN_TTL_SECONDS,
    USER_SESSION_REFRESH_TOKEN_TTL_SECONDS,
};
pub use limits::{
    GLOBAL_ORGANIZATION_LIMIT, MAX_CONCURRENT_SESSIONS, MAX_PASSKEYS_PER_USER,
    PER_USER_ORGANIZATION_LIMIT,
};
