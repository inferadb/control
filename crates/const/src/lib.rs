//! # InferaDB Control Constants
//!
//! Zero-dependency crate containing constants used across the Control codebase.
//!
//! This crate centralizes:
//! - Authentication constants (JWT issuer/audience, session cookies)
//! - Token and session duration constants (TTLs, expiry times)
//! - Business limit constants (max sessions, passkeys, organizations)
//! - Rate limit category identifiers

#![deny(unsafe_code)]

/// Authentication constants (JWT issuer/audience, session cookies).
pub mod auth;
/// Token and session duration constants.
pub mod duration;
/// Business constraint constants (max sessions, passkeys, organizations).
pub mod limits;
/// Rate limit category identifiers.
pub mod ratelimit;

pub use auth::{
    ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME, REQUIRED_AUDIENCE, REQUIRED_ISSUER,
    SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME, SYSTEM_CALLER_SLUG,
};
pub use duration::{
    ACCESS_COOKIE_MAX_AGE_SECONDS, AUTHORIZATION_CODE_TTL_SECONDS,
    CLIENT_REFRESH_TOKEN_TTL_SECONDS, EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS,
    HEALTH_CACHE_TTL_SECONDS, INVITATION_EXPIRY_DAYS, INVITATION_EXPIRY_HOURS,
    PASSWORD_RESET_TOKEN_EXPIRY_HOURS, REFRESH_COOKIE_MAX_AGE_SECONDS,
    USER_SESSION_REFRESH_TOKEN_TTL_SECONDS,
};
pub use limits::{
    GLOBAL_ORGANIZATION_LIMIT, MAX_CONCURRENT_SESSIONS, MAX_PASSKEYS_PER_USER, MIN_PASSWORD_LENGTH,
    PER_USER_ORGANIZATION_LIMIT,
};
