//! Authentication constants for JWT validation and session management.
//!
//! Shared between the Control Plane (issuing tokens) and the Engine
//! (validating tokens) to ensure consistent claim values.

/// Required JWT issuer claim value.
///
/// All vault-scoped JWTs must have this issuer. Used by both Control (when issuing)
/// and Engine (when validating) to ensure tokens originate from the InferaDB system.
pub const REQUIRED_ISSUER: &str = "https://api.inferadb.com";

/// Required JWT audience claim value.
///
/// All vault-scoped JWTs must have this audience. Ensures tokens are intended
/// for the InferaDB API and not repurposed from other systems.
pub const REQUIRED_AUDIENCE: &str = "https://api.inferadb.com";

/// Session cookie name used for user authentication.
///
/// This cookie stores the encrypted session token for authenticated users.
/// Must be consistent across all API handlers that read/write session state.
pub const SESSION_COOKIE_NAME: &str = "infera_session";

/// Session cookie maximum age in seconds (24 hours).
///
/// After this duration, the session cookie expires and users must re-authenticate.
pub const SESSION_COOKIE_MAX_AGE: i64 = 24 * 60 * 60;

/// Cookie name for the JWT access token (short-lived).
///
/// Used by web clients as an alternative to the `Authorization: Bearer` header.
/// HttpOnly, Secure, SameSite=Lax.
pub const ACCESS_TOKEN_COOKIE_NAME: &str = "inferadb_access";

/// Sentinel user slug for system-level Ledger RPCs (JWKS fetch, rate limiter).
///
/// System calls have no authenticated user context. Ledger treats this value
/// as an infrastructure caller for audit purposes.
pub const SYSTEM_CALLER_SLUG: u64 = 0;

/// Cookie name for the opaque refresh token (long-lived).
///
/// Stored in a separate HttpOnly cookie. Used to obtain new token pairs
/// when the access token expires.
pub const REFRESH_TOKEN_COOKIE_NAME: &str = "inferadb_refresh";
