//! Authentication constants for JWT validation and session management.

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
