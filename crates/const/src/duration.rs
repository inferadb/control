//! Token, session, and cookie TTL constants.
//!
//! All values are in their natural unit (seconds, hours, or days) as
//! documented on each constant. Conversion between units is done at the
//! point of use.

/// Authorization code TTL in seconds (10 minutes).
///
/// OAuth2 authorization codes are single-use and short-lived.
/// Must be exchanged for tokens within this window.
pub const AUTHORIZATION_CODE_TTL_SECONDS: i64 = 10 * 60;

/// User session refresh token TTL in seconds (1 hour).
///
/// Browser session refresh tokens use a shorter TTL than client refresh tokens
/// to limit exposure from compromised browser sessions.
pub const USER_SESSION_REFRESH_TOKEN_TTL_SECONDS: i64 = 3600;

/// Client (service) refresh token TTL in seconds (7 days).
///
/// Machine clients using Ed25519 certificate authentication receive a longer TTL
/// than browser sessions to reduce re-authentication overhead.
pub const CLIENT_REFRESH_TOKEN_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

/// Organization invitation TTL in days (7 days).
///
/// Invitations expire after this period. Recipients must accept within this window.
pub const INVITATION_EXPIRY_DAYS: i64 = 7;

/// Organization invitation TTL in hours, derived from [`INVITATION_EXPIRY_DAYS`].
pub const INVITATION_EXPIRY_HOURS: u32 = (INVITATION_EXPIRY_DAYS * 24) as u32;

/// Email verification token expiry in hours (24 hours).
///
/// Users must verify their email address within this window after registration
/// or requesting a new verification link.
pub const EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS: i64 = 24;

/// Password reset token expiry in hours (1 hour).
///
/// Short expiry limits the window of exposure if the reset link is intercepted.
pub const PASSWORD_RESET_TOKEN_EXPIRY_HOURS: i64 = 1;

/// Maximum age for access token cookie in seconds (15 minutes).
///
/// Short-lived access tokens limit the window of exposure if a token leaks.
/// Clients use the refresh token to obtain new access tokens transparently.
pub const ACCESS_COOKIE_MAX_AGE_SECONDS: i64 = 15 * 60;

/// Maximum age for refresh token cookie in seconds (30 days).
///
/// Long-lived refresh tokens reduce re-authentication friction for web users.
/// Stored in a scoped HttpOnly cookie restricted to the auth path.
pub const REFRESH_COOKIE_MAX_AGE_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Health check cache TTL in seconds.
///
/// Prevents health probe bursts from cascading to the Ledger backend.
pub const HEALTH_CACHE_TTL_SECONDS: u64 = 5;
