//! Token and session duration constants.

/// Authorization code TTL in seconds (10 minutes).
///
/// OAuth2 authorization codes are single-use and short-lived.
/// Must be exchanged for tokens within this window.
pub const AUTHORIZATION_CODE_TTL_SECONDS: i64 = 10 * 60;

/// User session refresh token TTL in seconds (1 hour).
///
/// For human users authenticating via browser sessions, refresh tokens
/// have a shorter lifetime for security.
pub const USER_SESSION_REFRESH_TOKEN_TTL_SECONDS: i64 = 3600;

/// Client (service) refresh token TTL in seconds (7 days).
///
/// For machine clients using Ed25519 certificate authentication,
/// refresh tokens have a longer lifetime to reduce re-authentication overhead.
pub const CLIENT_REFRESH_TOKEN_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

/// Organization invitation expiry in days.
pub const INVITATION_EXPIRY_DAYS: i64 = 7;

/// Email verification token expiry in hours.
pub const EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS: i64 = 24;

/// Password reset token expiry in hours.
pub const PASSWORD_RESET_TOKEN_EXPIRY_HOURS: i64 = 1;
