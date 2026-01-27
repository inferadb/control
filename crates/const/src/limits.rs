//! Business constraint constants.

/// Maximum number of passkeys (WebAuthn credentials) per user.
///
/// Limits credential sprawl and reduces attack surface.
pub const MAX_PASSKEYS_PER_USER: usize = 20;

/// Maximum number of concurrent sessions per user.
///
/// When exceeded, oldest sessions are invalidated.
pub const MAX_CONCURRENT_SESSIONS: usize = 10;

/// Global limit on total organizations in the system.
///
/// Safety limit to prevent runaway resource consumption.
pub const GLOBAL_ORGANIZATION_LIMIT: i64 = 100_000;

/// Maximum organizations a single user can create.
///
/// Prevents abuse by limiting organization creation per user.
pub const PER_USER_ORGANIZATION_LIMIT: i64 = 10;

/// Minimum password length for user accounts.
pub const MIN_PASSWORD_LENGTH: usize = 12;
