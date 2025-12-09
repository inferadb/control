//! Rate limit category identifiers.
//!
//! These string constants identify rate limit buckets. Using constants
//! prevents typos that could bypass rate limiting.

/// Rate limit category for login attempts by IP address.
pub const LOGIN_IP: &str = "login_ip";

/// Rate limit category for user registrations by IP address.
pub const REGISTRATION_IP: &str = "registration_ip";

/// Rate limit category for email verification token requests.
pub const EMAIL_VERIFICATION: &str = "email_verification";

/// Rate limit category for password reset token requests.
pub const PASSWORD_RESET: &str = "password_reset";
