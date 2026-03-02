//! Rate limiting re-exported from [`inferadb_common_ratelimit`].
//!
//! The core rate limiter, policy, outcome, and window types are provided by
//! the shared `inferadb-common-ratelimit` crate. This module re-exports them
//! under the names used throughout the Control codebase and adds
//! Control-specific categories and standard limits.

pub use inferadb_common_ratelimit::{
    AppRateLimiter as RateLimiter, RateLimitOutcome as RateLimitResult,
    RateLimitPolicy as RateLimit, RateLimitWindow,
};

/// Common rate limit categories
///
/// Re-exported from `inferadb-control-const` for convenience.
pub mod categories {
    pub use inferadb_control_const::ratelimit::*;
}

/// Standard rate limits for the management API
pub mod limits {
    use super::RateLimit;

    /// Login attempts: 100 per hour per IP
    pub fn login_ip() -> RateLimit {
        RateLimit::per_hour(100)
    }

    /// Registration attempts: 5 per day per IP
    pub fn registration_ip() -> RateLimit {
        RateLimit::per_day(5)
    }

    /// Email verification tokens: 5 per hour per email
    pub fn email_verification() -> RateLimit {
        RateLimit::per_hour(5)
    }

    /// Password reset tokens: 3 per hour per user
    pub fn password_reset() -> RateLimit {
        RateLimit::per_hour(3)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_limits() {
        let login = limits::login_ip();
        assert_eq!(login.max_requests, 100);

        let registration = limits::registration_ip();
        assert_eq!(registration.max_requests, 5);

        let email_verification = limits::email_verification();
        assert_eq!(email_verification.max_requests, 5);

        let password_reset = limits::password_reset();
        assert_eq!(password_reset.max_requests, 3);
    }
}
