//! Rate limiting re-exported from [`inferadb_common_ratelimit`].
//!
//! The core rate limiter, policy, outcome, and window types are provided by
//! the shared `inferadb-common-ratelimit` crate. This module re-exports them
//! under the names used throughout the Control codebase and adds
//! Control-specific categories and standard limits.

pub use inferadb_common_ratelimit::{
    AppRateLimiter as RateLimiter, RateLimitOutcome as RateLimitResult,
    RateLimitPolicy as RateLimit, RateLimitResponse, RateLimitWindow,
};
use inferadb_common_storage::MemoryBackend;

/// Concrete rate limiter backed by an in-memory storage backend.
///
/// Suitable for single-node deployments. For multi-node deployments,
/// use [`LedgerRateLimiter`] instead.
pub type InMemoryRateLimiter = RateLimiter<MemoryBackend>;

/// Concrete rate limiter backed by Ledger's entity store.
///
/// Suitable for multi-node deployments with shared rate limit state.
/// All rate limit counters are stored as entities in a system
/// organization namespace within Ledger.
pub type LedgerRateLimiter = RateLimiter<crate::ratelimit_ledger::LedgerStorageBackend>;

/// Creates a new in-memory rate limiter.
pub fn in_memory_rate_limiter() -> InMemoryRateLimiter {
    RateLimiter::new(MemoryBackend::new())
}

/// Common rate limit categories
///
/// Re-exported from `inferadb-control-const` for convenience.
pub mod categories {
    pub use inferadb_control_const::ratelimit::*;
}

/// Standard rate limits for the management API.
///
/// These functions construct policies from compile-time constants via direct
/// struct construction, avoiding the fallible `per_hour`/`per_day` constructors
/// (which validate runtime user input).
pub mod limits {
    use super::{RateLimit, RateLimitWindow};

    /// Login attempts: 100 per hour per IP.
    pub fn login_ip() -> RateLimit {
        RateLimit { max_requests: 100, window: RateLimitWindow::Hour }
    }

    /// Registration attempts: 5 per day per IP.
    pub fn registration_ip() -> RateLimit {
        RateLimit { max_requests: 5, window: RateLimitWindow::Day }
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
    }
}
