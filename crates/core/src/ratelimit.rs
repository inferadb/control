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
use inferadb_common_storage::{MemoryBackend, error::StorageResult};

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

/// Creates an [`InMemoryRateLimiter`] backed by a fresh [`MemoryBackend`].
pub fn in_memory_rate_limiter() -> InMemoryRateLimiter {
    RateLimiter::new(MemoryBackend::new())
}

/// Creates a [`LedgerRateLimiter`] that stores counters in Ledger's entity store.
pub fn ledger_rate_limiter(
    client: std::sync::Arc<inferadb_ledger_sdk::LedgerClient>,
    caller: inferadb_ledger_types::UserSlug,
    organization: inferadb_ledger_types::OrganizationSlug,
) -> LedgerRateLimiter {
    RateLimiter::new(crate::ratelimit_ledger::LedgerStorageBackend::new(
        client,
        caller,
        organization,
    ))
}

/// Dynamic dispatch over [`InMemoryRateLimiter`] and [`LedgerRateLimiter`].
pub enum AnyRateLimiter {
    /// In-memory backend for single-node deployments.
    InMemory(InMemoryRateLimiter),
    /// Ledger-backed backend for multi-node deployments with shared state.
    Ledger(LedgerRateLimiter),
}

impl Default for AnyRateLimiter {
    fn default() -> Self {
        Self::InMemory(in_memory_rate_limiter())
    }
}

impl std::fmt::Debug for AnyRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InMemory(_) => f.write_str("AnyRateLimiter::InMemory"),
            Self::Ledger(_) => f.write_str("AnyRateLimiter::Ledger"),
        }
    }
}

impl AnyRateLimiter {
    /// Checks a rate limit, delegating to the underlying backend.
    pub async fn check(
        &self,
        category: &str,
        identifier: &str,
        policy: &RateLimit,
    ) -> StorageResult<RateLimitResult> {
        match self {
            Self::InMemory(r) => r.check(category, identifier, policy).await,
            Self::Ledger(r) => r.check(category, identifier, policy).await,
        }
    }
}

/// Category string constants (e.g., `"login_ip"`, `"registration_ip"`).
///
/// Re-exported from `inferadb-control-const`.
pub mod categories {
    pub use inferadb_control_const::ratelimit::*;
}

/// Standard rate limit policies for the management API.
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

    // ── Standard limit policies ─────────────────────────────────

    #[test]
    fn test_login_ip_limit_is_100_per_hour() {
        let login = limits::login_ip();

        assert_eq!(login.max_requests, 100);
        assert!(matches!(login.window, RateLimitWindow::Hour));
    }

    #[test]
    fn test_registration_ip_limit_is_5_per_day() {
        let reg = limits::registration_ip();

        assert_eq!(reg.max_requests, 5);
        assert!(matches!(reg.window, RateLimitWindow::Day));
    }

    // ── AnyRateLimiter ──────────────────────────────────────────

    #[test]
    fn test_any_rate_limiter_default_is_in_memory() {
        let limiter = AnyRateLimiter::default();

        assert!(matches!(limiter, AnyRateLimiter::InMemory(_)));
    }

    #[test]
    fn test_any_rate_limiter_debug_shows_variant() {
        let limiter = AnyRateLimiter::default();

        assert_eq!(format!("{limiter:?}"), "AnyRateLimiter::InMemory");
    }

    #[tokio::test]
    async fn test_any_rate_limiter_check_allows_first_request() {
        let limiter = AnyRateLimiter::default();
        let policy = limits::login_ip();

        let result = limiter.check("test", "127.0.0.1", &policy).await.unwrap();

        assert!(matches!(result, RateLimitResult::Allowed { .. }));
    }

    // ── InMemoryRateLimiter ─────────────────────────────────────

    #[tokio::test]
    async fn test_in_memory_limiter_allows_first_request() {
        let limiter = in_memory_rate_limiter();
        let policy = limits::login_ip();

        let result = limiter.check("login_ip", "1.2.3.4", &policy).await.unwrap();

        assert!(matches!(result, RateLimitResult::Allowed { .. }));
    }

    #[tokio::test]
    async fn test_in_memory_limiter_denies_after_limit_exhausted() {
        let limiter = in_memory_rate_limiter();
        let policy = RateLimit { max_requests: 2, window: RateLimitWindow::Hour };

        for _ in 0..2 {
            let result = limiter.check("test", "ip", &policy).await.unwrap();
            assert!(matches!(result, RateLimitResult::Allowed { .. }));
        }

        let result = limiter.check("test", "ip", &policy).await.unwrap();
        assert!(matches!(result, RateLimitResult::Limited { .. }));
    }

    #[tokio::test]
    async fn test_in_memory_limiter_separate_keys_are_independent() {
        let limiter = in_memory_rate_limiter();
        let policy = RateLimit { max_requests: 1, window: RateLimitWindow::Hour };

        let r1 = limiter.check("test", "ip_a", &policy).await.unwrap();
        assert!(matches!(r1, RateLimitResult::Allowed { .. }));

        // Different key should still be allowed
        let r2 = limiter.check("test", "ip_b", &policy).await.unwrap();
        assert!(matches!(r2, RateLimitResult::Allowed { .. }));

        // Original key should now be limited
        let r3 = limiter.check("test", "ip_a", &policy).await.unwrap();
        assert!(matches!(r3, RateLimitResult::Limited { .. }));
    }

    #[tokio::test]
    async fn test_in_memory_limiter_separate_categories_are_independent() {
        let limiter = in_memory_rate_limiter();
        let policy = RateLimit { max_requests: 1, window: RateLimitWindow::Hour };

        let r1 = limiter.check("cat_a", "ip", &policy).await.unwrap();
        assert!(matches!(r1, RateLimitResult::Allowed { .. }));

        // Different category, same key should still be allowed
        let r2 = limiter.check("cat_b", "ip", &policy).await.unwrap();
        assert!(matches!(r2, RateLimitResult::Allowed { .. }));
    }
}
