use std::time::{SystemTime, UNIX_EPOCH};

use inferadb_control_storage::StorageBackend;
use inferadb_control_types::error::{Error, Result};

/// Rate limit window duration
#[derive(Debug, Clone, Copy)]
pub enum RateLimitWindow {
    /// Per hour (3600 seconds)
    Hour,
    /// Per day (86400 seconds)
    Day,
}

impl RateLimitWindow {
    fn seconds(&self) -> u64 {
        match self {
            RateLimitWindow::Hour => 3600,
            RateLimitWindow::Day => 86400,
        }
    }

    /// Get window start timestamp for current time
    fn window_start(&self, now: SystemTime) -> u64 {
        let timestamp = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let window_seconds = self.seconds();
        (timestamp / window_seconds) * window_seconds
    }

    /// Get seconds until window expires
    fn seconds_until_reset(&self, now: SystemTime) -> u64 {
        let window_start = self.window_start(now);
        let window_seconds = self.seconds();
        window_start + window_seconds - now.duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Maximum number of requests in the window
    pub max_requests: u32,
    /// Time window
    pub window: RateLimitWindow,
}

impl RateLimit {
    /// Create a new rate limit
    pub fn new(max_requests: u32, window: RateLimitWindow) -> Self {
        Self { max_requests, window }
    }

    /// Create hourly rate limit
    pub fn per_hour(max_requests: u32) -> Self {
        Self::new(max_requests, RateLimitWindow::Hour)
    }

    /// Create daily rate limit
    pub fn per_day(max_requests: u32) -> Self {
        Self::new(max_requests, RateLimitWindow::Day)
    }
}

/// Distributed rate limiter using storage backend
///
/// Uses a fixed window algorithm with atomic counter operations.
/// Counters are stored with TTL for automatic cleanup.
///
/// # Key Format
///
/// Rate limit counters are stored as:
/// `rate_limit:{category}:{identifier}:{window_start}`
///
/// For example:
/// - `rate_limit:login_ip:192.168.1.1:1700000000`
/// - `rate_limit:registration_ip:10.0.0.5:1700000000`
/// - `rate_limit:password_reset:user_123:1700000000`
///
/// # Usage
///
/// ```rust,no_run
/// use inferadb_control_core::{RateLimiter, RateLimit};
/// use inferadb_control_storage::MemoryBackend;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let storage = MemoryBackend::new();
/// let limiter = RateLimiter::new(storage);
///
/// // Check login rate limit (100 per hour per IP)
/// let rate_limit = RateLimit::per_hour(100);
/// let ip = "192.168.1.1";
///
/// if limiter.check("login_ip", ip, &rate_limit).await? {
///     // Allow request
/// } else {
///     // Rate limit exceeded
/// }
/// # Ok(())
/// # }
/// ```
pub struct RateLimiter<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> RateLimiter<S> {
    /// Create a new rate limiter
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate storage key for rate limit counter
    fn counter_key(category: &str, identifier: &str, window_start: u64) -> Vec<u8> {
        format!("rate_limit:{category}:{identifier}:{window_start}").into_bytes()
    }

    /// Check if request is allowed under rate limit
    ///
    /// Returns `Ok(true)` if request is allowed, `Ok(false)` if rate limit exceeded.
    ///
    /// # Arguments
    ///
    /// * `category` - Rate limit category (e.g., "login_ip", "registration_ip")
    /// * `identifier` - Unique identifier for this limit (e.g., IP address, user ID)
    /// * `limit` - Rate limit configuration
    pub async fn check(&self, category: &str, identifier: &str, limit: &RateLimit) -> Result<bool> {
        let now = SystemTime::now();
        let window_start = limit.window.window_start(now);
        let key = Self::counter_key(category, identifier, window_start);

        // Get current counter value
        let current_count = match self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get rate limit counter: {e}")))?
        {
            Some(bytes) => {
                let count_str = String::from_utf8(bytes.to_vec())
                    .map_err(|e| Error::Internal(format!("Invalid counter value: {e}")))?;
                count_str
                    .parse::<u32>()
                    .map_err(|e| Error::Internal(format!("Failed to parse counter value: {e}")))?
            },
            None => 0,
        };

        // Check if limit exceeded
        if current_count >= limit.max_requests {
            return Ok(false);
        }

        // Increment counter
        let new_count = current_count + 1;
        let ttl_seconds = limit.window.seconds();

        self.storage
            .set_with_ttl(key, new_count.to_string().into_bytes(), ttl_seconds)
            .await
            .map_err(|e| Error::Internal(format!("Failed to set rate limit counter: {e}")))?;

        Ok(true)
    }

    /// Get remaining requests in current window
    ///
    /// Returns the number of requests remaining before hitting the rate limit.
    pub async fn remaining(
        &self,
        category: &str,
        identifier: &str,
        limit: &RateLimit,
    ) -> Result<u32> {
        let now = SystemTime::now();
        let window_start = limit.window.window_start(now);
        let key = Self::counter_key(category, identifier, window_start);

        // Get current counter value
        let current_count = match self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get rate limit counter: {e}")))?
        {
            Some(bytes) => {
                let count_str = String::from_utf8(bytes.to_vec())
                    .map_err(|e| Error::Internal(format!("Invalid counter value: {e}")))?;
                count_str
                    .parse::<u32>()
                    .map_err(|e| Error::Internal(format!("Failed to parse counter value: {e}")))?
            },
            None => 0,
        };

        Ok(limit.max_requests.saturating_sub(current_count))
    }

    /// Get seconds until rate limit window resets
    pub fn reset_after(&self, limit: &RateLimit) -> u64 {
        limit.window.seconds_until_reset(SystemTime::now())
    }
}

/// Rate limit result with metadata
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Remaining requests in current window
    pub remaining: u32,
    /// Seconds until window resets
    pub reset_after: u64,
}

impl<S: StorageBackend> RateLimiter<S> {
    /// Check rate limit and return detailed result
    ///
    /// This is a convenience method that returns both the allow/deny decision
    /// and metadata useful for response headers (X-RateLimit-Remaining, Retry-After).
    pub async fn check_with_metadata(
        &self,
        category: &str,
        identifier: &str,
        limit: &RateLimit,
    ) -> Result<RateLimitResult> {
        let allowed = self.check(category, identifier, limit).await?;
        let remaining =
            if allowed { self.remaining(category, identifier, limit).await? } else { 0 };
        let reset_after = self.reset_after(limit);

        Ok(RateLimitResult { allowed, remaining, reset_after })
    }
}

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
mod tests {
    use std::time::Duration;

    use inferadb_control_storage::MemoryBackend;

    use super::*;

    #[test]
    fn test_rate_limit_window_hour() {
        let window = RateLimitWindow::Hour;
        assert_eq!(window.seconds(), 3600);
    }

    #[test]
    fn test_rate_limit_window_day() {
        let window = RateLimitWindow::Day;
        assert_eq!(window.seconds(), 86400);
    }

    #[test]
    fn test_window_start_calculation() {
        let window = RateLimitWindow::Hour;
        // Use a known timestamp (2024-01-01 00:00:00 UTC = 1704067200)
        let time = UNIX_EPOCH + Duration::from_secs(1704067200 + 1800); // 30 minutes in
        let window_start = window.window_start(time);

        // Should round down to hour boundary
        assert_eq!(window_start, 1704067200);
    }

    #[test]
    fn test_rate_limit_creation() {
        let limit = RateLimit::per_hour(100);
        assert_eq!(limit.max_requests, 100);
        assert_eq!(limit.window.seconds(), 3600);

        let limit = RateLimit::per_day(5);
        assert_eq!(limit.max_requests, 5);
        assert_eq!(limit.window.seconds(), 86400);
    }

    #[tokio::test]
    async fn test_rate_limiter_allows_under_limit() {
        let storage = MemoryBackend::new();
        let limiter = RateLimiter::new(storage);
        let limit = RateLimit::per_hour(5);

        // First 5 requests should be allowed
        for _ in 0..5 {
            let allowed = limiter.check("test", "user1", &limit).await.unwrap();
            assert!(allowed);
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_over_limit() {
        let storage = MemoryBackend::new();
        let limiter = RateLimiter::new(storage);
        let limit = RateLimit::per_hour(3);

        // First 3 requests allowed
        for _ in 0..3 {
            assert!(limiter.check("test", "user1", &limit).await.unwrap());
        }

        // 4th request should be blocked
        let allowed = limiter.check("test", "user1", &limit).await.unwrap();
        assert!(!allowed);
    }

    #[tokio::test]
    async fn test_rate_limiter_isolates_identifiers() {
        let storage = MemoryBackend::new();
        let limiter = RateLimiter::new(storage);
        let limit = RateLimit::per_hour(2);

        // user1 uses up their limit
        assert!(limiter.check("test", "user1", &limit).await.unwrap());
        assert!(limiter.check("test", "user1", &limit).await.unwrap());
        assert!(!limiter.check("test", "user1", &limit).await.unwrap());

        // user2 should still be able to make requests
        assert!(limiter.check("test", "user2", &limit).await.unwrap());
        assert!(limiter.check("test", "user2", &limit).await.unwrap());
    }

    #[tokio::test]
    async fn test_rate_limiter_isolates_categories() {
        let storage = MemoryBackend::new();
        let limiter = RateLimiter::new(storage);
        let limit = RateLimit::per_hour(2);

        // Use up limit in category1
        assert!(limiter.check("category1", "user1", &limit).await.unwrap());
        assert!(limiter.check("category1", "user1", &limit).await.unwrap());
        assert!(!limiter.check("category1", "user1", &limit).await.unwrap());

        // Should still be able to make requests in category2
        assert!(limiter.check("category2", "user1", &limit).await.unwrap());
        assert!(limiter.check("category2", "user1", &limit).await.unwrap());
    }

    #[tokio::test]
    async fn test_remaining_count() {
        let storage = MemoryBackend::new();
        let limiter = RateLimiter::new(storage);
        let limit = RateLimit::per_hour(5);

        assert_eq!(limiter.remaining("test", "user1", &limit).await.unwrap(), 5);

        limiter.check("test", "user1", &limit).await.unwrap();
        assert_eq!(limiter.remaining("test", "user1", &limit).await.unwrap(), 4);

        limiter.check("test", "user1", &limit).await.unwrap();
        assert_eq!(limiter.remaining("test", "user1", &limit).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_check_with_metadata() {
        let storage = MemoryBackend::new();
        let limiter = RateLimiter::new(storage);
        let limit = RateLimit::per_hour(3);

        // First request
        let result = limiter.check_with_metadata("test", "user1", &limit).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.remaining, 2);
        assert!(result.reset_after > 0);
        assert!(result.reset_after <= 3600);

        // Second request
        let result = limiter.check_with_metadata("test", "user1", &limit).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.remaining, 1);

        // Third request
        let result = limiter.check_with_metadata("test", "user1", &limit).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.remaining, 0);

        // Fourth request (over limit)
        let result = limiter.check_with_metadata("test", "user1", &limit).await.unwrap();
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }

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
