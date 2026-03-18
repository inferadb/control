//! Rate limiting middleware.
//!
//! Rate limiting is now handled at the infrastructure layer (e.g., API gateway).
//! These middleware functions are retained as pass-throughs for API compatibility.

use axum::{extract::Request, middleware::Next, response::Response};
use inferadb_control_core::RateLimit;

/// Configurable rate limits for the application.
///
/// Retained for `AppState` compatibility. Values are not enforced at this layer.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Rate limit for login attempts (default: 100/hour per IP)
    pub login: RateLimit,
    /// Rate limit for registration attempts (default: 5/day per IP)
    pub registration: RateLimit,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        use inferadb_control_core::limits;
        Self { login: limits::login_ip(), registration: limits::registration_ip() }
    }
}

/// Pass-through login rate limit middleware (no-op).
pub async fn login_rate_limit(req: Request, next: Next) -> Response {
    next.run(req).await
}

/// Pass-through registration rate limit middleware (no-op).
pub async fn registration_rate_limit(req: Request, next: Next) -> Response {
    next.run(req).await
}
