//! Rate limiting middleware.
//!
//! Enforces per-IP rate limits on authentication endpoints using the
//! application-level rate limiter from [`AppState`]. Returns HTTP 429
//! with a `Retry-After` header when the limit is exceeded.

use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use inferadb_control_core::{RateLimit, RateLimitResult};

use crate::{extract::extract_client_ip, handlers::AppState};

/// Configurable rate limits for the application.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Rate limit for login/auth attempts (default: 100/hour per IP).
    pub login: RateLimit,
    /// Rate limit for registration attempts (default: 5/day per IP).
    pub registration: RateLimit,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        use inferadb_control_core::limits;
        Self { login: limits::login_ip(), registration: limits::registration_ip() }
    }
}

/// Fixed sentinel key for clients whose IP cannot be determined.
///
/// All unidentifiable clients share a single rate limit bucket. This prevents
/// bypass by omitting proxy headers — unknown clients are collectively throttled
/// rather than each getting their own unlimited bucket.
const UNKNOWN_CLIENT_KEY: &str = "unknown";

/// Login/auth rate limit middleware (100/hour per IP).
///
/// Applied to all public authentication endpoints to prevent brute force attacks.
pub async fn login_rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let ip = extract_client_ip(&req, state.config.trusted_proxy_depth)
        .unwrap_or_else(|| UNKNOWN_CLIENT_KEY.to_string());
    match state.rate_limiter.check("login_ip", &ip, &state.rate_limits.login).await {
        Ok(RateLimitResult::Limited { retry_after_secs }) => rate_limit_response(retry_after_secs),
        Ok(_) => next.run(req).await,
        Err(e) => {
            tracing::warn!(error = %e, "Rate limiter storage error, allowing request");
            next.run(req).await
        },
    }
}

/// Registration rate limit middleware (5/day per IP).
///
/// Applied to account registration endpoints to prevent mass account creation.
pub async fn registration_rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&req, state.config.trusted_proxy_depth)
        .unwrap_or_else(|| UNKNOWN_CLIENT_KEY.to_string());
    match state.rate_limiter.check("registration_ip", &ip, &state.rate_limits.registration).await {
        Ok(RateLimitResult::Limited { retry_after_secs }) => rate_limit_response(retry_after_secs),
        Ok(_) => next.run(req).await,
        Err(e) => {
            tracing::warn!(error = %e, "Rate limiter storage error, allowing request");
            next.run(req).await
        },
    }
}

/// Builds a 429 Too Many Requests response with Retry-After header.
fn rate_limit_response(retry_after_secs: u64) -> Response {
    let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}
