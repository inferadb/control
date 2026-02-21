use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use inferadb_control_core::{RateLimit, RateLimiter, categories, limits};
use tracing::warn;

use crate::{extract::extract_client_ip, handlers::AppState};

/// Configurable rate limits for the application
///
/// Production code uses `Default` which delegates to the standard limits.
/// Tests can override with smaller values for faster execution.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Rate limit for login attempts (default: 100/hour per IP)
    pub login: RateLimit,
    /// Rate limit for registration attempts (default: 5/day per IP)
    pub registration: RateLimit,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self { login: limits::login_ip(), registration: limits::registration_ip() }
    }
}

/// Convert a display-able value to a HeaderValue.
///
/// # Safety
/// This is safe because integer/numeric `.to_string()` always produces valid ASCII,
/// which is always valid for HTTP headers. This avoids `.unwrap()` on infallible conversions.
fn header_value(value: impl std::fmt::Display) -> HeaderValue {
    HeaderValue::try_from(value.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0"))
}

/// Rate limiting middleware for login attempts
///
/// Reads the login rate limit from `AppState::rate_limits`.
/// Falls back to `"unknown"` if client IP cannot be determined, ensuring
/// requests are never blocked due to missing IP information.
pub async fn login_rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let ip = extract_client_ip(&req).unwrap_or_else(|| {
        warn!("could not determine client IP for login rate limiting");
        "unknown".to_string()
    });

    let limiter = RateLimiter::new((*state.storage).clone());
    let limit = state.rate_limits.login.clone();

    match limiter.check_with_metadata(categories::LOGIN_IP, &ip, &limit).await {
        Ok(result) => {
            if result.allowed {
                // Add rate limit headers to response
                let mut response = next.run(req).await;
                let headers = response.headers_mut();
                headers.insert("X-RateLimit-Limit", header_value(limit.max_requests));
                headers.insert("X-RateLimit-Remaining", header_value(result.remaining));
                headers.insert("X-RateLimit-Reset", header_value(result.reset_after));
                response
            } else {
                // Rate limit exceeded
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded. Too many login attempts.",
                )
                    .into_response();

                let headers = response.headers_mut();
                headers.insert(header::RETRY_AFTER, header_value(result.reset_after));
                headers.insert("X-RateLimit-Limit", header_value(limit.max_requests));
                headers.insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));
                headers.insert("X-RateLimit-Reset", header_value(result.reset_after));

                response
            }
        },
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Rate limit check failed").into_response(),
    }
}

/// Rate limiting middleware for registration attempts
///
/// Reads the registration rate limit from `AppState::rate_limits`.
/// Falls back to `"unknown"` if client IP cannot be determined.
pub async fn registration_rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&req).unwrap_or_else(|| {
        warn!("could not determine client IP for registration rate limiting");
        "unknown".to_string()
    });

    let limiter = RateLimiter::new((*state.storage).clone());
    let limit = state.rate_limits.registration.clone();

    match limiter.check_with_metadata(categories::REGISTRATION_IP, &ip, &limit).await {
        Ok(result) => {
            if result.allowed {
                let mut response = next.run(req).await;
                let headers = response.headers_mut();
                headers.insert("X-RateLimit-Limit", header_value(limit.max_requests));
                headers.insert("X-RateLimit-Remaining", header_value(result.remaining));
                headers.insert("X-RateLimit-Reset", header_value(result.reset_after));
                response
            } else {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded. Too many registration attempts.",
                )
                    .into_response();

                let headers = response.headers_mut();
                headers.insert(header::RETRY_AFTER, header_value(result.reset_after));
                headers.insert("X-RateLimit-Limit", header_value(limit.max_requests));
                headers.insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));
                headers.insert("X-RateLimit-Reset", header_value(result.reset_after));

                response
            }
        },
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Rate limit check failed").into_response(),
    }
}

/// Generic rate limiting middleware
///
/// This is a helper for creating rate limit middleware with custom categories and limits.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    category: &'static str,
    identifier: impl AsRef<str>,
    limit: RateLimit,
    error_message: &'static str,
    req: Request,
    next: Next,
) -> Response {
    let limiter = RateLimiter::new((*state.storage).clone());

    match limiter.check_with_metadata(category, identifier.as_ref(), &limit).await {
        Ok(result) => {
            if result.allowed {
                let mut response = next.run(req).await;
                let headers = response.headers_mut();
                headers.insert("X-RateLimit-Limit", header_value(limit.max_requests));
                headers.insert("X-RateLimit-Remaining", header_value(result.remaining));
                headers.insert("X-RateLimit-Reset", header_value(result.reset_after));
                response
            } else {
                let mut response = (StatusCode::TOO_MANY_REQUESTS, error_message).into_response();

                let headers = response.headers_mut();
                headers.insert(header::RETRY_AFTER, header_value(result.reset_after));
                headers.insert("X-RateLimit-Limit", header_value(limit.max_requests));
                headers.insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));
                headers.insert("X-RateLimit-Reset", header_value(result.reset_after));

                response
            }
        },
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Rate limit check failed").into_response(),
    }
}
