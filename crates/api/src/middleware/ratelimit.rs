use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use inferadb_control_core::{RateLimit, RateLimiter, categories, limits};

use crate::handlers::AppState;

/// Convert a display-able value to a HeaderValue.
///
/// # Safety
/// This is safe because integer/numeric `.to_string()` always produces valid ASCII,
/// which is always valid for HTTP headers. This avoids `.unwrap()` on infallible conversions.
fn header_value(value: impl std::fmt::Display) -> HeaderValue {
    HeaderValue::try_from(value.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0"))
}

/// Extract client IP address from request
///
/// Extracts the IP from ConnectInfo (peer address).
/// In production, this would ideally check X-Forwarded-For or similar headers
/// when behind a reverse proxy.
fn extract_client_ip(req: &Request) -> Option<String> {
    req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ConnectInfo(addr)| addr.ip().to_string())
}

/// Rate limiting middleware for login attempts
///
/// Applies: 100 requests per hour per IP
pub async fn login_rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(ip) = extract_client_ip(&req) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to extract client IP").into_response();
    };

    let limiter = RateLimiter::new((*state.storage).clone());
    let limit = limits::login_ip();

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
/// Applies: 5 requests per day per IP
pub async fn registration_rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let Some(ip) = extract_client_ip(&req) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to extract client IP").into_response();
    };

    let limiter = RateLimiter::new((*state.storage).clone());
    let limit = limits::registration_ip();

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_extract_client_ip() {
        let req = Request::builder().uri("/test").body(axum::body::Body::empty()).unwrap();

        // Without ConnectInfo, should return None
        assert!(extract_client_ip(&req).is_none());
    }
}
