use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use inferadb_control_core::{RateLimit, RateLimiter, categories, limits};

use crate::handlers::AppState;

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
    let ip = match extract_client_ip(&req) {
        Some(ip) => ip,
        None => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to extract client IP")
                .into_response();
        },
    };

    let limiter = RateLimiter::new((*state.storage).clone());
    let limit = limits::login_ip();

    match limiter.check_with_metadata(categories::LOGIN_IP, &ip, &limit).await {
        Ok(result) => {
            if result.allowed {
                // Add rate limit headers to response
                let mut response = next.run(req).await;
                let headers = response.headers_mut();
                headers
                    .insert("X-RateLimit-Limit", limit.max_requests.to_string().parse().unwrap());
                headers
                    .insert("X-RateLimit-Remaining", result.remaining.to_string().parse().unwrap());
                headers
                    .insert("X-RateLimit-Reset", result.reset_after.to_string().parse().unwrap());
                response
            } else {
                // Rate limit exceeded
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded. Too many login attempts.",
                )
                    .into_response();

                let headers = response.headers_mut();
                headers
                    .insert(header::RETRY_AFTER, result.reset_after.to_string().parse().unwrap());
                headers
                    .insert("X-RateLimit-Limit", limit.max_requests.to_string().parse().unwrap());
                headers.insert("X-RateLimit-Remaining", "0".parse().unwrap());
                headers
                    .insert("X-RateLimit-Reset", result.reset_after.to_string().parse().unwrap());

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
    let ip = match extract_client_ip(&req) {
        Some(ip) => ip,
        None => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to extract client IP")
                .into_response();
        },
    };

    let limiter = RateLimiter::new((*state.storage).clone());
    let limit = limits::registration_ip();

    match limiter.check_with_metadata(categories::REGISTRATION_IP, &ip, &limit).await {
        Ok(result) => {
            if result.allowed {
                let mut response = next.run(req).await;
                let headers = response.headers_mut();
                headers
                    .insert("X-RateLimit-Limit", limit.max_requests.to_string().parse().unwrap());
                headers
                    .insert("X-RateLimit-Remaining", result.remaining.to_string().parse().unwrap());
                headers
                    .insert("X-RateLimit-Reset", result.reset_after.to_string().parse().unwrap());
                response
            } else {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded. Too many registration attempts.",
                )
                    .into_response();

                let headers = response.headers_mut();
                headers
                    .insert(header::RETRY_AFTER, result.reset_after.to_string().parse().unwrap());
                headers
                    .insert("X-RateLimit-Limit", limit.max_requests.to_string().parse().unwrap());
                headers.insert("X-RateLimit-Remaining", "0".parse().unwrap());
                headers
                    .insert("X-RateLimit-Reset", result.reset_after.to_string().parse().unwrap());

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
                headers
                    .insert("X-RateLimit-Limit", limit.max_requests.to_string().parse().unwrap());
                headers
                    .insert("X-RateLimit-Remaining", result.remaining.to_string().parse().unwrap());
                headers
                    .insert("X-RateLimit-Reset", result.reset_after.to_string().parse().unwrap());
                response
            } else {
                let mut response = (StatusCode::TOO_MANY_REQUESTS, error_message).into_response();

                let headers = response.headers_mut();
                headers
                    .insert(header::RETRY_AFTER, result.reset_after.to_string().parse().unwrap());
                headers
                    .insert("X-RateLimit-Limit", limit.max_requests.to_string().parse().unwrap());
                headers.insert("X-RateLimit-Remaining", "0".parse().unwrap());
                headers
                    .insert("X-RateLimit-Reset", result.reset_after.to_string().parse().unwrap());

                response
            }
        },
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Rate limit check failed").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_extract_client_ip() {
        let req = Request::builder().uri("/test").body(axum::body::Body::empty()).unwrap();

        // Without ConnectInfo, should return None
        assert!(extract_client_ip(&req).is_none());
    }
}
