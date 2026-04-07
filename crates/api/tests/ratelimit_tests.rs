//! Integration tests for rate limiting middleware.
//!
//! Verifies that the rate limit middleware allows requests under the limit
//! and blocks requests that exceed the limit, using actual rate-limited
//! auth endpoints.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::http::StatusCode;
use inferadb_control_api::RateLimitConfig;
use inferadb_control_core::{
    IdGenerator,
    ratelimit::{RateLimit, RateLimitWindow},
};
use inferadb_control_test_fixtures::{create_test_app, create_test_state};
use serde_json::json;
use tower::ServiceExt;

fn auth_request(ip: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri("/control/v1/auth/email/initiate")
        .header("content-type", "application/json")
        .header("x-forwarded-for", ip)
        .body(axum::body::Body::from(
            json!({
                "email": "test@example.com"
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn test_ratelimit_login_under_limit_returns_non_429() {
    let _ = IdGenerator::init(800);

    let state = create_test_state();
    let app = create_test_app(state);

    let ip = "10.0.0.1";

    // A small number of requests should never trigger rate limiting
    // (login limit is 100/hour per IP).
    for i in 0..5 {
        let response = app.clone().oneshot(auth_request(ip)).await.unwrap();

        assert_ne!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request {} should not be rate limited",
            i + 1
        );
    }
}

/// Exceeding the login rate limit returns 429 with Retry-After header.
#[tokio::test]
async fn test_ratelimit_login_exceeded_returns_429_with_retry_after() {
    let _ = IdGenerator::init(801);

    let mut state = create_test_state();
    // Set a very low limit (2 requests/hour) so we can exceed it quickly.
    state.rate_limits = RateLimitConfig {
        login: RateLimit { max_requests: 2, window: RateLimitWindow::Hour },
        registration: RateLimit { max_requests: 5, window: RateLimitWindow::Day },
    };
    state.rate_limiter = Arc::new(inferadb_control_core::AnyRateLimiter::default());
    let app = create_test_app(state);

    let ip = "10.0.0.99";

    // First two requests should succeed (under limit).
    for i in 0..2 {
        let response = app.clone().oneshot(auth_request(ip)).await.unwrap();
        assert_ne!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request {} should not be rate limited",
            i + 1
        );
    }

    // Third request should be rate limited.
    let response = app.clone().oneshot(auth_request(ip)).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Request exceeding limit should return 429"
    );
    assert!(
        response.headers().get("retry-after").is_some(),
        "429 response must include Retry-After header"
    );
}
