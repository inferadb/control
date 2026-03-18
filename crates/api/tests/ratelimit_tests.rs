//! Integration tests for rate limiting middleware.
//!
//! Rate limiting is now handled at the infrastructure layer (e.g., API gateway).
//! The middleware functions are pass-throughs. These tests verify that requests
//! are not blocked by the (now no-op) rate limit middleware.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::http::StatusCode;
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{create_test_app, create_test_state};
use serde_json::json;
use tower::ServiceExt;

fn login_request(email: &str, password: &str, ip: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri("/control/v1/auth/login/password")
        .header("content-type", "application/json")
        .header("x-forwarded-for", ip)
        .body(axum::body::Body::from(
            json!({
                "email": email,
                "password": password
            })
            .to_string(),
        ))
        .unwrap()
}

/// Verify that the pass-through rate limit middleware does not block requests.
#[tokio::test]
async fn test_login_not_rate_limited() {
    let _ = IdGenerator::init(800);

    let state = create_test_state();
    let app = create_test_app(state);

    let ip = "10.0.0.1";

    // Multiple login attempts should never return 429 (rate limiting is a no-op)
    for i in 0..5 {
        let response = app
            .clone()
            .oneshot(login_request(&format!("attempt{i}@example.com"), "wrong", ip))
            .await
            .unwrap();

        assert_ne!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request {} should not be rate limited (middleware is a no-op)",
            i + 1
        );
    }
}
