//! Integration tests for rate limiting middleware.
//!
//! Verifies that the rate limit middleware allows requests under the limit
//! by sending requests to actual rate-limited auth endpoints.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::http::StatusCode;
use inferadb_control_core::IdGenerator;
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

/// Requests under the rate limit threshold should not be blocked.
#[tokio::test]
async fn test_login_not_rate_limited() {
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
