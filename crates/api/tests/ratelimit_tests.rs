//! Integration tests for rate limiting middleware.
//!
//! These tests verify that rate limiting is correctly enforced on login
//! and registration endpoints, including proper HTTP headers and per-IP isolation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use axum::http::StatusCode;
use inferadb_control_api::middleware::RateLimitConfig;
use inferadb_control_core::{IdGenerator, RateLimit};
use inferadb_control_test_fixtures::create_test_app;
use serde_json::json;
use tower::ServiceExt;

/// Creates a test state with small rate limits for fast test execution.
fn create_rate_limited_test_state(
    login_max: u32,
    registration_max: u32,
) -> inferadb_control_api::handlers::AppState {
    use inferadb_control_api::handlers::AppState;
    use inferadb_control_config::ControlConfig;
    use inferadb_control_storage::Backend;

    let backend = Backend::memory();
    let config =
        ControlConfig::builder().maybe_key_file(Some("/tmp/test-master.key".to_string())).build();

    let email_sender = Box::new(inferadb_control_core::MockEmailSender::new());
    let email_service = inferadb_control_core::EmailService::new(email_sender);

    AppState::builder()
        .storage(Arc::new(backend))
        .config(Arc::new(config))
        .worker_id(0)
        .email_service(Arc::new(email_service))
        .rate_limits(RateLimitConfig {
            login: RateLimit::per_hour(login_max),
            registration: RateLimit::per_hour(registration_max),
        })
        .build()
}

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

fn register_request(
    name: &str,
    email: &str,
    password: &str,
    ip: &str,
) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri("/control/v1/auth/register")
        .header("content-type", "application/json")
        .header("x-forwarded-for", ip)
        .body(axum::body::Body::from(
            json!({
                "name": name,
                "email": email,
                "password": password
            })
            .to_string(),
        ))
        .unwrap()
}

/// Login rate limit: make requests exceeding the limit, verify the last gets 429.
#[tokio::test]
async fn test_login_rate_limit_enforced() {
    let _ = IdGenerator::init(800);

    // Set login limit to 3 per hour
    let state = create_rate_limited_test_state(3, 10);
    let app = create_test_app(state);

    let ip = "10.0.0.1";

    // Make 3 login attempts (all should be allowed, even with wrong password)
    for i in 0..3 {
        let response = app
            .clone()
            .oneshot(login_request(&format!("attempt{}@example.com", i), "wrong", ip))
            .await
            .unwrap();

        assert_ne!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request {} should not be rate limited",
            i + 1
        );
    }

    // 4th attempt should be rate limited
    let response =
        app.clone().oneshot(login_request("attempt4@example.com", "wrong", ip)).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "4th login attempt should be rate limited"
    );
}

/// Registration rate limit: make requests exceeding the limit, verify the last gets 429.
#[tokio::test]
async fn test_registration_rate_limit_enforced() {
    let _ = IdGenerator::init(801);

    // Set registration limit to 2 per hour
    let state = create_rate_limited_test_state(100, 2);
    let app = create_test_app(state);

    let ip = "10.0.0.2";

    // Make 2 registration attempts (should be allowed)
    for i in 0..2 {
        let response = app
            .clone()
            .oneshot(register_request(
                &format!("User {}", i),
                &format!("reg{}@example.com", i),
                "SecurePass123!",
                ip,
            ))
            .await
            .unwrap();

        assert_ne!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Registration {} should not be rate limited",
            i + 1
        );
    }

    // 3rd registration attempt should be rate limited
    let response = app
        .clone()
        .oneshot(register_request("User 3", "reg3@example.com", "SecurePass123!", ip))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "3rd registration attempt should be rate limited"
    );
}

/// Rate limit headers are present on every auth response.
#[tokio::test]
async fn test_rate_limit_headers_present_on_auth_response() {
    let _ = IdGenerator::init(802);

    let state = create_rate_limited_test_state(10, 10);
    let app = create_test_app(state);

    let ip = "10.0.0.3";

    // Login attempt (will fail with 401 since user doesn't exist, but headers should be present)
    let response = app
        .clone()
        .oneshot(login_request("nonexistent@example.com", "password", ip))
        .await
        .unwrap();

    assert!(
        response.headers().get("X-RateLimit-Limit").is_some(),
        "X-RateLimit-Limit header should be present on login response"
    );
    assert!(
        response.headers().get("X-RateLimit-Remaining").is_some(),
        "X-RateLimit-Remaining header should be present on login response"
    );
    assert!(
        response.headers().get("X-RateLimit-Reset").is_some(),
        "X-RateLimit-Reset header should be present on login response"
    );

    // Verify X-RateLimit-Limit matches configured limit
    let limit_header = response.headers().get("X-RateLimit-Limit").unwrap().to_str().unwrap();
    assert_eq!(limit_header, "10", "X-RateLimit-Limit should match configured limit");

    // Registration attempt
    let response = app
        .clone()
        .oneshot(register_request("Header Test", "header@example.com", "SecurePass123!", ip))
        .await
        .unwrap();

    assert!(
        response.headers().get("X-RateLimit-Limit").is_some(),
        "X-RateLimit-Limit header should be present on registration response"
    );
    assert!(
        response.headers().get("X-RateLimit-Remaining").is_some(),
        "X-RateLimit-Remaining header should be present on registration response"
    );
}

/// Retry-After header is present on 429 responses.
#[tokio::test]
async fn test_retry_after_header_on_429() {
    let _ = IdGenerator::init(803);

    // Set login limit to 1 so second attempt triggers 429
    let state = create_rate_limited_test_state(1, 10);
    let app = create_test_app(state);

    let ip = "10.0.0.4";

    // First attempt consumes the limit
    let _response =
        app.clone().oneshot(login_request("first@example.com", "password", ip)).await.unwrap();

    // Second attempt should get 429 with Retry-After
    let response =
        app.clone().oneshot(login_request("second@example.com", "password", ip)).await.unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    assert!(
        response.headers().get("retry-after").is_some(),
        "Retry-After header should be present on 429 response"
    );

    // Verify Retry-After is a positive integer (seconds until reset)
    let retry_after = response
        .headers()
        .get("retry-after")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<u64>()
        .expect("Retry-After should be a valid integer");

    assert!(retry_after > 0, "Retry-After should be positive");

    // X-RateLimit-Remaining should be 0
    let remaining = response.headers().get("X-RateLimit-Remaining").unwrap().to_str().unwrap();
    assert_eq!(remaining, "0", "X-RateLimit-Remaining should be 0 on 429");
}

/// Different IPs have independent rate limits.
#[tokio::test]
async fn test_different_ips_have_independent_rate_limits() {
    let _ = IdGenerator::init(804);

    // Set login limit to 2 per hour
    let state = create_rate_limited_test_state(2, 10);
    let app = create_test_app(state);

    let ip_a = "10.0.0.10";
    let ip_b = "10.0.0.11";

    // Exhaust IP A's rate limit
    for i in 0..2 {
        let response = app
            .clone()
            .oneshot(login_request(&format!("a{}@example.com", i), "password", ip_a))
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // IP A should now be rate limited
    let response =
        app.clone().oneshot(login_request("a3@example.com", "password", ip_a)).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, "IP A should be rate limited");

    // IP B should still be allowed (independent limit)
    let response =
        app.clone().oneshot(login_request("b1@example.com", "password", ip_b)).await.unwrap();
    assert_ne!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "IP B should NOT be rate limited — independent limit from IP A"
    );
}

/// Rate-limited 429 response body contains error message.
#[tokio::test]
async fn test_rate_limit_429_response_body() {
    let _ = IdGenerator::init(805);

    let state = create_rate_limited_test_state(1, 1);
    let app = create_test_app(state);

    let ip = "10.0.0.20";

    // Exhaust login limit
    let _ = app.clone().oneshot(login_request("first@example.com", "p", ip)).await.unwrap();

    let response = app.clone().oneshot(login_request("second@example.com", "p", ip)).await.unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(
        body_str.contains("Rate limit exceeded"),
        "429 response body should contain rate limit message, got: {}",
        body_str
    );
}
