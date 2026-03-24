//! Test fixtures and utilities for InferaDB Control API integration tests.
//!
//! Shared test helpers for testing the Control API **without a running Ledger
//! backend**. When `AppState.ledger` is `None` (test mode), Ledger-dependent
//! endpoints return `500 "an internal error occurred"`. These helpers target:
//!
//! - Testing unauthenticated routes (health, metrics)
//! - Testing that authentication rejection works correctly
//! - Testing request validation and error responses
//! - Testing rate limiting behavior
//!
//! Full end-to-end integration tests that exercise auth flows and CRUD
//! operations require a running Ledger backend and are not covered by these
//! fixtures.
//!
//! # Usage
//!
//! ```no_run
//! use inferadb_control_test_fixtures::{create_test_state, create_test_app, get};
//!
//! #[tokio::test]
//! async fn health_check() {
//!     let state = create_test_state();
//!     let app = create_test_app(state);
//!
//!     let response = get(&app, "/healthz").await;
//!     assert_eq!(response.status(), axum::http::StatusCode::OK);
//! }
//! ```

// Test fixtures use unwrap/expect for clear failure messages in assertions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(unsafe_code)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
/// Re-exports from [`inferadb_control_api`] for test convenience.
pub use inferadb_control_api::{AppState, create_router_with_state};
/// Re-exports from [`inferadb_control_const`] for authentication test convenience.
pub use inferadb_control_const::auth::{ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME};
use serde_json::Value;
use tower::ServiceExt;

/// Creates a test `AppState` with in-memory storage backend and no Ledger
/// connection.
///
/// The returned state has `ledger: None`, so any handler that calls into the
/// Ledger SDK will return a 500 error. This is intentional — these fixtures
/// target tests that do not require a live Ledger.
///
/// # Example
///
/// ```no_run
/// use inferadb_control_test_fixtures::create_test_state;
///
/// let state = create_test_state();
/// ```
pub fn create_test_state() -> AppState {
    AppState::new_test()
}

/// Creates a fully configured Axum router with all middleware and routes.
///
/// Includes authentication middleware, rate limiting, security headers, and all
/// API routes. Requests can be dispatched via `tower::ServiceExt::oneshot`.
///
/// # Example
///
/// ```no_run
/// use inferadb_control_test_fixtures::{create_test_state, create_test_app};
///
/// let state = create_test_state();
/// let app = create_test_app(state);
/// ```
pub fn create_test_app(state: AppState) -> Router {
    create_router_with_state(state)
}

/// Extracts the access token cookie value from HTTP response headers.
///
/// Parses `Set-Cookie` headers looking for the `inferadb_access` cookie.
pub fn extract_access_token(headers: &axum::http::HeaderMap) -> Option<String> {
    extract_cookie(headers, ACCESS_TOKEN_COOKIE_NAME)
}

/// Extracts the refresh token cookie value from HTTP response headers.
///
/// Parses `Set-Cookie` headers looking for the `inferadb_refresh` cookie.
pub fn extract_refresh_token(headers: &axum::http::HeaderMap) -> Option<String> {
    extract_cookie(headers, REFRESH_TOKEN_COOKIE_NAME)
}

/// Extracts a named cookie value from HTTP response `Set-Cookie` headers.
fn extract_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    headers.get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()).find_map(|s| {
        s.split(';').next().and_then(|cookie| cookie.strip_prefix(&prefix)).map(|v| v.to_string())
    })
}

/// Parses an HTTP response body as JSON.
///
/// # Panics
///
/// Panics if the body cannot be read or parsed as valid JSON.
pub async fn body_json(response: axum::http::Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Builds an HTTP request with a JSON content-type header and no auth credentials.
///
/// Without a Ledger backend, JWT validation middleware rejects all requests to
/// protected routes. Use this for testing unauthenticated routes (health,
/// metrics) or verifying auth rejection.
pub fn json_request(method: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap()
}

/// Sends a JSON POST request and returns the response.
///
/// # Panics
///
/// Panics if the request cannot be dispatched.
pub async fn post_json(app: &Router, uri: &str, body: Value) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Sends a GET request and returns the response.
///
/// # Panics
///
/// Panics if the request cannot be dispatched.
pub async fn get(app: &Router, uri: &str) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(Request::builder().method("GET").uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// Asserts the response has the expected status code and returns the JSON
/// body.
///
/// # Panics
///
/// Panics if the status code does not match or if the body is not valid JSON.
pub async fn assert_status(response: axum::http::Response<Body>, expected: StatusCode) -> Value {
    let actual = response.status();
    let json = body_json(response).await;
    assert_eq!(actual, expected, "expected status {expected}, got {actual}; body: {json}");
    json
}
