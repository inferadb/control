//! Test fixtures and utilities for InferaDB Control API integration tests.
//!
//! This crate provides shared test helpers to eliminate duplication across integration tests.
//! All functions are designed to work with the Axum-based API and MemoryBackend storage.
//!
//! # Usage
//!
//! ```rust,no_run
//! use inferadb_control_test_fixtures::{create_test_state, create_test_app, register_user};
//! use inferadb_control_core::IdGenerator;
//!
//! #[tokio::test]
//! async fn my_test() {
//!     let _ = IdGenerator::init(1);
//!     let state = create_test_state();
//!     let app = create_test_app(state);
//!
//!     let session = register_user(&app, "Test User", "test@example.com", "password123").await;
//!     // Use session cookie for authenticated requests...
//! }
//! ```

use std::sync::Arc;

use axum::{body::Body, http::Request};
use inferadb_control_api::{AppState, create_router_with_state};
use inferadb_control_storage::{Backend, MemoryBackend};
use serde_json::json;
use tower::ServiceExt;

/// Creates a test AppState with in-memory storage backend.
///
/// This function initializes a new AppState configured for testing with:
/// - MemoryBackend for data persistence
/// - Test-specific configuration (no external services)
///
/// # Returns
///
/// A fully configured AppState ready for use in integration tests.
///
/// # Example
///
/// ```rust,no_run
/// use inferadb_control_test_fixtures::create_test_state;
///
/// let state = create_test_state();
/// // Use state to create test app or access repositories directly
/// ```
pub fn create_test_state() -> AppState {
    let storage = Backend::Memory(MemoryBackend::new());
    AppState::new_test(Arc::new(storage))
}

/// Creates a fully configured Axum router with all middleware and routes.
///
/// This function sets up the complete application router including:
/// - Authentication middleware
/// - Session management
/// - Rate limiting
/// - All API routes
///
/// # Arguments
///
/// * `state` - The AppState to use for the router (typically from `create_test_state`)
///
/// # Returns
///
/// An Axum Router ready to handle test requests via `tower::ServiceExt::oneshot`.
///
/// # Example
///
/// ```rust,no_run
/// use inferadb_control_test_fixtures::{create_test_state, create_test_app};
///
/// let state = create_test_state();
/// let app = create_test_app(state);
/// // Use app with tower::ServiceExt::oneshot for test requests
/// ```
pub fn create_test_app(state: AppState) -> axum::Router {
    create_router_with_state(state)
}

/// Extracts the session cookie value from HTTP response headers.
///
/// Parses the `Set-Cookie` header to extract the `infera_session` cookie value.
/// This is used to obtain session tokens for authenticated test requests.
///
/// # Arguments
///
/// * `headers` - The HTTP response headers to parse
///
/// # Returns
///
/// * `Some(String)` - The session cookie value if found
/// * `None` - If no session cookie is present in the headers
///
/// # Example
///
/// ```rust,no_run
/// use inferadb_control_test_fixtures::extract_session_cookie;
///
/// // Given response headers from an HTTP response:
/// # let headers = axum::http::HeaderMap::new();
/// if let Some(session) = extract_session_cookie(&headers) {
///     println!("Session cookie: {}", session);
/// }
/// ```
pub fn extract_session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(';').next().and_then(|cookie| cookie.strip_prefix("infera_session=")))
        .map(|s| s.to_string())
}

/// Registers a new user and returns their session cookie.
///
/// This helper performs a complete user registration flow:
/// 1. Sends POST request to `/v1/auth/register`
/// 2. Asserts registration succeeds (HTTP 200)
/// 3. Extracts and returns the session cookie
///
/// # Arguments
///
/// * `app` - The test application router
/// * `name` - Full name of the user to register
/// * `email` - Email address (must be unique)
/// * `password` - Password for the account (must meet security requirements)
///
/// # Returns
///
/// The session cookie value that can be used for authenticated requests.
///
/// # Panics
///
/// Panics if:
/// - The registration request fails
/// - Response status is not HTTP 200 OK
/// - Session cookie is not set in the response
///
/// # Example
///
/// ```rust,no_run
/// use inferadb_control_test_fixtures::{create_test_state, create_test_app, register_user};
///
/// # async fn example() {
/// let state = create_test_state();
/// let app = create_test_app(state);
///
/// let session = register_user(&app, "Alice Smith", "alice@example.com", "securepass123").await;
///
/// // Use session cookie for authenticated requests
/// // format!("infera_session={}", session)
/// # }
/// ```
pub async fn register_user(app: &axum::Router, name: &str, email: &str, password: &str) -> String {
    use axum::http::StatusCode;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": name,
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK, "Registration should succeed");
    extract_session_cookie(response.headers()).expect("Session cookie should be set")
}
