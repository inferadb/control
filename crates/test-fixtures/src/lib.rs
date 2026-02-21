// Test fixtures are allowed to use unwrap/expect for clear failure messages
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
//!
//! # Entity Builders
//!
//! When constructing entities directly in tests (e.g., for repository tests), use the
//! `bon` builder pattern. All entity types support builders via `Type::builder()`:
//!
//! ```ignore
//! use inferadb_control_types::{User, Organization, Vault, Client};
//!
//! // User with builder (fallible - returns Result)
//! let user = User::builder()
//!     .name("Alice")
//!     .build()
//!     .unwrap();
//!
//! // Organization with builder
//! let org = Organization::builder()
//!     .name("Acme Corp")
//!     .owner_id(user.id)
//!     .build()
//!     .unwrap();
//!
//! // Vault with builder
//! let vault = Vault::builder()
//!     .name("production")
//!     .organization_id(org.id)
//!     .build()
//!     .unwrap();
//!
//! // Client with builder
//! let client = Client::builder()
//!     .name("api-client")
//!     .vault_id(vault.id)
//!     .build()
//!     .unwrap();
//! ```
//!
//! For optional fields, use `.maybe_field()` to pass `Option<T>` values directly,
//! or omit the call entirely for `None`:
//!
//! ```ignore
//! use inferadb_control_types::AuditLog;
//!
//! let log = AuditLog::builder()
//!     .user_id(user_id)
//!     .action("login")
//!     .resource_type("session")
//!     .maybe_ip_address(request_ip)  // Pass Option<String> directly
//!     .maybe_user_agent(user_agent)  // Optional field
//!     .build();
//! ```

#![deny(unsafe_code)]

use std::sync::Arc;

use axum::{body::Body, http::Request};
use inferadb_control_api::{AppState, create_router_with_state};
use inferadb_control_storage::Backend;
use serde_json::{Value, json};
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
    let backend = Backend::memory();
    AppState::new_test(Arc::new(backend))
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

/// Parses an HTTP response body as JSON.
///
/// # Panics
///
/// Panics if the body cannot be read or parsed as valid JSON.
pub async fn body_json(response: axum::http::Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Logs in a user and returns their session cookie.
///
/// # Panics
///
/// Panics if login fails or no session cookie is returned.
pub async fn login_user(app: &axum::Router, email: &str, password: &str) -> String {
    use axum::http::StatusCode;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/login/password")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK, "Login should succeed");
    extract_session_cookie(response.headers()).expect("Session cookie should be set")
}

/// Gets the org_id from the first organization in the user's list.
///
/// # Panics
///
/// Panics if the organizations list is empty or the request fails.
pub async fn get_org_id(app: &axum::Router, session: &str) -> i64 {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/organizations")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let json = body_json(response).await;
    json["organizations"][0]["id"].as_i64().expect("Should have org ID")
}

/// Creates an organization and returns its ID and the full JSON response.
///
/// # Panics
///
/// Panics if creation fails.
pub async fn create_organization(app: &axum::Router, session: &str, name: &str) -> (i64, Value) {
    use axum::http::StatusCode;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/organizations")
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": name
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK, "Organization creation should succeed");
    let json = body_json(response).await;
    let org_id = json["organization"]["id"].as_i64().expect("Should have org ID");
    (org_id, json)
}

/// Creates a vault in an organization and returns its ID and the full JSON response.
///
/// # Panics
///
/// Panics if creation fails.
pub async fn create_vault(
    app: &axum::Router,
    session: &str,
    org_id: i64,
    name: &str,
) -> (i64, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": name,
                        "description": "Test vault"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert!(status.is_success(), "Vault creation should succeed, got {status}");
    let json = body_json(response).await;
    let vault_id = json["vault"]["id"].as_i64().expect("Should have vault ID");
    (vault_id, json)
}

/// Creates a client in an organization and returns its ID and the full JSON response.
///
/// # Panics
///
/// Panics if creation fails.
pub async fn create_client(
    app: &axum::Router,
    session: &str,
    org_id: i64,
    name: &str,
) -> (i64, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/clients"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": name,
                        "description": "Test client"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert!(status.is_success(), "Client creation should succeed, got {status}");
    let json = body_json(response).await;
    let client_id = json["client"]["id"].as_i64().expect("Should have client ID");
    (client_id, json)
}

/// Creates a client with a certificate and returns both IDs and the certificate JSON response.
///
/// # Panics
///
/// Panics if client or certificate creation fails.
pub async fn create_client_with_cert(
    app: &axum::Router,
    session: &str,
    org_id: i64,
) -> (i64, i64, Value) {
    let (client_id, _) = create_client(app, session, org_id, "test-client").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"name": "test-cert"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let json = body_json(response).await;

    if !status.is_success() {
        panic!("Failed to create certificate. Status: {status}, Body: {json}");
    }

    let cert_id = json["certificate"]["id"].as_i64().expect("Should have cert ID");
    (client_id, cert_id, json)
}

/// Verifies a user's email directly via the repository (bypasses HTTP).
///
/// # Panics
///
/// Panics if the user or email cannot be found.
pub async fn verify_user_email(state: &AppState, username: &str) {
    use inferadb_control_core::{UserEmailRepository, UserRepository};

    let user_repo = UserRepository::new((*state.storage).clone());
    let email_repo = UserEmailRepository::new((*state.storage).clone());

    let user = user_repo.get_by_name(username).await.unwrap().unwrap();
    let mut emails = email_repo.get_user_emails(user.id).await.unwrap();
    if let Some(email) = emails.first_mut() {
        email.verify();
        email_repo.update(email.clone()).await.unwrap();
    }
}

/// Invites a member to an organization and accepts the invitation.
///
/// # Panics
///
/// Panics if the invitation or acceptance fails.
pub async fn invite_and_accept_member(
    app: &axum::Router,
    owner_session: &str,
    member_session: &str,
    member_email: &str,
    org_id: i64,
) {
    use axum::http::StatusCode;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/invitations"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": member_email,
                        "role": "MEMBER"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK, "Invitation should succeed");

    let json = body_json(response).await;
    let token = json["invitation"]["token"].as_str().unwrap().to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/organizations/invitations/accept")
                .header("cookie", format!("infera_session={member_session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "token": token }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK, "Accepting invitation should succeed");
}
