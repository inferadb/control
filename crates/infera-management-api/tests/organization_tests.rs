use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use infera_management_api::{create_router_with_state, AppState};
use infera_management_core::IdGenerator;
use infera_management_storage::{Backend, MemoryBackend};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

/// Helper to create test app state
fn create_test_state() -> AppState {
    let storage = Backend::Memory(MemoryBackend::new());
    AppState::new_test(Arc::new(storage))
}

/// Helper to create configured app with middleware
fn create_test_app(state: AppState) -> axum::Router {
    create_router_with_state(state)
}

/// Helper to extract session cookie from response
fn extract_session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .next()
                .and_then(|cookie| cookie.strip_prefix("infera_session="))
        })
        .map(|s| s.to_string())
}

#[tokio::test]
async fn test_registration_creates_default_organization() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register a new user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "testuser",
                        "email": "test@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Extract session cookie
    let session_cookie =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // List organizations for the user
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/organizations")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify that the user has one organization with the same name
    let orgs = json["organizations"]
        .as_array()
        .expect("Should have organizations");
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0]["name"], "testuser");
    assert_eq!(orgs[0]["role"], "OWNER");
    assert_eq!(orgs[0]["tier"], "TIER_DEV_V1");
}

#[tokio::test]
async fn test_create_organization() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register a user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "testuser",
                        "email": "test@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_cookie =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Create a new organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "name": "Test Organization"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["organization"]["name"], "Test Organization");
    assert_eq!(json["organization"]["role"], "OWNER");
}

#[tokio::test]
async fn test_list_organizations() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register a user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "testuser",
                        "email": "test@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_cookie =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Create another organization
    let _response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "name": "Second Organization"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // List organizations
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/organizations")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let orgs = json["organizations"]
        .as_array()
        .expect("Should have organizations");
    assert_eq!(orgs.len(), 2);
}

#[tokio::test]
async fn test_get_organization_details() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register a user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "testuser",
                        "email": "test@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_cookie =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Create an organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "name": "Test Organization"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organization"]["id"].as_i64().unwrap();

    // Get organization details
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}", org_id))
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["organization"]["id"], org_id);
    assert_eq!(json["organization"]["name"], "Test Organization");
}

#[tokio::test]
async fn test_update_organization() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register a user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "testuser",
                        "email": "test@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_cookie =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Create an organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "name": "Old Name"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organization"]["id"].as_i64().unwrap();

    // Update organization
    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/organizations/{}", org_id))
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "name": "New Name"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["organization"]["name"], "New Name");
}

#[tokio::test]
async fn test_delete_organization() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register a user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "testuser",
                        "email": "test@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_cookie =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Create an organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "name": "Test Organization"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organization"]["id"].as_i64().unwrap();

    // Delete organization
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/organizations/{}", org_id))
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_non_member_cannot_access_organization() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register first user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "user1",
                        "email": "user1@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session1 =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Create an organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session1))
                .body(Body::from(
                    json!({
                        "name": "User1 Org"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organization"]["id"].as_i64().unwrap();

    // Register second user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "user2",
                        "email": "user2@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session2 =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Try to access the organization as user2
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}", org_id))
                .header("cookie", format!("infera_session={}", session2))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
