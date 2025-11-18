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
async fn test_create_and_list_invitations() {
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

    // Create an invitation
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/invitations", org_id))
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "email": "invite@example.com",
                        "role": "MEMBER"
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
    assert_eq!(json["invitation"]["email"], "invite@example.com");
    assert_eq!(json["invitation"]["role"], "MEMBER");

    // List invitations
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/invitations", org_id))
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

    let invitations = json["invitations"]
        .as_array()
        .expect("Should have invitations");
    assert_eq!(invitations.len(), 1);
}

#[tokio::test]
async fn test_delete_invitation() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register and create org
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

    // Create invitation
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/invitations", org_id))
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "email": "invite@example.com",
                        "role": "MEMBER"
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
    let invitation_id = json["invitation"]["id"].as_i64().unwrap();

    // Delete invitation
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/v1/organizations/{}/invitations/{}",
                    org_id, invitation_id
                ))
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify deletion
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/invitations", org_id))
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let invitations = json["invitations"].as_array().unwrap();
    assert_eq!(invitations.len(), 0);
}
