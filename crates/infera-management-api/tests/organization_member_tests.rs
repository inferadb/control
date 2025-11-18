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
async fn test_list_organization_members() {
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

    // List members
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/members", org_id))
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

    let members = json["members"].as_array().expect("Should have members");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["role"], "OWNER");
}

#[tokio::test]
async fn test_update_member_role() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register owner user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "owner",
                        "email": "owner@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let owner_session =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Get owner user ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/users/me")
                .header("cookie", format!("infera_session={}", owner_session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let _owner_id = json["user"]["id"].as_i64().unwrap();

    // Create an organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", owner_session))
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
                        "name": "member",
                        "email": "member@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let member_session =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Get member user ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/users/me")
                .header("cookie", format!("infera_session={}", member_session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let member_user_id = json["user"]["id"].as_i64().unwrap();

    // Manually add member to organization (using internal API for test)
    use infera_management_core::{
        OrganizationMember, OrganizationMemberRepository, OrganizationRole,
    };
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    let new_member_id = IdGenerator::next_id();
    let new_member = OrganizationMember::new(
        new_member_id,
        org_id,
        member_user_id,
        OrganizationRole::Member,
    );
    member_repo.create(new_member).await.unwrap();

    // List members to get member ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/members", org_id))
                .header("cookie", format!("infera_session={}", owner_session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let members = json["members"].as_array().expect("Should have members");
    let member_to_update = members
        .iter()
        .find(|m| m["user_id"] == member_user_id)
        .unwrap();
    let member_id = member_to_update["id"].as_i64().unwrap();

    // Update member role to ADMIN
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/v1/organizations/{}/members/{}",
                    org_id, member_id
                ))
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", owner_session))
                .body(Body::from(
                    json!({
                        "role": "ADMIN"
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

    assert_eq!(json["member"]["role"], "ADMIN");
}

#[tokio::test]
async fn test_cannot_demote_last_owner() {
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
                        "name": "owner",
                        "email": "owner@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session = extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Create an organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session))
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

    // List members to get owner member ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/members", org_id))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let members = json["members"].as_array().expect("Should have members");
    let member_id = members[0]["id"].as_i64().unwrap();

    // Try to demote the only owner
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/v1/organizations/{}/members/{}",
                    org_id, member_id
                ))
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session))
                .body(Body::from(
                    json!({
                        "role": "ADMIN"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_remove_member() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register owner
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "owner",
                        "email": "owner@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let owner_session =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Create organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", owner_session))
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
                        "name": "member",
                        "email": "member@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let member_session =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Get member user ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/users/me")
                .header("cookie", format!("infera_session={}", member_session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let member_user_id = json["user"]["id"].as_i64().unwrap();

    // Manually add member
    use infera_management_core::{
        OrganizationMember, OrganizationMemberRepository, OrganizationRole,
    };
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    let new_member_id = IdGenerator::next_id();
    let new_member = OrganizationMember::new(
        new_member_id,
        org_id,
        member_user_id,
        OrganizationRole::Member,
    );
    member_repo.create(new_member).await.unwrap();

    // List members to get member ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/members", org_id))
                .header("cookie", format!("infera_session={}", owner_session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let members = json["members"].as_array().expect("Should have members");
    let member_to_remove = members
        .iter()
        .find(|m| m["user_id"] == member_user_id)
        .unwrap();
    let member_id = member_to_remove["id"].as_i64().unwrap();

    // Remove member
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/v1/organizations/{}/members/{}",
                    org_id, member_id
                ))
                .header("cookie", format!("infera_session={}", owner_session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify member was removed
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/members", org_id))
                .header("cookie", format!("infera_session={}", owner_session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let members = json["members"].as_array().expect("Should have members");
    assert_eq!(members.len(), 1); // Only owner remains
}

#[tokio::test]
async fn test_cannot_remove_last_owner() {
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
                        "name": "owner",
                        "email": "owner@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session = extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Create organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session))
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

    // List members to get owner member ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/members", org_id))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let members = json["members"].as_array().expect("Should have members");
    let member_id = members[0]["id"].as_i64().unwrap();

    // Try to remove the only owner
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/v1/organizations/{}/members/{}",
                    org_id, member_id
                ))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
