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

/// Helper to register a user and get session cookie
async fn register_user(app: &axum::Router, name: &str, email: &str, password: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
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

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Registration should succeed"
    );
    extract_session_cookie(response.headers()).expect("Session cookie should be set")
}

#[tokio::test]
async fn test_create_team() {
    let _ = IdGenerator::init(10);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "teamowner", "team@example.com", "securepassword123").await;

    // Get organization ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/organizations")
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
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/teams", org_id))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "engineering",
                        "description": "Engineering team"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["team"]["name"], "engineering");
    assert_eq!(json["team"]["description"], "Engineering team");
}

#[tokio::test]
async fn test_list_teams() {
    let _ = IdGenerator::init(11);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(
        &app,
        "multiteam",
        "multiteam@example.com",
        "securepassword123",
    )
    .await;

    // Get organization ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/organizations")
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
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

    // Create multiple teams
    for (name, desc) in [
        ("backend", "Backend team"),
        ("frontend", "Frontend team"),
        ("devops", "DevOps team"),
    ] {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/organizations/{}/teams", org_id))
                    .header("cookie", format!("infera_session={}", session))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": name,
                            "description": desc
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // List teams
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/teams", org_id))
                .header("cookie", format!("infera_session={}", session))
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
    let teams = json["teams"].as_array().expect("Should have teams");

    assert_eq!(teams.len(), 3);
}

#[tokio::test]
async fn test_add_team_member() {
    let _ = IdGenerator::init(12);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let owner_session = register_user(
        &app,
        "teamowner2",
        "teamowner2@example.com",
        "securepassword123",
    )
    .await;
    let member_session = register_user(
        &app,
        "teammember",
        "teammember@example.com",
        "securepassword123",
    )
    .await;

    // Get owner's organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/organizations")
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
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

    // Get member's user ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/auth/me")
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

    // Add member to organization
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/members", org_id))
                .header("cookie", format!("infera_session={}", owner_session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "user_id": member_user_id,
                        "role": "MEMBER"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/teams", org_id))
                .header("cookie", format!("infera_session={}", owner_session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "security",
                        "description": "Security team"
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
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Add member to team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/organizations/{}/teams/{}/members",
                    org_id, team_id
                ))
                .header("cookie", format!("infera_session={}", owner_session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "user_id": member_user_id,
                        "is_manager": false
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["member"]["is_manager"], false);
}

#[tokio::test]
async fn test_grant_team_permission() {
    let _ = IdGenerator::init(13);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "permowner", "perm@example.com", "securepassword123").await;

    // Get organization ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/organizations")
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
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/teams", org_id))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "admins",
                        "description": "Admin team"
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
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Grant permission
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/organizations/{}/teams/{}/permissions",
                    org_id, team_id
                ))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "permission": "ORG_PERM_VAULT_CREATE"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["permission"]["permission"], "ORG_PERM_VAULT_CREATE");
}

#[tokio::test]
async fn test_grant_team_vault_access() {
    let _ = IdGenerator::init(14);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(
        &app,
        "teamvault",
        "teamvault@example.com",
        "securepassword123",
    )
    .await;

    // Get organization ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/organizations")
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
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/teams", org_id))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "data-team",
                        "description": "Data team"
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
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Create vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/vaults", org_id))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "team-vault",
                        "description": "Team vault"
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
    let vault_id = json["vault"]["id"].as_i64().unwrap();

    // Grant team access to vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/organizations/{}/vaults/{}/team-grants",
                    org_id, vault_id
                ))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "team_id": team_id,
                        "role": "WRITER"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["grant"]["role"], "WRITER");
}
