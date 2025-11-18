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
async fn test_create_vault() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register user and get session
    let session = register_user(&app, "vaultowner", "vault@example.com", "securepassword123").await;

    // Get the default organization ID
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
    let org_id = json["organizations"][0]["id"]
        .as_str()
        .expect("Should have org ID");

    // Create a vault
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
                        "name": "production-policies",
                        "description": "Production environment policies"
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

    assert_eq!(json["vault"]["name"], "production-policies");
    assert_eq!(
        json["vault"]["description"],
        "Production environment policies"
    );
    assert_eq!(json["vault"]["sync_status"], "PENDING");
}

#[tokio::test]
async fn test_list_vaults() {
    let _ = IdGenerator::init(2);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "multivaul", "multi@example.com", "securepassword123").await;

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

    // Create multiple vaults
    for (name, desc) in [
        ("vault-dev", "Development environment"),
        ("vault-staging", "Staging environment"),
        ("vault-prod", "Production environment"),
    ] {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/organizations/{}/vaults", org_id))
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

    // List vaults
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/vaults", org_id))
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
    let vaults = json["vaults"].as_array().expect("Should have vaults");

    assert_eq!(vaults.len(), 3);
}

#[tokio::test]
async fn test_update_vault() {
    let _ = IdGenerator::init(3);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "updater", "update@example.com", "securepassword123").await;

    // Get organization ID and create vault
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
                        "name": "original-name",
                        "description": "Original description"
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

    // Update vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/organizations/{}/vaults/{}", org_id, vault_id))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "updated-name",
                        "description": "Updated description"
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

    assert_eq!(json["vault"]["name"], "updated-name");
    assert_eq!(json["vault"]["description"], "Updated description");
}

#[tokio::test]
async fn test_delete_vault() {
    let _ = IdGenerator::init(4);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "deleter", "delete@example.com", "securepassword123").await;

    // Get organization ID and create vault
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
                        "name": "temp-vault",
                        "description": "Temporary vault"
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

    // Delete vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/organizations/{}/vaults/{}", org_id, vault_id))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify vault is deleted
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/vaults/{}", org_id, vault_id))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_grant_user_vault_access() {
    let _ = IdGenerator::init(5);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Create owner and member users
    let owner_session = register_user(
        &app,
        "vaultowner2",
        "owner2@example.com",
        "securepassword123",
    )
    .await;
    let member_session = register_user(
        &app,
        "vaultmember",
        "member@example.com",
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

    // Add member to organization first
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

    // Create a vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/vaults", org_id))
                .header("cookie", format!("infera_session={}", owner_session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "shared-vault",
                        "description": "Shared vault"
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

    // Grant user access to vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/organizations/{}/vaults/{}/user-grants",
                    org_id, vault_id
                ))
                .header("cookie", format!("infera_session={}", owner_session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "user_id": member_user_id,
                        "role": "READER"
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

    assert_eq!(json["grant"]["role"], "READER");
}

#[tokio::test]
async fn test_revoke_user_vault_access() {
    let _ = IdGenerator::init(6);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let owner_session = register_user(
        &app,
        "vaultowner3",
        "owner3@example.com",
        "securepassword123",
    )
    .await;
    let member_session = register_user(
        &app,
        "vaultmember2",
        "member2@example.com",
        "securepassword123",
    )
    .await;

    // Get organization and member user ID
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

    // Create vault and grant access
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/vaults", org_id))
                .header("cookie", format!("infera_session={}", owner_session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "test-vault",
                        "description": "Test vault"
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

    // Grant access
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/organizations/{}/vaults/{}/user-grants",
                    org_id, vault_id
                ))
                .header("cookie", format!("infera_session={}", owner_session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "user_id": member_user_id,
                        "role": "READER"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Revoke access
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/v1/organizations/{}/vaults/{}/user-grants/{}",
                    org_id, vault_id, member_user_id
                ))
                .header("cookie", format!("infera_session={}", owner_session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
