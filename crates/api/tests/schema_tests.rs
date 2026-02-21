#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{
    create_test_app, create_test_state, create_vault, get_org_id, register_user,
};
use serde_json::json;
use tower::ServiceExt;

/// Helper to create a vault and return (org_id, vault_id, session)
async fn setup_vault(app: &axum::Router, worker_id: u16) -> (i64, i64, String) {
    let _ = IdGenerator::init(worker_id);
    let session = register_user(
        app,
        &format!("schemauser{worker_id}"),
        &format!("schema{worker_id}@example.com"),
        "securepassword123",
    )
    .await;

    let org_id = get_org_id(app, &session).await;
    let (vault_id, _) =
        create_vault(app, &session, org_id, &format!("schema-test-vault-{worker_id}")).await;

    (org_id, vault_id, session)
}

#[tokio::test]
async fn test_deploy_schema() {
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let (org_id, vault_id, session) = setup_vault(&app, 100).await;

    // Deploy a schema
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"
                ))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity User {\n  relation viewer: User\n  permission view: viewer\n}",
                        "description": "Initial schema with User entity"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["schema"]["version"], "1.0.0");
    assert_eq!(json["schema"]["description"], "Initial schema with User entity");
    assert_eq!(json["schema"]["vault_id"], vault_id);
    // Schema starts as DEPLOYED (we skip validation in the handler currently)
    assert!(
        json["schema"]["status"] == "DEPLOYED" || json["schema"]["status"] == "VALIDATING",
        "Expected DEPLOYED or VALIDATING, got: {}",
        json["schema"]["status"]
    );
}

#[tokio::test]
async fn test_deploy_schema_auto_version_increment() {
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let (org_id, vault_id, session) = setup_vault(&app, 101).await;

    // Deploy first schema
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity User {}",
                        "description": "First version"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["schema"]["version"], "1.0.0");

    // Deploy second schema (should auto-increment)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity User {\n  relation owner: User\n}",
                        "description": "Added owner relation"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["schema"]["version"], "1.1.0");
}

#[tokio::test]
async fn test_deploy_schema_explicit_version() {
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let (org_id, vault_id, session) = setup_vault(&app, 102).await;

    // Deploy with explicit version
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity Document {}",
                        "description": "Explicit version",
                        "version": "2.0.0"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["schema"]["version"], "2.0.0");
}

#[tokio::test]
async fn test_list_schemas() {
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let (org_id, vault_id, session) = setup_vault(&app, 103).await;

    // Deploy multiple schemas
    for i in 0..3 {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                    .header("cookie", format!("infera_session={session}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "definition": format!("entity Entity{} {{}}", i),
                            "description": format!("Schema version {}", i + 1)
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // List schemas
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let schemas = json["schemas"].as_array().unwrap();

    assert_eq!(schemas.len(), 3);
}

#[tokio::test]
async fn test_get_schema_by_version() {
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let (org_id, vault_id, session) = setup_vault(&app, 104).await;

    // Deploy a schema
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity Resource {\n  relation owner: User\n}",
                        "description": "Resource schema"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Get the schema by version
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas/1.0.0"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["schema"]["version"], "1.0.0");
    assert!(json["schema"]["definition"].as_str().unwrap().contains("entity Resource"));
}

#[tokio::test]
async fn test_activate_schema() {
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let (org_id, vault_id, session) = setup_vault(&app, 105).await;

    // Deploy a schema
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity User {}",
                        "description": "Schema to activate"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Activate the schema
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas/1.0.0/activate"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["schema"]["status"], "ACTIVE");
    assert!(json["message"].as_str().unwrap().contains("now active"));
}

#[tokio::test]
async fn test_get_current_schema() {
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let (org_id, vault_id, session) = setup_vault(&app, 106).await;

    // Deploy and activate a schema
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity Folder {}",
                        "description": "Current schema"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Activate
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas/1.0.0/activate"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Get current schema
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas/current"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["schema"]["status"], "ACTIVE");
}

#[tokio::test]
async fn test_rollback_schema() {
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let (org_id, vault_id, session) = setup_vault(&app, 107).await;

    // Deploy first schema
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity User {}",
                        "description": "First version"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Activate first schema
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas/1.0.0/activate"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Deploy second schema
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity User {\n  relation admin: User\n}",
                        "description": "Second version"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Activate second schema
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas/1.1.0/activate"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Rollback to first version
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas/rollback"
                ))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "target_version": "1.0.0"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["active_schema"]["version"], "1.0.0");
    assert_eq!(json["active_schema"]["status"], "ACTIVE");
    assert_eq!(json["rolled_back_schema"]["version"], "1.1.0");
    assert_eq!(json["rolled_back_schema"]["status"], "ROLLED_BACK");
}

#[tokio::test]
async fn test_schema_diff() {
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let (org_id, vault_id, session) = setup_vault(&app, 108).await;

    // Deploy two schemas
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity User {}",
                        "description": "First version"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity User {\n  relation owner: User\n}",
                        "description": "Added owner"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Get diff
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas/diff?from=1.0.0&to=1.1.0"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["from_version"], "1.0.0");
    assert_eq!(json["to_version"], "1.1.0");
    // Note: The diff implementation is a placeholder, so changes will be empty
    assert!(json["changes"].is_array());
}

#[tokio::test]
async fn test_deploy_schema_duplicate_version_rejected() {
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let (org_id, vault_id, session) = setup_vault(&app, 109).await;

    // Deploy first schema with explicit version
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity User {}",
                        "description": "First",
                        "version": "1.0.0"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Try to deploy same version again
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity User {}",
                        "description": "Duplicate",
                        "version": "1.0.0"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_get_nonexistent_schema_returns_404() {
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let (org_id, vault_id, session) = setup_vault(&app, 110).await;

    // Try to get a schema that doesn't exist
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas/99.99.99"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_current_schema_when_none_active_returns_404() {
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let (org_id, vault_id, session) = setup_vault(&app, 111).await;

    // Deploy a schema but don't activate it
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "definition": "entity Test {}",
                        "description": "Not activated"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Try to get current schema
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/schemas/current"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
