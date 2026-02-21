#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for engine-internal endpoints.
//!
//! Tests the `GET /control/v1/vaults/{vault}` endpoint which is designed
//! for engine-to-control lookups without requiring organization membership.
//!
//! Note: `get_organization_by_id` exists as a handler but is not currently
//! routed — only the vault endpoint is testable via HTTP.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_test_fixtures::{
    body_json, create_test_app, create_test_state, create_vault, get_org_id, register_user,
};
use tower::ServiceExt;

#[tokio::test]
async fn test_get_vault_by_id_returns_correct_data() {
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "EngineUser", "engine-vault@test.com", "test-password-123456").await;
    let org_id = get_org_id(&app, &session).await;
    let (vault_id, _) = create_vault(&app, &session, org_id, "engine-lookup-vault").await;

    // Use the engine-internal endpoint to get vault by ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/vaults/{vault_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;

    assert_eq!(json["id"].as_i64().unwrap(), vault_id);
    assert_eq!(json["name"].as_str().unwrap(), "engine-lookup-vault");
    assert_eq!(json["description"].as_str().unwrap(), "Test vault");
    assert_eq!(json["organization_id"].as_i64().unwrap(), org_id);
    assert!(json["created_at"].as_str().is_some());
    assert!(json["updated_at"].as_str().is_some());
    assert!(json["deleted_at"].is_null(), "Active vault should have null deleted_at");
}

#[tokio::test]
async fn test_get_vault_by_id_nonexistent_returns_404() {
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "EngineUser404", "engine-404@test.com", "test-password-123456").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/vaults/999999")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND, "Nonexistent vault should return 404");
}

#[tokio::test]
async fn test_get_vault_by_id_deleted_vault_returns_404() {
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "EngineDelVault", "engine-del-vault@test.com", "test-password-123456")
            .await;
    let org_id = get_org_id(&app, &session).await;
    let (vault_id, _) = create_vault(&app, &session, org_id, "engine-delete-vault").await;

    // Delete the vault via the organization-scoped endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status().is_success(), "Vault deletion should succeed");

    // Engine-internal endpoint should return 404 for deleted vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/vaults/{vault_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "Deleted vault should return 404 via engine endpoint"
    );
}

#[tokio::test]
async fn test_get_vault_by_id_requires_authentication() {
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "EngineAuthUser", "engine-auth@test.com", "test-password-123456").await;
    let org_id = get_org_id(&app, &session).await;
    let (vault_id, _) = create_vault(&app, &session, org_id, "engine-auth-vault").await;

    // Request without session cookie — should be rejected
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/vaults/{vault_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Unauthenticated request should return 401"
    );
}

#[tokio::test]
async fn test_get_vault_by_id_accessible_without_org_membership() {
    let state = create_test_state();
    let app = create_test_app(state);

    // User A creates the vault
    let session_a =
        register_user(&app, "VaultOwner", "vault-owner@test.com", "test-password-123456").await;
    let org_id = get_org_id(&app, &session_a).await;
    let (vault_id, _) = create_vault(&app, &session_a, org_id, "cross-user-vault").await;

    // User B (not a member of User A's org) can still access via engine endpoint.
    // This is by design: this endpoint serves engine-to-control lookups where the
    // engine authenticates with a session/JWT and needs to resolve vault metadata
    // without being a member of the vault's organization.
    let session_b =
        register_user(&app, "OtherUser", "other-user@test.com", "test-password-123456").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/vaults/{vault_id}"))
                .header("cookie", format!("infera_session={session_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // This endpoint does NOT require org membership — it's designed for engine lookups
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Non-member should be able to access vault via engine endpoint"
    );
    let json = body_json(response).await;
    assert_eq!(json["id"].as_i64().unwrap(), vault_id);
    assert_eq!(json["name"].as_str().unwrap(), "cross-user-vault");
}
