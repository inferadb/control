#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration tests for organization suspend/resume functionality.
//!
//! Tests the full middleware stack through `create_test_app()`, covering:
//! - Owner suspend/resume lifecycle
//! - Non-owner suspend/resume authorization
//! - Resource access blocking while suspended
//! - Post-resume resource accessibility

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{
    create_test_app, create_test_state, get_org_id, invite_and_accept_member, register_user,
};
use serde_json::json;
use tower::ServiceExt;

/// Helper to suspend an organization
async fn suspend_org(app: &axum::Router, session: &str, org_id: i64) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/suspend"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper to resume an organization
async fn resume_org(app: &axum::Router, session: &str, org_id: i64) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/resume"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper to list vaults in an organization
async fn list_vaults(app: &axum::Router, session: &str, org_id: i64) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/vaults"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper to create a vault in an organization
async fn create_vault(
    app: &axum::Router,
    session: &str,
    org_id: i64,
    name: &str,
) -> axum::http::Response<Body> {
    app.clone()
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
        .unwrap()
}

#[tokio::test]
async fn test_owner_suspends_organization() {
    let _ = IdGenerator::init(900);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let owner_session =
        register_user(&app, "suspowner", "suspowner@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &owner_session).await;

    // Suspend the organization
    let response = suspend_org(&app, &owner_session, org_id).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["message"], "Organization suspended successfully");
}

#[tokio::test]
async fn test_non_owner_cannot_suspend_organization() {
    let _ = IdGenerator::init(901);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register owner and member
    let owner_session =
        register_user(&app, "suspowner2", "suspowner2@example.com", "securepassword123").await;
    let member_session =
        register_user(&app, "suspmember", "suspmember@example.com", "securepassword123").await;

    let org_id = get_org_id(&app, &owner_session).await;

    // Add member to organization via invitation flow
    invite_and_accept_member(
        &app,
        &owner_session,
        &member_session,
        "suspmember@example.com",
        org_id,
    )
    .await;

    // Member attempts to suspend — should fail with 403
    let response = suspend_org(&app, &member_session, org_id).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"].as_str().unwrap().contains("Owner role required"),
        "Error should indicate owner role is required, got: {}",
        json["error"]
    );
}

#[tokio::test]
async fn test_suspended_org_blocks_resource_access() {
    let _ = IdGenerator::init(902);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let owner_session =
        register_user(&app, "suspowner3", "suspowner3@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &owner_session).await;

    // Create a vault before suspension
    let response = create_vault(&app, &owner_session, org_id, "pre-suspend-vault").await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // Suspend the organization
    let response = suspend_org(&app, &owner_session, org_id).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Attempt to list vaults while suspended — should be blocked
    let response = list_vaults(&app, &owner_session, org_id).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"].as_str().unwrap().contains("suspended"),
        "Error should mention suspension, got: {}",
        json["error"]
    );

    // Attempt to create a vault while suspended — should be blocked
    let response = create_vault(&app, &owner_session, org_id, "during-suspend-vault").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Attempt to list teams while suspended — should be blocked
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={owner_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_owner_resumes_organization() {
    let _ = IdGenerator::init(903);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let owner_session =
        register_user(&app, "suspowner4", "suspowner4@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &owner_session).await;

    // Suspend the organization
    let response = suspend_org(&app, &owner_session, org_id).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Resume the organization
    let response = resume_org(&app, &owner_session, org_id).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["message"], "Organization resumed successfully");
}

#[tokio::test]
async fn test_post_resume_resources_accessible() {
    let _ = IdGenerator::init(904);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let owner_session =
        register_user(&app, "suspowner5", "suspowner5@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &owner_session).await;

    // Create a vault before suspension
    let response = create_vault(&app, &owner_session, org_id, "survive-suspend-vault").await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // Suspend
    let response = suspend_org(&app, &owner_session, org_id).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Verify access is blocked
    let response = list_vaults(&app, &owner_session, org_id).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Resume
    let response = resume_org(&app, &owner_session, org_id).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Verify access is restored — list vaults should work and show the pre-suspension vault
    let response = list_vaults(&app, &owner_session, org_id).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let vaults = json["vaults"].as_array().expect("Should have vaults array");
    assert!(!vaults.is_empty(), "Pre-suspension vault should still exist after resume");

    // Create a new vault post-resume — should succeed
    let response = create_vault(&app, &owner_session, org_id, "post-resume-vault").await;
    assert_eq!(response.status(), StatusCode::CREATED);
}
