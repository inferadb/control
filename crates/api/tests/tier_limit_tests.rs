#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration tests for organization tier limit enforcement.
//!
//! Verifies that the Dev tier limits are enforced for vaults (5) and teams (3),
//! returning HTTP 402 with `TIER_LIMIT_EXCEEDED` error code when exceeded.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{
    body_json, create_test_app, create_test_state, create_vault, get_org_id, register_user,
};
use serde_json::json;
use tower::ServiceExt;

/// Helper to create a team in an organization and return the raw response
async fn create_team_request(
    app: &axum::Router,
    session: &str,
    org_id: i64,
    name: &str,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": name,
                        "description": "Test team"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper to create a vault and return the raw response (for checking error status)
async fn create_vault_request(
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

/// Helper to soft-delete a team
async fn delete_team_request(
    app: &axum::Router,
    session: &str,
    org_id: i64,
    team_id: i64,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper to soft-delete a vault
async fn delete_vault_request(
    app: &axum::Router,
    session: &str,
    org_id: i64,
    vault_id: i64,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn test_vault_tier_limit_enforced() {
    let _ = IdGenerator::init(920);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "tiervaultuser", "tiervault@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &session).await;

    // Dev tier allows 5 vaults — create all 5
    for i in 1..=5 {
        let (..) = create_vault(&app, &session, org_id, &format!("vault-{i}")).await;
    }

    // 6th vault should be rejected with 402
    let response = create_vault_request(&app, &session, org_id, "vault-6").await;
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);

    let json = body_json(response).await;
    assert_eq!(json["code"].as_str().unwrap(), "TIER_LIMIT_EXCEEDED");
    assert!(json["error"].as_str().unwrap().contains("Vault limit reached"));
}

#[tokio::test]
async fn test_team_tier_limit_enforced() {
    let _ = IdGenerator::init(921);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "tierteamuser", "tierteam@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &session).await;

    // Dev tier allows 3 teams — create all 3
    for i in 1..=3 {
        let response = create_team_request(&app, &session, org_id, &format!("team-{i}")).await;
        assert!(
            response.status().is_success(),
            "Team {i} creation should succeed, got {}",
            response.status()
        );
    }

    // 4th team should be rejected with 402
    let response = create_team_request(&app, &session, org_id, "team-4").await;
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);

    let json = body_json(response).await;
    assert_eq!(json["code"].as_str().unwrap(), "TIER_LIMIT_EXCEEDED");
    assert!(json["error"].as_str().unwrap().contains("Team limit reached"));
}

#[tokio::test]
async fn test_soft_deleted_vaults_dont_count_against_limit() {
    let _ = IdGenerator::init(922);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "tiersoftdeluser", "tiersoftdel@example.com", "securepassword123")
            .await;
    let org_id = get_org_id(&app, &session).await;

    // Create 5 vaults (at the limit)
    let mut vault_ids = Vec::new();
    for i in 1..=5 {
        let (vault_id, _) = create_vault(&app, &session, org_id, &format!("vault-{i}")).await;
        vault_ids.push(vault_id);
    }

    // Confirm we're at the limit
    let response = create_vault_request(&app, &session, org_id, "vault-over-limit").await;
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);

    // Delete one vault
    let response = delete_vault_request(&app, &session, org_id, vault_ids[0]).await;
    assert!(response.status().is_success(), "Vault deletion should succeed");

    // Now we should be able to create a new vault (4 active + 1 deleted = under limit)
    let response = create_vault_request(&app, &session, org_id, "vault-replacement").await;
    assert!(
        response.status().is_success(),
        "Creating vault after deletion should succeed, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_soft_deleted_teams_dont_count_against_limit() {
    let _ = IdGenerator::init(924);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "tierteamdeluser", "tierteamdel@example.com", "securepassword123")
            .await;
    let org_id = get_org_id(&app, &session).await;

    // Create 3 teams (at the limit)
    let mut team_ids = Vec::new();
    for i in 1..=3 {
        let response = create_team_request(&app, &session, org_id, &format!("team-{i}")).await;
        assert!(response.status().is_success(), "Team {i} creation should succeed");
        let json = body_json(response).await;
        team_ids.push(json["team"]["id"].as_i64().expect("Should have team ID"));
    }

    // Confirm we're at the limit
    let response = create_team_request(&app, &session, org_id, "team-over-limit").await;
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);

    // Delete one team
    let response = delete_team_request(&app, &session, org_id, team_ids[0]).await;
    assert!(response.status().is_success(), "Team deletion should succeed");

    // Now we should be able to create a new team (2 active + 1 deleted = under limit)
    let response = create_team_request(&app, &session, org_id, "team-replacement").await;
    assert!(
        response.status().is_success(),
        "Creating team after deletion should succeed, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_tier_limit_error_response_format() {
    let _ = IdGenerator::init(925);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "tierfmtuser", "tierfmt@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &session).await;

    // Fill up vault limit
    for i in 1..=5 {
        let (..) = create_vault(&app, &session, org_id, &format!("vault-{i}")).await;
    }

    // Verify error response structure
    let response = create_vault_request(&app, &session, org_id, "vault-overflow").await;
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);

    let json = body_json(response).await;

    // Verify all expected fields are present
    assert!(json["error"].is_string(), "Response should have 'error' field");
    assert_eq!(json["code"].as_str().unwrap(), "TIER_LIMIT_EXCEEDED");

    // Verify the error message includes the tier and maximum
    let error_msg = json["error"].as_str().unwrap();
    assert!(error_msg.contains("Maximum:"), "Error should include the maximum limit");
}
