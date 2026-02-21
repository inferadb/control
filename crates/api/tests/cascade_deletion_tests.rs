#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration tests for cascade deletion completeness.
//!
//! Verifies that deleting a user, organization, or vault properly
//! cascades to all related entities (sessions, memberships, grants, etc.).

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{
    body_json, create_test_app, create_test_state, create_vault, get_org_id,
    invite_and_accept_member, register_user,
};
use serde_json::json;
use tower::ServiceExt;

// ============================================================================
// HTTP request helpers (return raw Response for status checking)
// ============================================================================

async fn get_json(app: &axum::Router, session: &str, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let json = body_json(response).await;
    (status, json)
}

async fn delete_request(
    app: &axum::Router,
    session: &str,
    uri: &str,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn post_json(
    app: &axum::Router,
    session: &str,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let json = body_json(response).await;
    (status, json)
}

// ============================================================================
// User Deletion Cascade Tests
// ============================================================================

#[tokio::test]
async fn test_delete_user_cascades_sessions() {
    let _ = IdGenerator::init(930);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "deluser1", "deluser1@example.com", "securepassword123").await;

    // Verify user has an active session
    let (status, json) = get_json(&app, &session, "/control/v1/users/sessions").await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["count"].as_u64().unwrap() >= 1, "Should have at least one session");

    // Must delete auto-created org first (delete_user blocks if sole owner)
    let org_id = get_org_id(&app, &session).await;
    let response =
        delete_request(&app, &session, &format!("/control/v1/organizations/{org_id}")).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Delete the user
    let response = delete_request(&app, &session, "/control/v1/users/me").await;
    assert_eq!(response.status(), StatusCode::OK);

    // Session should now be invalid — any authenticated request should fail
    let (status, _) = get_json(&app, &session, "/control/v1/users/sessions").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Session should be invalidated after user deletion"
    );
}

#[tokio::test]
async fn test_delete_user_cascades_memberships() {
    let _ = IdGenerator::init(931);
    let state = create_test_state();
    let app = create_test_app(state);

    // Create owner and a second user
    let owner_session =
        register_user(&app, "delowner2", "delowner2@example.com", "securepassword123").await;
    let member_session =
        register_user(&app, "delmember2", "delmember2@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &owner_session).await;

    // Capture member's auto-created org ID before they join another org
    let member_own_org_id = get_org_id(&app, &member_session).await;

    // Invite member to owner's org
    invite_and_accept_member(
        &app,
        &owner_session,
        &member_session,
        "delmember2@example.com",
        org_id,
    )
    .await;

    // Verify member is listed
    let (status, json) =
        get_json(&app, &owner_session, &format!("/control/v1/organizations/{org_id}/members"))
            .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        json["members"].as_array().unwrap().len() >= 2,
        "Should have at least 2 members (owner + invited)"
    );

    // Must delete the member's auto-created org before deleting the user
    let response = delete_request(
        &app,
        &member_session,
        &format!("/control/v1/organizations/{member_own_org_id}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Delete the member user
    let response = delete_request(&app, &member_session, "/control/v1/users/me").await;
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the member is removed from org members list
    let (status, json) =
        get_json(&app, &owner_session, &format!("/control/v1/organizations/{org_id}/members"))
            .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json["members"].as_array().unwrap().len(),
        1,
        "Only the owner should remain after member deletion"
    );
}

#[tokio::test]
async fn test_delete_user_allows_email_reregistration() {
    let _ = IdGenerator::init(932);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "delreuse3", "delreuse3@example.com", "securepassword123").await;

    // Must delete auto-created org first (delete_user blocks if sole owner)
    let org_id = get_org_id(&app, &session).await;
    let response =
        delete_request(&app, &session, &format!("/control/v1/organizations/{org_id}")).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Delete the user
    let response = delete_request(&app, &session, "/control/v1/users/me").await;
    assert_eq!(response.status(), StatusCode::OK);

    // Re-register with the same email should succeed
    let new_session =
        register_user(&app, "delreuse3new", "delreuse3@example.com", "securepassword123").await;

    // New session should work
    let (status, _) = get_json(&app, &new_session, "/control/v1/users/me").await;
    assert_eq!(status, StatusCode::OK, "New user with same email should be able to authenticate");
}

// ============================================================================
// Organization Deletion Cascade Tests
// ============================================================================

#[tokio::test]
async fn test_delete_organization_requires_no_active_vaults() {
    let _ = IdGenerator::init(933);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "delorgreq4", "delorgreq4@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &session).await;

    // Create a vault
    let _ = create_vault(&app, &session, org_id, "blocking-vault").await;

    // Try to delete org — should fail because of active vault
    let response =
        delete_request(&app, &session, &format!("/control/v1/organizations/{org_id}")).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Should reject deletion with active vaults"
    );
    let json = body_json(response).await;
    assert_eq!(json["code"].as_str().unwrap(), "VALIDATION_ERROR");
    assert!(json["error"].as_str().unwrap().contains("active vault"));
}

#[tokio::test]
async fn test_delete_organization_cascades_teams() {
    let _ = IdGenerator::init(934);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "delorgteam5", "delorgteam5@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &session).await;

    // Create a team
    let (status, _) = post_json(
        &app,
        &session,
        &format!("/control/v1/organizations/{org_id}/teams"),
        json!({"name": "test-team", "description": "A team"}),
    )
    .await;
    assert!(status.is_success(), "Team creation should succeed");

    // Verify team exists
    let (status, json) =
        get_json(&app, &session, &format!("/control/v1/organizations/{org_id}/teams")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!json["teams"].as_array().unwrap().is_empty(), "Should have a team");

    // Delete the organization
    let response =
        delete_request(&app, &session, &format!("/control/v1/organizations/{org_id}")).await;
    assert_eq!(response.status(), StatusCode::OK, "Org deletion should succeed");

    // Verify org is no longer accessible
    let (status, _) =
        get_json(&app, &session, &format!("/control/v1/organizations/{org_id}")).await;
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::FORBIDDEN,
        "Deleted org should not be accessible, got {status}"
    );

    // Verify the org no longer appears in the user's organization list
    let (status, json) = get_json(&app, &session, "/control/v1/organizations").await;
    assert_eq!(status, StatusCode::OK);
    let orgs = json["organizations"].as_array().unwrap();
    assert!(
        !orgs.iter().any(|o| o["id"].as_i64() == Some(org_id)),
        "Deleted org should not appear in user's org list"
    );
}

#[tokio::test]
async fn test_delete_organization_cascades_members_and_invitations() {
    let _ = IdGenerator::init(935);
    let state = create_test_state();
    let app = create_test_app(state);

    let owner_session =
        register_user(&app, "delorgmem6", "delorgmem6@example.com", "securepassword123").await;
    let member_session =
        register_user(&app, "delorgmem6b", "delorgmem6b@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &owner_session).await;

    // Invite and accept a member
    invite_and_accept_member(
        &app,
        &owner_session,
        &member_session,
        "delorgmem6b@example.com",
        org_id,
    )
    .await;

    // Create a pending invitation for another email
    let (status, _) = post_json(
        &app,
        &owner_session,
        &format!("/control/v1/organizations/{org_id}/invitations"),
        json!({"email": "pending@example.com", "role": "MEMBER"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Invitation creation should succeed");

    // Verify members and invitations exist
    let (_, json) =
        get_json(&app, &owner_session, &format!("/control/v1/organizations/{org_id}/members"))
            .await;
    assert!(json["members"].as_array().unwrap().len() >= 2);

    let (_, json) =
        get_json(&app, &owner_session, &format!("/control/v1/organizations/{org_id}/invitations"))
            .await;
    assert!(!json["invitations"].as_array().unwrap().is_empty());

    // Delete the organization
    let response =
        delete_request(&app, &owner_session, &format!("/control/v1/organizations/{org_id}")).await;
    assert_eq!(response.status(), StatusCode::OK, "Org deletion should succeed");

    // Verify org is gone
    let (status, _) =
        get_json(&app, &owner_session, &format!("/control/v1/organizations/{org_id}")).await;
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::FORBIDDEN,
        "Deleted org should not be accessible, got {status}"
    );

    // Verify the member's org list no longer includes the deleted org
    let (status, json) = get_json(&app, &member_session, "/control/v1/organizations").await;
    assert_eq!(status, StatusCode::OK);
    let member_orgs = json["organizations"].as_array().unwrap();
    assert!(
        !member_orgs.iter().any(|o| o["id"].as_i64() == Some(org_id)),
        "Deleted org should not appear in member's org list"
    );
}

// ============================================================================
// Vault Deletion Cascade Tests
// ============================================================================

#[tokio::test]
async fn test_delete_vault_cascades_user_grants() {
    let _ = IdGenerator::init(936);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "delvaultug7", "delvaultug7@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &session).await;
    let (vault_id, _) = create_vault(&app, &session, org_id, "grant-vault").await;

    // Owner automatically gets a user grant; verify it exists
    let (status, json) = get_json(
        &app,
        &session,
        &format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/user-grants"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !json["grants"].as_array().unwrap().is_empty(),
        "Should have at least the owner's grant"
    );

    // Delete the vault
    let response = delete_request(
        &app,
        &session,
        &format!("/control/v1/organizations/{org_id}/vaults/{vault_id}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify vault is no longer accessible
    let (status, _) =
        get_json(&app, &session, &format!("/control/v1/organizations/{org_id}/vaults/{vault_id}"))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "Deleted vault should return 404");
}

#[tokio::test]
async fn test_delete_vault_cascades_team_grants() {
    let _ = IdGenerator::init(937);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "delvaulttg8", "delvaulttg8@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &session).await;
    let (vault_id, _) = create_vault(&app, &session, org_id, "team-grant-vault").await;

    // Create a team
    let (status, team_json) = post_json(
        &app,
        &session,
        &format!("/control/v1/organizations/{org_id}/teams"),
        json!({"name": "grant-team", "description": "Team for grant test"}),
    )
    .await;
    assert!(status.is_success(), "Team creation should succeed");
    let team_id = team_json["team"]["id"].as_i64().unwrap();

    // Grant the team access to the vault
    let (status, _) = post_json(
        &app,
        &session,
        &format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/team-grants"),
        json!({"team_id": team_id, "role": "reader"}),
    )
    .await;
    assert!(status.is_success(), "Team grant creation should succeed, got {status}");

    // Verify team grant exists
    let (status, json) = get_json(
        &app,
        &session,
        &format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/team-grants"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!json["grants"].as_array().unwrap().is_empty(), "Should have a team grant");

    // Delete the vault
    let response = delete_request(
        &app,
        &session,
        &format!("/control/v1/organizations/{org_id}/vaults/{vault_id}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Vault is gone — can't query its grants
    let (status, _) =
        get_json(&app, &session, &format!("/control/v1/organizations/{org_id}/vaults/{vault_id}"))
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "Deleted vault should return 404");
}

#[tokio::test]
async fn test_delete_user_blocked_when_sole_owner() {
    let _ = IdGenerator::init(938);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "delsoleowner9", "delsoleowner9@example.com", "securepassword123")
            .await;

    // User is the sole owner of the auto-created org — deletion should be blocked
    let response = delete_request(&app, &session, "/control/v1/users/me").await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Should block deletion when user is sole org owner"
    );
    let json = body_json(response).await;
    assert_eq!(json["code"].as_str().unwrap(), "VALIDATION_ERROR");
    assert!(
        json["error"].as_str().unwrap().contains("only owner"),
        "Error should mention sole ownership"
    );
}
