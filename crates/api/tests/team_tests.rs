#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{
    body_json, create_test_app, create_test_state, get_org_id, invite_and_accept_member,
    register_user,
};
use serde_json::json;
use tower::ServiceExt;

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
                .uri("/control/v1/organizations")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={session}"))
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["team"]["name"], "engineering");
    assert_eq!(json["team"]["description"], "Engineering team");
}

#[tokio::test]
async fn test_list_teams() {
    let _ = IdGenerator::init(11);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "multiteam", "multiteam@example.com", "securepassword123").await;

    // Get organization ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/organizations")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

    // Create multiple teams
    for (name, desc) in
        [("backend", "Backend team"), ("frontend", "Frontend team"), ("devops", "DevOps team")]
    {
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
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let teams = json["teams"].as_array().expect("Should have teams");

    assert_eq!(teams.len(), 3);
}

#[tokio::test]
async fn test_add_team_member() {
    let _ = IdGenerator::init(12);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let owner_session =
        register_user(&app, "teamowner2", "teamowner2@example.com", "securepassword123").await;
    let member_session =
        register_user(&app, "teammember", "teammember@example.com", "securepassword123").await;

    // Get owner's organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/organizations")
                .header("cookie", format!("infera_session={owner_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

    // Get member's user email (for invitation)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/auth/me")
                .header("cookie", format!("infera_session={member_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let member_user_id = json["user"]["id"].as_i64().unwrap();

    // Invite member to organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/invitations"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": "teammember@example.com",
                        "role": "MEMBER"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let invitation_token = json["invitation"]["token"].as_str().unwrap().to_string();

    // Accept invitation as member
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/organizations/invitations/accept")
                .header("cookie", format!("infera_session={member_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "token": invitation_token
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
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={owner_session}"))
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Add member to team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/members"))
                .header("cookie", format!("infera_session={owner_session}"))
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

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8_lossy(&body);

    if status != StatusCode::CREATED {
        eprintln!("Response status: {status}");
        eprintln!("Response body: {body_str}");
    }

    assert_eq!(status, StatusCode::CREATED);

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
                .uri("/control/v1/organizations")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={session}"))
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Grant permission
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/permissions"))
                .header("cookie", format!("infera_session={session}"))
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["permission"]["permission"], "ORG_PERM_VAULT_CREATE");
}

#[tokio::test]
async fn test_grant_team_vault_access() {
    let _ = IdGenerator::init(14);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "teamvault", "teamvault@example.com", "securepassword123").await;

    // Get organization ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/organizations")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={session}"))
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Create vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults"))
                .header("cookie", format!("infera_session={session}"))
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let vault_id = json["vault"]["id"].as_i64().unwrap();

    // Grant team access to vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/team-grants"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "team_id": team_id,
                        "role": "writer"
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

    assert_eq!(json["grant"]["role"], "writer");
}

#[tokio::test]
async fn test_get_team() {
    let _ = IdGenerator::init(1500);
    let state = create_test_state();
    let app = create_test_app(state);

    let session = register_user(&app, "getteam", "getteam@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &session).await;

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name": "platform", "description": "Platform team"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Get single team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["name"], "platform");
    assert_eq!(json["description"], "Platform team");
    assert_eq!(json["organization_id"], org_id);
    assert!(json["deleted_at"].is_null());
}

#[tokio::test]
async fn test_update_team() {
    let _ = IdGenerator::init(1501);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "updateteam", "updateteam@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &session).await;

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name": "old-name", "description": "Old description"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Update team name and description
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name": "new-name", "description": "New description"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["team"]["name"], "new-name");
    assert_eq!(json["team"]["description"], "New description");

    // Verify via GET
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["name"], "new-name");
    assert_eq!(json["description"], "New description");

    // Partial update: only name, description should remain unchanged
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"name": "partial-only"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["team"]["name"], "partial-only");
    assert_eq!(json["team"]["description"], "New description");
}

#[tokio::test]
async fn test_delete_team_with_cascade() {
    let _ = IdGenerator::init(1502);
    let state = create_test_state();
    let app = create_test_app(state);

    let session = register_user(&app, "delteam", "delteam@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &session).await;

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name": "doomed", "description": "To be deleted"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Grant a permission so we can verify cascade
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/permissions"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"permission": "ORG_PERM_VAULT_CREATE"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Delete team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert!(json["message"].as_str().unwrap().contains("deleted"));

    // GET should return 404 (soft-deleted)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Listing permissions on a soft-deleted team returns 404 (handler checks is_deleted)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/permissions"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Listing members on a soft-deleted team also returns 404
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/members"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_team_member_role() {
    let _ = IdGenerator::init(1503);
    let state = create_test_state();
    let app = create_test_app(state);

    let owner_session =
        register_user(&app, "roleowner", "roleowner@example.com", "securepassword123").await;
    let member_session =
        register_user(&app, "rolemember", "rolemember@example.com", "securepassword123").await;

    let org_id = get_org_id(&app, &owner_session).await;

    // Invite and accept member into org
    invite_and_accept_member(
        &app,
        &owner_session,
        &member_session,
        "rolemember@example.com",
        org_id,
    )
    .await;

    // Get member user ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/auth/me")
                .header("cookie", format!("infera_session={member_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let json = body_json(response).await;
    let member_user_id = json["user"]["id"].as_i64().unwrap();

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name": "role-test", "description": "Role test team"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Add member to team (not as manager)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/members"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"user_id": member_user_id, "is_manager": false}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let member_id = json["member"]["id"].as_i64().unwrap();
    assert!(!json["member"]["is_manager"].as_bool().unwrap());

    // Promote to manager
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/teams/{team_id}/members/{member_id}"
                ))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"manager": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert!(json["manager"].as_bool().unwrap());

    // Demote back to regular member
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/teams/{team_id}/members/{member_id}"
                ))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"manager": false}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert!(!json["manager"].as_bool().unwrap());
}

#[tokio::test]
async fn test_remove_team_member() {
    let _ = IdGenerator::init(1504);
    let state = create_test_state();
    let app = create_test_app(state);

    let owner_session =
        register_user(&app, "rmowner", "rmowner@example.com", "securepassword123").await;
    let member_session =
        register_user(&app, "rmmember", "rmmember@example.com", "securepassword123").await;

    let org_id = get_org_id(&app, &owner_session).await;

    // Invite and accept
    invite_and_accept_member(&app, &owner_session, &member_session, "rmmember@example.com", org_id)
        .await;

    // Get member user ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/auth/me")
                .header("cookie", format!("infera_session={member_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let json = body_json(response).await;
    let member_user_id = json["user"]["id"].as_i64().unwrap();

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name": "rm-team", "description": "Removal test"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Add member to team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/members"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"user_id": member_user_id, "is_manager": false}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let member_id = json["member"]["id"].as_i64().unwrap();

    // Remove member from team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/teams/{team_id}/members/{member_id}"
                ))
                .header("cookie", format!("infera_session={owner_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert!(json["message"].as_str().unwrap().contains("removed"));

    // Verify member list is now empty
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/members"))
                .header("cookie", format!("infera_session={owner_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let members = json["members"].as_array().unwrap();
    assert!(members.is_empty(), "Member list should be empty after removal");
}

#[tokio::test]
async fn test_revoke_team_permission() {
    let _ = IdGenerator::init(1505);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "revokeperm", "revokeperm@example.com", "securepassword123").await;
    let org_id = get_org_id(&app, &session).await;

    // Create team
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name": "perm-team", "description": "Permission test"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Grant permission
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/permissions"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"permission": "ORG_PERM_VAULT_CREATE"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let permission_id = json["permission"]["id"].as_i64().unwrap();

    // List permissions to verify it exists
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/permissions"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["permissions"].as_array().unwrap().len(), 1);

    // Revoke permission
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/teams/{team_id}/permissions/{permission_id}"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert!(json["message"].as_str().unwrap().contains("revoked"));

    // List permissions should be empty
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/permissions"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert!(json["permissions"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_member_cannot_update_team() {
    let _ = IdGenerator::init(1506);
    let state = create_test_state();
    let app = create_test_app(state);

    let owner_session =
        register_user(&app, "authzowner", "authzowner@example.com", "securepassword123").await;
    let member_session =
        register_user(&app, "authzmember", "authzmember@example.com", "securepassword123").await;

    let org_id = get_org_id(&app, &owner_session).await;

    // Invite and accept member into org
    invite_and_accept_member(
        &app,
        &owner_session,
        &member_session,
        "authzmember@example.com",
        org_id,
    )
    .await;

    // Create team as owner
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name": "authz-team", "description": "Auth test"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Regular member tries to update team — should fail with 403
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}"))
                .header("cookie", format!("infera_session={member_session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"name": "hacked"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Verify team name was not changed despite the 403
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}"))
                .header("cookie", format!("infera_session={owner_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["name"], "authz-team", "Team name should be unchanged after 403");

    // Regular member tries to delete team — should fail with 403
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}"))
                .header("cookie", format!("infera_session={member_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Verify team still exists after failed delete
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}"))
                .header("cookie", format!("infera_session={owner_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_member_cannot_grant_or_revoke_permissions() {
    let _ = IdGenerator::init(1507);
    let state = create_test_state();
    let app = create_test_app(state);

    let owner_session =
        register_user(&app, "permowner2", "permowner2@example.com", "securepassword123").await;
    let member_session =
        register_user(&app, "permmember", "permmember@example.com", "securepassword123").await;

    let org_id = get_org_id(&app, &owner_session).await;

    // Invite and accept member into org
    invite_and_accept_member(
        &app,
        &owner_session,
        &member_session,
        "permmember@example.com",
        org_id,
    )
    .await;

    // Create team as owner
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"name": "perm-authz", "description": "Perm authz test"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let team_id = json["team"]["id"].as_i64().unwrap();

    // Member tries to grant permission — should fail with 403
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/permissions"))
                .header("cookie", format!("infera_session={member_session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"permission": "ORG_PERM_VAULT_CREATE"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Owner grants a permission so we can test revoke authorization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/permissions"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"permission": "ORG_PERM_VAULT_CREATE"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let permission_id = json["permission"]["id"].as_i64().unwrap();

    // Member tries to revoke permission — should fail with 403
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/teams/{team_id}/permissions/{permission_id}"
                ))
                .header("cookie", format!("infera_session={member_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Verify the permission still exists after failed revoke
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/teams/{team_id}/permissions"))
                .header("cookie", format!("infera_session={owner_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json["permissions"].as_array().unwrap().len(),
        1,
        "Permission should still exist after failed revoke"
    );
}
