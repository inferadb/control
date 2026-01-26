#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{create_test_app, create_test_state, register_user};
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
                        "role": "WRITER"
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

    assert_eq!(json["grant"]["role"], "WRITER");
}
