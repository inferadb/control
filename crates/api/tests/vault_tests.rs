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
                .uri("/control/v1/organizations")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organizations"][0]["id"].as_i64().expect("Should have org ID");

    // Create a vault
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
                        "name": "production-policies",
                        "description": "Production environment policies"
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

    assert_eq!(json["vault"]["name"], "production-policies");
    assert_eq!(json["vault"]["description"], "Production environment policies");
    // Note: In unit tests without a real server, sync will fail (FAILED status).
    // In integration tests with real server, status should be PENDING then SYNCED.
    let sync_status = json["vault"]["sync_status"].as_str().unwrap();
    assert!(
        sync_status == "PENDING" || sync_status == "SYNCED" || sync_status == "FAILED",
        "sync_status should be PENDING, SYNCED, or FAILED (in test env), got: {sync_status}"
    );
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
                    .uri(format!("/control/v1/organizations/{org_id}/vaults"))
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

    // List vaults
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/vaults"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
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
                        "name": "original-name",
                        "description": "Original description"
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

    // Update vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}"))
                .header("cookie", format!("infera_session={session}"))
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
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
                        "name": "temp-vault",
                        "description": "Temporary vault"
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

    // Delete vault
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

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify vault is deleted
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}"))
                .header("cookie", format!("infera_session={session}"))
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
    let owner_session =
        register_user(&app, "vaultowner2", "owner2@example.com", "securepassword123").await;
    let member_session =
        register_user(&app, "vaultmember", "member@example.com", "securepassword123").await;

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

    // Get member's user ID
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

    // Add member to organization first
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/members"))
                .header("cookie", format!("infera_session={owner_session}"))
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
                .uri(format!("/control/v1/organizations/{org_id}/vaults"))
                .header("cookie", format!("infera_session={owner_session}"))
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let vault_id = json["vault"]["id"].as_i64().unwrap();

    // Grant user access to vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/user-grants"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "user_id": member_user_id,
                        "role": "reader"
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

    assert_eq!(json["grant"]["role"], "reader");
}

#[tokio::test]
async fn test_revoke_user_vault_access() {
    let _ = IdGenerator::init(6);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let owner_session =
        register_user(&app, "vaultowner3", "owner3@example.com", "securepassword123").await;
    let member_session =
        register_user(&app, "vaultmember2", "member2@example.com", "securepassword123").await;

    // Get organization and member user ID
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

    // Add member to organization
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/members"))
                .header("cookie", format!("infera_session={owner_session}"))
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
                .uri(format!("/control/v1/organizations/{org_id}/vaults"))
                .header("cookie", format!("infera_session={owner_session}"))
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let vault_id = json["vault"]["id"].as_i64().unwrap();

    // Grant access
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/user-grants"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "user_id": member_user_id,
                        "role": "reader"
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
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/user-grants/{member_user_id}"
                ))
                .header("cookie", format!("infera_session={owner_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_team_grant() {
    let _ = IdGenerator::init(20);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "teamgrantdel", "teamgrantdel@example.com", "securepassword123").await;

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

    // Create a team
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
                        "name": "delete-grant-team",
                        "description": "Team for grant deletion test"
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

    // Create a vault
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
                        "name": "team-grant-del-vault",
                        "description": "Vault for team grant deletion"
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
    let grant_id = json["grant"]["id"].as_i64().unwrap();

    // Delete the team grant
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/team-grants/{grant_id}"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify team grant no longer exists by listing team grants
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/team-grants"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let grants = json["grants"].as_array().unwrap();
    assert!(grants.is_empty(), "Team grant should be deleted but still exists");
}

#[tokio::test]
async fn test_delete_team_grant_does_not_affect_user_grants() {
    let _ = IdGenerator::init(30);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let owner_session =
        register_user(&app, "tgowner", "tgowner@example.com", "securepassword123").await;
    let member_session =
        register_user(&app, "tgmember", "tgmember@example.com", "securepassword123").await;

    // Get organization ID
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let member_user_id = json["user"]["id"].as_i64().unwrap();

    // Add member to organization
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/members"))
                .header("cookie", format!("infera_session={owner_session}"))
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

    // Create a team
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
                        "name": "isolation-team",
                        "description": "Team for isolation test"
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

    // Create a vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "isolation-vault",
                        "description": "Vault for isolation test"
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

    // Create a user grant
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/user-grants"))
                .header("cookie", format!("infera_session={owner_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "user_id": member_user_id,
                        "role": "reader"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Create a team grant
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/team-grants"))
                .header("cookie", format!("infera_session={owner_session}"))
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
    let team_grant_id = json["grant"]["id"].as_i64().unwrap();

    // Delete the team grant
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/vaults/{vault_id}/team-grants/{team_grant_id}"
                ))
                .header("cookie", format!("infera_session={owner_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify user grant is unaffected
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/user-grants"))
                .header("cookie", format!("infera_session={owner_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let user_grants = json["grants"].as_array().unwrap();
    assert_eq!(user_grants.len(), 2, "User grants should be unaffected after deleting team grant");

    // Verify team grant is deleted
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/team-grants"))
                .header("cookie", format!("infera_session={owner_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let team_grants = json["grants"].as_array().unwrap();
    assert!(team_grants.is_empty(), "Team grant should be deleted");
}
