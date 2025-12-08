use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{create_test_app, create_test_state, register_user};
use serde_json::json;
use tower::ServiceExt;

/// Helper to create a client with certificate
async fn create_client_with_cert(app: &axum::Router, session: &str, org_id: i64) -> (i64, i64) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/clients", org_id))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "test-client",
                        "description": "Test client"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let client_id = json["client"]["id"].as_i64().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/clients/{}/certificates", org_id, client_id))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "test-cert"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let cert_id = json["certificate"]["id"].as_i64().unwrap();

    (client_id, cert_id)
}

#[tokio::test]
async fn test_concurrent_vault_access_from_multiple_teams() {
    let _ = IdGenerator::init(100);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register owner and create organization
    let owner_session =
        register_user(&app, "owner", "owner@example.com", "securepassword123").await;

    // Get organization
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

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
                        "description": "Vault shared by multiple teams"
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

    // Create two teams
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
                        "name": "team-readers",
                        "description": "Reader team"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let team1_id = json["team"]["id"].as_i64().unwrap();

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
                        "name": "team-writers",
                        "description": "Writer team"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let team2_id = json["team"]["id"].as_i64().unwrap();

    // Grant both teams access to the vault with different roles
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/vaults/{}/team-grants", org_id, vault_id))
                .header("cookie", format!("infera_session={}", owner_session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "team_id": team1_id,
                        "role": "READER"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/vaults/{}/team-grants", org_id, vault_id))
                .header("cookie", format!("infera_session={}", owner_session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "team_id": team2_id,
                        "role": "WRITER"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify both grants exist by listing them
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/vaults/{}/team-grants", org_id, vault_id))
                .header("cookie", format!("infera_session={}", owner_session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let grants = json["grants"].as_array().unwrap();

    assert_eq!(grants.len(), 2);

    // Verify one grant is for READER role and one is for WRITER role
    let roles: Vec<&str> = grants.iter().map(|g| g["role"].as_str().unwrap()).collect();
    assert!(roles.contains(&"READER"));
    assert!(roles.contains(&"WRITER"));
}

#[tokio::test]
async fn test_token_refresh_with_expired_access_token() {
    let _ = IdGenerator::init(101);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "tokenuser", "token@example.com", "securepassword123").await;

    // Get organization
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
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
                        "name": "token-test-vault",
                        "description": "Vault for token testing"
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

    // Create client and certificate
    let (_client_id, _cert_id) = create_client_with_cert(&app, &session, org_id).await;

    // Generate vault token with very short TTL (1 second)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/vaults/{}/tokens", org_id, vault_id))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "access_token_ttl": 1
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

    let access_token = json["access_token"].as_str().unwrap();
    let refresh_token = json["refresh_token"].as_str().unwrap();
    let expires_in = json["expires_in"].as_i64().unwrap();

    assert_eq!(expires_in, 1); // Verify short TTL

    // Wait for access token to expire
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // The access token should now be expired (we can't directly test this without
    // the server endpoint, but we can verify the refresh token still works)

    // Use refresh token to get new access token (should succeed even though old one expired)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/tokens/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "refresh_token": refresh_token
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

    let new_access_token = json["access_token"].as_str().unwrap();
    let new_refresh_token = json["refresh_token"].as_str().unwrap();

    // Verify we got new tokens
    assert_ne!(new_access_token, access_token);
    assert_ne!(new_refresh_token, refresh_token);
    assert_eq!(json["token_type"], "Bearer");
    assert!(json["expires_in"].as_i64().is_some());
}

#[tokio::test]
async fn test_certificate_rotation_scenario() {
    let _ = IdGenerator::init(102);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "certuser", "cert@example.com", "securepassword123").await;

    // Get organization
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

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organizations"][0]["id"].as_i64().unwrap();

    // Create client
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/clients", org_id))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "rotation-client",
                        "description": "Client for cert rotation"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let client_id = json["client"]["id"].as_i64().unwrap();

    // Create first certificate
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/clients/{}/certificates", org_id, client_id))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "cert-v1"
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
    let cert1_id = json["certificate"]["id"].as_i64().unwrap();
    let cert1_kid = json["certificate"]["kid"].as_str().unwrap().to_string();

    // Create second certificate (rotation)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/clients/{}/certificates", org_id, client_id))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "cert-v2"
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
    let cert2_id = json["certificate"]["id"].as_i64().unwrap();
    let cert2_kid = json["certificate"]["kid"].as_str().unwrap().to_string();

    // Verify both certificates exist
    assert_ne!(cert1_id, cert2_id);
    assert_ne!(cert1_kid, cert2_kid);

    // List certificates for the client
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/clients/{}/certificates", org_id, client_id))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let certs = json["certificates"].as_array().unwrap();

    assert_eq!(certs.len(), 2);

    // Revoke the first certificate
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/organizations/{}/clients/{}/certificates/{}/revoke",
                    org_id, client_id, cert1_id
                ))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify first cert is revoked
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/v1/organizations/{}/clients/{}/certificates/{}",
                    org_id, client_id, cert1_id
                ))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        json["certificate"]["is_active"], false,
        "Certificate should be revoked (is_active=false)"
    );

    // Verify second cert is still active
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/v1/organizations/{}/clients/{}/certificates/{}",
                    org_id, client_id, cert2_id
                ))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["certificate"]["is_active"], true, "Certificate should still be active");
}
