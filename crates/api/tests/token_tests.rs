#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{create_test_app, create_test_state, register_user};
use serde_json::json;
use tower::ServiceExt;

/// Helper to create a client with certificate for token generation
async fn create_client_with_cert(app: &axum::Router, session: &str, org_id: i64) -> (i64, i64) {
    // Create client
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/clients"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "test-client",
                        "description": "Test client for tokens"
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

    // Create certificate for client
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"name": "test-cert"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

    if !status.is_success() {
        let body_str = String::from_utf8_lossy(&body);
        panic!("Failed to create certificate. Status: {status}, Body: {body_str}");
    }

    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let cert_id = json["certificate"]["id"].as_i64().unwrap();

    (client_id, cert_id)
}

#[tokio::test]
async fn test_generate_vault_token() {
    let _ = IdGenerator::init(20);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "tokenuser", "token@example.com", "securepassword123").await;

    // Get organization
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
    let _vault_id = json["vault"]["id"].as_i64().unwrap();

    // Create client certificate
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/clients"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "test-client",
                        "description": "Test client for tokens"
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

    // Create certificate for client
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "primary-cert"
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

    // Verify certificate was created with private key
    assert!(json["certificate"]["kid"].is_string());
    assert!(json["certificate"]["public_key"].is_string());
    assert!(json["private_key"].is_string());
}

#[tokio::test]
async fn test_refresh_token_flow() {
    let _ = IdGenerator::init(21);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "refreshuser", "refresh@example.com", "securepassword123").await;

    // Get user ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/auth/me")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let user_id = json["user"]["id"].as_i64().unwrap();

    // Get organization
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
                        "name": "refresh-test-vault",
                        "description": "Vault for refresh testing"
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

    // Create client and certificate for token generation
    let (_client_id, _cert_id) = create_client_with_cert(&app, &session, org_id).await;

    // Generate vault token (this creates a refresh token)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/tokens"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "role": "READER"
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

    let access_token = json["access_token"].as_str().expect("Should have access_token");
    let refresh_token = json["refresh_token"].as_str().expect("Should have refresh_token");

    assert!(!access_token.is_empty());
    assert!(!refresh_token.is_empty());
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["expires_in"], 300); // 5 minutes (default per spec)

    // Wait 1 second to ensure new token has different iat timestamp
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Use refresh token to get new access token
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/tokens/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "refresh_token": refresh_token,
                        "vault_id": vault_id,
                        "user_id": user_id
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

    let new_access_token = json["access_token"].as_str().expect("Should have new access_token");
    let new_refresh_token = json["refresh_token"].as_str().expect("Should have new refresh_token");

    // New tokens should be different from original
    assert_ne!(new_access_token, access_token);
    assert_ne!(new_refresh_token, refresh_token);
}

#[tokio::test]
async fn test_refresh_token_replay_protection() {
    let _ = IdGenerator::init(22);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "replayuser", "replay@example.com", "securepassword123").await;

    // Get user ID and organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/auth/me")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let user_id = json["user"]["id"].as_i64().unwrap();

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
                        "name": "replay-test-vault",
                        "description": "Vault for replay testing"
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

    // Create client and certificate for token generation
    let (_client_id, _cert_id) = create_client_with_cert(&app, &session, org_id).await;

    // Generate initial token
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/tokens"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "role": "READER"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let refresh_token = json["refresh_token"].as_str().unwrap();

    // Use refresh token once
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/tokens/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "refresh_token": refresh_token,
                        "vault_id": vault_id,
                        "user_id": user_id
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Try to reuse the same refresh token (should fail - replay attack)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/tokens/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "refresh_token": refresh_token,
                        "vault_id": vault_id,
                        "user_id": user_id
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return error (token already used or not found)
    assert!(response.status().is_client_error() || response.status() == StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_revoke_refresh_tokens() {
    let _ = IdGenerator::init(23);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "revokeuser", "revoke@example.com", "securepassword123").await;

    // Get user ID and organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/auth/me")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let user_id = json["user"]["id"].as_i64().unwrap();

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
                        "name": "revoke-test-vault",
                        "description": "Vault for revoke testing"
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

    // Create client and certificate for token generation
    let (_client_id, _cert_id) = create_client_with_cert(&app, &session, org_id).await;

    // Generate token
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/vaults/{vault_id}/tokens"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "role": "READER"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let refresh_token = json["refresh_token"].as_str().unwrap();

    // Revoke all refresh tokens for vault
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/tokens/revoke/vault/{vault_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Try to use revoked refresh token (should fail)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/tokens/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "refresh_token": refresh_token,
                        "vault_id": vault_id,
                        "user_id": user_id
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status().is_client_error() || response.status() == StatusCode::NOT_FOUND);
}
