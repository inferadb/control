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
                        "role": "reader"
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
                        "role": "reader"
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

#[tokio::test]
async fn test_client_assertion_authenticate() {
    use base64::engine::{Engine as Base64Engine, general_purpose::STANDARD as BASE64};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;

    let _ = IdGenerator::init(24);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "assertuser", "assert@example.com", "securepassword123").await;

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
    let orgs: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = orgs["organizations"][0]["id"].as_i64().unwrap();

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
                        "name": "assertion-test-vault",
                        "description": "Vault for client assertion testing"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let vault_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let vault_id = vault_json["vault"]["id"].as_i64().unwrap();

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
                        "name": "assertion-test-client",
                        "description": "Client for assertion testing"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let client_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let client_id = client_json["client"]["id"].as_i64().unwrap();

    // Create certificate
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"name": "assertion-test-cert"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let cert_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let kid = cert_json["certificate"]["kid"].as_str().unwrap().to_string();
    let private_key_b64 = cert_json["private_key"].as_str().unwrap();

    // Decode private key (returned as STANDARD base64) and wrap in PKCS#8 DER
    let private_key_bytes = BASE64.decode(private_key_b64).expect("decode private_key");
    assert_eq!(private_key_bytes.len(), 32);

    let mut pkcs8_der = vec![
        0x30, 0x2e, // SEQUENCE, 46 bytes
        0x02, 0x01, 0x00, // INTEGER version 0
        0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
    ];
    pkcs8_der.extend_from_slice(&private_key_bytes);

    // Build JWT client assertion (RFC 7523)
    #[derive(Serialize)]
    struct AssertionClaims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
        iat: i64,
        jti: String,
    }

    let now = chrono::Utc::now().timestamp();
    let claims = AssertionClaims {
        iss: client_id.to_string(),
        sub: client_id.to_string(),
        aud: "https://api.inferadb.com/token".to_string(),
        exp: now + 300,
        iat: now,
        jti: "test-jti-client-assertion-1".to_string(),
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid);

    let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);
    let client_assertion = encode(&header, &claims, &encoding_key).expect("encode JWT");

    // POST to /control/v1/token with client assertion (form-encoded)
    let form_body = format!(
        "grant_type=client_credentials\
         &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
         &client_assertion={client_assertion}\
         &vault_id={vault_id}\
         &requested_role=reader"
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();

    if !status.is_success() {
        let body_str = String::from_utf8_lossy(&body);
        panic!("Client assertion failed. Status: {status}, Body: {body_str}");
    }

    assert_eq!(status, StatusCode::OK);

    let token_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify response shape
    assert!(token_json["access_token"].is_string());
    assert_eq!(token_json["token_type"], "Bearer");
    assert_eq!(token_json["expires_in"], 300);
    assert!(token_json["scope"].as_str().unwrap().contains("vault:read"));
    assert_eq!(token_json["vault_role"], "reader");
    assert!(token_json["refresh_token"].is_string());
}

#[tokio::test]
async fn test_manager_role_token_generation() {
    let _ = IdGenerator::init(25);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "manageruser", "manager@example.com", "securepassword123").await;

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

    // Create vault (creator gets Admin role)
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
                        "name": "manager-test-vault",
                        "description": "Vault for manager role testing"
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

    // Request a token with Manager role (user has Admin, so Manager should be allowed)
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
                        "requested_role": "manager"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(status, StatusCode::CREATED, "Manager role token should succeed: {json}");
    assert_eq!(json["vault_role"], "manager");
    assert_eq!(json["token_type"], "Bearer");
    assert!(json["access_token"].is_string());
    assert!(json["refresh_token"].is_string());
}
