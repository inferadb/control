use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{create_test_app, create_test_state, register_user};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn test_create_client() {
    let _ = IdGenerator::init(30);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "clientowner", "client@example.com", "securepassword123").await;

    // Get organization ID
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
                        "name": "backend-service",
                        "description": "Backend microservice"
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

    assert_eq!(json["client"]["name"], "backend-service");
    assert_eq!(json["client"]["description"], "Backend microservice");
    assert_eq!(json["client"]["is_active"], true);
}

#[tokio::test]
async fn test_list_clients() {
    let _ = IdGenerator::init(31);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "multiclient", "multi@example.com", "securepassword123").await;

    // Get organization ID
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

    // Create multiple clients
    for (name, desc) in [
        ("api-server", "API server"),
        ("worker-service", "Background worker"),
        ("analytics", "Analytics service"),
    ] {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/organizations/{}/clients", org_id))
                    .header("cookie", format!("infera_session={}", session))
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

    // List clients
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/clients", org_id))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let clients = json["clients"].as_array().expect("Should have clients");

    assert_eq!(clients.len(), 3);
}

#[tokio::test]
async fn test_create_certificate() {
    let _ = IdGenerator::init(32);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "certowner", "cert@example.com", "securepassword123").await;

    // Get organization and create client
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

    // Create certificate
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
                        "name": "primary-certificate"
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

    // Verify certificate structure
    assert_eq!(json["certificate"]["name"], "primary-certificate");
    assert!(json["certificate"]["kid"].is_string());
    assert!(json["certificate"]["public_key"].is_string());
    assert!(json["private_key"].is_string());
    assert_eq!(json["certificate"]["is_active"], true);

    // Verify kid format: org-{org_id}-client-{client_id}-cert-{cert_id}
    let kid = json["certificate"]["kid"].as_str().unwrap();
    assert!(kid.starts_with(&format!("org-{}-client-{}-cert-", org_id, client_id)));
}

#[tokio::test]
async fn test_revoke_certificate() {
    let _ = IdGenerator::init(33);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "revoker", "revoker@example.com", "securepassword123").await;

    // Get organization and create client
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
                        "name": "revoke-test",
                        "description": "Client for revoke test"
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

    // Create certificate
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
                        "name": "temp-cert"
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

    // Revoke certificate (DELETE method)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/v1/organizations/{}/clients/{}/certificates/{}",
                    org_id, client_id, cert_id
                ))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Get certificate to verify it's revoked
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/v1/organizations/{}/clients/{}/certificates/{}",
                    org_id, client_id, cert_id
                ))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["certificate"]["is_active"], false);
}

#[tokio::test]
async fn test_jwks_endpoint() {
    let _ = IdGenerator::init(34);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "jwksuser", "jwks@example.com", "securepassword123").await;

    // Get organization and create client with certificate
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
                        "name": "jwks-client",
                        "description": "JWKS test client"
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

    // Create certificate
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/clients/{}/certificates", org_id, client_id))
                .header("cookie", format!("infera_session={}", session))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "jwks-cert"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Get organization-specific JWKS
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/.well-known/jwks.json", org_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify JWKS structure
    assert!(json["keys"].is_array());
    let keys = json["keys"].as_array().unwrap();
    assert!(!keys.is_empty());

    // Verify key format (RFC 8037)
    let key = &keys[0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert!(key["kid"].is_string());
    assert!(key["x"].is_string());
    assert_eq!(key["use"], "sig");
}

#[tokio::test]
async fn test_delete_client() {
    let _ = IdGenerator::init(35);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "deleter", "delete@example.com", "securepassword123").await;

    // Get organization and create client
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
                        "name": "delete-test",
                        "description": "Client to delete"
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

    // Delete client
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/organizations/{}/clients/{}", org_id, client_id))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify client is marked as deleted (soft delete)
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/clients/{}", org_id, client_id))
                .header("cookie", format!("infera_session={}", session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Client should be soft deleted (is_active becomes false after soft delete)
    assert_eq!(json["client"]["is_active"], false);
}
