use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::{IdGenerator, RepositoryContext};
use inferadb_control_test_fixtures::{create_test_app, create_test_state, register_user};
use inferadb_control_types::entities::AuditEventType;
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
                    .uri(format!("/control/v1/organizations/{org_id}/clients"))
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

    // List clients
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{org_id}/clients"))
                .header("cookie", format!("infera_session={session}"))
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
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
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
    assert!(kid.starts_with(&format!("org-{org_id}-client-{client_id}-cert-")));
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
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
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
                    "/control/v1/organizations/{org_id}/clients/{client_id}/certificates/{cert_id}"
                ))
                .header("cookie", format!("infera_session={session}"))
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
                    "/control/v1/organizations/{org_id}/clients/{client_id}/certificates/{cert_id}"
                ))
                .header("cookie", format!("infera_session={session}"))
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
async fn test_delete_client() {
    let _ = IdGenerator::init(35);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "deleter", "delete@example.com", "securepassword123").await;

    // Get organization and create client
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
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}"))
                .header("cookie", format!("infera_session={session}"))
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
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}"))
                .header("cookie", format!("infera_session={session}"))
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

#[tokio::test]
async fn test_rotate_certificate() {
    let _ = IdGenerator::init(36);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "rotator", "rotate@example.com", "securepassword123").await;

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
                        "name": "rotate-test-client",
                        "description": "Client for rotation test"
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

    // Create initial certificate
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
                        "name": "original-certificate"
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
    let original_cert_id = json["certificate"]["id"].as_i64().unwrap();
    let original_kid = json["certificate"]["kid"].as_str().unwrap();

    // Rotate the certificate with a 60 second grace period
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/clients/{client_id}/certificates/{original_cert_id}/rotate"
                ))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "rotated-certificate",
                        "grace_period_seconds": 60
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

    // Verify rotation response structure
    assert_eq!(json["certificate"]["name"], "rotated-certificate");
    assert!(json["certificate"]["id"].as_i64().unwrap() != original_cert_id);
    assert!(json["certificate"]["kid"].as_str().unwrap() != original_kid);
    assert!(json["private_key"].is_string());
    assert!(json["valid_from"].is_string());

    // Verify rotated_from contains the original certificate info
    assert_eq!(json["rotated_from"]["id"], original_cert_id);
    assert_eq!(json["rotated_from"]["kid"], original_kid);
    assert_eq!(json["rotated_from"]["name"], "original-certificate");
    assert_eq!(json["rotated_from"]["is_active"], true);
}

#[tokio::test]
async fn test_rotate_certificate_default_grace_period() {
    let _ = IdGenerator::init(37);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "rotator2", "rotate2@example.com", "securepassword123").await;

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
                        "name": "rotate-default-client",
                        "description": "Client for default grace period test"
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

    // Create initial certificate
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
                        "name": "original-cert"
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

    // Rotate without specifying grace_period_seconds (should use default of 300)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/clients/{client_id}/certificates/{cert_id}/rotate"
                ))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "default-rotated-cert"
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

    // Verify rotation succeeded
    assert_eq!(json["certificate"]["name"], "default-rotated-cert");
    assert!(json["valid_from"].is_string());

    // The valid_from should be approximately 300 seconds in the future
    // We can't assert exact time, but we can verify the field exists and has a valid timestamp
    let valid_from = chrono::DateTime::parse_from_rfc3339(json["valid_from"].as_str().unwrap());
    assert!(valid_from.is_ok());
}

#[tokio::test]
async fn test_rotate_revoked_certificate_fails() {
    let _ = IdGenerator::init(38);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "rotator3", "rotate3@example.com", "securepassword123").await;

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
                        "name": "revoke-rotate-client",
                        "description": "Client for revoke rotation test"
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
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "to-be-revoked"
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

    // Revoke the certificate
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/clients/{client_id}/certificates/{cert_id}"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Try to rotate the revoked certificate - should fail
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/clients/{client_id}/certificates/{cert_id}/rotate"
                ))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "should-fail"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail with a validation error
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Test that certificate creation writes the public signing key to Ledger storage.
///
/// This integration test verifies that when a certificate is created:
/// 1. The certificate is saved to the database
/// 2. The public signing key is written to Ledger (in org namespace)
/// 3. The key can be retrieved using the `PublicSigningKeyStore` trait
#[tokio::test]
async fn test_certificate_creation_writes_to_ledger() {
    let _ = IdGenerator::init(100);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "ledgertest", "ledger@example.com", "securepassword123").await;

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
                        "name": "ledger-test-client",
                        "description": "Client for Ledger integration test"
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
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "ledger-test-cert"
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

    let kid = json["certificate"]["kid"].as_str().unwrap();
    let public_key_from_response = json["certificate"]["public_key"].as_str().unwrap();

    // Verify the public signing key was written to Ledger storage
    let signing_key_store = state.storage.signing_key_store();
    let stored_key = signing_key_store
        .get_key(org_id, kid)
        .await
        .expect("get_key should not fail")
        .expect("key should exist in Ledger storage");

    // Verify key properties
    assert_eq!(stored_key.kid, kid);
    assert_eq!(stored_key.public_key, public_key_from_response);
    assert_eq!(stored_key.client_id, client_id);
    assert!(stored_key.active, "key should be active");
    assert!(stored_key.revoked_at.is_none(), "key should not be revoked");
}

/// Test that certificate revocation updates the public signing key in Ledger storage.
///
/// This integration test verifies that when a certificate is revoked:
/// 1. The certificate is marked as revoked in the database
/// 2. The public signing key in Ledger is updated with revocation timestamp
/// 3. The key's active status is updated appropriately
#[tokio::test]
async fn test_certificate_revocation_updates_ledger() {
    let _ = IdGenerator::init(101);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "revokeledger", "revokeledger@example.com", "securepassword123").await;

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
                        "name": "revoke-ledger-client",
                        "description": "Client for revocation Ledger test"
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
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "to-be-revoked-ledger"
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
    let kid = json["certificate"]["kid"].as_str().unwrap().to_string();

    // Verify key is active before revocation
    let signing_key_store = state.storage.signing_key_store();
    let key_before = signing_key_store
        .get_key(org_id, &kid)
        .await
        .expect("get_key should not fail")
        .expect("key should exist");

    assert!(key_before.active, "key should be active before revocation");
    assert!(key_before.revoked_at.is_none(), "key should not be revoked before revocation");

    // Revoke the certificate
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/clients/{client_id}/certificates/{cert_id}"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify key is now revoked in Ledger storage
    let key_after = signing_key_store
        .get_key(org_id, &kid)
        .await
        .expect("get_key should not fail")
        .expect("key should still exist after revocation");

    assert!(key_after.revoked_at.is_some(), "key should have revoked_at set after revocation");
}

/// Test that certificate rotation writes both old and new keys to Ledger storage.
///
/// This integration test verifies that when a certificate is rotated:
/// 1. A new certificate is created with future valid_from
/// 2. The new public signing key is written to Ledger
/// 3. The old key remains unchanged (still active)
/// 4. Both keys coexist during the grace period
#[tokio::test]
async fn test_certificate_rotation_writes_to_ledger() {
    let _ = IdGenerator::init(102);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "rotateledger", "rotateledger@example.com", "securepassword123").await;

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
                        "name": "rotate-ledger-client",
                        "description": "Client for rotation Ledger test"
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

    // Create initial certificate
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
                        "name": "original-cert"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let original_cert_id = json["certificate"]["id"].as_i64().unwrap();
    let original_kid = json["certificate"]["kid"].as_str().unwrap().to_string();

    // Rotate the certificate
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/clients/{client_id}/certificates/{original_cert_id}/rotate"
                ))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "rotated-cert",
                        "grace_period_seconds": 300
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
    let new_kid = json["certificate"]["kid"].as_str().unwrap();

    // Verify both keys exist in Ledger storage
    let signing_key_store = state.storage.signing_key_store();

    // Original key should still exist and be active
    let original_key = signing_key_store
        .get_key(org_id, &original_kid)
        .await
        .expect("get_key should not fail")
        .expect("original key should still exist");

    assert!(original_key.active, "original key should still be active during grace period");
    assert!(original_key.revoked_at.is_none(), "original key should not be revoked");

    // New rotated key should exist
    let new_key = signing_key_store
        .get_key(org_id, new_kid)
        .await
        .expect("get_key should not fail")
        .expect("new rotated key should exist");

    assert!(new_key.active, "new key should be active");
    assert!(new_key.revoked_at.is_none(), "new key should not be revoked");
    // The new key has a future valid_from (grace period)
    assert!(
        new_key.valid_from > original_key.valid_from,
        "new key should have later valid_from (grace period)"
    );
}

/// Test that certificate revocation creates an audit log entry.
///
/// This test verifies that when a certificate is revoked, an audit log
/// entry is created with the correct event type, user ID, and resource info.
#[tokio::test]
async fn test_certificate_revocation_creates_audit_log() {
    let _ = IdGenerator::init(103);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "auditrevoke", "auditrevoke@example.com", "securepassword123").await;

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
                        "name": "audit-revoke-client",
                        "description": "Client for audit revocation test"
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
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "to-be-revoked-audit"
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

    // Revoke the certificate
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/clients/{client_id}/certificates/{cert_id}"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Query audit logs for this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let (logs, _total) = repos
        .audit_log
        .list_by_organization(org_id, inferadb_control_core::AuditLogFilters::default(), 100, 0)
        .await
        .expect("list_by_organization should not fail");

    // Find the certificate revocation audit log
    let revoke_log = logs
        .iter()
        .find(|log| log.event_type == AuditEventType::ClientCertificateRevoked)
        .expect("should have a ClientCertificateRevoked audit log");

    // Verify audit log contains correct information
    assert_eq!(revoke_log.organization_id, Some(org_id));
    assert!(revoke_log.user_id.is_some(), "audit log should have user_id");
    assert_eq!(revoke_log.client_id, Some(client_id));
    assert_eq!(revoke_log.resource_id, Some(cert_id));

    // Verify event_data contains the kid
    let event_data = revoke_log.event_data.as_ref().expect("should have event_data");
    assert!(event_data.get("kid").is_some(), "event_data should contain kid");
    assert!(event_data.get("revoked_by").is_some(), "event_data should contain revoked_by");
}

/// Test emergency revocation of a signing key via internal endpoint.
///
/// This test verifies:
/// 1. A key can be revoked via the privileged internal endpoint
/// 2. The key's revoked_at field is set
/// 3. The response includes the correct kid and namespace
#[tokio::test]
async fn test_emergency_revoke_key() {
    use inferadb_control_test_fixtures::create_internal_test_app;

    let _ = IdGenerator::init(104);
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let internal_app = create_internal_test_app(state.clone());

    let session =
        register_user(&app, "emergency", "emergency@example.com", "securepassword123").await;

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
                        "name": "emergency-test-client",
                        "description": "Client for emergency revocation test"
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
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "emergency-revoke-cert"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let kid = json["certificate"]["kid"].as_str().unwrap().to_string();

    // Verify key exists and is not revoked
    let signing_key_store = state.storage.signing_key_store();
    let key_before = signing_key_store
        .get_key(org_id, &kid)
        .await
        .expect("get_key should not fail")
        .expect("key should exist");

    assert!(
        key_before.revoked_at.is_none(),
        "key should not be revoked before emergency revocation"
    );

    // Emergency revoke the key via internal endpoint
    let response = internal_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/internal/namespaces/{org_id}/keys/{kid}/revoke"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "reason": "Security incident detected"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK, "emergency revocation should succeed");

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["kid"], kid);
    assert_eq!(json["namespace_id"], org_id);
    assert_eq!(json["message"], "Key revoked successfully");

    // Verify key is now revoked
    let key_after = signing_key_store
        .get_key(org_id, &kid)
        .await
        .expect("get_key should not fail")
        .expect("key should still exist");

    assert!(key_after.revoked_at.is_some(), "key should be revoked after emergency revocation");
}

/// Test emergency revocation of non-existent key returns 404.
#[tokio::test]
async fn test_emergency_revoke_nonexistent_key() {
    use inferadb_control_test_fixtures::create_internal_test_app;

    let _ = IdGenerator::init(105);
    let state = create_test_state();
    let internal_app = create_internal_test_app(state.clone());

    // Try to revoke a key that doesn't exist
    let response = internal_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/namespaces/12345/keys/nonexistent-kid/revoke")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "reason": "Testing nonexistent key"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND, "should return 404 for nonexistent key");
}

/// Test emergency revocation is idempotent (re-revoking already revoked key succeeds).
#[tokio::test]
async fn test_emergency_revoke_already_revoked_key() {
    use inferadb_control_test_fixtures::create_internal_test_app;

    let _ = IdGenerator::init(106);
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let internal_app = create_internal_test_app(state.clone());

    let session =
        register_user(&app, "idempotent", "idempotent@example.com", "securepassword123").await;

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
                        "name": "idempotent-client",
                        "description": "Client for idempotent test"
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
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "idempotent-cert"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let kid = json["certificate"]["kid"].as_str().unwrap().to_string();

    // First emergency revocation
    let response = internal_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/internal/namespaces/{org_id}/keys/{kid}/revoke"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "reason": "First revocation"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Second emergency revocation (should be idempotent)
    let response = internal_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/internal/namespaces/{org_id}/keys/{kid}/revoke"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "reason": "Second revocation"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK, "re-revoking should succeed (idempotent)");

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["message"], "Key was already revoked");
}

/// Test emergency revocation creates audit log entry.
#[tokio::test]
async fn test_emergency_revoke_creates_audit_log() {
    use inferadb_control_test_fixtures::create_internal_test_app;

    let _ = IdGenerator::init(107);
    let state = create_test_state();
    let app = create_test_app(state.clone());
    let internal_app = create_internal_test_app(state.clone());

    let session =
        register_user(&app, "auditemer", "auditemer@example.com", "securepassword123").await;

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
                        "name": "audit-emergency-client",
                        "description": "Client for audit emergency test"
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
                .uri(format!("/control/v1/organizations/{org_id}/clients/{client_id}/certificates"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "audit-emergency-cert"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let kid = json["certificate"]["kid"].as_str().unwrap().to_string();

    // Emergency revoke
    let response = internal_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/internal/namespaces/{org_id}/keys/{kid}/revoke"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "reason": "Emergency audit test"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Query audit logs
    let repos = RepositoryContext::new((*state.storage).clone());
    let (logs, _total) = repos
        .audit_log
        .list_by_organization(org_id, inferadb_control_core::AuditLogFilters::default(), 100, 0)
        .await
        .expect("list_by_organization should not fail");

    // Find the emergency revocation audit log
    let emergency_log = logs
        .iter()
        .find(|log| {
            log.event_type == AuditEventType::ClientCertificateRevoked
                && log
                    .event_data
                    .as_ref()
                    .is_some_and(|data| data.get("emergency") == Some(&json!(true)))
        })
        .expect("should have an emergency revocation audit log");

    // Verify audit log contains emergency flag
    let event_data = emergency_log.event_data.as_ref().expect("should have event_data");
    assert_eq!(event_data.get("emergency"), Some(&json!(true)));
    assert!(event_data.get("kid").is_some());
    assert!(event_data.get("reason").is_some());
}

/// Test that Engine rejects tokens after Control revokes the signing key.
///
/// This integration test verifies the end-to-end revocation flow:
/// 1. Control creates a certificate and writes public key to Ledger
/// 2. Client issues a JWT signed with the private key
/// 3. Engine validates the token successfully using SigningKeyCache
/// 4. Control revokes the certificate, marking key as revoked in Ledger
/// 5. Engine's cache is cleared (simulating TTL expiry)
/// 6. Engine rejects the token with KeyRevoked error
#[tokio::test]
async fn test_engine_rejects_tokens_after_revocation() {
    use std::time::Duration;

    use base64::engine::{Engine as Base64Engine, general_purpose::STANDARD as BASE64};
    use chrono::Utc;
    use inferadb_engine_auth::{
        SigningKeyCache, error::AuthError, jwt::verify_with_signing_key_cache,
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    let _ = IdGenerator::init(200);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "engine_revoke", "engine_revoke@example.com", "securepassword123")
            .await;

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
                        "name": "engine-revoke-test-client",
                        "description": "Client for engine revocation test"
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

    // Create certificate - this returns the private key
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
                        "name": "engine-revoke-test-cert"
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
    let cert_id = json["certificate"]["id"].as_i64().unwrap();
    let kid = json["certificate"]["kid"].as_str().unwrap().to_string();
    let private_key_b64 = json["private_key"].as_str().unwrap();

    // Decode private key and wrap in PKCS#8 DER format for jsonwebtoken
    let private_key_bytes = BASE64.decode(private_key_b64).expect("decode private_key");
    assert_eq!(private_key_bytes.len(), 32, "Ed25519 private key should be 32 bytes");

    // PKCS#8 DER header for Ed25519
    let mut pkcs8_der = vec![
        0x30, 0x2e, // SEQUENCE, 46 bytes
        0x02, 0x01, 0x00, // INTEGER version 0
        0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
    ];
    pkcs8_der.extend_from_slice(&private_key_bytes);

    // Create JWT claims
    let now = Utc::now().timestamp() as u64;
    let claims = inferadb_engine_auth::jwt::JwtClaims {
        iss: "https://api.inferadb.com".into(),
        sub: format!("client:{client_id}"),
        aud: "https://api.inferadb.com/evaluate".into(),
        exp: now + 3600,
        iat: now,
        nbf: None,
        jti: Some("test-jti-engine-revoke".into()),
        scope: "vault:read vault:write".into(),
        vault_id: Some("123456789".into()),
        org_id: Some(org_id.to_string()),
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.clone());

    let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);
    let token = encode(&header, &claims, &encoding_key).expect("encode JWT");

    // Create SigningKeyCache using shared storage
    let signing_key_store = state.storage.signing_key_store();
    let cache = SigningKeyCache::new(signing_key_store.clone(), Duration::from_secs(300));

    // Verify token is valid before revocation
    let result = verify_with_signing_key_cache(&token, &cache).await;
    assert!(result.is_ok(), "token should be valid before revocation: {:?}", result);

    // Revoke the certificate
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/control/v1/organizations/{org_id}/clients/{client_id}/certificates/{cert_id}"
                ))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Clear the cache to simulate TTL expiry
    // In production, Engine would naturally refresh after TTL expires
    cache.clear_all().await;

    // Verify token is now rejected (KeyInactive or KeyRevoked - both indicate invalidation)
    // The key state validation checks active flag first, then revoked_at, so we may get either
    let result = verify_with_signing_key_cache(&token, &cache).await;
    assert!(
        matches!(
            result,
            Err(AuthError::KeyInactive { kid: ref k }) | Err(AuthError::KeyRevoked { kid: ref k }) if k == &kid
        ),
        "token should be rejected after revocation (KeyInactive or KeyRevoked): {:?}",
        result
    );
}
