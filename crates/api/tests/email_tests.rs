#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for email management endpoints.
//!
//! Tests `add`, `list`, `update primary`, `delete`, and `verify` email operations
//! through the full middleware stack.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::UserEmailVerificationTokenRepository;
use inferadb_control_test_fixtures::{
    body_json, create_test_app, create_test_state, register_user,
};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn test_add_email_appears_in_list() {
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "EmailUser", "primary@test.com", "test-password-123456").await;

    // Add a secondary email
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"email": "secondary@test.com"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["email"]["email"], "secondary@test.com");
    assert!(!json["email"]["is_primary"].as_bool().unwrap());
    assert!(!json["email"]["is_verified"].as_bool().unwrap());

    // List emails — should include both primary and secondary
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let emails = json["emails"].as_array().unwrap();
    assert_eq!(emails.len(), 2, "Should have primary + secondary email");

    let email_addrs: Vec<&str> = emails.iter().map(|e| e["email"].as_str().unwrap()).collect();
    assert!(email_addrs.contains(&"primary@test.com"));
    assert!(email_addrs.contains(&"secondary@test.com"));
}

#[tokio::test]
async fn test_set_primary_requires_verified() {
    let state = create_test_state();
    let app = create_test_app(state);

    let session = register_user(&app, "PrimaryUser", "main@test.com", "test-password-123456").await;

    // Add a secondary email (unverified)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"email": "unverified@test.com"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let email_id = json["email"]["id"].as_i64().unwrap();

    // Try to set unverified email as primary — should fail
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/control/v1/users/emails/{email_id}"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"is_primary": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Setting unverified email as primary should fail"
    );
}

#[tokio::test]
async fn test_cannot_delete_primary_email() {
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "DelPrimary", "delprimary@test.com", "test-password-123456").await;

    // List emails to get the primary email ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let primary_email = json["emails"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["is_primary"].as_bool().unwrap())
        .expect("Should have a primary email");
    let primary_id = primary_email["id"].as_i64().unwrap();

    // Try to delete primary email — should fail
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/users/emails/{primary_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Deleting primary email should fail");
}

#[tokio::test]
async fn test_delete_non_primary_email() {
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "DelSecondary", "keepme@test.com", "test-password-123456").await;

    // Add a secondary email
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"email": "deleteme@test.com"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let secondary_id = json["email"]["id"].as_i64().unwrap();

    // Delete secondary email — should succeed
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/users/emails/{secondary_id}"))
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // List emails — should only have primary
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["emails"].as_array().unwrap().len(), 1, "Only primary should remain");
}

#[tokio::test]
async fn test_verify_email_with_valid_token() {
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "VerifyUser", "verify-main@test.com", "test-password-123456").await;

    // Add an email
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"email": "verify-me@test.com"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let email_id = json["email"]["id"].as_i64().unwrap();

    // Get the verification token from the repository
    let token_repo = UserEmailVerificationTokenRepository::new((*state.storage).clone());
    let tokens = token_repo.get_by_email(email_id).await.unwrap();
    assert!(!tokens.is_empty(), "Should have a verification token");
    let token_str = tokens[0].secure_token.token.clone();

    // Verify the email via the auth endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/verify-email")
                .header("content-type", "application/json")
                .body(Body::from(json!({"token": token_str}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert!(json["message"].as_str().unwrap().contains("verified"));

    // List emails and verify the email is now verified
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let verified_email = json["emails"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["email"].as_str().unwrap() == "verify-me@test.com")
        .expect("Should find the email");
    assert!(verified_email["is_verified"].as_bool().unwrap(), "Email should be verified");
}

#[tokio::test]
async fn test_verify_email_with_invalid_token() {
    let state = create_test_state();
    let app = create_test_app(state);

    // Try to verify with a bogus token
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/verify-email")
                .header("content-type", "application/json")
                .body(Body::from(json!({"token": "invalid-token-12345"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Invalid token should return 400");
}

#[tokio::test]
async fn test_cross_user_email_isolation() {
    let state = create_test_state();
    let app = create_test_app(state);

    // Register two users
    let session_a =
        register_user(&app, "UserA", "usera-email@test.com", "test-password-123456").await;
    let session_b =
        register_user(&app, "UserB", "userb-email@test.com", "test-password-123456").await;

    // User A adds a secondary email
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session_a}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"email": "usera-secondary@test.com"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let email_id = json["email"]["id"].as_i64().unwrap();

    // User B tries to delete User A's email — should fail with 401
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/users/emails/{email_id}"))
                .header("cookie", format!("infera_session={session_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Should not be able to delete another user's email"
    );

    // User B tries to set User A's email as primary — should fail with 401
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/control/v1/users/emails/{email_id}"))
                .header("cookie", format!("infera_session={session_b}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"is_primary": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Should not be able to modify another user's email"
    );

    // Verify User A's email is still intact
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session_a}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["emails"].as_array().unwrap().len(), 2, "User A should still have both emails");
}

#[tokio::test]
async fn test_reused_verification_token_rejected() {
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "ReuseToken", "reuse-main@test.com", "test-password-123456").await;

    // Add an email
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"email": "reuse-verify@test.com"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let email_id = json["email"]["id"].as_i64().unwrap();

    // Get the verification token
    let token_repo = UserEmailVerificationTokenRepository::new((*state.storage).clone());
    let tokens = token_repo.get_by_email(email_id).await.unwrap();
    let token_str = tokens[0].secure_token.token.clone();

    // First verification — should succeed
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/verify-email")
                .header("content-type", "application/json")
                .body(Body::from(json!({"token": token_str}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Second verification with same token — should fail
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/verify-email")
                .header("content-type", "application/json")
                .body(Body::from(json!({"token": token_str}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Token was marked used after first verification, so is_valid() returns false
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Reused token should fail validation");
}

#[tokio::test]
async fn test_verified_email_cannot_become_primary_while_another_exists() {
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session =
        register_user(&app, "VerifyPrimary", "vp-main@test.com", "test-password-123456").await;

    // Add a secondary email
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"email": "vp-secondary@test.com"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let email_id = json["email"]["id"].as_i64().unwrap();

    // Get the verification token and verify the email
    let token_repo = UserEmailVerificationTokenRepository::new((*state.storage).clone());
    let tokens = token_repo.get_by_email(email_id).await.unwrap();
    let token_str = tokens[0].secure_token.token.clone();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/verify-email")
                .header("content-type", "application/json")
                .body(Body::from(json!({"token": token_str}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Confirm the email is now verified
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/emails")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let verified = json["emails"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["email"].as_str().unwrap() == "vp-secondary@test.com")
        .expect("Should find secondary email");
    assert!(verified["is_verified"].as_bool().unwrap(), "Email should be verified");

    // Try to set as primary — should fail because another primary already exists
    // (repository enforces single-primary constraint)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/control/v1/users/emails/{email_id}"))
                .header("cookie", format!("infera_session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"is_primary": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Cannot set as primary while another primary exists"
    );
}
