#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for the CLI OAuth PKCE authorization flow.
//!
//! Exercises the full `POST /control/v1/auth/cli/authorize` →
//! `POST /control/v1/auth/cli/token` flow through the router,
//! including PKCE verification, replay prevention, and session
//! validation.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};
use inferadb_common_storage::backend::StorageBackend;
use inferadb_control_core::{IdGenerator, RepositoryContext};
use inferadb_control_test_fixtures::{
    body_json, create_test_app, create_test_state, register_user,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

/// Generate a PKCE code_verifier and its S256 code_challenge.
fn generate_pkce_pair() -> (String, String) {
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let code_challenge = URL_SAFE_NO_PAD.encode(hash);
    (code_verifier.to_string(), code_challenge)
}

/// Helper: send a CLI authorize request (requires a valid session).
async fn cli_authorize_request(
    app: &axum::Router,
    session_cookie: &str,
    code_challenge: &str,
    code_challenge_method: &str,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/cli/authorize")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={session_cookie}"))
                .body(Body::from(
                    json!({
                        "code_challenge": code_challenge,
                        "code_challenge_method": code_challenge_method
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper: send a CLI token exchange request (no session needed).
async fn cli_token_exchange_request(
    app: &axum::Router,
    code: &str,
    code_verifier: &str,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/cli/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "code": code,
                        "code_verifier": code_verifier
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Test 1: Full PKCE flow — authorize → token exchange → valid CLI session
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cli_pkce_full_flow() {
    let _ = IdGenerator::init(700);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register user and get a web session
    let session = register_user(&app, "Alice CLI", "alice-cli@example.com", "Password123!").await;

    // Generate PKCE pair
    let (code_verifier, code_challenge) = generate_pkce_pair();

    // Step 1: Authorize — get authorization code
    let authorize_resp = cli_authorize_request(&app, &session, &code_challenge, "S256").await;
    assert_eq!(authorize_resp.status(), StatusCode::OK, "Authorize should succeed");

    let authorize_body = body_json(authorize_resp).await;
    let code = authorize_body["code"].as_str().expect("Response should contain 'code'");
    let expires_in =
        authorize_body["expires_in"].as_i64().expect("Response should contain 'expires_in'");
    assert!(!code.is_empty(), "Authorization code should not be empty");
    assert_eq!(expires_in, 600, "Authorization code TTL should be 600 seconds (10 min)");

    // Step 2: Token exchange — exchange code for CLI session
    let exchange_resp = cli_token_exchange_request(&app, code, &code_verifier).await;
    assert_eq!(exchange_resp.status(), StatusCode::OK, "Token exchange should succeed");

    let exchange_body = body_json(exchange_resp).await;
    let session_token =
        exchange_body["session_token"].as_str().expect("Response should contain 'session_token'");
    let cli_expires =
        exchange_body["expires_in"].as_i64().expect("Response should contain 'expires_in'");
    assert!(!session_token.is_empty(), "Session token should not be empty");
    assert!(cli_expires > 0, "CLI session should have positive expiry");

    // Step 3: Verify the CLI session works — use it to call a protected endpoint
    let me_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/auth/me")
                .header("authorization", format!("Bearer {session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(me_resp.status(), StatusCode::OK, "CLI session should authenticate to /me");
}

// ---------------------------------------------------------------------------
// Test 2: Token exchange with wrong code_verifier → 401
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cli_pkce_wrong_code_verifier() {
    let _ = IdGenerator::init(701);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "Bob CLI", "bob-cli@example.com", "Password123!").await;

    let (_code_verifier, code_challenge) = generate_pkce_pair();

    // Authorize
    let authorize_resp = cli_authorize_request(&app, &session, &code_challenge, "S256").await;
    assert_eq!(authorize_resp.status(), StatusCode::OK);
    let authorize_body = body_json(authorize_resp).await;
    let code = authorize_body["code"].as_str().unwrap();

    // Token exchange with WRONG code_verifier
    let exchange_resp = cli_token_exchange_request(&app, code, "completely-wrong-verifier").await;
    assert_eq!(
        exchange_resp.status(),
        StatusCode::UNAUTHORIZED,
        "Wrong code_verifier should return 401"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Token exchange with used authorization code → 401 (replay)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cli_pkce_replay_prevention() {
    let _ = IdGenerator::init(702);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "Carol CLI", "carol-cli@example.com", "Password123!").await;

    let (code_verifier, code_challenge) = generate_pkce_pair();

    // Authorize
    let authorize_resp = cli_authorize_request(&app, &session, &code_challenge, "S256").await;
    assert_eq!(authorize_resp.status(), StatusCode::OK);
    let authorize_body = body_json(authorize_resp).await;
    let code = authorize_body["code"].as_str().unwrap();

    // First exchange — should succeed
    let exchange_resp = cli_token_exchange_request(&app, code, &code_verifier).await;
    assert_eq!(exchange_resp.status(), StatusCode::OK, "First exchange should succeed");

    // Second exchange with same code — replay attack, should fail
    let replay_resp = cli_token_exchange_request(&app, code, &code_verifier).await;
    assert_eq!(
        replay_resp.status(),
        StatusCode::UNAUTHORIZED,
        "Replayed authorization code should return 401"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Token exchange with expired authorization code → 401
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cli_pkce_expired_authorization_code() {
    let _ = IdGenerator::init(703);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    let session = register_user(&app, "Dave CLI", "dave-cli@example.com", "Password123!").await;

    let (code_verifier, code_challenge) = generate_pkce_pair();

    // Authorize — get the code
    let authorize_resp = cli_authorize_request(&app, &session, &code_challenge, "S256").await;
    assert_eq!(authorize_resp.status(), StatusCode::OK);
    let authorize_body = body_json(authorize_resp).await;
    let code_str = authorize_body["code"].as_str().unwrap();

    // Manually expire the authorization code in storage
    let repos = RepositoryContext::new((*state.storage).clone());
    let mut auth_code = repos
        .authorization_code
        .get_by_code(code_str)
        .await
        .expect("Storage read should succeed")
        .expect("Authorization code should exist");

    // Set expires_at to the past
    auth_code.expires_at = chrono::Utc::now() - chrono::Duration::seconds(60);

    // Write the expired code back directly via storage (bypass is_valid check
    // in the repository's update method by writing the raw bytes)
    let code_key = format!("authz_code:{code_str}");
    let code_data = serde_json::to_vec(&auth_code).unwrap();
    state
        .storage
        .set_with_ttl(code_key.into_bytes(), code_data, std::time::Duration::from_secs(60))
        .await
        .unwrap();

    // Token exchange with expired code should fail
    let exchange_resp = cli_token_exchange_request(&app, code_str, &code_verifier).await;
    assert_eq!(
        exchange_resp.status(),
        StatusCode::UNAUTHORIZED,
        "Expired authorization code should return 401"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Authorize without valid session → 401
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cli_authorize_without_session() {
    let _ = IdGenerator::init(704);
    let state = create_test_state();
    let app = create_test_app(state);

    let (_code_verifier, code_challenge) = generate_pkce_pair();

    // Attempt to authorize without any session cookie
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/cli/authorize")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Authorize without session should return 401"
    );
}
