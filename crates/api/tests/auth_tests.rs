#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for auth endpoints: registration atomicity, password
//! reset enumeration prevention, login, logout, verify-email, password-reset
//! confirm, and session cookie attribute verification.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::{IdGenerator, RepositoryContext};
use inferadb_control_storage::{Backend, BufferedBackend};
use inferadb_control_test_fixtures::{
    create_test_app, create_test_state, extract_session_cookie, register_user,
};
use inferadb_control_types::entities::{
    Organization, OrganizationMember, OrganizationRole, OrganizationTier, SessionType, User,
    UserEmail, UserEmailVerificationToken, UserSession,
};
use serde_json::json;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Test 1: Simulate partial failure — buffered writes dropped without commit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_registration_no_orphans_when_uncommitted() {
    let _ = IdGenerator::init(30);
    let backend = Backend::memory();

    // Simulate what the register handler does, but never commit
    {
        let buffered = BufferedBackend::new(backend.clone());
        let repos = RepositoryContext::new(buffered.clone());

        // Create user (1st entity)
        let user = User::builder()
            .id(IdGenerator::next_id())
            .name("Alice")
            .password_hash("argon2hash")
            .create()
            .unwrap();
        repos.user.create(user).await.unwrap();

        // Create email (2nd entity)
        let email = UserEmail::builder()
            .id(IdGenerator::next_id())
            .user_id(1)
            .email("alice@example.com")
            .primary(true)
            .create()
            .unwrap();
        repos.user_email.create(email).await.unwrap();

        // Create verification token (3rd entity)
        let token = UserEmailVerificationToken::builder()
            .id(IdGenerator::next_id())
            .user_email_id(2)
            .token(UserEmailVerificationToken::generate_token())
            .create()
            .unwrap();
        repos.user_email_verification_token.create(token).await.unwrap();

        // Simulate failure before session creation (4th entity) —
        // drop the buffered backend without calling commit()
    }

    // Verify nothing persisted on the real storage
    let repos = RepositoryContext::new(backend);
    assert!(
        !repos.user_email.is_email_in_use("alice@example.com").await.unwrap(),
        "Email should NOT be in use — registration was not committed"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Failed registration allows retry with the same email
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_failed_registration_allows_retry() {
    let _ = IdGenerator::init(31);
    let backend = Backend::memory();

    // First attempt: create entities but don't commit (simulating failure)
    {
        let buffered = BufferedBackend::new(backend.clone());
        let repos = RepositoryContext::new(buffered.clone());

        let user_id = IdGenerator::next_id();
        let email_id = IdGenerator::next_id();

        let user = User::builder().id(user_id).name("Bob").password_hash("hash").create().unwrap();
        repos.user.create(user).await.unwrap();

        let email = UserEmail::builder()
            .id(email_id)
            .user_id(user_id)
            .email("bob@example.com")
            .primary(true)
            .create()
            .unwrap();
        repos.user_email.create(email).await.unwrap();

        // Don't commit — simulating a crash or error
    }

    // Second attempt with the same email — should succeed
    let buffered = BufferedBackend::new(backend.clone());
    let repos = RepositoryContext::new(buffered.clone());

    let user_id = IdGenerator::next_id();
    let email_id = IdGenerator::next_id();

    let user = User::builder().id(user_id).name("Bob").password_hash("hash2").create().unwrap();
    repos.user.create(user).await.unwrap();

    let email = UserEmail::builder()
        .id(email_id)
        .user_id(user_id)
        .email("bob@example.com")
        .primary(true)
        .create()
        .unwrap();
    repos.user_email.create(email).await.unwrap();

    // This time, commit
    buffered.commit().await.unwrap();

    // Verify the second attempt persisted
    let verify_repos = RepositoryContext::new(backend);
    assert!(
        verify_repos.user_email.is_email_in_use("bob@example.com").await.unwrap(),
        "Email should be in use after successful retry"
    );
    assert!(
        verify_repos.user.get(user_id).await.unwrap().is_some(),
        "User should exist after successful retry"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Successful registration commits all 6 entities atomically
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_registration_commits_all_entities_atomically() {
    let _ = IdGenerator::init(32);
    let backend = Backend::memory();

    let buffered = BufferedBackend::new(backend.clone());
    let repos = RepositoryContext::new(buffered.clone());

    let user_id = IdGenerator::next_id();
    let email_id = IdGenerator::next_id();
    let session_id = IdGenerator::next_id();
    let token_id = IdGenerator::next_id();
    let org_id = IdGenerator::next_id();
    let member_id = IdGenerator::next_id();

    // 1. Create user
    let mut user =
        User::builder().id(user_id).name("Charlie").password_hash("hash").create().unwrap();
    user.accept_tos();
    repos.user.create(user).await.unwrap();

    // 2. Create email
    let email = UserEmail::builder()
        .id(email_id)
        .user_id(user_id)
        .email("charlie@example.com")
        .primary(true)
        .create()
        .unwrap();
    repos.user_email.create(email).await.unwrap();

    // 3. Create verification token
    let token = UserEmailVerificationToken::builder()
        .id(token_id)
        .user_email_id(email_id)
        .token(UserEmailVerificationToken::generate_token())
        .create()
        .unwrap();
    repos.user_email_verification_token.create(token).await.unwrap();

    // 4. Create session
    let session = UserSession::builder()
        .id(session_id)
        .user_id(user_id)
        .session_type(SessionType::Web)
        .create();
    repos.user_session.create(session).await.unwrap();

    // 5. Create organization
    let org = Organization::builder()
        .id(org_id)
        .name("Charlie's Org")
        .tier(OrganizationTier::TierDevV1)
        .create()
        .unwrap();
    repos.org.create(org).await.unwrap();

    // 6. Create org member
    let member = OrganizationMember::new(member_id, org_id, user_id, OrganizationRole::Owner);
    repos.org_member.create(member).await.unwrap();

    // Before commit: nothing on real storage
    let pre_repos = RepositoryContext::new(backend.clone());
    assert!(
        pre_repos.user.get(user_id).await.unwrap().is_none(),
        "User should NOT exist before commit"
    );
    assert!(
        !pre_repos.user_email.is_email_in_use("charlie@example.com").await.unwrap(),
        "Email should NOT be in use before commit"
    );

    // Commit atomically
    buffered.commit().await.unwrap();

    // After commit: all 6 entities exist
    let post_repos = RepositoryContext::new(backend);
    assert!(
        post_repos.user.get(user_id).await.unwrap().is_some(),
        "User should exist after commit"
    );
    assert!(
        post_repos.user_email.is_email_in_use("charlie@example.com").await.unwrap(),
        "Email should be in use after commit"
    );
    assert!(
        post_repos.user_session.get(session_id).await.unwrap().is_some(),
        "Session should exist after commit"
    );
    assert!(
        post_repos.org.get(org_id).await.unwrap().is_some(),
        "Organization should exist after commit"
    );
    assert!(
        post_repos.org_member.get(member_id).await.unwrap().is_some(),
        "Org member should exist after commit"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Full HTTP endpoint — registration still works end-to-end
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_register_endpoint_success() {
    let _ = IdGenerator::init(33);
    let state = create_test_state();
    let app = create_test_app(state);

    let session = register_user(&app, "Diana", "diana@example.com", "strong-password-123").await;
    assert!(!session.is_empty(), "Session cookie should be returned");
}

// ---------------------------------------------------------------------------
// Test 5: Full HTTP endpoint — duplicate email is rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_register_endpoint_duplicate_email_rejected() {
    let _ = IdGenerator::init(34);
    let state = create_test_state();
    let app = create_test_app(state);

    // First registration succeeds
    register_user(&app, "Eve", "eve@example.com", "password-123").await;

    // Second registration with same email fails
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Eve Clone",
                        "email": "eve@example.com",
                        "password": "another-password-456"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Duplicate email should be rejected");
}

// ===========================================================================
// Task 4: Password reset email enumeration prevention
// ===========================================================================

/// Helper: send a password reset request and return (status, response body).
async fn request_password_reset(
    app: &axum::Router,
    email: &str,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/password-reset/request")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "email": email }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, json)
}

// ---------------------------------------------------------------------------
// Test 6: All four password-reset cases return the same 200 response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_password_reset_no_email_enumeration() {
    let _ = IdGenerator::init(36);
    let backend = Backend::memory();
    let state = inferadb_control_api::handlers::auth::AppState::new_test(Arc::new(backend.clone()));
    let app = create_test_app(state);

    // Register a user — email is unverified by default
    let _session = register_user(&app, "Frank", "frank@example.com", "strong-password-123").await;

    // Manually verify the email for a second user to get a "valid" case
    let repos = RepositoryContext::new(backend.clone());
    let mut email = repos.user_email.get_by_email("frank@example.com").await.unwrap().unwrap();
    let user_id = email.user_id;
    email.verify();
    repos.user_email.update(email).await.unwrap();

    // Register another user whose email stays unverified
    let _session2 = register_user(&app, "Gina", "gina@example.com", "strong-password-456").await;

    // Register and soft-delete a third user
    let _session3 = register_user(&app, "Hank", "hank@example.com", "strong-password-789").await;
    let mut hank_email = repos.user_email.get_by_email("hank@example.com").await.unwrap().unwrap();
    let hank_user_id = hank_email.user_id;
    hank_email.verify();
    repos.user_email.update(hank_email).await.unwrap();
    let mut hank = repos.user.get(hank_user_id).await.unwrap().unwrap();
    hank.soft_delete();
    repos.user.update(hank).await.unwrap();

    // Case 1: Non-existent email
    let (status1, body1) = request_password_reset(&app, "nobody@example.com").await;

    // Case 2: Unverified email
    let (status2, body2) = request_password_reset(&app, "gina@example.com").await;

    // Case 3: Deleted user (email verified)
    let (status3, body3) = request_password_reset(&app, "hank@example.com").await;

    // Case 4: Valid email (verified, active user)
    let (status4, body4) = request_password_reset(&app, "frank@example.com").await;

    // All four must return identical status and response shape
    assert_eq!(status1, StatusCode::OK, "Non-existent email should return 200");
    assert_eq!(status2, StatusCode::OK, "Unverified email should return 200");
    assert_eq!(status3, StatusCode::OK, "Deleted user should return 200");
    assert_eq!(status4, StatusCode::OK, "Valid email should return 200");

    assert_eq!(body1, body2, "Response bodies must be identical (non-existent vs unverified)");
    assert_eq!(body2, body3, "Response bodies must be identical (unverified vs deleted)");
    assert_eq!(body3, body4, "Response bodies must be identical (deleted vs valid)");

    // Verify a reset token was created ONLY for the valid case
    let frank_tokens = repos.user_password_reset_token.get_by_user(user_id).await.unwrap();
    assert_eq!(frank_tokens.len(), 1, "One reset token should exist for the valid user");
}

// ---------------------------------------------------------------------------
// Test 7: Valid password reset still works end-to-end after enumeration fix
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_password_reset_end_to_end_after_enumeration_fix() {
    let _ = IdGenerator::init(37);
    let backend = Backend::memory();
    let state = inferadb_control_api::handlers::auth::AppState::new_test(Arc::new(backend.clone()));
    let app = create_test_app(state);

    // Register and verify email
    let _session = register_user(&app, "Iris", "iris@example.com", "old-password-123").await;
    let repos = RepositoryContext::new(backend.clone());
    let mut email = repos.user_email.get_by_email("iris@example.com").await.unwrap().unwrap();
    let user_id = email.user_id;
    email.verify();
    repos.user_email.update(email).await.unwrap();

    // Request password reset
    let (status, _) = request_password_reset(&app, "iris@example.com").await;
    assert_eq!(status, StatusCode::OK);

    // Retrieve the token from storage and confirm the reset
    let tokens = repos.user_password_reset_token.get_by_user(user_id).await.unwrap();
    assert_eq!(tokens.len(), 1);
    let reset_token = tokens[0].secure_token.token.clone();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/password-reset/confirm")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "token": reset_token,
                        "new_password": "new-password-456"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "Password reset confirm should succeed");

    // Login with the new password
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/login/password")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": "iris@example.com",
                        "password": "new-password-456"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "Login with new password should succeed");
}

// ===========================================================================
// Task 23: Auth endpoint integration tests through the full router
// ===========================================================================

/// Helper: send a login request and return the full response.
async fn login_request(
    app: &axum::Router,
    email: &str,
    password: &str,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/login/password")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper: send a logout request with the given session cookie.
async fn logout_request(app: &axum::Router, session_cookie: &str) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/logout")
                .header("cookie", format!("infera_session={session_cookie}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper: verify an email token via the API.
async fn verify_email_request(app: &axum::Router, token: &str) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/verify-email")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "token": token }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper: extract the full Set-Cookie header value for the session cookie.
fn extract_set_cookie_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|s| s.starts_with("infera_session="))
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Test 8: Login with valid credentials returns 200 + session cookie
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_login_valid_credentials() {
    let _ = IdGenerator::init(44);
    let state = create_test_state();
    let app = create_test_app(state);

    register_user(&app, "LoginUser", "login@example.com", "strong-password-123").await;

    let response = login_request(&app, "login@example.com", "strong-password-123").await;

    assert_eq!(response.status(), StatusCode::OK, "Login should succeed");

    let session = extract_session_cookie(response.headers());
    assert!(session.is_some(), "Session cookie should be set on login");

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("user_id").is_some(), "Response should contain user_id");
    assert!(json.get("session_id").is_some(), "Response should contain session_id");
}

// ---------------------------------------------------------------------------
// Test 9: Login with wrong password returns 401
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_login_wrong_password() {
    let _ = IdGenerator::init(45);
    let state = create_test_state();
    let app = create_test_app(state);

    register_user(&app, "WrongPw", "wrongpw@example.com", "strong-password-123").await;

    let response = login_request(&app, "wrongpw@example.com", "completely-wrong-pw").await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "Wrong password should return 401");
}

// ---------------------------------------------------------------------------
// Test 10: Login with non-existent email returns 401 (same as wrong password)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_login_nonexistent_email() {
    let _ = IdGenerator::init(46);
    let state = create_test_state();
    let app = create_test_app(state);

    let response = login_request(&app, "nobody@example.com", "any-password-here").await;

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Non-existent email should return 401 (same as wrong password)"
    );
}

// ---------------------------------------------------------------------------
// Test 11: Login error messages are identical for wrong password vs
//          non-existent email (no user enumeration)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_login_no_user_enumeration() {
    let _ = IdGenerator::init(47);
    let state = create_test_state();
    let app = create_test_app(state);

    register_user(&app, "EnumUser", "enum@example.com", "strong-password-123").await;

    // Wrong password for existing user
    let resp_wrong_pw = login_request(&app, "enum@example.com", "wrong-password-xxx").await;
    let body_wrong_pw = axum::body::to_bytes(resp_wrong_pw.into_body(), usize::MAX).await.unwrap();

    // Non-existent email
    let resp_no_user = login_request(&app, "ghost@example.com", "any-password-123").await;
    let body_no_user = axum::body::to_bytes(resp_no_user.into_body(), usize::MAX).await.unwrap();

    let json_wrong: serde_json::Value = serde_json::from_slice(&body_wrong_pw).unwrap();
    let json_ghost: serde_json::Value = serde_json::from_slice(&body_no_user).unwrap();

    // Error responses should be identical to prevent enumeration
    assert_eq!(
        json_wrong.get("error"),
        json_ghost.get("error"),
        "Error messages must be identical for wrong-pw vs non-existent email"
    );
}

// ---------------------------------------------------------------------------
// Test 12: Logout clears session cookie
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_logout_clears_session() {
    let _ = IdGenerator::init(48);
    let state = create_test_state();
    let app = create_test_app(state);

    let session =
        register_user(&app, "LogoutUser", "logout@example.com", "strong-password-123").await;

    let response = logout_request(&app, &session).await;
    assert_eq!(response.status(), StatusCode::OK, "Logout should return 200");

    // The Set-Cookie header should indicate cookie removal (empty value or
    // max-age=0)
    let cookie_header = extract_set_cookie_header(response.headers());
    assert!(
        cookie_header.is_some(),
        "Logout response should set a cookie header to clear the session"
    );
    let cookie_str = cookie_header.unwrap();
    // axum/tower_cookies clears cookies by setting them to empty or with
    // max-age=0
    let cleared = cookie_str.contains("infera_session=;")
        || cookie_str.contains("infera_session=\"\"")
        || cookie_str.contains("Max-Age=0");
    assert!(cleared, "Session cookie should be cleared on logout, got: {cookie_str}");
}

// ---------------------------------------------------------------------------
// Test 13: Using a logged-out session for an authenticated request fails
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_logged_out_session_is_invalid() {
    let _ = IdGenerator::init(49);
    let backend = Backend::memory();
    let state = inferadb_control_api::handlers::auth::AppState::new_test(Arc::new(backend.clone()));
    let app = create_test_app(state);

    let session =
        register_user(&app, "Revoked", "revoked@example.com", "strong-password-123").await;

    // Logout
    logout_request(&app, &session).await;

    // Try to access a protected endpoint with the old session
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

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "Revoked session should be rejected");
}

// ---------------------------------------------------------------------------
// Test 14: Verify email with valid token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_verify_email_valid_token() {
    let _ = IdGenerator::init(50);
    let backend = Backend::memory();
    let state = inferadb_control_api::handlers::auth::AppState::new_test(Arc::new(backend.clone()));
    let app = create_test_app(state);

    register_user(&app, "VerifyMe", "verifyme@example.com", "strong-password-123").await;

    // Fetch the verification token from storage
    let repos = RepositoryContext::new(backend.clone());
    let email = repos.user_email.get_by_email("verifyme@example.com").await.unwrap().unwrap();
    let tokens = repos.user_email_verification_token.get_by_email(email.id).await.unwrap();
    assert!(!tokens.is_empty(), "Verification token should exist after registration");
    let token_value = tokens[0].secure_token.token.clone();

    let response = verify_email_request(&app, &token_value).await;
    assert_eq!(response.status(), StatusCode::OK, "Verify email should succeed");

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json.get("email").and_then(|v| v.as_str()),
        Some("verifyme@example.com"),
        "Response should contain the verified email"
    );

    // Verify the email is now marked as verified in storage
    let updated_email =
        repos.user_email.get_by_email("verifyme@example.com").await.unwrap().unwrap();
    assert!(updated_email.is_verified(), "Email should be verified in storage");
}

// ---------------------------------------------------------------------------
// Test 15: Verify email with invalid token returns 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_verify_email_invalid_token() {
    let _ = IdGenerator::init(51);
    let state = create_test_state();
    let app = create_test_app(state);

    let response = verify_email_request(&app, "not-a-real-token-at-all").await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Invalid verification token should return 400"
    );
}

// ---------------------------------------------------------------------------
// Test 16: Verify email with expired/used token returns 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_verify_email_used_token_rejected() {
    let _ = IdGenerator::init(52);
    let backend = Backend::memory();
    let state = inferadb_control_api::handlers::auth::AppState::new_test(Arc::new(backend.clone()));
    let app = create_test_app(state);

    register_user(&app, "UsedToken", "usedtoken@example.com", "strong-password-123").await;

    let repos = RepositoryContext::new(backend.clone());
    let email = repos.user_email.get_by_email("usedtoken@example.com").await.unwrap().unwrap();
    let tokens = repos.user_email_verification_token.get_by_email(email.id).await.unwrap();
    let token_value = tokens[0].secure_token.token.clone();

    // First verification succeeds
    let resp1 = verify_email_request(&app, &token_value).await;
    assert_eq!(resp1.status(), StatusCode::OK);

    // Second verification with same (now used) token: the handler checks
    // token validity first (used → "Invalid or expired" via `error` field) OR
    // email already verified (200 via `message` field). Both are acceptable.
    let resp2 = verify_email_request(&app, &token_value).await;
    let status2 = resp2.status();
    let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX).await.unwrap();
    let json2: serde_json::Value = serde_json::from_slice(&body2).unwrap();

    // Success responses use "message", error responses use "error"
    let msg =
        json2.get("message").or_else(|| json2.get("error")).and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        (status2 == StatusCode::OK && msg.contains("already verified"))
            || (status2 == StatusCode::BAD_REQUEST && msg.contains("Invalid or expired")),
        "Reusing a token should indicate already verified or invalid, got status={status2} msg={msg}"
    );
}

// ---------------------------------------------------------------------------
// Test 17: Password reset confirm with invalid token returns 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_password_reset_confirm_invalid_token() {
    let _ = IdGenerator::init(53);
    let state = create_test_state();
    let app = create_test_app(state);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/password-reset/confirm")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "token": "completely-bogus-token",
                        "new_password": "new-password-456"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Invalid reset token should return 400");
}

// ---------------------------------------------------------------------------
// Test 18: Password reset confirm revokes all sessions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_password_reset_confirm_revokes_sessions() {
    let _ = IdGenerator::init(54);
    let backend = Backend::memory();
    let state = inferadb_control_api::handlers::auth::AppState::new_test(Arc::new(backend.clone()));
    let app = create_test_app(state);

    // Register and verify email
    let session =
        register_user(&app, "SessionRevoke", "sessrevoke@example.com", "old-password-123").await;

    let repos = RepositoryContext::new(backend.clone());
    let mut email = repos.user_email.get_by_email("sessrevoke@example.com").await.unwrap().unwrap();
    email.verify();
    repos.user_email.update(email).await.unwrap();

    // Request and confirm password reset
    request_password_reset(&app, "sessrevoke@example.com").await;

    let user_email =
        repos.user_email.get_by_email("sessrevoke@example.com").await.unwrap().unwrap();
    let tokens = repos.user_password_reset_token.get_by_user(user_email.user_id).await.unwrap();
    let reset_token = tokens[0].secure_token.token.clone();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/password-reset/confirm")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "token": reset_token,
                        "new_password": "new-password-456"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Old session should be revoked
    let me_response = app
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
    assert_eq!(
        me_response.status(),
        StatusCode::UNAUTHORIZED,
        "Old session should be revoked after password reset"
    );

    // Login with the new password should work
    let login_resp = login_request(&app, "sessrevoke@example.com", "new-password-456").await;
    assert_eq!(login_resp.status(), StatusCode::OK, "Login with new password should succeed");
}

// ---------------------------------------------------------------------------
// Test 19: Session cookie has HttpOnly, Secure, and SameSite attributes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_session_cookie_attributes() {
    let _ = IdGenerator::init(55);
    let state = create_test_state();
    let app = create_test_app(state);

    // Register a user — this sets a session cookie
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "CookieTest",
                        "email": "cookietest@example.com",
                        "password": "strong-password-123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let cookie_header = extract_set_cookie_header(response.headers())
        .expect("Registration should set a session cookie");
    let cookie_lower = cookie_header.to_lowercase();

    assert!(
        cookie_lower.contains("httponly"),
        "Session cookie must have HttpOnly attribute, got: {cookie_header}"
    );
    assert!(
        cookie_lower.contains("secure"),
        "Session cookie must have Secure attribute, got: {cookie_header}"
    );
    assert!(
        cookie_lower.contains("samesite=lax"),
        "Session cookie must have SameSite=Lax, got: {cookie_header}"
    );
    assert!(
        cookie_header.contains("Path=/"),
        "Session cookie should have Path=/, got: {cookie_header}"
    );
}

// ---------------------------------------------------------------------------
// Test 20: Login also sets correct cookie attributes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_login_cookie_attributes() {
    let _ = IdGenerator::init(56);
    let state = create_test_state();
    let app = create_test_app(state);

    register_user(&app, "LoginCookie", "logincookie@example.com", "strong-password-123").await;

    let response = login_request(&app, "logincookie@example.com", "strong-password-123").await;
    assert_eq!(response.status(), StatusCode::OK);

    let cookie_header =
        extract_set_cookie_header(response.headers()).expect("Login should set a session cookie");
    let cookie_lower = cookie_header.to_lowercase();

    assert!(
        cookie_lower.contains("httponly"),
        "Login session cookie must have HttpOnly, got: {cookie_header}"
    );
    assert!(
        cookie_lower.contains("secure"),
        "Login session cookie must have Secure, got: {cookie_header}"
    );
    assert!(
        cookie_lower.contains("samesite=lax"),
        "Login session cookie must have SameSite=Lax, got: {cookie_header}"
    );
}

// ---------------------------------------------------------------------------
// Test 21: Password reset request always returns 200 regardless of input
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_password_reset_request_always_200() {
    let _ = IdGenerator::init(57);
    let state = create_test_state();
    let app = create_test_app(state);

    let (status, _) = request_password_reset(&app, "nonexistent@example.com").await;
    assert_eq!(status, StatusCode::OK, "Password reset for unknown email must return 200");
}
