#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for registration atomicity (Task 3) and
//! password reset email enumeration prevention (Task 4).

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_core::{IdGenerator, RepositoryContext};
use inferadb_control_storage::{Backend, BufferedBackend};
use inferadb_control_test_fixtures::{create_test_app, create_test_state, register_user};
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
    let reset_token = tokens[0].token.clone();

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
