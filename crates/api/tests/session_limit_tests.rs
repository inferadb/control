#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for concurrent session limit enforcement.
//!
//! Verifies that `MAX_CONCURRENT_SESSIONS` (10) is enforced by evicting the
//! oldest session (by `last_activity_at`) when the limit is exceeded.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_test_fixtures::{
    body_json, create_test_app, create_test_state, login_user, register_user,
};
use tower::ServiceExt;

/// Helper to check if a session is valid by hitting a protected endpoint.
async fn session_is_valid(app: &axum::Router, session: &str) -> bool {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/sessions")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    response.status() == StatusCode::OK
}

/// Helper to list sessions and return the count.
async fn list_session_count(app: &axum::Router, session: &str) -> usize {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/sessions")
                .header("cookie", format!("infera_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    json["sessions"].as_array().expect("sessions should be an array").len()
}

#[tokio::test]
async fn test_session_eviction_on_limit_exceeded() {
    let state = create_test_state();
    let app = create_test_app(state);

    let email = "session-limit@test.com";
    let password = "test-password-123456";

    // Registration creates the first session
    let session_0 = register_user(&app, "Session User", email, password).await;

    // Create 9 more sessions via login (total: 10 = MAX_CONCURRENT_SESSIONS)
    let mut sessions = vec![session_0];
    for _ in 1..10 {
        let session = login_user(&app, email, password).await;
        sessions.push(session);
    }

    // All 10 sessions should be valid
    for (i, session) in sessions.iter().enumerate() {
        assert!(
            session_is_valid(&app, session).await,
            "Session {i} should be valid before eviction"
        );
    }

    // Create the 11th session — should evict the oldest (session_0)
    let session_11 = login_user(&app, email, password).await;

    // Session 0 (the oldest) should be evicted
    assert!(
        !session_is_valid(&app, &sessions[0]).await,
        "Session 0 should be evicted after 11th session is created"
    );

    // Session 11 should be valid
    assert!(session_is_valid(&app, &session_11).await, "The 11th session should be valid");

    // Sessions 1-9 should still be valid
    for (i, session) in sessions.iter().enumerate().skip(1) {
        assert!(
            session_is_valid(&app, session).await,
            "Session {i} should still be valid after eviction of session 0"
        );
    }
}

#[tokio::test]
async fn test_list_sessions_respects_limit() {
    let state = create_test_state();
    let app = create_test_app(state);

    let email = "session-list@test.com";
    let password = "test-password-123456";

    // Registration creates the first session
    let _session_0 = register_user(&app, "List User", email, password).await;

    // Create 9 more sessions via login (total: 10)
    let mut last_session = String::new();
    for _ in 1..10 {
        last_session = login_user(&app, email, password).await;
    }

    // Should have exactly 10 sessions
    assert_eq!(list_session_count(&app, &last_session).await, 10);

    // Create the 11th session — evicts the oldest
    let session_11 = login_user(&app, email, password).await;

    // Should still have at most 10 sessions
    assert_eq!(list_session_count(&app, &session_11).await, 10);
}

#[tokio::test]
async fn test_multiple_evictions() {
    let state = create_test_state();
    let app = create_test_app(state);

    let email = "multi-evict@test.com";
    let password = "test-password-123456";

    // Registration creates session 0
    let session_0 = register_user(&app, "Multi Evict", email, password).await;

    // Create 9 more sessions (total: 10)
    let mut sessions = vec![session_0];
    for _ in 1..10 {
        sessions.push(login_user(&app, email, password).await);
    }

    // Create 3 more sessions — should evict sessions 0, 1, 2
    for _ in 0..3 {
        sessions.push(login_user(&app, email, password).await);
    }

    // Sessions 0, 1, 2 should be evicted
    for (i, session) in sessions.iter().enumerate().take(3) {
        assert!(!session_is_valid(&app, session).await, "Session {i} should be evicted");
    }

    // Sessions 3-12 should still be valid (10 total)
    for (i, session) in sessions.iter().enumerate().take(13).skip(3) {
        assert!(session_is_valid(&app, session).await, "Session {i} should still be valid");
    }
}
