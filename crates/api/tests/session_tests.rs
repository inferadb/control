#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for session management endpoints.
//!
//! Tests `list`, `revoke`, and `revoke-others` session operations
//! through the full middleware stack.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_test_fixtures::{
    body_json, create_test_app, create_test_state, login_user, register_user,
};
use tower::ServiceExt;

#[tokio::test]
async fn test_list_sessions_shows_active_sessions() {
    let state = create_test_state();
    let app = create_test_app(state);

    let email = "session-list@test.com";
    let password = "test-password-123456";

    // Registration creates session 1
    let session = register_user(&app, "Session User", email, password).await;

    // Login creates session 2
    let _session2 = login_user(&app, email, password).await;

    // List sessions via first session
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

    let sessions = json["sessions"].as_array().expect("sessions should be an array");
    assert_eq!(sessions.len(), 2, "Should have 2 active sessions");
    assert_eq!(json["count"].as_u64().unwrap(), 2);
}

#[tokio::test]
async fn test_revoke_specific_session() {
    let state = create_test_state();
    let app = create_test_app(state);

    let email = "revoke-session@test.com";
    let password = "test-password-123456";

    // Registration creates session 1
    let session1 = register_user(&app, "Revoke User", email, password).await;

    // Login creates session 2
    let session2 = login_user(&app, email, password).await;

    // List sessions from session2 to determine all session IDs
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/sessions")
                .header("cookie", format!("infera_session={session2}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let sessions = json["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);

    // Collect all session IDs
    let all_ids: Vec<i64> = sessions.iter().map(|s| s["session_id"].as_i64().unwrap()).collect();

    // Revoke the first ID in the list using session1
    let target_id = all_ids[0];
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/users/sessions/{target_id}"))
                .header("cookie", format!("infera_session={session1}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert!(json["message"].as_str().unwrap().contains("revoked"));

    // Verify at least one session still works and only 1 remains
    // Try session1 first; if it was the one revoked, try session2
    let mut valid_session = None;
    for s in [&session1, &session2] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/control/v1/users/sessions")
                    .header("cookie", format!("infera_session={s}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        if response.status() == StatusCode::OK {
            let json = body_json(response).await;
            assert_eq!(
                json["count"].as_u64().unwrap(),
                1,
                "Should have 1 session after revocation"
            );
            valid_session = Some(s.clone());
            break;
        }
    }

    assert!(valid_session.is_some(), "At least one session should remain valid");
}

#[tokio::test]
async fn test_revoke_other_sessions() {
    let state = create_test_state();
    let app = create_test_app(state);

    let email = "revoke-others@test.com";
    let password = "test-password-123456";

    // Registration creates session 1
    let session1 = register_user(&app, "Others User", email, password).await;

    // Login creates sessions 2, 3, 4
    let _session2 = login_user(&app, email, password).await;
    let _session3 = login_user(&app, email, password).await;
    let current_session = login_user(&app, email, password).await;

    // Verify we have 4 sessions
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/sessions")
                .header("cookie", format!("infera_session={current_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["count"].as_u64().unwrap(), 4);

    // Revoke all other sessions (keep current)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/users/sessions/revoke-others")
                .header("cookie", format!("infera_session={current_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert!(
        json["message"].as_str().unwrap().contains("Revoked 3"),
        "Should say 'Revoked 3', got: {}",
        json["message"]
    );

    // Current session should still work and show only 1 session
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/sessions")
                .header("cookie", format!("infera_session={current_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["count"].as_u64().unwrap(), 1, "Only current session should remain");

    // Old sessions should be unauthorized
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/sessions")
                .header("cookie", format!("infera_session={session1}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "Revoked session should return 401");
}

#[tokio::test]
async fn test_cannot_revoke_another_users_session() {
    let state = create_test_state();
    let app = create_test_app(state);

    // Register two separate users
    let session_a = register_user(&app, "User A", "usera@test.com", "test-password-123456").await;
    let session_b = register_user(&app, "User B", "userb@test.com", "test-password-123456").await;

    // Get User A's session ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/sessions")
                .header("cookie", format!("infera_session={session_a}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let user_a_session_id = json["sessions"][0]["session_id"].as_i64().unwrap();

    // User B tries to revoke User A's session — should fail with 403
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/users/sessions/{user_a_session_id}"))
                .header("cookie", format!("infera_session={session_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Should not be able to revoke another user's session"
    );

    // Verify User A's session is still valid
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/sessions")
                .header("cookie", format!("infera_session={session_a}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["count"].as_u64().unwrap(), 1, "User A should still have 1 session");
}
