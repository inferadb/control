use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_management_core::IdGenerator;
use inferadb_management_test_fixtures::{
    create_test_app, create_test_state, extract_session_cookie,
};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn test_create_and_list_invitations() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register a user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "testuser",
                        "email": "test@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_cookie =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Verify the user's email by directly updating the database
    // (In production this would be done via the verification endpoint with a token)
    {
        use inferadb_management_core::UserRepository;
        let user_repo = UserRepository::new((*state.storage).clone());
        let email_repo =
            inferadb_management_core::UserEmailRepository::new((*state.storage).clone());

        // Get the user
        let user = user_repo.get_by_name("testuser").await.unwrap().unwrap();

        // Get and verify the user's email
        let mut emails = email_repo.get_user_emails(user.id).await.unwrap();
        if let Some(email) = emails.first_mut() {
            email.verify();
            email_repo.update(email.clone()).await.unwrap();
        }
    }

    // Create an organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "name": "Test Organization"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organization"]["id"].as_i64().unwrap();

    // Create an invitation
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/invitations", org_id))
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "email": "invite@example.com",
                        "role": "MEMBER"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["invitation"]["email"], "invite@example.com");
    assert_eq!(json["invitation"]["role"], "MEMBER");

    // List invitations
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/invitations", org_id))
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let invitations = json["invitations"].as_array().expect("Should have invitations");
    assert_eq!(invitations.len(), 1);
}

#[tokio::test]
async fn test_delete_invitation() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register and create org
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "testuser",
                        "email": "test@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_cookie =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Verify the user's email by directly updating the database
    // (In production this would be done via the verification endpoint with a token)
    {
        use inferadb_management_core::UserRepository;
        let user_repo = UserRepository::new((*state.storage).clone());
        let email_repo =
            inferadb_management_core::UserEmailRepository::new((*state.storage).clone());

        // Get the user
        let user = user_repo.get_by_name("testuser").await.unwrap().unwrap();

        // Get and verify the user's email
        let mut emails = email_repo.get_user_emails(user.id).await.unwrap();
        if let Some(email) = emails.first_mut() {
            email.verify();
            email_repo.update(email.clone()).await.unwrap();
        }
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "name": "Test Organization"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let org_id = json["organization"]["id"].as_i64().unwrap();

    // Create invitation
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/invitations", org_id))
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "email": "invite@example.com",
                        "role": "MEMBER"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let invitation_id = json["invitation"]["id"].as_i64().unwrap();

    // Delete invitation
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/organizations/{}/invitations/{}", org_id, invitation_id))
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify deletion
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/invitations", org_id))
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let invitations = json["invitations"].as_array().unwrap();
    assert_eq!(invitations.len(), 0);
}
