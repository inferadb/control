use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_api::AppState;
use inferadb_control_core::IdGenerator;
use inferadb_control_test_fixtures::{create_test_app, create_test_state, extract_session_cookie};
use serde_json::json;
use tower::ServiceExt;

/// Helper to verify a user's email (for testing)
async fn verify_user_email(state: &AppState, username: &str) {
    use inferadb_control_core::UserRepository;
    let user_repo = UserRepository::new((*state.storage).clone());
    let email_repo = inferadb_control_core::UserEmailRepository::new((*state.storage).clone());

    // Get the user
    let user = user_repo.get_by_name(username).await.unwrap().unwrap();

    // Get and verify the user's email
    let mut emails = email_repo.get_user_emails(user.id).await.unwrap();
    if let Some(email) = emails.first_mut() {
        email.verify();
        email_repo.update(email.clone()).await.unwrap();
    }
}

#[tokio::test]
async fn test_registration_creates_default_organization() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register a new user
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

    assert_eq!(response.status(), StatusCode::OK);

    // Extract session cookie
    let session_cookie =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // List organizations for the user
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/organizations")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify that the user has one organization with the same name
    let orgs = json["organizations"].as_array().expect("Should have organizations");
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0]["name"], "testuser");
    assert_eq!(orgs[0]["role"], "OWNER");
    assert_eq!(orgs[0]["tier"], "TIER_DEV_V1");
}

#[tokio::test]
async fn test_create_organization() {
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

    // Verify user's email (required to create organization)
    verify_user_email(&state, "testuser").await;

    // Create a new organization
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

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["organization"]["name"], "Test Organization");
    assert_eq!(json["organization"]["role"], "OWNER");
}

#[tokio::test]
async fn test_list_organizations() {
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

    // Verify user's email (required to create organization)
    verify_user_email(&state, "testuser").await;

    // Create another organization
    let _response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "name": "Second Organization"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // List organizations
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/organizations")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let orgs = json["organizations"].as_array().expect("Should have organizations");
    assert_eq!(orgs.len(), 2);
}

#[tokio::test]
async fn test_get_organization_details() {
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

    // Verify user's email (required to create organization)
    verify_user_email(&state, "testuser").await;

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

    // Get organization details
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}", org_id))
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["organization"]["id"], org_id);
    assert_eq!(json["organization"]["name"], "Test Organization");
}

#[tokio::test]
async fn test_update_organization() {
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

    // Verify user's email (required to create organization)
    verify_user_email(&state, "testuser").await;

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
                        "name": "Old Name"
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

    // Update organization
    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/organizations/{}", org_id))
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::from(
                    json!({
                        "name": "New Name"
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

    assert_eq!(json["organization"]["name"], "New Name");
}

#[tokio::test]
async fn test_delete_organization() {
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

    // Verify user's email (required to create organization)
    verify_user_email(&state, "testuser").await;

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

    // Delete organization
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/organizations/{}", org_id))
                .header("cookie", format!("infera_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_non_member_cannot_access_organization() {
    let _ = IdGenerator::init(1);
    let state = create_test_state();
    let app = create_test_app(state.clone());

    // Register first user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "user1",
                        "email": "user1@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session1 =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Verify user's email (required to create organization)
    verify_user_email(&state, "user1").await;

    // Create an organization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("cookie", format!("infera_session={}", session1))
                .body(Body::from(
                    json!({
                        "name": "User1 Org"
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

    // Register second user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "user2",
                        "email": "user2@example.com",
                        "password": "securepassword123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let session2 =
        extract_session_cookie(response.headers()).expect("Session cookie should be set");

    // Try to access the organization as user2
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}", org_id))
                .header("cookie", format!("infera_session={}", session2))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
