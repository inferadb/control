use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_api::{AppState, create_router_with_state};
use inferadb_control_core::{
    IdGenerator, OrganizationMemberRepository, OrganizationRepository, UserRepository,
    UserSessionRepository,
};
use inferadb_control_test_fixtures::create_test_state;
use inferadb_control_types::entities::{
    Organization, OrganizationMember, OrganizationRole, OrganizationTier, SessionType, User,
    UserSession,
};
use serde_json::json;
use tower::ServiceExt;

/// Helper to setup a user with organization
async fn setup_user_and_org(
    state: &AppState,
    user_id: i64,
    session_id: i64,
    org_id: i64,
    member_id: i64,
) -> (User, UserSession, Organization) {
    let user = User::builder().id(user_id).name("testuser").create().unwrap();
    let user_repo = UserRepository::new((*state.storage).clone());
    user_repo.create(user.clone()).await.unwrap();

    let session = UserSession::builder()
        .id(session_id)
        .user_id(user_id)
        .session_type(SessionType::Web)
        .create();
    let session_repo = UserSessionRepository::new((*state.storage).clone());
    session_repo.create(session.clone()).await.unwrap();

    let org = Organization::builder()
        .id(org_id)
        .name("Test Org")
        .tier(OrganizationTier::TierDevV1)
        .create()
        .unwrap();
    let org_repo = OrganizationRepository::new((*state.storage).clone());
    org_repo.create(org.clone()).await.unwrap();

    let member = OrganizationMember::new(member_id, org_id, user_id, OrganizationRole::Owner);
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    member_repo.create(member).await.unwrap();

    (user, session, org)
}

// =============================================================================
// XSS Prevention Tests
// =============================================================================

#[tokio::test]
async fn test_xss_in_organization_name_rejected() {
    let _ = IdGenerator::init(600);
    let state = create_test_state();
    let (_, session, _) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    // Try to create organization with XSS payload in name
    let xss_payloads = vec![
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
        "<svg onload=alert('xss')>",
        "';alert('xss');//",
    ];

    for payload in xss_payloads {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/control/v1/organizations")
                    .header("cookie", format!("infera_session={}", session.id))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": payload
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should be rejected with bad request (validation error)
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "XSS payload should be rejected: {payload}"
        );
    }
}

#[tokio::test]
async fn test_xss_in_vault_name_rejected() {
    let _ = IdGenerator::init(601);
    let state = create_test_state();
    let (_, session, org) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{}/vaults", org.id))
                .header("cookie", format!("infera_session={}", session.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "<script>alert('xss')</script>"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be rejected
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_xss_in_team_name_rejected() {
    let _ = IdGenerator::init(602);
    let state = create_test_state();
    let (_, session, org) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{}/teams", org.id))
                .header("cookie", format!("infera_session={}", session.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "<img src=x onerror=alert('xss')>"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be rejected
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_xss_in_client_name_handled_safely() {
    let _ = IdGenerator::init(603);
    let state = create_test_state();
    let (_, session, org) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    let xss_name = "javascript:alert('xss')";
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{}/clients", org.id))
                .header("cookie", format!("infera_session={}", session.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": xss_name
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // For JSON APIs, XSS patterns can be stored as-is since they don't execute in the API
    // The key is that they're returned as JSON (not HTML) and frontends must escape when rendering
    // So we accept either CREATED (stored safely) or BAD_REQUEST (rejected)
    assert!(
        response.status() == StatusCode::CREATED || response.status() == StatusCode::BAD_REQUEST,
        "XSS input should either be stored safely or rejected, got {:?}",
        response.status()
    );

    // If it was created, verify the data is returned correctly as JSON (not executed)
    if response.status() == StatusCode::CREATED {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Verify the XSS string is returned as-is in JSON (safe)
        assert_eq!(json["client"]["name"].as_str().unwrap(), xss_name);
    }
}

// =============================================================================
// Path Traversal Prevention Tests
// =============================================================================

#[tokio::test]
async fn test_path_traversal_in_organization_name_rejected() {
    let _ = IdGenerator::init(604);
    let state = create_test_state();
    let (_, session, _) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    let path_traversal_payloads = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f",
        "..%252f..%252f",
    ];

    for payload in path_traversal_payloads {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/control/v1/organizations")
                    .header("cookie", format!("infera_session={}", session.id))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": payload
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should be rejected
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Path traversal payload should be rejected: {payload}"
        );
    }
}

#[tokio::test]
async fn test_null_byte_injection_rejected() {
    let _ = IdGenerator::init(605);
    let state = create_test_state();
    let (_, session, _) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/organizations")
                .header("cookie", format!("infera_session={}", session.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "test\0null"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be rejected
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// =============================================================================
// Boundary Condition Tests
// =============================================================================

#[tokio::test]
async fn test_empty_organization_name_rejected() {
    let _ = IdGenerator::init(606);
    let state = create_test_state();
    let (_, session, _) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/organizations")
                .header("cookie", format!("infera_session={}", session.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": ""
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be rejected
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_whitespace_only_name_rejected() {
    let _ = IdGenerator::init(607);
    let state = create_test_state();
    let (_, session, _) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    let whitespace_inputs = vec!["   ", "\t\t", "\n\n", "  \t\n  "];

    for input in whitespace_inputs {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/control/v1/organizations")
                    .header("cookie", format!("infera_session={}", session.id))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": input
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should be rejected
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Whitespace-only input should be rejected: {input:?}"
        );
    }
}

#[tokio::test]
async fn test_excessively_long_name_rejected() {
    let _ = IdGenerator::init(608);
    let state = create_test_state();
    let (_, session, _) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    // Create a name that exceeds reasonable limits (256 characters)
    let long_name = "A".repeat(300);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/control/v1/organizations")
                .header("cookie", format!("infera_session={}", session.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": long_name
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be rejected
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_unicode_edge_cases_handled() {
    let _ = IdGenerator::init(609);
    let state = create_test_state();
    let (_, session, _) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    // Test various Unicode edge cases
    let unicode_inputs = vec![
        "Test\u{200B}Org",  // Zero-width space
        "Test\u{FEFF}Org",  // Zero-width no-break space
        "Test\u{202E}Org",  // Right-to-left override
        "\u{E0000}Test",    // Language tags
        "Test\u{1F4A9}Org", // Emoji (pile of poo)
    ];

    for input in unicode_inputs {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/control/v1/organizations")
                    .header("cookie", format!("infera_session={}", session.id))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": input
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // These should either succeed (if properly sanitized) or be rejected
        // The key is they shouldn't cause crashes or undefined behavior
        assert!(
            response.status() == StatusCode::CREATED
                || response.status() == StatusCode::BAD_REQUEST,
            "Unicode input should be handled safely: {input:?}"
        );
    }
}

#[tokio::test]
async fn test_sql_injection_patterns_rejected() {
    let _ = IdGenerator::init(610);
    let state = create_test_state();
    let (_, session, _) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    let sql_injection_payloads = vec![
        "'; DROP TABLE organizations;--",
        "1' OR '1'='1",
        "admin'--",
        "' UNION SELECT * FROM users--",
        "1; DELETE FROM organizations WHERE '1'='1",
    ];

    for payload in sql_injection_payloads {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/control/v1/organizations")
                    .header("cookie", format!("infera_session={}", session.id))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": payload
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should be rejected
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "SQL injection payload should be rejected: {payload}"
        );
    }
}

#[tokio::test]
async fn test_control_characters_rejected() {
    let _ = IdGenerator::init(611);
    let state = create_test_state();
    let (_, session, _) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    // Test various control characters
    let control_char_inputs = vec![
        "Test\x00Org",    // NULL
        "Test\x01Org",    // Start of heading
        "Test\x1BOrgOrg", // Escape
        "Test\x7FOrg",    // Delete
    ];

    for input in control_char_inputs {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/control/v1/organizations")
                    .header("cookie", format!("infera_session={}", session.id))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": input
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should be rejected
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Control character input should be rejected: {input:?}"
        );
    }
}

#[tokio::test]
async fn test_negative_pagination_values_rejected() {
    let _ = IdGenerator::init(612);
    let state = create_test_state();
    let (_, session, org) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    // Test negative limit
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{}/vaults?limit=-10", org.id))
                .header("cookie", format!("infera_session={}", session.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be bad request or the negative value gets clamped to positive
    assert!(response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::OK);

    // Test negative offset
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{}/vaults?offset=-5", org.id))
                .header("cookie", format!("infera_session={}", session.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be bad request or the negative value gets clamped to 0
    assert!(response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::OK);
}

#[tokio::test]
async fn test_excessive_pagination_limit_clamped() {
    let _ = IdGenerator::init(613);
    let state = create_test_state();
    let (_, session, org) = setup_user_and_org(&state, 100, 1, 1000, 10000).await;

    let app = create_router_with_state(state.clone());

    // Try to request more than max limit (100)
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/control/v1/organizations/{}/vaults?limit=1000", org.id))
                .header("cookie", format!("infera_session={}", session.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify limit was clamped to max (100)
    if let Some(pagination) = json.get("pagination") {
        assert_eq!(pagination["limit"].as_u64().unwrap(), 100);
    }
}
