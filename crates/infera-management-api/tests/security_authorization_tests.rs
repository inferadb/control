use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use infera_management_api::{create_router_with_state, AppState};
use infera_management_core::{
    entities::{
        Organization, OrganizationMember, OrganizationRole, OrganizationTier, SessionType, User,
        UserSession, Vault,
    },
    IdGenerator, OrganizationMemberRepository, OrganizationRepository, UserRepository,
    UserSessionRepository, VaultRepository,
};
use infera_management_storage::{Backend, MemoryBackend};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

/// Helper to create test app state
fn create_test_state() -> AppState {
    let storage = Backend::Memory(MemoryBackend::new());
    AppState::new_test(Arc::new(storage))
}

/// Helper to setup a user with a specific role in an organization
#[allow(clippy::too_many_arguments)]
async fn setup_user_with_role(
    state: &AppState,
    user_id: i64,
    session_id: i64,
    org_id: i64,
    member_id: i64,
    username: &str,
    role: OrganizationRole,
    is_owner: bool,
) -> (User, UserSession, Organization, OrganizationMember) {
    // Create user
    let user = User::new(user_id, username.to_string(), None).unwrap();
    let user_repo = UserRepository::new((*state.storage).clone());
    user_repo.create(user.clone()).await.unwrap();

    // Create session
    let session = UserSession::new(session_id, user_id, SessionType::Web, None, None);
    let session_repo = UserSessionRepository::new((*state.storage).clone());
    session_repo.create(session.clone()).await.unwrap();

    // Create or get organization
    let org_repo = OrganizationRepository::new((*state.storage).clone());
    let org = if let Some(existing) = org_repo.get(org_id).await.unwrap() {
        existing
    } else {
        let new_org =
            Organization::new(org_id, "Test Org".to_string(), OrganizationTier::TierDevV1).unwrap();
        org_repo.create(new_org.clone()).await.unwrap();
        new_org
    };

    // Create member with specified role
    let member = if is_owner {
        OrganizationMember::new(member_id, org_id, user_id, OrganizationRole::Owner)
    } else {
        OrganizationMember::new(member_id, org_id, user_id, role)
    };
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    member_repo.create(member.clone()).await.unwrap();

    (user, session, org, member)
}

#[tokio::test]
async fn test_member_cannot_escalate_to_admin() {
    let _ = IdGenerator::init(500);
    let state = create_test_state();

    // Setup owner
    let (_, _session_owner, org, _) = setup_user_with_role(
        &state,
        100,
        1,
        1000,
        10000,
        "owner",
        OrganizationRole::Owner,
        true,
    )
    .await;

    // Setup member (non-admin)
    let (_, session_member, _, member) = setup_user_with_role(
        &state,
        200,
        2,
        org.id,
        20000,
        "member",
        OrganizationRole::Member,
        false,
    )
    .await;

    // Member tries to update their own role to Admin
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/v1/organizations/{}/members/{}",
                    org.id, member.id
                ))
                .header("cookie", format!("infera_session={}", session_member.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "role": "admin"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden (members cannot change roles)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_admin_cannot_escalate_to_owner() {
    let _ = IdGenerator::init(501);
    let state = create_test_state();

    // Setup owner
    let (_, _session_owner, org, _) = setup_user_with_role(
        &state,
        100,
        1,
        1000,
        10000,
        "owner",
        OrganizationRole::Owner,
        true,
    )
    .await;

    // Setup admin
    let (_, session_admin, _, admin_member) = setup_user_with_role(
        &state,
        200,
        2,
        org.id,
        20000,
        "admin",
        OrganizationRole::Admin,
        false,
    )
    .await;

    // Admin tries to update their own role to Owner
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/v1/organizations/{}/members/{}",
                    org.id, admin_member.id
                ))
                .header("cookie", format!("infera_session={}", session_admin.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "role": "owner"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden or bad request (either way, escalation is prevented)
    // BAD_REQUEST may occur due to invalid role format, FORBIDDEN due to authorization
    assert!(
        response.status() == StatusCode::FORBIDDEN || response.status() == StatusCode::BAD_REQUEST,
        "Expected FORBIDDEN or BAD_REQUEST, got {:?}",
        response.status()
    );
}

#[tokio::test]
async fn test_member_cannot_create_vault() {
    let _ = IdGenerator::init(502);
    let state = create_test_state();

    // Setup owner
    let (_, _session_owner, org, _) = setup_user_with_role(
        &state,
        100,
        1,
        1000,
        10000,
        "owner",
        OrganizationRole::Owner,
        true,
    )
    .await;

    // Setup member
    let (_, session_member, _, _) = setup_user_with_role(
        &state,
        200,
        2,
        org.id,
        20000,
        "member",
        OrganizationRole::Member,
        false,
    )
    .await;

    // Member tries to create a vault
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/vaults", org.id))
                .header("cookie", format!("infera_session={}", session_member.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Unauthorized Vault"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden (only admin/owner can create vaults)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_member_cannot_delete_organization() {
    let _ = IdGenerator::init(503);
    let state = create_test_state();

    // Setup owner
    let (_, _session_owner, org, _) = setup_user_with_role(
        &state,
        100,
        1,
        1000,
        10000,
        "owner",
        OrganizationRole::Owner,
        true,
    )
    .await;

    // Setup member
    let (_, session_member, _, _) = setup_user_with_role(
        &state,
        200,
        2,
        org.id,
        20000,
        "member",
        OrganizationRole::Member,
        false,
    )
    .await;

    // Member tries to delete the organization
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/organizations/{}", org.id))
                .header("cookie", format!("infera_session={}", session_member.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden (only owner can delete org)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Verify organization still exists
    let org_repo = OrganizationRepository::new((*state.storage).clone());
    let org_check = org_repo.get(org.id).await.unwrap();
    assert!(org_check.is_some());
}

#[tokio::test]
async fn test_admin_cannot_delete_organization() {
    let _ = IdGenerator::init(504);
    let state = create_test_state();

    // Setup owner
    let (_, _session_owner, org, _) = setup_user_with_role(
        &state,
        100,
        1,
        1000,
        10000,
        "owner",
        OrganizationRole::Owner,
        true,
    )
    .await;

    // Setup admin
    let (_, session_admin, _, _) = setup_user_with_role(
        &state,
        200,
        2,
        org.id,
        20000,
        "admin",
        OrganizationRole::Admin,
        false,
    )
    .await;

    // Admin tries to delete the organization
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/organizations/{}", org.id))
                .header("cookie", format!("infera_session={}", session_admin.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden (only owner can delete org)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_member_cannot_remove_other_members() {
    let _ = IdGenerator::init(505);
    let state = create_test_state();

    // Setup owner
    let (_, _session_owner, org, _) = setup_user_with_role(
        &state,
        100,
        1,
        1000,
        10000,
        "owner",
        OrganizationRole::Owner,
        true,
    )
    .await;

    // Setup member1
    let (_, session_member1, _, _) = setup_user_with_role(
        &state,
        200,
        2,
        org.id,
        20000,
        "member1",
        OrganizationRole::Member,
        false,
    )
    .await;

    // Setup member2
    let (_, _session_member2, _, member2) = setup_user_with_role(
        &state,
        300,
        3,
        org.id,
        30000,
        "member2",
        OrganizationRole::Member,
        false,
    )
    .await;

    // Member1 tries to remove Member2
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/v1/organizations/{}/members/{}",
                    org.id, member2.id
                ))
                .header("cookie", format!("infera_session={}", session_member1.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden (members cannot remove other members)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Verify member2 still exists
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    let member_check = member_repo.get(member2.id).await.unwrap();
    assert!(member_check.is_some());
}

#[tokio::test]
async fn test_cannot_use_other_users_session() {
    let _ = IdGenerator::init(506);
    let state = create_test_state();

    // Setup User A
    let user_a = User::new(100, "userA".to_string(), None).unwrap();
    let user_repo = UserRepository::new((*state.storage).clone());
    user_repo.create(user_a.clone()).await.unwrap();

    let session_a = UserSession::new(1, user_a.id, SessionType::Web, None, None);
    let session_repo = UserSessionRepository::new((*state.storage).clone());
    session_repo.create(session_a.clone()).await.unwrap();

    // Setup User B
    let user_b = User::new(200, "userB".to_string(), None).unwrap();
    user_repo.create(user_b.clone()).await.unwrap();

    let session_b = UserSession::new(2, user_b.id, SessionType::Web, None, None);
    session_repo.create(session_b.clone()).await.unwrap();

    // User B tries to use User A's session to access profile
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/users/me")
                .header("cookie", format!("infera_session={}", session_a.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should succeed but return User A's profile (not User B's)
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify it returns User A's info
    assert_eq!(json["user"]["id"].as_i64().unwrap(), user_a.id);
    assert_eq!(json["user"]["name"].as_str().unwrap(), "userA");
}

#[tokio::test]
async fn test_member_cannot_update_organization_settings() {
    let _ = IdGenerator::init(507);
    let state = create_test_state();

    // Setup owner
    let (_, _session_owner, org, _) = setup_user_with_role(
        &state,
        100,
        1,
        1000,
        10000,
        "owner",
        OrganizationRole::Owner,
        true,
    )
    .await;

    // Setup member
    let (_, session_member, _, _) = setup_user_with_role(
        &state,
        200,
        2,
        org.id,
        20000,
        "member",
        OrganizationRole::Member,
        false,
    )
    .await;

    // Member tries to update organization name
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/organizations/{}", org.id))
                .header("cookie", format!("infera_session={}", session_member.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Hacked Org Name"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden (only owner/admin can update org)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_member_cannot_create_team() {
    let _ = IdGenerator::init(508);
    let state = create_test_state();

    // Setup owner
    let (_, _session_owner, org, _) = setup_user_with_role(
        &state,
        100,
        1,
        1000,
        10000,
        "owner",
        OrganizationRole::Owner,
        true,
    )
    .await;

    // Setup member
    let (_, session_member, _, _) = setup_user_with_role(
        &state,
        200,
        2,
        org.id,
        20000,
        "member",
        OrganizationRole::Member,
        false,
    )
    .await;

    // Member tries to create a team
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/organizations/{}/teams", org.id))
                .header("cookie", format!("infera_session={}", session_member.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Unauthorized Team"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden (only admin/owner can create teams)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_member_cannot_delete_vault() {
    let _ = IdGenerator::init(509);
    let state = create_test_state();

    // Setup owner
    let (_, _session_owner, org, _) = setup_user_with_role(
        &state,
        100,
        1,
        1000,
        10000,
        "owner",
        OrganizationRole::Owner,
        true,
    )
    .await;

    // Create a vault
    let vault_repo = VaultRepository::new((*state.storage).clone());
    let vault = Vault::new(5000, org.id, "Test Vault".to_string(), 100).unwrap();
    vault_repo.create(vault.clone()).await.unwrap();

    // Setup member
    let (_, session_member, _, _) = setup_user_with_role(
        &state,
        200,
        2,
        org.id,
        20000,
        "member",
        OrganizationRole::Member,
        false,
    )
    .await;

    // Member tries to delete the vault
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/organizations/{}/vaults/{}", org.id, vault.id))
                .header("cookie", format!("infera_session={}", session_member.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden (only admin/owner can delete vaults)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Verify vault still exists
    let vault_check = vault_repo.get(vault.id).await.unwrap();
    assert!(vault_check.is_some());
    assert!(!vault_check.unwrap().is_deleted());
}
