use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bon::Builder;
use inferadb_control_api::{AppState, create_router_with_state};
use inferadb_control_core::{
    IdGenerator, OrganizationMemberRepository, OrganizationRepository, UserRepository,
    UserSessionRepository, VaultRepository,
    entities::{
        Organization, OrganizationMember, OrganizationRole, OrganizationTier, SessionType, User,
        UserSession, Vault,
    },
};
use inferadb_control_test_fixtures::create_test_state;
use serde_json::json;
use tower::ServiceExt;

/// Parameters for setting up a user with a specific role in an organization
#[derive(Builder)]
#[builder(on(String, into))]
struct SetupUserParams<'a> {
    state: &'a AppState,
    user_id: i64,
    session_id: i64,
    org_id: i64,
    member_id: i64,
    username: String,
    role: OrganizationRole,
    is_owner: bool,
}

/// Helper to setup a user with a specific role in an organization
async fn setup_user_with_role(
    params: SetupUserParams<'_>,
) -> (User, UserSession, Organization, OrganizationMember) {
    let SetupUserParams { state, user_id, session_id, org_id, member_id, username, role, is_owner } =
        params;
    // Create user
    let user = User::builder().id(user_id).name(username).create().unwrap();
    let user_repo = UserRepository::new((*state.storage).clone());
    user_repo.create(user.clone()).await.unwrap();

    // Create session
    let session = UserSession::builder()
        .id(session_id)
        .user_id(user_id)
        .session_type(SessionType::Web)
        .create();
    let session_repo = UserSessionRepository::new((*state.storage).clone());
    session_repo.create(session.clone()).await.unwrap();

    // Create or get organization
    let org_repo = OrganizationRepository::new((*state.storage).clone());
    let org = if let Some(existing) = org_repo.get(org_id).await.unwrap() {
        existing
    } else {
        let new_org = Organization::builder()
            .id(org_id)
            .name("Test Org")
            .tier(OrganizationTier::TierDevV1)
            .create()
            .unwrap();
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
        SetupUserParams::builder()
            .state(&state)
            .user_id(100)
            .session_id(1)
            .org_id(1000)
            .member_id(10000)
            .username("owner")
            .role(OrganizationRole::Owner)
            .is_owner(true)
            .build(),
    )
    .await;

    // Setup member (non-admin)
    let (_, session_member, _, member) = setup_user_with_role(
        SetupUserParams::builder()
            .state(&state)
            .user_id(200)
            .session_id(2)
            .org_id(org.id)
            .member_id(20000)
            .username("member")
            .role(OrganizationRole::Member)
            .is_owner(false)
            .build(),
    )
    .await;

    // Member tries to update their own role to Admin
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/control/v1/organizations/{}/members/{}", org.id, member.id))
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
        SetupUserParams::builder()
            .state(&state)
            .user_id(100)
            .session_id(1)
            .org_id(1000)
            .member_id(10000)
            .username("owner")
            .role(OrganizationRole::Owner)
            .is_owner(true)
            .build(),
    )
    .await;

    // Setup admin
    let (_, session_admin, _, admin_member) = setup_user_with_role(
        SetupUserParams::builder()
            .state(&state)
            .user_id(200)
            .session_id(2)
            .org_id(org.id)
            .member_id(20000)
            .username("admin")
            .role(OrganizationRole::Admin)
            .is_owner(false)
            .build(),
    )
    .await;

    // Admin tries to update their own role to Owner
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/control/v1/organizations/{}/members/{}", org.id, admin_member.id))
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
        SetupUserParams::builder()
            .state(&state)
            .user_id(100)
            .session_id(1)
            .org_id(1000)
            .member_id(10000)
            .username("owner")
            .role(OrganizationRole::Owner)
            .is_owner(true)
            .build(),
    )
    .await;

    // Setup member
    let (_, session_member, ..) = setup_user_with_role(
        SetupUserParams::builder()
            .state(&state)
            .user_id(200)
            .session_id(2)
            .org_id(org.id)
            .member_id(20000)
            .username("member")
            .role(OrganizationRole::Member)
            .is_owner(false)
            .build(),
    )
    .await;

    // Member tries to create a vault
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{}/vaults", org.id))
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
        SetupUserParams::builder()
            .state(&state)
            .user_id(100)
            .session_id(1)
            .org_id(1000)
            .member_id(10000)
            .username("owner")
            .role(OrganizationRole::Owner)
            .is_owner(true)
            .build(),
    )
    .await;

    // Setup member
    let (_, session_member, ..) = setup_user_with_role(
        SetupUserParams::builder()
            .state(&state)
            .user_id(200)
            .session_id(2)
            .org_id(org.id)
            .member_id(20000)
            .username("member")
            .role(OrganizationRole::Member)
            .is_owner(false)
            .build(),
    )
    .await;

    // Member tries to delete the organization
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/organizations/{}", org.id))
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
        SetupUserParams::builder()
            .state(&state)
            .user_id(100)
            .session_id(1)
            .org_id(1000)
            .member_id(10000)
            .username("owner")
            .role(OrganizationRole::Owner)
            .is_owner(true)
            .build(),
    )
    .await;

    // Setup admin
    let (_, session_admin, ..) = setup_user_with_role(
        SetupUserParams::builder()
            .state(&state)
            .user_id(200)
            .session_id(2)
            .org_id(org.id)
            .member_id(20000)
            .username("admin")
            .role(OrganizationRole::Admin)
            .is_owner(false)
            .build(),
    )
    .await;

    // Admin tries to delete the organization
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/organizations/{}", org.id))
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
        SetupUserParams::builder()
            .state(&state)
            .user_id(100)
            .session_id(1)
            .org_id(1000)
            .member_id(10000)
            .username("owner")
            .role(OrganizationRole::Owner)
            .is_owner(true)
            .build(),
    )
    .await;

    // Setup member1
    let (_, session_member1, ..) = setup_user_with_role(
        SetupUserParams::builder()
            .state(&state)
            .user_id(200)
            .session_id(2)
            .org_id(org.id)
            .member_id(20000)
            .username("member1")
            .role(OrganizationRole::Member)
            .is_owner(false)
            .build(),
    )
    .await;

    // Setup member2
    let (_, _session_member2, _, member2) = setup_user_with_role(
        SetupUserParams::builder()
            .state(&state)
            .user_id(300)
            .session_id(3)
            .org_id(org.id)
            .member_id(30000)
            .username("member2")
            .role(OrganizationRole::Member)
            .is_owner(false)
            .build(),
    )
    .await;

    // Member1 tries to remove Member2
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/organizations/{}/members/{}", org.id, member2.id))
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
    let user_a = User::builder().id(100).name("userA").create().unwrap();
    let user_repo = UserRepository::new((*state.storage).clone());
    user_repo.create(user_a.clone()).await.unwrap();

    let session_a =
        UserSession::builder().id(1).user_id(user_a.id).session_type(SessionType::Web).create();
    let session_repo = UserSessionRepository::new((*state.storage).clone());
    session_repo.create(session_a.clone()).await.unwrap();

    // Setup User B
    let user_b = User::builder().id(200).name("userB").create().unwrap();
    user_repo.create(user_b.clone()).await.unwrap();

    let session_b =
        UserSession::builder().id(2).user_id(user_b.id).session_type(SessionType::Web).create();
    session_repo.create(session_b.clone()).await.unwrap();

    // User B tries to use User A's session to access profile
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/users/me")
                .header("cookie", format!("infera_session={}", session_a.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should succeed but return User A's profile (not User B's)
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
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
        SetupUserParams::builder()
            .state(&state)
            .user_id(100)
            .session_id(1)
            .org_id(1000)
            .member_id(10000)
            .username("owner")
            .role(OrganizationRole::Owner)
            .is_owner(true)
            .build(),
    )
    .await;

    // Setup member
    let (_, session_member, ..) = setup_user_with_role(
        SetupUserParams::builder()
            .state(&state)
            .user_id(200)
            .session_id(2)
            .org_id(org.id)
            .member_id(20000)
            .username("member")
            .role(OrganizationRole::Member)
            .is_owner(false)
            .build(),
    )
    .await;

    // Member tries to update organization name
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/control/v1/organizations/{}", org.id))
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
        SetupUserParams::builder()
            .state(&state)
            .user_id(100)
            .session_id(1)
            .org_id(1000)
            .member_id(10000)
            .username("owner")
            .role(OrganizationRole::Owner)
            .is_owner(true)
            .build(),
    )
    .await;

    // Setup member
    let (_, session_member, ..) = setup_user_with_role(
        SetupUserParams::builder()
            .state(&state)
            .user_id(200)
            .session_id(2)
            .org_id(org.id)
            .member_id(20000)
            .username("member")
            .role(OrganizationRole::Member)
            .is_owner(false)
            .build(),
    )
    .await;

    // Member tries to create a team
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/organizations/{}/teams", org.id))
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
        SetupUserParams::builder()
            .state(&state)
            .user_id(100)
            .session_id(1)
            .org_id(1000)
            .member_id(10000)
            .username("owner")
            .role(OrganizationRole::Owner)
            .is_owner(true)
            .build(),
    )
    .await;

    // Create a vault
    let vault_repo = VaultRepository::new((*state.storage).clone());
    let vault = Vault::builder()
        .id(5000)
        .organization_id(org.id)
        .name("Test Vault")
        .created_by_user_id(100)
        .create()
        .unwrap();
    vault_repo.create(vault.clone()).await.unwrap();

    // Setup member
    let (_, session_member, ..) = setup_user_with_role(
        SetupUserParams::builder()
            .state(&state)
            .user_id(200)
            .session_id(2)
            .org_id(org.id)
            .member_id(20000)
            .username("member")
            .role(OrganizationRole::Member)
            .is_owner(false)
            .build(),
    )
    .await;

    // Member tries to delete the vault
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/organizations/{}/vaults/{}", org.id, vault.id))
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
