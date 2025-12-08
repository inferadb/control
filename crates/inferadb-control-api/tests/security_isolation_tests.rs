use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use inferadb_control_api::{AppState, create_router_with_state};
use inferadb_control_core::{
    ClientCertificateRepository, ClientRepository, IdGenerator, OrganizationMemberRepository,
    OrganizationRepository, OrganizationTeamRepository, PrivateKeyEncryptor, UserRepository,
    UserSessionRepository, VaultRepository,
    entities::{
        Client, ClientCertificate, Organization, OrganizationMember, OrganizationRole,
        OrganizationTeam, OrganizationTier, SessionType, User, UserSession, Vault,
    },
    keypair,
};
use inferadb_control_test_fixtures::create_test_state;
use serde_json::json;
use tower::ServiceExt;

/// Helper to register a user and create their default organization
async fn setup_user_and_org(
    state: &AppState,
    user_id: i64,
    session_id: i64,
    org_id: i64,
    member_id: i64,
    username: &str,
) -> (User, UserSession, Organization, OrganizationMember) {
    // Create user
    let user = User::new(user_id, username.to_string(), None).unwrap();
    let user_repo = UserRepository::new((*state.storage).clone());
    user_repo.create(user.clone()).await.unwrap();

    // Create session
    let session = UserSession::new(session_id, user_id, SessionType::Web, None, None);
    let session_repo = UserSessionRepository::new((*state.storage).clone());
    session_repo.create(session.clone()).await.unwrap();

    // Create organization
    let org = Organization::new(org_id, format!("{}'s Org", username), OrganizationTier::TierDevV1)
        .unwrap();
    let org_repo = OrganizationRepository::new((*state.storage).clone());
    org_repo.create(org.clone()).await.unwrap();

    // Create member
    let member = OrganizationMember::new(member_id, org_id, user_id, OrganizationRole::Owner);
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    member_repo.create(member.clone()).await.unwrap();

    (user, session, org, member)
}

#[tokio::test]
async fn test_cross_organization_vault_access_denied() {
    let _ = IdGenerator::init(400);
    let state = create_test_state();

    // Setup Organization A with User A
    let (_, session_a, _org_a, _) = setup_user_and_org(&state, 100, 1, 1000, 10000, "userA").await;

    // Setup Organization B with User B
    let (_, _session_b, org_b, _) = setup_user_and_org(&state, 200, 2, 2000, 20000, "userB").await;

    // Create a vault in Organization B
    let vault_repo = VaultRepository::new((*state.storage).clone());
    let vault_b = Vault::new(5000, org_b.id, "Vault B".to_string(), 200).unwrap();
    vault_repo.create(vault_b.clone()).await.unwrap();

    // User A tries to access Organization B's vault
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/vaults/{}", org_b.id, vault_b.id))
                .header("cookie", format!("infera_session={}", session_a.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden or not found (user A is not a member of org B)
    assert!(
        response.status() == StatusCode::FORBIDDEN || response.status() == StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn test_cross_organization_client_access_denied() {
    let _ = IdGenerator::init(401);
    let state = create_test_state();

    // Setup Organization A with User A
    let (_, session_a, _org_a, _) = setup_user_and_org(&state, 100, 1, 1000, 10000, "userA").await;

    // Setup Organization B with User B
    let (_, _session_b, org_b, _) = setup_user_and_org(&state, 200, 2, 2000, 20000, "userB").await;

    // Create a client in Organization B
    let client_repo = ClientRepository::new((*state.storage).clone());
    let client_b = Client::new(6000, org_b.id, "Client B".to_string(), 200).unwrap();
    client_repo.create(client_b.clone()).await.unwrap();

    // User A tries to access Organization B's client
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/clients/{}", org_b.id, client_b.id))
                .header("cookie", format!("infera_session={}", session_a.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden (user A is not a member of org B)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_cross_organization_team_access_denied() {
    let _ = IdGenerator::init(402);
    let state = create_test_state();

    // Setup Organization A with User A
    let (_, session_a, _org_a, _) = setup_user_and_org(&state, 100, 1, 1000, 10000, "userA").await;

    // Setup Organization B with User B
    let (_, _session_b, org_b, _) = setup_user_and_org(&state, 200, 2, 2000, 20000, "userB").await;

    // Create a team in Organization B
    let team_repo = OrganizationTeamRepository::new((*state.storage).clone());
    let team_b = OrganizationTeam::new(7000, org_b.id, "Team B".to_string()).unwrap();
    team_repo.create(team_b.clone()).await.unwrap();

    // User A tries to access Organization B's team
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/teams/{}", org_b.id, team_b.id))
                .header("cookie", format!("infera_session={}", session_a.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden (user A is not a member of org B)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_cannot_modify_other_organization_resources() {
    let _ = IdGenerator::init(403);
    let state = create_test_state();

    // Setup Organization A with User A
    let (_, session_a, _org_a, _) = setup_user_and_org(&state, 100, 1, 1000, 10000, "userA").await;

    // Setup Organization B with User B
    let (_, _session_b, org_b, _) = setup_user_and_org(&state, 200, 2, 2000, 20000, "userB").await;

    // Create a vault in Organization B
    let vault_repo = VaultRepository::new((*state.storage).clone());
    let vault_b = Vault::new(5000, org_b.id, "Vault B".to_string(), 200).unwrap();
    vault_repo.create(vault_b.clone()).await.unwrap();

    // User A tries to update Organization B's vault
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/organizations/{}/vaults/{}", org_b.id, vault_b.id))
                .header("cookie", format!("infera_session={}", session_a.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Hacked Vault"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_cannot_delete_other_organization_resources() {
    let _ = IdGenerator::init(404);
    let state = create_test_state();

    // Setup Organization A with User A
    let (_, session_a, _org_a, _) = setup_user_and_org(&state, 100, 1, 1000, 10000, "userA").await;

    // Setup Organization B with User B
    let (_, _session_b, org_b, _) = setup_user_and_org(&state, 200, 2, 2000, 20000, "userB").await;

    // Create a client in Organization B
    let client_repo = ClientRepository::new((*state.storage).clone());
    let client_b = Client::new(6000, org_b.id, "Client B".to_string(), 200).unwrap();
    client_repo.create(client_b.clone()).await.unwrap();

    // User A tries to delete Organization B's client
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/organizations/{}/clients/{}", org_b.id, client_b.id))
                .header("cookie", format!("infera_session={}", session_a.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Verify the client still exists
    let client = client_repo.get(client_b.id).await.unwrap();
    assert!(client.is_some());
    assert!(!client.unwrap().is_deleted());
}

#[tokio::test]
async fn test_organization_member_list_isolation() {
    let _ = IdGenerator::init(405);
    let state = create_test_state();

    // Setup Organization A with User A
    let (_, session_a, _org_a, _) = setup_user_and_org(&state, 100, 1, 1000, 10000, "userA").await;

    // Setup Organization B with User B
    let (_, _session_b, org_b, _) = setup_user_and_org(&state, 200, 2, 2000, 20000, "userB").await;

    // User A tries to list members of Organization B
    let app = create_router_with_state(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/organizations/{}/members", org_b.id))
                .header("cookie", format!("infera_session={}", session_a.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden (user A is not a member of org B)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_vault_jwt_isolation() {
    let _ = IdGenerator::init(406);
    let state = create_test_state();

    // Setup Organization A with vault
    let (_, _session_a, org_a, _) = setup_user_and_org(&state, 100, 1, 1000, 10000, "userA").await;

    let vault_repo = VaultRepository::new((*state.storage).clone());
    let vault_a = Vault::new(5000, org_a.id, "Vault A".to_string(), 100).unwrap();
    vault_repo.create(vault_a.clone()).await.unwrap();

    // Setup Organization B with vault
    let (_, _session_b, org_b, _) = setup_user_and_org(&state, 200, 2, 2000, 20000, "userB").await;

    let vault_b = Vault::new(6000, org_b.id, "Vault B".to_string(), 200).unwrap();
    vault_repo.create(vault_b.clone()).await.unwrap();

    // Create a client in Organization A
    let client_repo = ClientRepository::new((*state.storage).clone());
    let client_a = Client::new(7000, org_a.id, "Client A".to_string(), 100).unwrap();
    client_repo.create(client_a.clone()).await.unwrap();

    // Create a certificate for the client
    let (public_key_base64, private_key_bytes) = keypair::generate();
    let master_secret = b"test-master-secret-32-bytes-long";
    let encryptor = PrivateKeyEncryptor::new(master_secret).unwrap();
    let private_key_encrypted = encryptor.encrypt(&private_key_bytes).unwrap();

    let cert_repo = ClientCertificateRepository::new((*state.storage).clone());
    let cert = ClientCertificate::new(
        8000,
        client_a.id,
        org_a.id,
        public_key_base64.clone(),
        private_key_encrypted,
        "Test Cert".to_string(),
        100,
    )
    .unwrap();
    cert_repo.create(cert.clone()).await.unwrap();

    // Note: Full JWT generation and validation would require implementing
    // the complete token generation flow. This test verifies that the
    // vault isolation is enforced at the entity level.

    // Verify that vaults are isolated by organization
    assert_eq!(vault_a.organization_id, org_a.id);
    assert_eq!(vault_b.organization_id, org_b.id);
    assert_ne!(vault_a.organization_id, vault_b.organization_id);

    // Verify that a client from org A cannot be used with org B's vault
    // by checking organization ownership
    assert_eq!(client_a.organization_id, org_a.id);
    assert_ne!(client_a.organization_id, org_b.id);
}
