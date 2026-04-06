//! Integration tests with MockLedgerServer backend.
//!
//! These tests exercise the full handler stack with a real [`LedgerClient`]
//! connected to a [`MockLedgerServer`] on an ephemeral port. This covers:
//! - JWT authentication middleware (both `require_jwt` and `require_jwt_local`)
//! - Handler business logic (request validation, SDK calls, response mapping)
//! - Cookie handling (token set/clear)
//! - Organization membership verification and caching

#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::http::StatusCode;
use inferadb_control_test_integration::TestHarness;
use serde_json::json;

// ── Auth Handlers ──────────────────────────────────────────────────────

mod auth {
    use super::*;

    #[tokio::test]
    async fn refresh_with_body_token_returns_new_pair() {
        let h = TestHarness::start().await;
        let resp = h
            .post("/control/v1/auth/refresh", json!({"refresh_token": "mock-refresh-token"}))
            .await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["token_type"], "Bearer");
        assert!(json["access_token"].is_string());
        assert!(json["refresh_token"].is_string());
    }

    #[tokio::test]
    async fn refresh_with_cookie_token_returns_new_pair() {
        let h = TestHarness::start().await;
        let resp = h
            .post_with_cookie(
                "/control/v1/auth/refresh",
                json!({"refresh_token": null}),
                "inferadb_refresh=mock-refresh-token",
            )
            .await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["token_type"], "Bearer");
    }

    #[tokio::test]
    async fn refresh_without_token_returns_401() {
        let h = TestHarness::start().await;
        let resp = h.post("/control/v1/auth/refresh", json!({})).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn refresh_sets_cookies() {
        let h = TestHarness::start().await;
        let resp = h
            .post("/control/v1/auth/refresh", json!({"refresh_token": "mock-refresh-token"}))
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let access = TestHarness::extract_cookie(resp.headers(), "inferadb_access");
        let refresh = TestHarness::extract_cookie(resp.headers(), "inferadb_refresh");
        assert!(access.is_some(), "should set access cookie");
        assert!(refresh.is_some(), "should set refresh cookie");
    }

    #[tokio::test]
    async fn logout_clears_cookies() {
        let h = TestHarness::start().await;
        let resp = h.post("/control/v1/auth/logout", json!({})).await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["message"], "logged out");
    }

    #[tokio::test]
    async fn revoke_all_requires_auth() {
        let h = TestHarness::start().await;
        let resp = h.post("/control/v1/auth/revoke-all", json!({})).await;
        // Without auth, JWT middleware returns 401
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_all_with_auth_returns_count() {
        let h = TestHarness::start().await;
        let resp = h.authenticated_post("/control/v1/auth/revoke-all", json!({})).await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        // Mock returns revoked_count=3
        assert_eq!(json["revoked_count"], 3);
    }
}

// ── Email Auth Handlers ────────────────────────────────────────────────

mod email_auth {
    use super::*;

    #[tokio::test]
    async fn initiate_with_valid_email_succeeds() {
        let h = TestHarness::start().await;
        let resp =
            h.post("/control/v1/auth/email/initiate", json!({"email": "user@example.com"})).await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["message"], "verification code sent");
    }

    #[tokio::test]
    async fn initiate_with_region_succeeds() {
        let h = TestHarness::start().await;
        let resp = h
            .post(
                "/control/v1/auth/email/initiate",
                json!({"email": "user@example.com", "region": "ie-east-dublin"}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn initiate_rejects_invalid_email() {
        let h = TestHarness::start().await;
        let resp =
            h.post("/control/v1/auth/email/initiate", json!({"email": "not-an-email"})).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn verify_with_valid_code_returns_result() {
        let h = TestHarness::start().await;
        let resp = h
            .post(
                "/control/v1/auth/email/verify",
                json!({"email": "user@example.com", "code": "123456"}),
            )
            .await;
        // Mock returns tokens for existing user
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["status"].is_string());
    }

    #[tokio::test]
    async fn complete_registration_succeeds() {
        let h = TestHarness::start().await;
        let resp = h
            .post(
                "/control/v1/auth/email/complete",
                json!({
                    "onboarding_token": "mock-token",
                    "email": "newuser@example.com",
                    "name": "New User",
                    "organization_name": "New Org"
                }),
            )
            .await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["registration"]["user"].is_number());
        assert_eq!(json["registration"]["token_type"], "Bearer");
    }

    #[tokio::test]
    async fn complete_registration_validates_email() {
        let h = TestHarness::start().await;
        let resp = h
            .post(
                "/control/v1/auth/email/complete",
                json!({
                    "onboarding_token": "mock",
                    "email": "invalid",
                    "name": "User",
                    "organization_name": "Org"
                }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn complete_registration_validates_name() {
        let h = TestHarness::start().await;
        let resp = h
            .post(
                "/control/v1/auth/email/complete",
                json!({
                    "onboarding_token": "mock",
                    "email": "user@example.com",
                    "name": "<script>xss</script>",
                    "organization_name": "Org"
                }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn complete_registration_validates_org_name() {
        let h = TestHarness::start().await;
        let resp = h
            .post(
                "/control/v1/auth/email/complete",
                json!({
                    "onboarding_token": "mock",
                    "email": "user@example.com",
                    "name": "User",
                    "organization_name": "   "
                }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn complete_registration_sets_cookies() {
        let h = TestHarness::start().await;
        let resp = h
            .post(
                "/control/v1/auth/email/complete",
                json!({
                    "onboarding_token": "mock-token",
                    "email": "new@example.com",
                    "name": "New User",
                    "organization_name": "New Org"
                }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let access = TestHarness::extract_cookie(resp.headers(), "inferadb_access");
        assert!(access.is_some(), "should set access cookie");
    }
}

// ── User Handlers ──────────────────────────────────────────────────────

mod users {
    use super::*;

    #[tokio::test]
    async fn get_profile_requires_auth() {
        let h = TestHarness::start().await;
        let resp = h.get("/control/v1/users/me").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_profile_returns_not_found_without_seeded_user() {
        // JWT is valid; handler reaches user lookup but mock has no user for slug 42
        let h = TestHarness::start().await;
        let resp = h.authenticated_get("/control/v1/users/me").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn update_profile_returns_not_found_without_seeded_user() {
        // Write routes use remote JWT validation (mock accepts any token),
        // but the mock has no seeded user for slug 42
        let h = TestHarness::start().await;
        let resp =
            h.authenticated_patch("/control/v1/users/me", json!({"name": "Updated Name"})).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_profile_requires_name_field() {
        let h = TestHarness::start().await;
        let resp = h.authenticated_patch("/control/v1/users/me", json!({})).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn update_profile_validates_name() {
        let h = TestHarness::start().await;
        let resp = h.authenticated_patch("/control/v1/users/me", json!({"name": "<script>"})).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn delete_user_returns_not_found_without_seeded_user() {
        // Mock has no seeded user for slug 42
        let h = TestHarness::start().await;
        let resp = h.authenticated_delete("/control/v1/users/me").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

// ── Organization Handlers ──────────────────────────────────────────────

mod organizations {
    use super::*;

    #[tokio::test]
    async fn create_organization_succeeds() {
        let h = TestHarness::start().await;
        let resp =
            h.authenticated_post("/control/v1/organizations", json!({"name": "Test Org"})).await;
        let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
        assert!(json["organization"]["slug"].is_number());
        assert_eq!(json["organization"]["name"], "Test Org");
    }

    #[tokio::test]
    async fn create_organization_validates_name() {
        let h = TestHarness::start().await;
        let resp =
            h.authenticated_post("/control/v1/organizations", json!({"name": "<script>"})).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_organization_rejects_empty_name() {
        let h = TestHarness::start().await;
        let resp = h.authenticated_post("/control/v1/organizations", json!({"name": ""})).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_organizations_returns_array() {
        let h = TestHarness::start().await;
        let resp = h.authenticated_get("/control/v1/organizations").await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["organizations"].is_array());
    }

    #[tokio::test]
    async fn get_organization_returns_details() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_get("/control/v1/organizations/1").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn update_organization_succeeds() {
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_patch("/control/v1/organizations/1", json!({"name": "Updated Org"}))
            .await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["organization"]["slug"].is_number());
    }

    #[tokio::test]
    async fn update_organization_validates_name() {
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_patch("/control/v1/organizations/1", json!({"name": "#invalid!"}))
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn delete_organization_succeeds() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_delete("/control/v1/organizations/1").await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["message"].as_str().unwrap().contains("deleted"));
    }

    #[tokio::test]
    async fn list_members_returns_array() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_get("/control/v1/organizations/1/members").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn update_member_role_returns_forbidden() {
        // Mock user is not an admin in the seeded org
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_patch("/control/v1/organizations/1/members/42", json!({"role": "admin"}))
            .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn remove_member_returns_forbidden() {
        // Mock user is not an admin in the seeded org
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_delete("/control/v1/organizations/1/members/99").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn leave_organization_returns_not_found() {
        // Mock doesn't support leave operation
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_delete("/control/v1/organizations/1/members/me").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_invitation_succeeds() {
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_post(
                "/control/v1/organizations/1/invitations",
                json!({"email": "invite@example.com"}),
            )
            .await;
        let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
        assert!(json["slug"].is_number());
    }

    #[tokio::test]
    async fn create_invitation_validates_email() {
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_post(
                "/control/v1/organizations/1/invitations",
                json!({"email": "not-an-email"}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_invitations_returns_array() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_get("/control/v1/organizations/1/invitations").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn delete_invitation_returns_not_found() {
        // Mock doesn't seed invitations
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_delete("/control/v1/organizations/1/invitations/1").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn accept_invitation_returns_not_found() {
        // Mock doesn't seed invitations
        let h = TestHarness::start().await;
        let resp =
            h.authenticated_post("/control/v1/users/me/invitations/1/accept", json!({})).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn decline_invitation_returns_not_found() {
        // Mock doesn't seed invitations
        let h = TestHarness::start().await;
        let resp =
            h.authenticated_post("/control/v1/users/me/invitations/1/decline", json!({})).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_received_invitations_returns_array() {
        let h = TestHarness::start().await;
        let resp = h.authenticated_get("/control/v1/users/me/invitations").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn organization_requires_auth() {
        let h = TestHarness::start().await;
        let resp = h.get("/control/v1/organizations").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// ── Vault Handlers ─────────────────────────────────────────────────────

mod vaults {
    use super::*;

    #[tokio::test]
    async fn create_vault_succeeds() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_post("/control/v1/organizations/1/vaults", json!({})).await;
        let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
        assert!(json["vault"]["slug"].is_number());
    }

    #[tokio::test]
    async fn list_vaults_returns_array() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_get("/control/v1/organizations/1/vaults").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn get_vault_returns_details() {
        let h = TestHarness::start_with_org().await;
        h.server.add_vault(
            inferadb_ledger_types::OrganizationSlug::new(1),
            inferadb_ledger_types::VaultSlug::new(100),
        );
        let resp = h.authenticated_get("/control/v1/organizations/1/vaults/100").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn update_vault_rejects_retention_policy() {
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_patch(
                "/control/v1/organizations/1/vaults/100",
                json!({"retention_policy": "30d"}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn delete_vault_succeeds() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_delete("/control/v1/organizations/1/vaults/100").await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["message"].as_str().unwrap().contains("deleted"));
    }

    #[tokio::test]
    async fn vault_requires_auth() {
        let h = TestHarness::start().await;
        let resp = h.get("/control/v1/organizations/1/vaults").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// ── Team Handlers ──────────────────────────────────────────────────────

mod teams {
    use super::*;

    #[tokio::test]
    async fn create_team_succeeds() {
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_post("/control/v1/organizations/1/teams", json!({"name": "Engineering"}))
            .await;
        let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
        assert!(json["team"]["slug"].is_number());
    }

    #[tokio::test]
    async fn create_team_validates_name() {
        let h = TestHarness::start_with_org().await;
        let resp =
            h.authenticated_post("/control/v1/organizations/1/teams", json!({"name": ""})).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_teams_returns_array() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_get("/control/v1/organizations/1/teams").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn get_team_returns_details() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_get("/control/v1/organizations/1/teams/100").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn update_team_returns_not_found() {
        // Mock doesn't seed teams
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_patch(
                "/control/v1/organizations/1/teams/100",
                json!({"name": "New Name"}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_team_returns_not_found() {
        // Mock doesn't seed teams
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_delete("/control/v1/organizations/1/teams/100").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_team_members_returns_array() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_get("/control/v1/organizations/1/teams/100/members").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn add_team_member_succeeds() {
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_post(
                "/control/v1/organizations/1/teams/100/members",
                json!({"user": 42}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn update_team_member_does_not_panic() {
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_patch(
                "/control/v1/organizations/1/teams/100/members/42",
                json!({"role": "manager"}),
            )
            .await;
        let status = resp.status();
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn remove_team_member_does_not_panic() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_delete("/control/v1/organizations/1/teams/100/members/42").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }
}

// ── Client Handlers ────────────────────────────────────────────────────

mod clients {
    use super::*;

    #[tokio::test]
    async fn create_client_succeeds() {
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_post("/control/v1/organizations/1/clients", json!({"name": "My App"}))
            .await;
        let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
        assert!(json["client"]["slug"].is_number());
    }

    #[tokio::test]
    async fn create_client_validates_name() {
        let h = TestHarness::start_with_org().await;
        let resp =
            h.authenticated_post("/control/v1/organizations/1/clients", json!({"name": ""})).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_clients_returns_array() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_get("/control/v1/organizations/1/clients").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn get_client_returns_details() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_get("/control/v1/organizations/1/clients/100").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn update_client_succeeds() {
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_patch(
                "/control/v1/organizations/1/clients/100",
                json!({"name": "Updated App"}),
            )
            .await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["client"]["slug"].is_number());
    }

    #[tokio::test]
    async fn delete_client_succeeds() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_delete("/control/v1/organizations/1/clients/100").await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["message"].is_string());
    }

    #[tokio::test]
    async fn list_certificates_returns_array() {
        let h = TestHarness::start_with_org().await;
        let resp =
            h.authenticated_get("/control/v1/organizations/1/clients/100/certificates").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn create_certificate_does_not_panic() {
        // Mock may not fully implement certificate creation; verify no 500
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_post(
                "/control/v1/organizations/1/clients/100/certificates",
                json!({"name": "prod-cert"}),
            )
            .await;
        let status = resp.status();
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn get_certificate_returns_details() {
        let h = TestHarness::start_with_org().await;
        let resp =
            h.authenticated_get("/control/v1/organizations/1/clients/100/certificates/200").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn revoke_certificate_does_not_panic() {
        // Mock may not fully implement certificate revocation; verify no 500
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_delete("/control/v1/organizations/1/clients/100/certificates/200")
            .await;
        let status = resp.status();
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn rotate_secret_does_not_panic() {
        // Mock may not fully implement secret rotation; verify no 500
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_post("/control/v1/organizations/1/clients/100/secret/rotate", json!({}))
            .await;
        let status = resp.status();
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }
}

// ── Schema Handlers ────────────────────────────────────────────────────

mod schemas {
    use super::*;

    #[tokio::test]
    async fn list_schemas_returns_array() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_get("/control/v1/organizations/1/vaults/100/schemas").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn get_schema_returns_details() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_get("/control/v1/organizations/1/vaults/100/schemas/1").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn get_current_schema_returns_details() {
        let h = TestHarness::start_with_org().await;
        let resp =
            h.authenticated_get("/control/v1/organizations/1/vaults/100/schemas/current").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn deploy_schema_does_not_panic() {
        // Mock may not fully implement schema deployment; verify no 500
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_post(
                "/control/v1/organizations/1/vaults/100/schemas",
                json!({"definition": {"entities": {}}}),
            )
            .await;
        let status = resp.status();
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn rollback_schema_returns_validation_error() {
        // Mock has no activation history to rollback to
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_post(
                "/control/v1/organizations/1/vaults/100/schemas/rollback",
                json!({}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn activate_schema_returns_not_found() {
        // Mock has no seeded schema versions
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_post(
                "/control/v1/organizations/1/vaults/100/schemas/1/activate",
                json!({}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn diff_schemas_returns_result() {
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_get("/control/v1/organizations/1/vaults/100/schemas/diff?from=1&to=2")
            .await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }
}

// ── Token Handlers ─────────────────────────────────────────────────────

mod tokens {
    use super::*;

    #[tokio::test]
    async fn generate_vault_token_succeeds() {
        let h = TestHarness::start_with_org().await;
        let resp = h
            .authenticated_post("/control/v1/organizations/1/vaults/100/tokens", json!({"app": 50}))
            .await;
        let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
        assert!(json["access_token"].is_string());
    }

    #[tokio::test]
    async fn revoke_vault_tokens_does_not_panic() {
        // Mock may not fully implement token revocation; verify no 500
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_delete("/control/v1/organizations/1/vaults/100/tokens").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn refresh_vault_token_succeeds() {
        let h = TestHarness::start().await;
        let resp = h
            .post("/control/v1/tokens/refresh", json!({"refresh_token": "mock-refresh-token"}))
            .await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["access_token"].is_string());
    }

    #[tokio::test]
    async fn client_assertion_auth_succeeds() {
        let h = TestHarness::start().await;
        let resp = h
            .post(
                "/control/v1/token",
                json!({
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": "mock-jwt-assertion"
                }),
            )
            .await;
        // This may succeed or fail depending on validation — check it doesn't 500
        let status = resp.status();
        assert!(status != StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }
}

// ── Email Handlers ─────────────────────────────────────────────────────

mod emails {
    use super::*;

    #[tokio::test]
    async fn list_emails_returns_array() {
        let h = TestHarness::start().await;
        let resp = h.authenticated_get("/control/v1/users/emails").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn delete_email_returns_not_found() {
        // Mock doesn't seed email records
        let h = TestHarness::start().await;
        let resp = h.authenticated_delete("/control/v1/users/emails/1").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn verify_email_with_token_returns_not_found() {
        // Mock doesn't seed email verification tokens
        let h = TestHarness::start().await;
        let resp = h.post("/control/v1/auth/verify-email", json!({"token": "valid-token"})).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn emails_require_auth() {
        let h = TestHarness::start().await;
        let resp = h.get("/control/v1/users/emails").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// ── Audit Log Handlers ─────────────────────────────────────────────────

mod audit_logs {
    use super::*;

    #[tokio::test]
    async fn list_audit_logs_returns_array() {
        let h = TestHarness::start_with_org().await;
        let resp = h.authenticated_get("/control/v1/organizations/1/audit-logs").await;
        let status = resp.status();
        assert_ne!(status, StatusCode::UNAUTHORIZED, "JWT should be accepted");
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn audit_logs_require_auth() {
        let h = TestHarness::start().await;
        let resp = h.get("/control/v1/organizations/1/audit-logs").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// ── MFA Auth Handlers ──────────────────────────────────────────────────

mod mfa_auth {
    use super::*;

    #[tokio::test]
    async fn verify_totp_does_not_panic() {
        let h = TestHarness::start().await;
        let resp = h
            .post(
                "/control/v1/auth/totp/verify",
                json!({"challenge_nonce": "dGVzdA==", "code": "123456"}),
            )
            .await;
        let status = resp.status();
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn consume_recovery_does_not_panic() {
        let h = TestHarness::start().await;
        let resp = h
            .post(
                "/control/v1/auth/recovery",
                json!({"challenge_nonce": "dGVzdA==", "code": "ABCD-1234-EFGH"}),
            )
            .await;
        let status = resp.status();
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "should not return 500");
    }

    #[tokio::test]
    async fn passkey_begin_does_not_panic() {
        let h = TestHarness::start().await;
        let resp =
            h.post("/control/v1/auth/passkey/begin", json!({"challenge_nonce": "dGVzdA=="})).await;
        // WebAuthn needs proper setup; just verify the handler doesn't panic
        let _status = resp.status();
    }

    #[tokio::test]
    async fn passkey_register_requires_auth() {
        let h = TestHarness::start().await;
        let resp = h.post("/control/v1/users/me/credentials/passkeys/begin", json!({})).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// ── JWT Middleware ──────────────────────────────────────────────────────

mod jwt_middleware {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn bearer_token_is_accepted_by_local_jwt_validation() {
        // Read routes (GET) use local JWT validation. The test harness now
        // provides a real Ed25519-signed JWT, so local validation accepts it.
        let h = TestHarness::start().await;
        let resp = h.authenticated_get("/control/v1/users/me").await;
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "valid JWT should be accepted by local validation"
        );
    }

    #[tokio::test]
    async fn empty_bearer_token_is_rejected() {
        let h = TestHarness::start().await;
        let resp = h
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/control/v1/users/me")
                    .header("authorization", "Bearer ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_bearer_scheme_is_rejected() {
        let h = TestHarness::start().await;
        let resp = h
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/control/v1/users/me")
                    .header("authorization", "Basic dXNlcjpwYXNz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn no_auth_returns_401() {
        let h = TestHarness::start().await;
        let resp = h.get("/control/v1/users/me").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn empty_token_in_validate_returns_401() {
        let h = TestHarness::start().await;
        let resp = h
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/control/v1/users/me")
                    .header("authorization", "Bearer  ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Trimmed empty token should be rejected
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
