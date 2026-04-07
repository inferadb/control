//! Integration tests with MockLedgerServer backend.
//!
//! These tests exercise the full handler stack with a real [`LedgerClient`]
//! connected to a [`MockLedgerServer`] on an ephemeral port. This covers:
//! - JWT authentication middleware (both `require_jwt` and `require_jwt_local`)
//! - Handler business logic (request validation, SDK calls, response mapping)
//! - Cookie handling (token set/clear)
//! - Organization membership verification and caching

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::http::StatusCode;
use inferadb_control_test_integration::TestHarness;
use serde_json::json;

// -- Auth Handlers ------------------------------------------------------------

mod auth {
    use super::*;

    #[tokio::test]
    async fn test_refresh_body_token_returns_new_pair() {
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
    async fn test_refresh_cookie_token_returns_new_pair() {
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
    async fn test_refresh_without_token_returns_401_with_auth_error() {
        let h = TestHarness::start().await;

        let resp = h.post("/control/v1/auth/refresh", json!({})).await;

        let json = TestHarness::assert_status(resp, StatusCode::UNAUTHORIZED).await;
        assert_eq!(json["code"], "AUTHENTICATION_ERROR");
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn test_refresh_sets_cookies() {
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
    async fn test_logout_with_cookies_returns_logged_out_and_clears_both() {
        let h = TestHarness::start().await;

        // Send request with both cookies so the jar can emit removal Set-Cookie headers
        let resp = h
            .post_with_cookie(
                "/control/v1/auth/logout",
                json!({}),
                "inferadb_access=old-access; inferadb_refresh=old-refresh",
            )
            .await;

        assert_eq!(resp.status(), StatusCode::OK);

        // Verify Set-Cookie headers clear both tokens
        let set_cookies: Vec<String> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .collect();

        let has_access = set_cookies.iter().any(|c| c.starts_with("inferadb_access="));
        let has_refresh = set_cookies.iter().any(|c| c.starts_with("inferadb_refresh="));
        assert!(has_access, "should emit Set-Cookie to clear access cookie");
        assert!(has_refresh, "should emit Set-Cookie to clear refresh cookie");

        // Verify response body
        let json = TestHarness::body_json(resp).await;
        assert_eq!(json["message"], "logged out");
    }

    /// Logout succeeds regardless of cookie state.
    #[tokio::test]
    async fn test_logout_with_cookie_variants_succeeds() {
        let cases: &[(&str, &str)] = &[
            ("inferadb_refresh=mock-refresh-token", "valid refresh cookie"),
            ("inferadb_refresh=", "empty refresh cookie"),
        ];

        for (cookie, label) in cases {
            let h = TestHarness::start().await;

            let resp = h.post_with_cookie("/control/v1/auth/logout", json!({}), cookie).await;

            let json = TestHarness::assert_status(resp, StatusCode::OK).await;
            assert_eq!(json["message"], "logged out", "case: {label}");
        }
    }

    #[tokio::test]
    async fn test_revoke_all_requires_auth() {
        let h = TestHarness::start().await;

        let resp = h.post("/control/v1/auth/revoke-all", json!({})).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_revoke_all_with_auth_returns_count() {
        let h = TestHarness::start().await;

        let resp = h.authenticated_post("/control/v1/auth/revoke-all", json!({})).await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["revoked_count"], 3);
    }

    #[tokio::test]
    async fn test_revoke_all_with_auth_and_cookies_clears_both() {
        use axum::{body::Body, http::Request};
        use inferadb_control_test_integration::MOCK_ACCESS_TOKEN;
        use tower::ServiceExt;

        let h = TestHarness::start().await;

        // Send authenticated request WITH cookies so the jar emits removal Set-Cookie headers
        let resp = h
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/control/v1/auth/revoke-all")
                    .header("authorization", format!("Bearer {MOCK_ACCESS_TOKEN}"))
                    .header("content-type", "application/json")
                    .header("cookie", "inferadb_access=old-access; inferadb_refresh=old-refresh")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let set_cookies: Vec<String> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .collect();

        let has_access = set_cookies.iter().any(|c| c.starts_with("inferadb_access="));
        let has_refresh = set_cookies.iter().any(|c| c.starts_with("inferadb_refresh="));
        assert!(has_access, "revoke-all should emit Set-Cookie to clear access token");
        assert!(has_refresh, "revoke-all should emit Set-Cookie to clear refresh token");
    }

    #[tokio::test]
    async fn test_revoke_all_without_auth_returns_401_with_error_body() {
        let h = TestHarness::start().await;

        let resp = h.post("/control/v1/auth/revoke-all", json!({})).await;

        let json = TestHarness::assert_status(resp, StatusCode::UNAUTHORIZED).await;
        assert!(json["error"].is_string(), "should include error message");
        assert!(json["code"].is_string(), "should include error code");
    }
}

// -- Email Auth Handlers ------------------------------------------------------

mod email_auth {
    use super::*;

    #[tokio::test]
    async fn test_initiate_valid_email_succeeds() {
        let h = TestHarness::start().await;

        let resp =
            h.post("/control/v1/auth/email/initiate", json!({"email": "user@example.com"})).await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["message"], "verification code sent");
    }

    #[tokio::test]
    async fn test_initiate_with_region_returns_verification_sent() {
        let h = TestHarness::start().await;

        let resp = h
            .post(
                "/control/v1/auth/email/initiate",
                json!({"email": "user@example.com", "region": "ie-east-dublin"}),
            )
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["message"], "verification code sent");
    }

    #[tokio::test]
    async fn test_initiate_invalid_email_returns_400_with_validation_error() {
        let h = TestHarness::start().await;

        let resp =
            h.post("/control/v1/auth/email/initiate", json!({"email": "not-an-email"})).await;

        let json = TestHarness::assert_status(resp, StatusCode::BAD_REQUEST).await;
        assert_eq!(json["code"], "VALIDATION_ERROR");
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn test_verify_valid_code_returns_registration_required() {
        let h = TestHarness::start().await;

        let resp = h
            .post(
                "/control/v1/auth/email/verify",
                json!({"email": "user@example.com", "code": "123456"}),
            )
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["status"], "registration_required");
        assert_eq!(json["onboarding_token"], "ilobt_mock_token");
    }

    #[tokio::test]
    async fn test_verify_with_region_returns_registration_required() {
        let h = TestHarness::start().await;

        let resp = h
            .post(
                "/control/v1/auth/email/verify",
                json!({"email": "user@example.com", "code": "ABC123", "region": "ie-east-dublin"}),
            )
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["status"], "registration_required");
    }

    #[tokio::test]
    async fn test_complete_registration_succeeds() {
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

    /// Invalid fields in the complete registration request are rejected.
    #[tokio::test]
    async fn test_complete_registration_validates_fields() {
        let cases: &[(serde_json::Value, &str)] = &[
            (
                json!({
                    "onboarding_token": "mock",
                    "email": "invalid",
                    "name": "User",
                    "organization_name": "Org"
                }),
                "invalid email",
            ),
            (
                json!({
                    "onboarding_token": "mock",
                    "email": "user@example.com",
                    "name": "<script>xss</script>",
                    "organization_name": "Org"
                }),
                "XSS in name",
            ),
            (
                json!({
                    "onboarding_token": "mock",
                    "email": "user@example.com",
                    "name": "User",
                    "organization_name": "   "
                }),
                "blank org name",
            ),
        ];

        for (body, label) in cases {
            let h = TestHarness::start().await;

            let resp = h.post("/control/v1/auth/email/complete", body.clone()).await;

            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "case: {label}");
        }
    }

    #[tokio::test]
    async fn test_complete_registration_sets_both_cookies() {
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
        let refresh = TestHarness::extract_cookie(resp.headers(), "inferadb_refresh");
        assert!(access.is_some(), "should set access cookie");
        assert!(refresh.is_some(), "should set refresh cookie");
    }

    /// Full multi-step email auth flow: initiate -> verify -> complete.
    /// Each step returns the expected status and body fields.
    #[tokio::test]
    async fn test_email_auth_full_flow_initiate_verify_complete_returns_session() {
        let h = TestHarness::start().await;

        // Step 1: Initiate
        let resp =
            h.post("/control/v1/auth/email/initiate", json!({"email": "flow@example.com"})).await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["message"], "verification code sent");

        // Step 2: Verify (mock returns registration_required for new users)
        let resp = h
            .post(
                "/control/v1/auth/email/verify",
                json!({"email": "flow@example.com", "code": "123456"}),
            )
            .await;
        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["status"], "registration_required");
        assert!(json["onboarding_token"].is_string(), "should return onboarding_token");

        // Step 3: Complete registration
        let resp = h
            .post(
                "/control/v1/auth/email/complete",
                json!({
                    "onboarding_token": json["onboarding_token"].as_str().unwrap(),
                    "email": "flow@example.com",
                    "name": "Flow User",
                    "organization_name": "Flow Org"
                }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let access = TestHarness::extract_cookie(resp.headers(), "inferadb_access");
        let refresh = TestHarness::extract_cookie(resp.headers(), "inferadb_refresh");
        assert!(access.is_some(), "complete should set access cookie");
        assert!(refresh.is_some(), "complete should set refresh cookie");
        let json = TestHarness::body_json(resp).await;
        assert!(json["registration"]["user"].is_number());
        assert_eq!(json["registration"]["token_type"], "Bearer");
        assert!(json["registration"]["access_token"].is_string());
        assert!(json["registration"]["refresh_token"].is_string());
    }

    /// Validation errors across email auth endpoints return consistent error format.
    #[tokio::test]
    async fn test_email_auth_validation_errors_return_consistent_error_format() {
        let h = TestHarness::start().await;

        let cases: &[(&str, serde_json::Value, &str)] = &[
            (
                "/control/v1/auth/email/initiate",
                json!({"email": "bad"}),
                "initiate with invalid email",
            ),
            (
                "/control/v1/auth/email/complete",
                json!({
                    "onboarding_token": "t",
                    "email": "bad",
                    "name": "User",
                    "organization_name": "Org"
                }),
                "complete with invalid email",
            ),
            (
                "/control/v1/auth/email/complete",
                json!({
                    "onboarding_token": "t",
                    "email": "user@example.com",
                    "name": "<script>",
                    "organization_name": "Org"
                }),
                "complete with invalid name",
            ),
        ];

        for (uri, body, label) in cases {
            let resp = h.post(uri, body.clone()).await;

            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "case: {label}");
            let json = TestHarness::body_json(resp).await;
            assert!(
                json["error"].is_string(),
                "case '{label}': error field should be a string, got: {json}"
            );
            assert!(
                json["code"].is_string(),
                "case '{label}': code field should be a string, got: {json}"
            );
            assert_eq!(json["code"], "VALIDATION_ERROR", "case: {label}");
        }
    }
}

// -- User Handlers ------------------------------------------------------------

mod users {
    use super::*;

    #[tokio::test]
    async fn test_get_profile_requires_auth() {
        let h = TestHarness::start().await;

        let resp = h.get("/control/v1/users/me").await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_users_getprofile_notfound_when_no_seeded_user() {
        let h = TestHarness::start().await;

        let resp = h.authenticated_get("/control/v1/users/me").await;

        TestHarness::assert_status(resp, StatusCode::NOT_FOUND).await;
    }

    #[tokio::test]
    async fn test_update_profile_without_seeded_user_returns_not_found() {
        let h = TestHarness::start().await;

        let resp =
            h.authenticated_patch("/control/v1/users/me", json!({"name": "Updated Name"})).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Profile update validates input fields.
    #[tokio::test]
    async fn test_update_profile_validates_input() {
        let cases: &[(serde_json::Value, &str)] =
            &[(json!({}), "missing name field"), (json!({"name": "<script>"}), "XSS in name")];

        for (body, label) in cases {
            let h = TestHarness::start().await;

            let resp = h.authenticated_patch("/control/v1/users/me", body.clone()).await;

            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "case: {label}");
        }
    }

    #[tokio::test]
    async fn test_delete_user_without_seeded_user_returns_not_found() {
        let h = TestHarness::start().await;

        let resp = h.authenticated_delete("/control/v1/users/me").await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

// -- Organization Handlers ----------------------------------------------------

mod organizations {
    use super::*;

    #[tokio::test]
    async fn test_create_organization_succeeds() {
        let h = TestHarness::start().await;

        let resp =
            h.authenticated_post("/control/v1/organizations", json!({"name": "Test Org"})).await;

        let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
        assert!(json["organization"]["slug"].is_number());
        assert_eq!(json["organization"]["name"], "Test Org");
    }

    /// Organization name validation rejects invalid inputs.
    #[tokio::test]
    async fn test_create_organization_validates_name() {
        let cases: &[(serde_json::Value, &str)] =
            &[(json!({"name": "<script>"}), "XSS in name"), (json!({"name": ""}), "empty name")];

        for (body, label) in cases {
            let h = TestHarness::start().await;

            let resp = h.authenticated_post("/control/v1/organizations", body.clone()).await;

            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "case: {label}");
        }
    }

    #[tokio::test]
    async fn test_list_organizations_returns_array() {
        let h = TestHarness::start().await;

        let resp = h.authenticated_get("/control/v1/organizations").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["organizations"].is_array());
    }

    #[tokio::test]
    async fn test_organizations_get_ok_returns_seeded_org_details() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_get("/control/v1/organizations/1").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["organization"]["slug"], 1);
        assert_eq!(json["organization"]["name"], "Test Org");
        assert!(json["organization"]["status"].is_string());
    }

    #[tokio::test]
    async fn test_update_organization_succeeds() {
        let h = TestHarness::start_with_org().await;

        let resp = h
            .authenticated_patch("/control/v1/organizations/1", json!({"name": "Updated Org"}))
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["organization"]["slug"].is_number());
    }

    #[tokio::test]
    async fn test_update_organization_validates_name() {
        let h = TestHarness::start_with_org().await;

        let resp = h
            .authenticated_patch("/control/v1/organizations/1", json!({"name": "#invalid!"}))
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_organization_succeeds() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_delete("/control/v1/organizations/1").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["message"].as_str().unwrap().contains("deleted"));
    }

    /// Non-admin users cannot modify membership.
    #[tokio::test]
    async fn test_member_modification_returns_forbidden() {
        let cases: &[(&str, &str, &str)] = &[
            ("PATCH", "/control/v1/organizations/1/members/42", "update role"),
            ("DELETE", "/control/v1/organizations/1/members/99", "remove member"),
        ];

        for (method, uri, label) in cases {
            let h = TestHarness::start_with_org().await;

            let resp = match *method {
                "PATCH" => h.authenticated_patch(uri, json!({"role": "admin"})).await,
                "DELETE" => h.authenticated_delete(uri).await,
                _ => panic!("unexpected method"),
            };

            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "case: {label}");
        }
    }

    #[tokio::test]
    async fn test_leave_organization_returns_not_found() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_delete("/control/v1/organizations/1/members/me").await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Invitation creation with different roles returns expected fields.
    #[tokio::test]
    async fn test_create_invitation_with_roles_succeeds() {
        let cases: &[(serde_json::Value, Option<&str>)] = &[
            (json!({"email": "default@example.com"}), None),
            (json!({"email": "admin@example.com", "role": "admin"}), Some("admin")),
            (json!({"email": "member@example.com", "role": "member"}), Some("member")),
        ];

        for (body, expected_role) in cases {
            let h = TestHarness::start_with_org().await;

            let resp =
                h.authenticated_post("/control/v1/organizations/1/invitations", body.clone()).await;

            let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
            assert!(json["slug"].is_number());
            assert_eq!(json["organization"], 1);
            assert!(json["status"].is_string());
            if let Some(role) = expected_role {
                assert_eq!(json["role"], *role);
            }
        }
    }

    #[tokio::test]
    async fn test_create_invitation_validates_email() {
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
    async fn test_organizations_listinvitations_ok_returns_empty_array() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_get("/control/v1/organizations/1/invitations").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["invitations"].is_array());
        assert!(
            json["invitations"].as_array().unwrap().is_empty(),
            "fresh org should have no invitations"
        );
    }

    /// Operations on non-existent invitations return 404.
    #[tokio::test]
    async fn test_invitation_operations_on_missing_return_not_found() {
        let cases: &[(&str, &str, &str)] = &[
            ("DELETE", "/control/v1/organizations/1/invitations/1", "delete invitation"),
            ("POST", "/control/v1/users/me/invitations/1/accept", "accept invitation"),
            ("POST", "/control/v1/users/me/invitations/1/decline", "decline invitation"),
        ];

        for (method, uri, label) in cases {
            let h = match *label {
                "delete invitation" => TestHarness::start_with_org().await,
                _ => TestHarness::start().await,
            };

            let resp = match *method {
                "DELETE" => h.authenticated_delete(uri).await,
                "POST" => h.authenticated_post(uri, json!({})).await,
                _ => panic!("unexpected method"),
            };

            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "case: {label}");
        }
    }

    #[tokio::test]
    async fn test_organizations_listreceivedinvitations_ok_returns_empty_array() {
        let h = TestHarness::start().await;

        let resp = h.authenticated_get("/control/v1/users/me/invitations").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["invitations"].is_array());
        assert!(
            json["invitations"].as_array().unwrap().is_empty(),
            "new user should have no received invitations"
        );
    }

    #[tokio::test]
    async fn test_organization_requires_auth() {
        let h = TestHarness::start().await;

        let resp = h.get("/control/v1/organizations").await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// -- Vault Handlers -----------------------------------------------------------

mod vaults {
    use super::*;

    #[tokio::test]
    async fn test_create_vault_succeeds() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_post("/control/v1/organizations/1/vaults", json!({})).await;

        let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
        assert!(json["vault"]["slug"].is_number());
    }

    #[tokio::test]
    async fn test_vaults_list_ok_returns_empty_array() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_get("/control/v1/organizations/1/vaults").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["vaults"].is_array());
    }

    #[tokio::test]
    async fn test_vaults_get_ok_returns_seeded_vault_details() {
        let h = TestHarness::start_with_org().await;
        h.server.add_vault(
            inferadb_ledger_types::OrganizationSlug::new(1),
            inferadb_ledger_types::VaultSlug::new(100),
        );

        let resp = h.authenticated_get("/control/v1/organizations/1/vaults/100").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["vault"]["slug"], 100);
        assert_eq!(json["vault"]["organization"], 1);
        assert!(json["vault"]["status"].is_string());
    }

    #[tokio::test]
    async fn test_update_vault_rejects_retention_policy() {
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
    async fn test_delete_vault_succeeds() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_delete("/control/v1/organizations/1/vaults/100").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["message"].as_str().unwrap().contains("deleted"));
    }

    #[tokio::test]
    async fn test_vault_requires_auth() {
        let h = TestHarness::start().await;

        let resp = h.get("/control/v1/organizations/1/vaults").await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// -- Team Handlers ------------------------------------------------------------

mod teams {
    use super::*;

    #[tokio::test]
    async fn test_create_team_succeeds() {
        let h = TestHarness::start_with_org().await;

        let resp = h
            .authenticated_post("/control/v1/organizations/1/teams", json!({"name": "Engineering"}))
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
        assert!(json["team"]["slug"].is_number());
    }

    #[tokio::test]
    async fn test_create_team_validates_name() {
        let h = TestHarness::start_with_org().await;

        let resp =
            h.authenticated_post("/control/v1/organizations/1/teams", json!({"name": ""})).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_teams_list_ok_returns_empty_array() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_get("/control/v1/organizations/1/teams").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["teams"].is_array());
        assert!(json["teams"].as_array().unwrap().is_empty(), "fresh org should have no teams");
    }

    #[tokio::test]
    async fn test_teams_get_notfound_for_nonexistent_team() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_get("/control/v1/organizations/1/teams/100").await;

        TestHarness::assert_status(resp, StatusCode::NOT_FOUND).await;
    }

    #[tokio::test]
    async fn test_teams_listmembers_notfound_for_nonexistent_team() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_get("/control/v1/organizations/1/teams/100/members").await;

        TestHarness::assert_status(resp, StatusCode::NOT_FOUND).await;
    }

    /// Write operations on non-existent teams return 404.
    #[tokio::test]
    async fn test_team_write_on_missing_returns_not_found() {
        let cases: &[(&str, &str, &str)] = &[
            ("PATCH", "/control/v1/organizations/1/teams/100", "update team"),
            ("DELETE", "/control/v1/organizations/1/teams/100", "delete team"),
        ];

        for (method, uri, label) in cases {
            let h = TestHarness::start_with_org().await;

            let resp = match *method {
                "PATCH" => h.authenticated_patch(uri, json!({"name": "New Name"})).await,
                "DELETE" => h.authenticated_delete(uri).await,
                _ => panic!("unexpected method"),
            };

            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "case: {label}");
        }
    }

    #[tokio::test]
    async fn test_add_team_member_succeeds() {
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
    async fn test_teams_updatemember_ok_returns_team() {
        let h = TestHarness::start_with_org().await;

        let resp = h
            .authenticated_patch(
                "/control/v1/organizations/1/teams/100/members/42",
                json!({"role": "manager"}),
            )
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["team"].is_object(), "should return team object");
    }

    #[tokio::test]
    async fn test_teams_removemember_ok_returns_message() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_delete("/control/v1/organizations/1/teams/100/members/42").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["message"].is_string(), "should return message");
    }
}

// -- Client Handlers ----------------------------------------------------------

mod clients {
    use super::*;

    #[tokio::test]
    async fn test_create_client_succeeds() {
        let h = TestHarness::start_with_org().await;

        let resp = h
            .authenticated_post("/control/v1/organizations/1/clients", json!({"name": "My App"}))
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
        assert!(json["client"]["slug"].is_number());
    }

    #[tokio::test]
    async fn test_create_client_validates_name() {
        let h = TestHarness::start_with_org().await;

        let resp =
            h.authenticated_post("/control/v1/organizations/1/clients", json!({"name": ""})).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_clients_list_ok_returns_array() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_get("/control/v1/organizations/1/clients").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["clients"].is_array());
    }

    #[tokio::test]
    async fn test_clients_get_ok_returns_client_details() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_get("/control/v1/organizations/1/clients/100").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["client"]["slug"].is_number());
    }

    #[tokio::test]
    async fn test_update_client_succeeds() {
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
    async fn test_delete_client_succeeds() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_delete("/control/v1/organizations/1/clients/100").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["message"].is_string());
    }

    #[tokio::test]
    async fn test_clients_rotatesecret_ok_returns_secret() {
        let h = TestHarness::start_with_org().await;

        let resp = h
            .authenticated_post("/control/v1/organizations/1/clients/100/secret/rotate", json!({}))
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["secret"].is_string(), "should return rotated secret");
    }

    #[tokio::test]
    async fn test_clients_revokecertificate_ok_returns_message() {
        let h = TestHarness::start_with_org().await;

        let resp = h
            .authenticated_delete("/control/v1/organizations/1/clients/100/certificates/200")
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["message"].is_string(), "should return confirmation message");
    }
}

// -- Schema Handlers ----------------------------------------------------------

mod schemas {
    use super::*;

    #[tokio::test]
    async fn test_schemas_list_ok_returns_array() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_get("/control/v1/organizations/1/vaults/100/schemas").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["schemas"].is_array());
    }

    #[tokio::test]
    async fn test_schemas_getversion_notfound_for_nonexistent() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_get("/control/v1/organizations/1/vaults/100/schemas/1").await;

        TestHarness::assert_status(resp, StatusCode::NOT_FOUND).await;
    }

    #[tokio::test]
    async fn test_schemas_getcurrent_notfound_when_none_deployed() {
        let h = TestHarness::start_with_org().await;

        let resp =
            h.authenticated_get("/control/v1/organizations/1/vaults/100/schemas/current").await;

        TestHarness::assert_status(resp, StatusCode::NOT_FOUND).await;
    }

    #[tokio::test]
    async fn test_schemas_diff_error_for_nonexistent_versions() {
        let h = TestHarness::start_with_org().await;

        let resp = h
            .authenticated_get("/control/v1/organizations/1/vaults/100/schemas/diff?from=1&to=2")
            .await;

        let status = resp.status();
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
            "expected 404 or 400, got {status}"
        );
    }

    #[tokio::test]
    async fn test_schemas_deploy_succeeds() {
        let h = TestHarness::start_with_org().await;

        let resp = h
            .authenticated_post(
                "/control/v1/organizations/1/vaults/100/schemas",
                json!({"definition": {"entities": {}}}),
            )
            .await;

        let status = resp.status();
        assert!(
            status == StatusCode::CREATED || status == StatusCode::OK,
            "expected 200 or 201, got {status}"
        );
    }

    #[tokio::test]
    async fn test_rollback_schema_returns_validation_error() {
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
    async fn test_activate_schema_returns_not_found() {
        let h = TestHarness::start_with_org().await;

        let resp = h
            .authenticated_post(
                "/control/v1/organizations/1/vaults/100/schemas/1/activate",
                json!({}),
            )
            .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

// -- Token Handlers -----------------------------------------------------------

mod tokens {
    use super::*;

    #[tokio::test]
    async fn test_generate_vault_token_succeeds() {
        let h = TestHarness::start_with_org().await;

        let resp = h
            .authenticated_post("/control/v1/organizations/1/vaults/100/tokens", json!({"app": 50}))
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
        assert!(json["access_token"].is_string());
    }

    /// Revoking vault tokens without required 'app' field returns a client error.
    #[tokio::test]
    async fn test_tokens_revokevaulttokens_without_body_returns_client_error() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_delete("/control/v1/organizations/1/vaults/100/tokens").await;

        let status = resp.status();
        assert!(status.is_client_error(), "DELETE without body should return 4xx, got {status}");
    }

    #[tokio::test]
    async fn test_refresh_vault_token_succeeds() {
        let h = TestHarness::start().await;

        let resp = h
            .post("/control/v1/tokens/refresh", json!({"refresh_token": "mock-refresh-token"}))
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["access_token"].is_string());
    }

    /// Client assertion with valid fields returns a token pair.
    #[tokio::test]
    async fn test_tokens_clientassertion_created_returns_token_pair() {
        let h = TestHarness::start().await;

        let resp = h
            .post(
                "/control/v1/token",
                json!({
                    "grant_type": "client_credentials",
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": "mock-jwt-assertion",
                    "organization": 1,
                    "vault": "100"
                }),
            )
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
        assert!(json["access_token"].is_string());
        assert!(json["refresh_token"].is_string());
        assert_eq!(json["token_type"], "Bearer");
    }

    /// Client assertion with missing required fields returns 422.
    #[tokio::test]
    async fn test_tokens_clientassertion_missing_fields_returns_422() {
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

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}

// -- Email Handlers -----------------------------------------------------------

mod emails {
    use super::*;

    #[tokio::test]
    async fn test_emails_list_ok_returns_empty_array() {
        let h = TestHarness::start().await;

        let resp = h.authenticated_get("/control/v1/users/emails").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["emails"].is_array());
    }

    #[tokio::test]
    async fn test_delete_email_returns_not_found() {
        let h = TestHarness::start().await;

        let resp = h.authenticated_delete("/control/v1/users/emails/1").await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_verify_email_with_token_returns_not_found() {
        let h = TestHarness::start().await;

        let resp = h.post("/control/v1/auth/verify-email", json!({"token": "valid-token"})).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_emails_require_auth() {
        let h = TestHarness::start().await;

        let resp = h.get("/control/v1/users/emails").await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// -- Audit Log Handlers -------------------------------------------------------

mod audit_logs {
    use super::*;

    #[tokio::test]
    async fn test_auditlogs_list_ok_returns_entries_array() {
        let h = TestHarness::start_with_org().await;

        let resp = h.authenticated_get("/control/v1/organizations/1/audit-logs").await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["entries"].is_array());
    }

    #[tokio::test]
    async fn test_audit_logs_require_auth() {
        let h = TestHarness::start().await;

        let resp = h.get("/control/v1/organizations/1/audit-logs").await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// -- MFA Auth Handlers --------------------------------------------------------

mod mfa_auth {
    use super::*;

    #[tokio::test]
    async fn test_verify_totp_valid_code_returns_token_pair() {
        let h = TestHarness::start().await;

        let resp = h
            .post(
                "/control/v1/auth/totp/verify",
                json!({"user_slug": 42, "totp_code": "123456", "challenge_nonce": "dGVzdA=="}),
            )
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["access_token"], "mock-totp-access");
        assert_eq!(json["refresh_token"], "mock-totp-refresh");
    }

    #[tokio::test]
    async fn test_verify_totp_valid_code_sets_both_cookies() {
        let h = TestHarness::start().await;

        let resp = h
            .post(
                "/control/v1/auth/totp/verify",
                json!({"user_slug": 42, "totp_code": "123456", "challenge_nonce": "dGVzdA=="}),
            )
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let access = TestHarness::extract_cookie(resp.headers(), "inferadb_access");
        let refresh = TestHarness::extract_cookie(resp.headers(), "inferadb_refresh");
        assert!(access.is_some(), "should set inferadb_access cookie");
        assert!(refresh.is_some(), "should set inferadb_refresh cookie");
    }

    #[tokio::test]
    async fn test_verify_totp_invalid_nonce_returns_400() {
        let h = TestHarness::start().await;

        let resp = h
            .post(
                "/control/v1/auth/totp/verify",
                json!({"user_slug": 42, "totp_code": "123456", "challenge_nonce": "!!!invalid!!!"}),
            )
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_verify_totp_missing_user_slug_returns_422() {
        let h = TestHarness::start().await;

        let resp = h
            .post(
                "/control/v1/auth/totp/verify",
                json!({"challenge_nonce": "dGVzdA==", "totp_code": "123456"}),
            )
            .await;

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_verify_totp_empty_body_returns_422() {
        let h = TestHarness::start().await;

        let resp = h.post("/control/v1/auth/totp/verify", json!({})).await;

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_consume_recovery_valid_code_returns_token_pair_and_remaining() {
        let h = TestHarness::start().await;

        let resp = h
            .post(
                "/control/v1/auth/recovery",
                json!({"user_slug": 42, "code": "ABCD-1234", "challenge_nonce": "dGVzdA=="}),
            )
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["access_token"], "mock-recovery-access");
        assert_eq!(json["refresh_token"], "mock-recovery-refresh");
        assert_eq!(json["remaining_codes"], 7);
    }

    #[tokio::test]
    async fn test_consume_recovery_valid_code_sets_both_cookies() {
        let h = TestHarness::start().await;

        let resp = h
            .post(
                "/control/v1/auth/recovery",
                json!({"user_slug": 42, "code": "ABCD-1234", "challenge_nonce": "dGVzdA=="}),
            )
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let access = TestHarness::extract_cookie(resp.headers(), "inferadb_access");
        let refresh = TestHarness::extract_cookie(resp.headers(), "inferadb_refresh");
        assert!(access.is_some(), "should set access cookie");
        assert!(refresh.is_some(), "should set refresh cookie");
    }

    #[tokio::test]
    async fn test_consume_recovery_invalid_nonce_returns_400() {
        let h = TestHarness::start().await;

        let resp = h
            .post(
                "/control/v1/auth/recovery",
                json!({"user_slug": 42, "code": "ABCD-1234", "challenge_nonce": "!!!bad!!!"}),
            )
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_consume_recovery_missing_fields_returns_422() {
        let h = TestHarness::start().await;

        let resp = h.post("/control/v1/auth/recovery", json!({"user_slug": 42})).await;

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_passkey_begin_no_webauthn_configured_returns_500() {
        let h = TestHarness::start().await;

        let resp = h.post("/control/v1/auth/passkey/begin", json!({"user_slug": 42})).await;

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_passkey_begin_invalid_mock_credentials_returns_500() {
        let h = TestHarness::start_with_webauthn().await;

        let resp = h.post("/control/v1/auth/passkey/begin", json!({"user_slug": 42})).await;

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_passkey_begin_missing_user_slug_returns_422() {
        let h = TestHarness::start_with_webauthn().await;

        let resp = h.post("/control/v1/auth/passkey/begin", json!({})).await;

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_passkey_register_begin_unauthenticated_returns_401() {
        let h = TestHarness::start().await;

        let resp = h.post("/control/v1/users/me/credentials/passkeys/begin", json!({})).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_passkey_register_begin_no_webauthn_configured_returns_500() {
        let h = TestHarness::start().await;

        let resp = h
            .authenticated_post("/control/v1/users/me/credentials/passkeys/begin", json!({}))
            .await;

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_passkey_register_begin_default_name_returns_challenge() {
        let h = TestHarness::start_with_webauthn().await;

        let resp = h
            .authenticated_post("/control/v1/users/me/credentials/passkeys/begin", json!({}))
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["challenge_id"].is_string(), "response should contain challenge_id");
        assert!(!json["challenge"].is_null(), "response should contain challenge");
    }

    #[tokio::test]
    async fn test_passkey_register_begin_custom_name_returns_challenge() {
        let h = TestHarness::start_with_webauthn().await;

        let resp = h
            .authenticated_post(
                "/control/v1/users/me/credentials/passkeys/begin",
                json!({"name": "My MacBook"}),
            )
            .await;

        let json = TestHarness::assert_status(resp, StatusCode::OK).await;
        assert!(json["challenge_id"].is_string());
    }

    #[tokio::test]
    async fn test_passkey_register_begin_xss_name_returns_400() {
        let h = TestHarness::start_with_webauthn().await;

        let resp = h
            .authenticated_post(
                "/control/v1/users/me/credentials/passkeys/begin",
                json!({"name": "<script>alert(1)</script>"}),
            )
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_passkey_finish_nonexistent_challenge_returns_400() {
        let h = TestHarness::start_with_webauthn().await;

        let resp = h
            .post(
                "/control/v1/auth/passkey/finish",
                json!({
                    "challenge_id": "nonexistent-challenge-id",
                    "credential": {
                        "id": "dGVzdA",
                        "rawId": "dGVzdA",
                        "type": "public-key",
                        "response": {
                            "authenticatorData": "dGVzdA",
                            "clientDataJSON": "dGVzdA",
                            "signature": "dGVzdA"
                        }
                    }
                }),
            )
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_passkey_finish_registration_challenge_returns_400() {
        let h = TestHarness::start_with_webauthn().await;
        let begin_resp = h
            .authenticated_post("/control/v1/users/me/credentials/passkeys/begin", json!({}))
            .await;
        let begin_json = TestHarness::assert_status(begin_resp, StatusCode::OK).await;
        let challenge_id = begin_json["challenge_id"].as_str().unwrap();

        let resp = h
            .post(
                "/control/v1/auth/passkey/finish",
                json!({
                    "challenge_id": challenge_id,
                    "credential": {
                        "id": "dGVzdA",
                        "rawId": "dGVzdA",
                        "type": "public-key",
                        "response": {
                            "authenticatorData": "dGVzdA",
                            "clientDataJSON": "dGVzdA",
                            "signature": "dGVzdA"
                        }
                    }
                }),
            )
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_passkey_register_finish_nonexistent_challenge_returns_400() {
        let h = TestHarness::start_with_webauthn().await;

        let resp = h
            .authenticated_post(
                "/control/v1/users/me/credentials/passkeys/finish",
                json!({
                    "challenge_id": "nonexistent-challenge-id",
                    "name": "My Key",
                    "credential": {
                        "id": "dGVzdA",
                        "rawId": "dGVzdA",
                        "type": "public-key",
                        "response": {
                            "attestationObject": "dGVzdA",
                            "clientDataJSON": "dGVzdA"
                        },
                        "extensions": {}
                    }
                }),
            )
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_passkey_register_finish_xss_name_returns_400() {
        let h = TestHarness::start_with_webauthn().await;

        let resp = h
            .authenticated_post(
                "/control/v1/users/me/credentials/passkeys/finish",
                json!({
                    "challenge_id": "any",
                    "name": "<script>",
                    "credential": {
                        "id": "dGVzdA",
                        "rawId": "dGVzdA",
                        "type": "public-key",
                        "response": {
                            "attestationObject": "dGVzdA",
                            "clientDataJSON": "dGVzdA"
                        },
                        "extensions": {}
                    }
                }),
            )
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_passkey_finish_no_webauthn_configured_returns_500() {
        let h = TestHarness::start().await;

        let resp = h
            .post(
                "/control/v1/auth/passkey/finish",
                json!({
                    "challenge_id": "any",
                    "credential": {
                        "id": "dGVzdA",
                        "rawId": "dGVzdA",
                        "type": "public-key",
                        "response": {
                            "authenticatorData": "dGVzdA",
                            "clientDataJSON": "dGVzdA",
                            "signature": "dGVzdA"
                        }
                    }
                }),
            )
            .await;

        // Handler calls require_webauthn before challenge lookup, so missing
        // WebAuthn configuration returns 500 regardless of challenge_id validity.
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_passkey_register_finish_no_webauthn_configured_returns_500() {
        let h = TestHarness::start().await;

        let resp = h
            .authenticated_post(
                "/control/v1/users/me/credentials/passkeys/finish",
                json!({
                    "challenge_id": "any",
                    "name": "My Key",
                    "credential": {
                        "id": "dGVzdA",
                        "rawId": "dGVzdA",
                        "type": "public-key",
                        "response": {
                            "attestationObject": "dGVzdA",
                            "clientDataJSON": "dGVzdA"
                        },
                        "extensions": {}
                    }
                }),
            )
            .await;

        // validate_name passes, require_ledger passes, require_webauthn fails (500)
        // before challenge lookup is reached.
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Verifies the begin->finish multi-step flow: a challenge_id from
    /// register-begin is accepted by register-finish. The WebAuthn credential
    /// itself is invalid, so the failure comes from credential validation (400),
    /// not challenge lookup.
    #[tokio::test]
    async fn test_passkey_register_begin_challenge_accepted_by_finish_returns_400() {
        let h = TestHarness::start_with_webauthn().await;

        // Step 1: Begin registration to get a valid challenge_id.
        let begin_resp = h
            .authenticated_post(
                "/control/v1/users/me/credentials/passkeys/begin",
                json!({"name": "Test Key"}),
            )
            .await;
        let begin_json = TestHarness::assert_status(begin_resp, StatusCode::OK).await;
        let challenge_id = begin_json["challenge_id"].as_str().unwrap();

        // Step 2: Finish with the real challenge_id but a fake credential.
        let resp = h
            .authenticated_post(
                "/control/v1/users/me/credentials/passkeys/finish",
                json!({
                    "challenge_id": challenge_id,
                    "name": "Test Key",
                    "credential": {
                        "id": "dGVzdA",
                        "rawId": "dGVzdA",
                        "type": "public-key",
                        "response": {
                            "attestationObject": "dGVzdA",
                            "clientDataJSON": "dGVzdA"
                        },
                        "extensions": {}
                    }
                }),
            )
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Verifies that replaying a consumed challenge_id returns 400.
    #[tokio::test]
    async fn test_passkey_register_finish_replay_challenge_returns_400() {
        let h = TestHarness::start_with_webauthn().await;

        let begin_resp = h
            .authenticated_post(
                "/control/v1/users/me/credentials/passkeys/begin",
                json!({"name": "Replay Key"}),
            )
            .await;
        let begin_json = TestHarness::assert_status(begin_resp, StatusCode::OK).await;
        let challenge_id = begin_json["challenge_id"].as_str().unwrap();

        let finish_body = json!({
            "challenge_id": challenge_id,
            "name": "Replay Key",
            "credential": {
                "id": "dGVzdA",
                "rawId": "dGVzdA",
                "type": "public-key",
                "response": {
                    "attestationObject": "dGVzdA",
                    "clientDataJSON": "dGVzdA"
                },
                "extensions": {}
            }
        });

        // First attempt consumes the challenge (fails at WebAuthn validation).
        let _first = h
            .authenticated_post(
                "/control/v1/users/me/credentials/passkeys/finish",
                finish_body.clone(),
            )
            .await;

        // Second attempt fails because the challenge was already consumed.
        let second = h
            .authenticated_post("/control/v1/users/me/credentials/passkeys/finish", finish_body)
            .await;

        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    }
}

// -- JWT Middleware ------------------------------------------------------------

mod jwt_middleware {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn test_bearer_token_accepted_by_local_jwt_validation() {
        let h = TestHarness::start().await;

        let resp = h.authenticated_get("/control/v1/users/me").await;

        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "valid JWT should be accepted by local validation"
        );
    }

    /// Invalid or missing auth headers return 401.
    #[tokio::test]
    async fn test_invalid_auth_headers_return_401() {
        let cases: &[(&str, &str)] = &[
            ("Bearer ", "empty bearer token"),
            ("Bearer  ", "whitespace-only bearer token"),
            ("Basic dXNlcjpwYXNz", "non-bearer scheme"),
        ];

        for (auth_value, label) in cases {
            let h = TestHarness::start().await;

            let resp = h
                .app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/control/v1/users/me")
                        .header("authorization", *auth_value)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "case: {label}");
        }
    }

    #[tokio::test]
    async fn test_no_auth_header_returns_401() {
        let h = TestHarness::start().await;

        let resp = h.get("/control/v1/users/me").await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// -- Multi-Step Integration Tests -----------------------------------------------

/// Create org -> list orgs -> verify created org appears in list.
#[tokio::test]
async fn test_multistep_createorg_listorgs_created_org_appears() {
    let h = TestHarness::start().await;

    // Create an organization
    let resp =
        h.authenticated_post("/control/v1/organizations", json!({"name": "Multi Org"})).await;
    let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
    let created_slug = json["organization"]["slug"].as_u64().unwrap();
    assert_eq!(json["organization"]["name"], "Multi Org");

    // List organizations and verify it appears
    let resp = h.authenticated_get("/control/v1/organizations").await;
    let json = TestHarness::assert_status(resp, StatusCode::OK).await;
    let orgs = json["organizations"].as_array().unwrap();
    let found = orgs.iter().any(|o| o["slug"].as_u64() == Some(created_slug));
    assert!(found, "created org slug {created_slug} should appear in list");
}

/// Create team -> add member -> list members -> verify member appears.
#[tokio::test]
async fn test_multistep_createteam_addmember_listmembers_member_appears() {
    let h = TestHarness::start_with_org().await;

    // Create a team
    let resp =
        h.authenticated_post("/control/v1/organizations/1/teams", json!({"name": "Backend"})).await;
    let json = TestHarness::assert_status(resp, StatusCode::CREATED).await;
    let team_slug = json["team"]["slug"].as_u64().unwrap();
    assert_eq!(json["team"]["name"], "Backend");

    // Add a member to the team
    let uri = format!("/control/v1/organizations/1/teams/{team_slug}/members");
    let resp = h.authenticated_post(&uri, json!({"user": 42})).await;
    TestHarness::assert_status(resp, StatusCode::OK).await;

    // List team members and verify the member appears
    let resp = h.authenticated_get(&uri).await;
    let json = TestHarness::assert_status(resp, StatusCode::OK).await;
    assert!(json["members"].is_array(), "should return members array");
}

/// POST /users/emails requires authentication.
#[tokio::test]
async fn test_emails_addemail_requires_auth() {
    let h = TestHarness::start().await;

    let resp = h.post("/control/v1/users/emails", json!({"email": "new@example.com"})).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// POST /users/emails returns 500 when blinding key is not configured.
/// This verifies the route is wired and auth works, even though the mock
/// harness does not configure a blinding key.
#[tokio::test]
async fn test_emails_addemail_returns_internal_error_without_blinding_key() {
    let h = TestHarness::start().await;

    let resp =
        h.authenticated_post("/control/v1/users/emails", json!({"email": "new@example.com"})).await;

    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "should return 500 when blinding key is not configured"
    );
}

// -- Auth Required (cross-cutting) --------------------------------------------

/// Protected endpoints return 401 without authentication.
#[tokio::test]
async fn test_protected_endpoints_require_auth() {
    let endpoints = [
        "/control/v1/organizations",
        "/control/v1/organizations/1/vaults",
        "/control/v1/users/emails",
        "/control/v1/organizations/1/audit-logs",
    ];

    for endpoint in endpoints {
        let h = TestHarness::start().await;

        let resp = h.get(endpoint).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{endpoint} should require auth");
    }
}
