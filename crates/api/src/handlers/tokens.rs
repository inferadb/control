//! Token management handlers.
//!
//! Delegates vault token operations to the Ledger SDK.
//! User session tokens are managed in [`auth`](super::auth).

use std::time::Instant;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use inferadb_control_core::SdkResultExt;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{AppSlug, OrganizationSlug, VaultSlug};
use serde::{Deserialize, Serialize};

use super::common::require_ledger;
use crate::{
    handlers::state::{AppState, Result},
    middleware::UserClaims,
};

// ── Constants ────────────────────────────────────────────────────────

/// Expected OAuth 2.0 grant type for client credentials.
const EXPECTED_GRANT_TYPE: &str = "client_credentials";

/// Expected assertion type for JWT Bearer (RFC 7523).
const EXPECTED_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

// ── Request Types ─────────────────────────────────────────────────────

/// Request body for generating a vault token.
#[derive(Debug, Deserialize)]
pub struct GenerateVaultTokenRequest {
    /// App slug to create the token for.
    pub app: u64,
    /// Scopes to grant (e.g., `["vault:read", "vault:write"]`).
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Request body for refreshing a vault token.
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Request body for client assertion authentication (OAuth 2.0 JWT Bearer, RFC 7523).
#[derive(Debug, Deserialize)]
pub struct ClientAssertionRequest {
    /// Must be `"client_credentials"`.
    pub grant_type: String,
    /// Must be `"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"`.
    pub client_assertion_type: String,
    /// Signed JWT assertion (Ed25519/EdDSA).
    pub client_assertion: String,
    /// Organization slug for the vault token.
    pub organization: u64,
    /// Vault slug to create the token for.
    pub vault: String,
    /// Scopes to grant (e.g., `["vault:read", "vault:write"]`).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Requested role (mapped to scope if provided).
    pub requested_role: Option<String>,
}

/// Request body for revoking vault tokens.
#[derive(Debug, Deserialize)]
pub struct RevokeVaultTokensRequest {
    /// App slug whose sessions to revoke.
    pub app: u64,
}

// ── Response Types ────────────────────────────────────────────────────

/// Response containing an access/refresh token pair.
#[derive(Debug, Serialize)]
pub struct TokenPairResponse {
    /// JWT access token.
    pub access_token: String,
    /// Opaque refresh token for obtaining new access tokens.
    pub refresh_token: String,
    /// Token type (always `"Bearer"`).
    pub token_type: &'static str,
    /// Seconds until the access token expires.
    pub expires_in: u64,
}

/// Response containing the number of revoked tokens.
#[derive(Debug, Serialize)]
pub struct RevokeTokensResponse {
    /// Number of tokens that were revoked.
    pub revoked_count: u64,
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Converts a Ledger [`TokenPair`](inferadb_ledger_sdk::token::TokenPair) to an API response.
fn token_pair_to_response(pair: inferadb_ledger_sdk::token::TokenPair) -> TokenPairResponse {
    use std::time::SystemTime;

    let expires_in = pair
        .access_expires_at
        .and_then(|t| t.duration_since(SystemTime::now()).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    TokenPairResponse {
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        token_type: "Bearer",
        expires_in,
    }
}

/// Validates the OAuth 2.0 grant type and assertion type fields.
fn validate_assertion_request(req: &ClientAssertionRequest) -> std::result::Result<(), CoreError> {
    if req.grant_type != EXPECTED_GRANT_TYPE {
        return Err(CoreError::validation(format!(
            "unsupported grant_type: expected '{EXPECTED_GRANT_TYPE}'"
        )));
    }

    if req.client_assertion_type != EXPECTED_ASSERTION_TYPE {
        return Err(CoreError::validation(format!(
            "unsupported client_assertion_type: expected '{EXPECTED_ASSERTION_TYPE}'"
        )));
    }

    if req.client_assertion.is_empty() {
        return Err(CoreError::validation("client_assertion must not be empty"));
    }

    Ok(())
}

/// Builds the effective scopes list, incorporating `requested_role` if present.
fn build_scopes(req: &ClientAssertionRequest) -> Vec<String> {
    let mut scopes = req.scopes.clone();
    if let Some(ref role) = req.requested_role
        && !scopes.iter().any(|s| s == role)
    {
        scopes.push(role.clone());
    }
    scopes
}

// ── Token Handlers ───────────────────────────────────────────────────

/// POST /control/v1/organizations/{org}/vaults/{vault}/tokens
///
/// Generates a vault access token for an app.
pub async fn generate_vault_token(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
    Json(req): Json<GenerateVaultTokenRequest>,
) -> Result<(StatusCode, Json<TokenPairResponse>)> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);
    let app_slug = AppSlug::new(req.app);

    // Verify caller has access to the app in this organization.
    let start = Instant::now();
    ledger
        .get_app(organization, claims.user_slug, app_slug)
        .await
        .map_sdk_err_instrumented("get_app", start)?;

    let start = Instant::now();
    let pair = ledger
        .create_vault_token(organization, app_slug, vault_slug, &req.scopes)
        .await
        .map_sdk_err_instrumented("create_vault_token", start)?;

    Ok((StatusCode::CREATED, Json(token_pair_to_response(pair))))
}

/// POST /control/v1/tokens/refresh
///
/// Refreshes a vault token using a refresh token.
/// Public endpoint (refresh token provides authentication).
pub async fn refresh_vault_token(
    State(state): State<AppState>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<Json<TokenPairResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let pair = ledger
        .refresh_token(&req.refresh_token)
        .await
        .map_sdk_err_instrumented("refresh_token", start)?;

    Ok(Json(token_pair_to_response(pair)))
}

/// POST /control/v1/token
///
/// Authenticates via client assertion (OAuth 2.0 JWT Bearer, RFC 7523).
/// Public endpoint for machine-to-machine authentication. Accepts a signed JWT
/// assertion that identifies an app, validates the assertion structure, and
/// delegates JWT signature verification to Ledger, which validates the
/// assertion against the app's registered public keys before issuing a scoped
/// vault token.
pub async fn client_assertion_authenticate(
    State(state): State<AppState>,
    Json(req): Json<ClientAssertionRequest>,
) -> Result<(StatusCode, Json<TokenPairResponse>)> {
    validate_assertion_request(&req)?;

    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(req.organization);

    let vault_id: u64 =
        req.vault.parse().map_err(|_| CoreError::validation("vault must be a numeric slug"))?;
    let vault_slug = VaultSlug::new(vault_id);

    let scopes = build_scopes(&req);

    let start = Instant::now();
    let pair = ledger
        .authenticate_client_assertion(organization, vault_slug, &req.client_assertion, &scopes)
        .await
        .map_sdk_err_instrumented("authenticate_client_assertion", start)?;

    Ok((StatusCode::CREATED, Json(token_pair_to_response(pair))))
}

/// DELETE /control/v1/organizations/{org}/vaults/{vault}/tokens
///
/// Revokes all vault tokens for an app.
pub async fn revoke_vault_tokens(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, _vault)): Path<(u64, u64)>,
    Json(req): Json<RevokeVaultTokensRequest>,
) -> Result<Json<RevokeTokensResponse>> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);
    let app_slug = AppSlug::new(req.app);

    // Verify caller has access to the app in this organization before revoking.
    let start = Instant::now();
    ledger
        .get_app(organization, claims.user_slug, app_slug)
        .await
        .map_sdk_err_instrumented("get_app", start)?;

    let start = Instant::now();
    let revoked_count = ledger
        .revoke_all_app_sessions(app_slug)
        .await
        .map_sdk_err_instrumented("revoke_all_app_sessions", start)?;

    Ok(Json(RevokeTokensResponse { revoked_count }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;

    fn make_assertion_request(
        grant_type: &str,
        assertion_type: &str,
        assertion: &str,
    ) -> ClientAssertionRequest {
        ClientAssertionRequest {
            grant_type: grant_type.to_string(),
            client_assertion_type: assertion_type.to_string(),
            client_assertion: assertion.to_string(),
            organization: 1,
            vault: "42".to_string(),
            scopes: vec![],
            requested_role: None,
        }
    }

    fn make_scopes_request(scopes: Vec<&str>, role: Option<&str>) -> ClientAssertionRequest {
        ClientAssertionRequest {
            grant_type: String::new(),
            client_assertion_type: String::new(),
            client_assertion: String::new(),
            organization: 1,
            vault: "1".to_string(),
            scopes: scopes.into_iter().map(String::from).collect(),
            requested_role: role.map(String::from),
        }
    }

    // ── validate_assertion_request ──────────────────────────────────────

    #[test]
    fn test_validate_assertion_request_valid_inputs_returns_ok() {
        let req =
            make_assertion_request(EXPECTED_GRANT_TYPE, EXPECTED_ASSERTION_TYPE, "some.jwt.token");

        assert!(validate_assertion_request(&req).is_ok());
    }

    #[test]
    fn test_validate_assertion_request_wrong_grant_type_returns_error() {
        let req =
            make_assertion_request("authorization_code", EXPECTED_ASSERTION_TYPE, "some.jwt.token");

        let err = validate_assertion_request(&req).unwrap_err();

        let msg = format!("{err}");
        assert!(msg.contains("grant_type"), "error should mention grant_type: {msg}");
    }

    #[test]
    fn test_validate_assertion_request_wrong_assertion_type_returns_error() {
        let req = make_assertion_request(EXPECTED_GRANT_TYPE, "urn:wrong:type", "some.jwt.token");

        let err = validate_assertion_request(&req).unwrap_err();

        let msg = format!("{err}");
        assert!(
            msg.contains("client_assertion_type"),
            "error should mention client_assertion_type: {msg}"
        );
    }

    #[test]
    fn test_validate_assertion_request_empty_assertion_returns_error() {
        let req = make_assertion_request(EXPECTED_GRANT_TYPE, EXPECTED_ASSERTION_TYPE, "");

        let err = validate_assertion_request(&req).unwrap_err();

        let msg = format!("{err}");
        assert!(msg.contains("client_assertion"), "error should mention client_assertion: {msg}");
    }

    // ── build_scopes ────────────────────────────────────────────────────

    #[test]
    fn test_build_scopes_no_role_returns_scopes_unchanged() {
        let req = make_scopes_request(vec!["vault:read", "vault:write"], None);

        let scopes = build_scopes(&req);

        assert_eq!(scopes, vec!["vault:read", "vault:write"]);
    }

    #[test]
    fn test_build_scopes_new_role_appended() {
        let req = make_scopes_request(vec!["vault:read"], Some("admin"));

        let scopes = build_scopes(&req);

        assert_eq!(scopes, vec!["vault:read", "admin"]);
    }

    #[test]
    fn test_build_scopes_duplicate_role_not_appended() {
        let req = make_scopes_request(vec!["vault:read", "admin"], Some("admin"));

        let scopes = build_scopes(&req);

        assert_eq!(scopes, vec!["vault:read", "admin"]);
    }

    #[test]
    fn test_build_scopes_empty_scopes_with_role_returns_role() {
        let req = make_scopes_request(vec![], Some("reader"));

        let scopes = build_scopes(&req);

        assert_eq!(scopes, vec!["reader"]);
    }

    // ── token_pair_to_response ──────────────────────────────────────────

    #[test]
    fn test_token_pair_to_response_future_expiry_returns_positive_ttl() {
        let pair = inferadb_ledger_sdk::token::TokenPair {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            access_expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
            refresh_expires_at: None,
        };

        let resp = token_pair_to_response(pair);

        assert_eq!(resp.access_token, "access");
        assert_eq!(resp.refresh_token, "refresh");
        assert_eq!(resp.token_type, "Bearer");
        assert!(resp.expires_in > 0);
        assert!(resp.expires_in <= 3600);
    }

    #[test]
    fn test_token_pair_to_response_past_expiry_returns_zero() {
        let pair = inferadb_ledger_sdk::token::TokenPair {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            access_expires_at: Some(SystemTime::now() - Duration::from_secs(60)),
            refresh_expires_at: None,
        };

        let resp = token_pair_to_response(pair);

        assert_eq!(resp.expires_in, 0);
    }

    #[test]
    fn test_token_pair_to_response_no_expiry_returns_zero() {
        let pair = inferadb_ledger_sdk::token::TokenPair {
            access_token: "a".to_string(),
            refresh_token: "r".to_string(),
            access_expires_at: None,
            refresh_expires_at: None,
        };

        let resp = token_pair_to_response(pair);

        assert_eq!(resp.expires_in, 0);
    }

    // ── Request type deserialization ────────────────────────────────────

    #[test]
    fn test_generate_vault_token_request_deserializes_with_scopes() {
        let json = r#"{"app": 42, "scopes": ["vault:read"]}"#;

        let req: GenerateVaultTokenRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.app, 42);
        assert_eq!(req.scopes, vec!["vault:read"]);
    }

    #[test]
    fn test_generate_vault_token_request_defaults_scopes_to_empty() {
        let json = r#"{"app": 1}"#;

        let req: GenerateVaultTokenRequest = serde_json::from_str(json).unwrap();

        assert!(req.scopes.is_empty());
    }

    #[test]
    fn test_refresh_token_request_deserializes() {
        let json = r#"{"refresh_token": "tok"}"#;

        let req: RefreshTokenRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.refresh_token, "tok");
    }

    #[test]
    fn test_client_assertion_request_defaults_optional_fields() {
        let json = r#"{
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": "jwt",
            "organization": 1,
            "vault": "5"
        }"#;

        let req: ClientAssertionRequest = serde_json::from_str(json).unwrap();

        assert!(req.scopes.is_empty());
        assert!(req.requested_role.is_none());
    }

    #[test]
    fn test_revoke_vault_tokens_request_deserializes() {
        let json = r#"{"app": 99}"#;

        let req: RevokeVaultTokensRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.app, 99);
    }

    // ── Response type serialization ────────────────────────────────────

    #[test]
    fn test_token_pair_response_serializes() {
        let resp = TokenPairResponse {
            access_token: "at".to_string(),
            refresh_token: "rt".to_string(),
            token_type: "Bearer",
            expires_in: 3600,
        };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["access_token"], "at");
        assert_eq!(json["expires_in"], 3600);
    }

    #[test]
    fn test_revoke_tokens_response_serializes() {
        let resp = RevokeTokensResponse { revoked_count: 7 };

        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["revoked_count"], 7);
    }
}
