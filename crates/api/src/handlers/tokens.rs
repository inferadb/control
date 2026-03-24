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
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Response containing the number of revoked tokens.
#[derive(Debug, Serialize)]
pub struct RevokeTokensResponse {
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
        token_type: "Bearer".to_string(),
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
