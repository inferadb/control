//! Token management handlers.
//!
//! Delegates vault token operations to the Ledger SDK.
//! User session tokens are managed in `auth_v2.rs` and `session.rs`.

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use inferadb_control_core::service;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{AppSlug, OrganizationSlug, VaultSlug};
use serde::{Deserialize, Serialize};

use crate::{
    handlers::auth::{AppState, Result},
    middleware::UserClaims,
};

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
    pub grant_type: String,
    pub client_assertion_type: String,
    pub client_assertion: String,
    pub vault: String,
    pub requested_role: Option<String>,
}

/// Request body for revoking vault tokens.
#[derive(Debug, Deserialize)]
pub struct RevokeVaultTokensRequest {
    /// App slug whose sessions to revoke.
    pub app: u64,
}

// ── Response Types ────────────────────────────────────────────────────

/// Token pair response (access + refresh).
#[derive(Debug, Serialize)]
pub struct TokenPairResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Simple message response.
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

/// Revoke tokens response.
#[derive(Debug, Serialize)]
pub struct RevokeTokensResponse {
    pub revoked_count: u64,
}

// ── Helpers ───────────────────────────────────────────────────────────

fn require_ledger(
    state: &AppState,
) -> std::result::Result<&inferadb_ledger_sdk::LedgerClient, CoreError> {
    state.ledger.as_deref().ok_or_else(|| CoreError::internal("Ledger client not configured"))
}

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

// ── Token Handlers ───────────────────────────────────────────────────

/// Generate a vault access token for an app.
///
/// POST /control/v1/organizations/{org}/vaults/{vault}/tokens
pub async fn generate_vault_token(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
    Json(req): Json<GenerateVaultTokenRequest>,
) -> Result<(StatusCode, Json<TokenPairResponse>)> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);
    let app_slug = AppSlug::new(req.app);

    let pair =
        service::vault::create_vault_token(ledger, organization, app_slug, vault_slug, &req.scopes)
            .await?;

    Ok((StatusCode::CREATED, Json(token_pair_to_response(pair))))
}

/// Refresh a vault token using a refresh token.
///
/// POST /control/v1/tokens/refresh
///
/// Public endpoint (refresh token provides authentication).
pub async fn refresh_vault_token(
    State(state): State<AppState>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<Json<TokenPairResponse>> {
    let ledger = require_ledger(&state)?;

    let pair = service::session::refresh_token(ledger, &req.refresh_token).await?;

    Ok(Json(token_pair_to_response(pair)))
}

/// Client assertion authentication (OAuth 2.0 JWT Bearer, RFC 7523).
///
/// POST /control/v1/token
///
/// Public endpoint. Returns 500 until the Ledger SDK token service integration
/// is complete.
pub async fn client_assertion_authenticate(
    State(_state): State<AppState>,
    Json(_req): Json<ClientAssertionRequest>,
) -> Result<Json<MessageResponse>> {
    Err(CoreError::internal(
        "client assertion authentication is not yet implemented; pending Ledger SDK token service integration",
    )
    .into())
}

/// Revoke all vault tokens for an app.
///
/// DELETE /control/v1/organizations/{org}/vaults/{vault}/tokens
pub async fn revoke_vault_tokens(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((_org, _vault)): Path<(u64, u64)>,
    Json(req): Json<RevokeVaultTokensRequest>,
) -> Result<Json<RevokeTokensResponse>> {
    let ledger = require_ledger(&state)?;
    let app_slug = AppSlug::new(req.app);

    let revoked_count = service::vault::revoke_all_app_sessions(ledger, app_slug).await?;

    Ok(Json(RevokeTokensResponse { revoked_count }))
}
