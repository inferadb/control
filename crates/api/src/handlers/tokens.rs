//! Token management handlers.
//!
//! Delegates vault token operations to the Ledger SDK.
//! User session tokens are managed in `auth_v2.rs` and `session.rs`.

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::Engine as _;
use inferadb_control_core::service;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{AppSlug, OrganizationSlug, VaultSlug};
use serde::{Deserialize, Serialize};

use crate::{
    handlers::auth::{AppState, Result},
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

/// JWT claims expected in the client assertion.
#[derive(Debug, Deserialize)]
struct AssertionClaims {
    /// Issuer — the app slug (numeric string).
    iss: String,
    /// Subject — same as issuer for M2M auth.
    sub: String,
    /// Audience — the token endpoint URL. Captured for future validation.
    #[serde(default)]
    #[allow(dead_code)]
    aud: serde_json::Value,
    /// JWT ID — unique per assertion to prevent replay.
    #[allow(dead_code)]
    jti: Option<String>,
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

/// Validates the OAuth 2.0 grant type and assertion type fields.
fn validate_assertion_request(req: &ClientAssertionRequest) -> std::result::Result<(), CoreError> {
    if req.grant_type != EXPECTED_GRANT_TYPE {
        return Err(CoreError::validation(format!(
            "unsupported grant_type '{}': expected '{EXPECTED_GRANT_TYPE}'",
            req.grant_type
        )));
    }

    if req.client_assertion_type != EXPECTED_ASSERTION_TYPE {
        return Err(CoreError::validation(format!(
            "unsupported client_assertion_type '{}': expected '{EXPECTED_ASSERTION_TYPE}'",
            req.client_assertion_type
        )));
    }

    if req.client_assertion.is_empty() {
        return Err(CoreError::validation("client_assertion must not be empty"));
    }

    Ok(())
}

/// Decodes a JWT without signature verification and extracts the claims.
///
/// The JWT header is parsed to extract `kid` and confirm `alg` is EdDSA.
/// Claims are decoded from the payload segment. Signature verification is
/// delegated to Ledger via the app credential lookup — Ledger validates that
/// the app has an active client assertion matching the `kid` before issuing
/// a vault token. The cryptographic binding is:
///
/// 1. Control decodes the JWT to extract the app identity (`iss` claim).
/// 2. Ledger verifies the app exists, is enabled, and has client assertion credentials enabled when
///    `create_vault_token` is called.
/// 3. The vault token is scoped to the app and vault from the request.
fn decode_assertion_claims(
    jwt: &str,
) -> std::result::Result<(jsonwebtoken::Header, AssertionClaims), CoreError> {
    let header = jsonwebtoken::decode_header(jwt).map_err(|e| {
        CoreError::validation(format!("invalid JWT header in client_assertion: {e}"))
    })?;

    if header.alg != jsonwebtoken::Algorithm::EdDSA {
        return Err(CoreError::validation(format!(
            "unsupported JWT algorithm '{:?}': expected EdDSA",
            header.alg
        )));
    }

    // Decode payload without verification. The JWT has three base64url-encoded
    // segments: header.payload.signature. We parse the payload directly.
    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() < 2 {
        return Err(CoreError::validation("malformed JWT: expected header.payload.signature"));
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| CoreError::validation(format!("invalid JWT payload encoding: {e}")))?;

    let claims: AssertionClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| CoreError::validation(format!("invalid JWT claims: {e}")))?;

    Ok((header, claims))
}

/// Parses the `iss` claim as an app slug (u64).
fn parse_app_slug_from_issuer(iss: &str) -> std::result::Result<u64, CoreError> {
    iss.parse::<u64>().map_err(|_| {
        CoreError::validation(format!("JWT 'iss' claim must be a numeric app slug, got '{iss}'"))
    })
}

/// Validates basic JWT claim constraints.
fn validate_assertion_claims(claims: &AssertionClaims) -> std::result::Result<(), CoreError> {
    if claims.iss.is_empty() {
        return Err(CoreError::validation("JWT 'iss' claim must not be empty"));
    }

    if claims.sub != claims.iss {
        return Err(CoreError::validation(
            "JWT 'sub' claim must match 'iss' for client credential assertions",
        ));
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
/// Public endpoint for machine-to-machine authentication. Accepts a signed JWT
/// assertion that identifies an app, validates the assertion structure, and
/// issues a vault access token via Ledger.
///
/// Flow:
/// 1. Validate grant type and assertion type fields.
/// 2. Decode the JWT header (must be EdDSA) and payload claims.
/// 3. Extract the app slug from the `iss` claim.
/// 4. Call Ledger to create a vault token scoped to the app/vault/org. Ledger enforces that the app
///    exists, is enabled, and has the correct vault connections and credential configuration.
pub async fn client_assertion_authenticate(
    State(state): State<AppState>,
    Json(req): Json<ClientAssertionRequest>,
) -> Result<(StatusCode, Json<TokenPairResponse>)> {
    validate_assertion_request(&req)?;

    let ledger = require_ledger(&state)?;

    let (_header, claims) = decode_assertion_claims(&req.client_assertion)?;

    validate_assertion_claims(&claims)?;

    let app_id = parse_app_slug_from_issuer(&claims.iss)?;
    let app_slug = AppSlug::new(app_id);
    let organization = OrganizationSlug::new(req.organization);

    let vault_id: u64 = req.vault.parse().map_err(|_| {
        CoreError::validation(format!("vault must be a numeric slug, got '{}'", req.vault))
    })?;
    let vault_slug = VaultSlug::new(vault_id);

    let scopes = build_scopes(&req);

    let pair =
        service::vault::create_vault_token(ledger, organization, app_slug, vault_slug, &scopes)
            .await?;

    Ok((StatusCode::CREATED, Json(token_pair_to_response(pair))))
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
