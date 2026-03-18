//! Vault management handlers.
//!
//! All operations delegate to Ledger SDK via the service layer.
//! Vault state (access, tokens) is owned by Ledger; direct user/team grants
//! are not a concept in the Ledger model (access is managed via app-vault connections).

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use inferadb_control_core::service;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{OrganizationSlug, VaultSlug};
use serde::{Deserialize, Serialize};

use crate::{
    handlers::auth::{AppState, Result},
    middleware::UserClaims,
};

// ── Request Types ─────────────────────────────────────────────────────

/// Pagination query for cursor-based pagination.
#[derive(Debug, Deserialize)]
pub struct CursorPaginationQuery {
    /// Number of items per page (default 50, max 100).
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// Opaque cursor for the next page (base64-encoded).
    pub page_token: Option<String>,
}

fn default_page_size() -> u32 {
    50
}

impl CursorPaginationQuery {
    fn validated_page_size(&self) -> u32 {
        self.page_size.clamp(1, 100)
    }

    fn decoded_page_token(&self) -> Option<Vec<u8>> {
        use base64::Engine;
        self.page_token
            .as_deref()
            .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok())
    }
}

// ── Response Types ────────────────────────────────────────────────────

/// Vault summary response.
#[derive(Debug, Serialize)]
pub struct VaultResponse {
    pub organization: u64,
    pub vault: u64,
    pub height: u64,
    pub status: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leader: Option<String>,
}

/// Wrapper for a single vault.
#[derive(Debug, Serialize)]
pub struct SingleVaultResponse {
    pub vault: VaultResponse,
}

/// Paginated list of vaults.
#[derive(Debug, Serialize)]
pub struct ListVaultsResponse {
    pub vaults: Vec<VaultResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// Simple message response.
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// ── Helpers ───────────────────────────────────────────────────────────

fn vault_info_to_response(info: inferadb_ledger_sdk::VaultInfo) -> VaultResponse {
    VaultResponse {
        organization: info.organization.value(),
        vault: info.vault.value(),
        height: info.height,
        status: format!("{:?}", info.status),
        nodes: info.nodes,
        leader: info.leader,
    }
}

fn require_ledger(
    state: &AppState,
) -> std::result::Result<&inferadb_ledger_sdk::LedgerClient, CoreError> {
    state.ledger.as_deref().ok_or_else(|| CoreError::internal("Ledger client not configured"))
}

// ── Vault CRUD Handlers ──────────────────────────────────────────────

/// Create a new vault in an organization.
///
/// POST /control/v1/organizations/{org}/vaults
pub async fn create_vault(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path(org): Path<u64>,
) -> Result<(StatusCode, Json<SingleVaultResponse>)> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);

    let info = service::vault::create_vault(ledger, organization).await?;

    Ok((StatusCode::CREATED, Json(SingleVaultResponse { vault: vault_info_to_response(info) })))
}

/// List vaults (paginated).
///
/// GET /control/v1/organizations/{org}/vaults
pub async fn list_vaults(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path(_org): Path<u64>,
    Query(pagination): Query<CursorPaginationQuery>,
) -> Result<Json<ListVaultsResponse>> {
    let ledger = require_ledger(&state)?;

    let (vaults, next_token) = service::vault::list_vaults(
        ledger,
        pagination.validated_page_size(),
        pagination.decoded_page_token(),
    )
    .await?;

    let next_page_token = next_token.map(|t| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(t)
    });

    Ok(Json(ListVaultsResponse {
        vaults: vaults.into_iter().map(vault_info_to_response).collect(),
        next_page_token,
    }))
}

/// Get a vault by organization and vault slug.
///
/// GET /control/v1/organizations/{org}/vaults/{vault}
pub async fn get_vault(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
) -> Result<Json<SingleVaultResponse>> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);

    let info = service::vault::get_vault(ledger, organization, vault_slug).await?;

    Ok(Json(SingleVaultResponse { vault: vault_info_to_response(info) }))
}

/// Get a vault by ID (engine-to-control endpoint, no org context needed).
///
/// GET /control/v1/vaults/{vault}
///
/// The Ledger SDK requires both organization and vault slugs. This endpoint
/// returns 501 until the SDK supports vault lookup by slug alone.
pub async fn get_vault_by_id(
    State(_state): State<AppState>,
    Path(_vault): Path<u64>,
) -> Result<Json<MessageResponse>> {
    Err(CoreError::internal("vault lookup by ID without organization context is not yet supported")
        .into())
}

/// Update a vault.
///
/// PATCH /control/v1/organizations/{org}/vaults/{vault}
pub async fn update_vault(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
) -> Result<Json<MessageResponse>> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);

    service::vault::update_vault(ledger, organization, vault_slug).await?;

    Ok(Json(MessageResponse { message: "Vault updated".to_string() }))
}

/// Delete a vault.
///
/// DELETE /control/v1/organizations/{org}/vaults/{vault}
///
/// Vault deletion is not yet supported by the Ledger SDK.
pub async fn delete_vault(
    State(_state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((_org, _vault)): Path<(u64, u64)>,
) -> Result<Json<MessageResponse>> {
    Err(CoreError::internal("vault deletion is not yet supported by the Ledger SDK").into())
}
