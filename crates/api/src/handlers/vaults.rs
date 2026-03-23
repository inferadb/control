//! Vault management handlers.
//!
//! All operations delegate to Ledger SDK via the service layer.
//! Vault state (access, tokens) is owned by Ledger; direct user/team grants
//! are not a concept in the Ledger model (access is managed via app-vault connections).

use std::time::Instant;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use inferadb_control_core::SdkResultExt;
use inferadb_ledger_sdk::{OrganizationSlug, VaultSlug};
use serde::{Deserialize, Serialize};

use super::common::{
    CursorPaginationQuery, MessageResponse, encode_page_token, require_ledger,
    verify_org_membership_from_claims,
};
use crate::{
    handlers::state::{AppState, Result},
    middleware::UserClaims,
};

// ── Request Types ────────────────────────────────────────────────────

/// Request body for updating a vault.
///
/// `retention_policy` is accepted but not yet wired to the Ledger proto type.
/// Providing it returns a validation error until the mapping is implemented.
#[derive(Debug, Deserialize)]
pub struct UpdateVaultRequest {
    pub retention_policy: Option<String>,
}

// ── Response Types ────────────────────────────────────────────────────

/// Vault summary response.
#[derive(Debug, Serialize)]
pub struct VaultResponse {
    pub organization: u64,
    pub slug: u64,
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

// ── Helpers ───────────────────────────────────────────────────────────

fn vault_info_to_response(info: inferadb_ledger_sdk::VaultInfo) -> VaultResponse {
    VaultResponse {
        organization: info.organization.value(),
        slug: info.vault.value(),
        height: info.height,
        status: info.status.to_string(),
        nodes: info.nodes,
        leader: info.leader,
    }
}

// ── Vault CRUD Handlers ──────────────────────────────────────────────

/// Create a new vault in an organization.
///
/// POST /control/v1/organizations/{org}/vaults
pub async fn create_vault(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
) -> Result<(StatusCode, Json<SingleVaultResponse>)> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);

    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    let info = ledger
        .create_vault(claims.user_slug, organization)
        .await
        .map_sdk_err_instrumented("create_vault", start)?;

    Ok((StatusCode::CREATED, Json(SingleVaultResponse { vault: vault_info_to_response(info) })))
}

/// List vaults (paginated).
///
/// GET /control/v1/organizations/{org}/vaults
///
/// Returns vaults belonging to the specified organization.
pub async fn list_vaults(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Query(pagination): Query<CursorPaginationQuery>,
) -> Result<Json<ListVaultsResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);

    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    let (vaults, next_token) = ledger
        .list_vaults(
            claims.user_slug,
            pagination.validated_page_size(),
            pagination.decoded_page_token(),
            Some(org_slug),
        )
        .await
        .map_sdk_err_instrumented("list_vaults", start)?;

    Ok(Json(ListVaultsResponse {
        vaults: vaults.into_iter().map(vault_info_to_response).collect(),
        next_page_token: encode_page_token(&next_token),
    }))
}

/// Get a vault by organization and vault slug.
///
/// GET /control/v1/organizations/{org}/vaults/{vault}
pub async fn get_vault(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
) -> Result<Json<SingleVaultResponse>> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);

    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    let info = ledger
        .get_vault(claims.user_slug, organization, vault_slug)
        .await
        .map_sdk_err_instrumented("get_vault", start)?;

    Ok(Json(SingleVaultResponse { vault: vault_info_to_response(info) }))
}

/// Update a vault.
///
/// PATCH /control/v1/organizations/{org}/vaults/{vault}
pub async fn update_vault(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
    Json(body): Json<UpdateVaultRequest>,
) -> Result<Json<MessageResponse>> {
    if body.retention_policy.is_some() {
        return Err(inferadb_control_types::Error::validation(
            "retention_policy updates are not yet supported",
        )
        .into());
    }
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);

    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    ledger
        .update_vault(claims.user_slug, organization, vault_slug, None)
        .await
        .map_sdk_err_instrumented("update_vault", start)?;

    Ok(Json(MessageResponse { message: "Vault updated".to_string() }))
}

/// Delete a vault.
///
/// DELETE /control/v1/organizations/{org}/vaults/{vault}
pub async fn delete_vault(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
) -> Result<Json<MessageResponse>> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);

    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    ledger
        .delete_vault(claims.user_slug, organization, vault_slug)
        .await
        .map_sdk_err_instrumented("delete_vault", start)?;

    Ok(Json(MessageResponse { message: "Vault deleted".to_string() }))
}
