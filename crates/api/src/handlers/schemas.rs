//! Schema management handlers (stub).
//!
//! Schema CRUD depends on the Ledger's vault entity store API for persisting
//! schema data as key-value entities within a vault. These handlers return 500
//! until the vault entity store integration is finalized.

use axum::{
    Extension, Json,
    extract::{Path, State},
};
use inferadb_control_types::Error as CoreError;
use serde::Serialize;

use crate::{
    handlers::auth::{AppState, Result},
    middleware::UserClaims,
};

// ── Response Types ────────────────────────────────────────────────────

/// Stub message response for unimplemented endpoints.
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// ── Schema Handlers (stubs) ──────────────────────────────────────────

/// Deploy a new schema version.
///
/// POST /control/v1/organizations/{org}/vaults/{vault}/schemas
pub async fn deploy_schema(
    State(_state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((_org, _vault)): Path<(u64, u64)>,
) -> Result<Json<MessageResponse>> {
    Err(CoreError::internal(
        "schema deployment is not yet implemented; pending vault entity store integration",
    )
    .into())
}

/// List all schema versions for a vault.
///
/// GET /control/v1/organizations/{org}/vaults/{vault}/schemas
pub async fn list_schemas(
    State(_state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((_org, _vault)): Path<(u64, u64)>,
) -> Result<Json<MessageResponse>> {
    Err(CoreError::internal(
        "schema listing is not yet implemented; pending vault entity store integration",
    )
    .into())
}

/// Get a specific schema version.
///
/// GET /control/v1/organizations/{org}/vaults/{vault}/schemas/{version}
pub async fn get_schema(
    State(_state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((_org, _vault, _version)): Path<(u64, u64, String)>,
) -> Result<Json<MessageResponse>> {
    Err(CoreError::internal(
        "schema retrieval is not yet implemented; pending vault entity store integration",
    )
    .into())
}

/// Get the currently active schema.
///
/// GET /control/v1/organizations/{org}/vaults/{vault}/schemas/current
pub async fn get_current_schema(
    State(_state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((_org, _vault)): Path<(u64, u64)>,
) -> Result<Json<MessageResponse>> {
    Err(CoreError::internal(
        "current schema retrieval is not yet implemented; pending vault entity store integration",
    )
    .into())
}

/// Activate a specific schema version.
///
/// POST /control/v1/organizations/{org}/vaults/{vault}/schemas/{version}/activate
pub async fn activate_schema(
    State(_state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((_org, _vault, _version)): Path<(u64, u64, String)>,
) -> Result<Json<MessageResponse>> {
    Err(CoreError::internal(
        "schema activation is not yet implemented; pending vault entity store integration",
    )
    .into())
}

/// Rollback to a previous schema version.
///
/// POST /control/v1/organizations/{org}/vaults/{vault}/schemas/rollback
pub async fn rollback_schema(
    State(_state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((_org, _vault)): Path<(u64, u64)>,
) -> Result<Json<MessageResponse>> {
    Err(CoreError::internal(
        "schema rollback is not yet implemented; pending vault entity store integration",
    )
    .into())
}

/// Compare two schema versions.
///
/// GET /control/v1/organizations/{org}/vaults/{vault}/schemas/diff
pub async fn diff_schemas(
    State(_state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((_org, _vault)): Path<(u64, u64)>,
) -> Result<Json<MessageResponse>> {
    Err(CoreError::internal(
        "schema diff is not yet implemented; pending vault entity store integration",
    )
    .into())
}
