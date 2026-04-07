//! Schema management handlers.
//!
//! All operations delegate to Ledger SDK. Schema state (versions,
//! definitions, active status) is owned by Ledger.

use std::time::Instant;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use inferadb_control_core::SdkResultExt;
use inferadb_ledger_sdk::{OrganizationSlug, VaultSlug};
use serde::{Deserialize, Serialize};

use super::common::{require_ledger, verify_org_membership_from_claims};
use crate::{
    handlers::state::{AppState, Result},
    middleware::UserClaims,
};

// ── Request / Response Types ────────────────────────────────────────

/// Request body for deploying a new schema version.
#[derive(Debug, Deserialize)]
pub struct DeploySchemaRequest {
    /// The schema definition as an arbitrary JSON object.
    pub definition: serde_json::Value,
    /// Explicit version number. If omitted, auto-increments from the latest.
    pub version: Option<u32>,
    /// Optional human-readable description.
    pub description: Option<String>,
}

/// Response for schema deploy and activate operations.
#[derive(Debug, Serialize)]
pub struct SchemaStatusResponse {
    pub version: u32,
    pub status: String,
}

/// Summary of a schema version.
#[derive(Debug, Serialize)]
pub struct SchemaVersionSummary {
    pub version: u32,
    pub has_definition: bool,
    pub is_active: bool,
}

/// Response containing schema versions for a vault.
#[derive(Debug, Serialize)]
pub struct ListSchemasResponse {
    pub schemas: Vec<SchemaVersionSummary>,
}

/// Schema version with its full definition.
#[derive(Debug, Serialize)]
pub struct SchemaDefinitionResponse {
    pub version: u32,
    pub definition: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Query parameters for the schema diff endpoint.
#[derive(Debug, Deserialize)]
pub struct DiffQuery {
    /// Source schema version number.
    pub from: u32,
    /// Target schema version number.
    pub to: u32,
}

/// A field-level change between two schema versions.
#[derive(Debug, Serialize)]
pub struct FieldChange {
    /// Dotted path to the changed field (e.g., `"users.email"`).
    pub field: String,
    /// Kind of change (e.g., `"added"`, `"removed"`, `"modified"`).
    pub change_type: String,
}

/// Diff between two schema versions.
#[derive(Debug, Serialize)]
pub struct DiffResponse {
    /// Source schema version.
    pub from: u32,
    /// Target schema version.
    pub to: u32,
    /// Field-level changes between the two versions.
    pub changes: Vec<FieldChange>,
}

// ── Schema Handlers ─────────────────────────────────────────────────

/// POST /control/v1/organizations/{org}/vaults/{vault}/schemas
///
/// Deploys a new schema version.
pub async fn deploy_schema(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
    Json(body): Json<DeploySchemaRequest>,
) -> Result<(StatusCode, Json<SchemaStatusResponse>)> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);
    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    let result = ledger
        .deploy_schema(
            claims.user_slug,
            org_slug,
            vault_slug,
            body.definition,
            body.version,
            body.description,
        )
        .await
        .map_sdk_err_instrumented("deploy_schema", start)?;

    Ok((
        StatusCode::CREATED,
        Json(SchemaStatusResponse { version: result.version, status: "deployed".to_string() }),
    ))
}

/// GET /control/v1/organizations/{org}/vaults/{vault}/schemas
///
/// Lists all schema versions for a vault.
pub async fn list_schemas(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
) -> Result<Json<ListSchemasResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);
    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    let versions = ledger
        .list_schema_versions(claims.user_slug, org_slug, vault_slug)
        .await
        .map_sdk_err_instrumented("list_schema_versions", start)?;

    let schemas = versions
        .into_iter()
        .map(|v| SchemaVersionSummary {
            version: v.version,
            has_definition: v.has_definition,
            is_active: v.is_active,
        })
        .collect();

    Ok(Json(ListSchemasResponse { schemas }))
}

/// GET /control/v1/organizations/{org}/vaults/{vault}/schemas/{version}
///
/// Returns a specific schema version.
pub async fn get_schema(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, vault, version)): Path<(u64, u64, u32)>,
) -> Result<Json<SchemaDefinitionResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);
    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    let schema = ledger
        .get_schema(claims.user_slug, org_slug, vault_slug, version)
        .await
        .map_sdk_err_instrumented("get_schema", start)?;

    Ok(Json(SchemaDefinitionResponse {
        version: schema.version,
        definition: schema.definition,
        description: schema.description,
    }))
}

/// GET /control/v1/organizations/{org}/vaults/{vault}/schemas/current
///
/// Returns the currently active schema.
pub async fn get_current_schema(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
) -> Result<Json<SchemaDefinitionResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);
    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    let schema = ledger
        .get_active_schema(claims.user_slug, org_slug, vault_slug)
        .await
        .map_sdk_err_instrumented("get_active_schema", start)?;

    Ok(Json(SchemaDefinitionResponse {
        version: schema.version,
        definition: schema.definition,
        description: schema.description,
    }))
}

/// POST /control/v1/organizations/{org}/vaults/{vault}/schemas/{version}/activate
///
/// Activates a specific schema version.
pub async fn activate_schema(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, vault, version)): Path<(u64, u64, u32)>,
) -> Result<Json<SchemaStatusResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);
    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    let activated_version = ledger
        .activate_schema(claims.user_slug, org_slug, vault_slug, version)
        .await
        .map_sdk_err_instrumented("activate_schema", start)?;

    Ok(Json(SchemaStatusResponse { version: activated_version, status: "active".to_string() }))
}

/// POST /control/v1/organizations/{org}/vaults/{vault}/schemas/rollback
///
/// Rolls back to a previous schema version.
pub async fn rollback_schema(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
) -> Result<Json<SchemaStatusResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);
    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    let restored_version = ledger
        .rollback_schema(claims.user_slug, org_slug, vault_slug)
        .await
        .map_sdk_err_instrumented("rollback_schema", start)?;

    Ok(Json(SchemaStatusResponse { version: restored_version, status: "active".to_string() }))
}

/// GET /control/v1/organizations/{org}/vaults/{vault}/schemas/diff?from=N&to=M
///
/// Compares two schema versions.
pub async fn diff_schemas(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
    Query(params): Query<DiffQuery>,
) -> Result<Json<DiffResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);
    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    let changes = ledger
        .diff_schemas(claims.user_slug, org_slug, vault_slug, params.from, params.to)
        .await
        .map_sdk_err_instrumented("diff_schemas", start)?;

    let field_changes = changes
        .into_iter()
        .map(|c| FieldChange { field: c.field, change_type: c.change_type })
        .collect();

    Ok(Json(DiffResponse { from: params.from, to: params.to, changes: field_changes }))
}
