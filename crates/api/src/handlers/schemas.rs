//! Schema management handlers.
//!
//! Schemas are stored as JSON blobs in the Ledger vault entity store with
//! well-known key prefixes:
//! - `schema:v{version}` — schema definition JSON for a specific version
//! - `schema:current` — pointer to the currently active version
//! - `schema:latest` — pointer to the highest deployed version

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

/// Stored schema definition (persisted in the entity store).
#[derive(Debug, Serialize, Deserialize)]
struct StoredSchema {
    definition: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

/// Version pointer stored at `schema:current` and `schema:latest`.
#[derive(Debug, Serialize, Deserialize)]
struct VersionPointer {
    version: u32,
}

/// Response for deploy and activate operations.
#[derive(Debug, Serialize)]
pub struct SchemaStatusResponse {
    pub version: u32,
    pub status: String,
}

/// Summary of a single schema version in a listing.
#[derive(Debug, Serialize)]
pub struct SchemaVersionSummary {
    pub version: u32,
    pub has_definition: bool,
}

/// Response for listing schema versions.
#[derive(Debug, Serialize)]
pub struct ListSchemasResponse {
    pub schemas: Vec<SchemaVersionSummary>,
}

/// Response for get schema (includes the definition).
#[derive(Debug, Serialize)]
pub struct SchemaDefinitionResponse {
    pub version: u32,
    pub definition: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Query parameters for the diff endpoint.
#[derive(Debug, Deserialize)]
pub struct DiffQuery {
    pub from: u32,
    pub to: u32,
}

/// A single field change in a schema diff.
#[derive(Debug, Serialize)]
pub struct FieldChange {
    pub field: String,
    pub change_type: String,
}

/// Response for schema diff.
#[derive(Debug, Serialize)]
pub struct DiffResponse {
    pub from: u32,
    pub to: u32,
    pub changes: Vec<FieldChange>,
}

// ── Helpers ─────────────────────────────────────────────────────────

fn require_ledger(
    state: &AppState,
) -> std::result::Result<&inferadb_ledger_sdk::LedgerClient, CoreError> {
    state.ledger.as_deref().ok_or_else(|| CoreError::internal("Ledger client not configured"))
}

fn schema_version_key(version: u32) -> String {
    format!("schema:v{version}")
}

async fn read_version_pointer(
    ledger: &inferadb_ledger_sdk::LedgerClient,
    org: OrganizationSlug,
    vault: VaultSlug,
    key: &str,
) -> std::result::Result<Option<VersionPointer>, CoreError> {
    let data = service::vault::read_entity(ledger, org, vault, key).await?;
    match data {
        Some(bytes) => {
            let pointer: VersionPointer = serde_json::from_slice(&bytes).map_err(|e| {
                CoreError::internal(format!("corrupt version pointer at {key}: {e}"))
            })?;
            Ok(Some(pointer))
        },
        None => Ok(None),
    }
}

async fn write_version_pointer(
    ledger: &inferadb_ledger_sdk::LedgerClient,
    org: OrganizationSlug,
    vault: VaultSlug,
    key: &str,
    version: u32,
) -> std::result::Result<(), CoreError> {
    let pointer = VersionPointer { version };
    let bytes = serde_json::to_vec(&pointer)
        .map_err(|e| CoreError::internal(format!("failed to serialize version pointer: {e}")))?;
    service::vault::write_entity(ledger, org, vault, key, bytes).await
}

async fn read_stored_schema(
    ledger: &inferadb_ledger_sdk::LedgerClient,
    org: OrganizationSlug,
    vault: VaultSlug,
    version: u32,
) -> std::result::Result<Option<StoredSchema>, CoreError> {
    let key = schema_version_key(version);
    let data = service::vault::read_entity(ledger, org, vault, &key).await?;
    match data {
        Some(bytes) => {
            let schema: StoredSchema = serde_json::from_slice(&bytes)
                .map_err(|e| CoreError::internal(format!("corrupt schema at {key}: {e}")))?;
            Ok(Some(schema))
        },
        None => Ok(None),
    }
}

/// Computes flat key-level differences between two JSON objects.
fn diff_json_objects(from: &serde_json::Value, to: &serde_json::Value) -> Vec<FieldChange> {
    let empty = serde_json::Map::new();
    let from_obj = from.as_object().unwrap_or(&empty);
    let to_obj = to.as_object().unwrap_or(&empty);

    let mut changes = Vec::new();

    for key in from_obj.keys() {
        if !to_obj.contains_key(key) {
            changes.push(FieldChange { field: key.clone(), change_type: "removed".to_string() });
        } else if from_obj.get(key) != to_obj.get(key) {
            changes.push(FieldChange { field: key.clone(), change_type: "changed".to_string() });
        }
    }

    for key in to_obj.keys() {
        if !from_obj.contains_key(key) {
            changes.push(FieldChange { field: key.clone(), change_type: "added".to_string() });
        }
    }

    changes.sort_by(|a, b| a.field.cmp(&b.field));
    changes
}

// ── Schema Handlers ─────────────────────────────────────────────────

/// Deploy a new schema version.
///
/// POST /control/v1/organizations/{org}/vaults/{vault}/schemas
pub async fn deploy_schema(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
    Json(body): Json<DeploySchemaRequest>,
) -> Result<(StatusCode, Json<SchemaStatusResponse>)> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);

    let version = match body.version {
        Some(v) => {
            if v == 0 {
                return Err(CoreError::validation("schema version must be greater than 0").into());
            }
            v
        },
        None => {
            let latest =
                read_version_pointer(ledger, org_slug, vault_slug, "schema:latest").await?;
            latest.map_or(1, |p| p.version + 1)
        },
    };

    let stored = StoredSchema { definition: body.definition, description: body.description };
    let bytes = serde_json::to_vec(&stored)
        .map_err(|e| CoreError::internal(format!("failed to serialize schema: {e}")))?;

    let key = schema_version_key(version);
    service::vault::write_entity(ledger, org_slug, vault_slug, &key, bytes).await?;
    write_version_pointer(ledger, org_slug, vault_slug, "schema:latest", version).await?;

    Ok((
        StatusCode::CREATED,
        Json(SchemaStatusResponse { version, status: "deployed".to_string() }),
    ))
}

/// List all schema versions for a vault.
///
/// GET /control/v1/organizations/{org}/vaults/{vault}/schemas
pub async fn list_schemas(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
) -> Result<Json<ListSchemasResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);

    let latest = read_version_pointer(ledger, org_slug, vault_slug, "schema:latest").await?;

    let max_version = match latest {
        Some(p) => p.version,
        None => {
            return Ok(Json(ListSchemasResponse { schemas: vec![] }));
        },
    };

    let mut schemas = Vec::with_capacity(max_version as usize);
    for v in 1..=max_version {
        let key = schema_version_key(v);
        let exists =
            service::vault::read_entity(ledger, org_slug, vault_slug, &key).await?.is_some();
        schemas.push(SchemaVersionSummary { version: v, has_definition: exists });
    }

    Ok(Json(ListSchemasResponse { schemas }))
}

/// Get a specific schema version.
///
/// GET /control/v1/organizations/{org}/vaults/{vault}/schemas/{version}
pub async fn get_schema(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((org, vault, version)): Path<(u64, u64, u32)>,
) -> Result<Json<SchemaDefinitionResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);

    let stored = read_stored_schema(ledger, org_slug, vault_slug, version)
        .await?
        .ok_or_else(|| CoreError::not_found(format!("schema version {version} not found")))?;

    Ok(Json(SchemaDefinitionResponse {
        version,
        definition: stored.definition,
        description: stored.description,
    }))
}

/// Get the currently active schema.
///
/// GET /control/v1/organizations/{org}/vaults/{vault}/schemas/current
pub async fn get_current_schema(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
) -> Result<Json<SchemaDefinitionResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);

    let current = read_version_pointer(ledger, org_slug, vault_slug, "schema:current")
        .await?
        .ok_or_else(|| CoreError::not_found("no active schema version"))?;

    let stored = read_stored_schema(ledger, org_slug, vault_slug, current.version)
        .await?
        .ok_or_else(|| {
            CoreError::not_found(format!(
                "active schema version {} has no definition",
                current.version
            ))
        })?;

    Ok(Json(SchemaDefinitionResponse {
        version: current.version,
        definition: stored.definition,
        description: stored.description,
    }))
}

/// Activate a specific schema version.
///
/// POST /control/v1/organizations/{org}/vaults/{vault}/schemas/{version}/activate
pub async fn activate_schema(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((org, vault, version)): Path<(u64, u64, u32)>,
) -> Result<Json<SchemaStatusResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);

    let key = schema_version_key(version);
    let exists = service::vault::read_entity(ledger, org_slug, vault_slug, &key).await?.is_some();
    if !exists {
        return Err(CoreError::not_found(format!("schema version {version} not found")).into());
    }

    write_version_pointer(ledger, org_slug, vault_slug, "schema:current", version).await?;

    Ok(Json(SchemaStatusResponse { version, status: "active".to_string() }))
}

/// Rollback to a previous schema version.
///
/// POST /control/v1/organizations/{org}/vaults/{vault}/schemas/rollback
pub async fn rollback_schema(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
) -> Result<Json<SchemaStatusResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);

    let current = read_version_pointer(ledger, org_slug, vault_slug, "schema:current")
        .await?
        .ok_or_else(|| CoreError::validation("no active schema version to rollback from"))?;

    if current.version <= 1 {
        return Err(
            CoreError::validation("cannot rollback: already at the earliest version").into()
        );
    }

    let previous = current.version - 1;
    write_version_pointer(ledger, org_slug, vault_slug, "schema:current", previous).await?;

    Ok(Json(SchemaStatusResponse { version: previous, status: "active".to_string() }))
}

/// Compare two schema versions.
///
/// GET /control/v1/organizations/{org}/vaults/{vault}/schemas/diff?from=N&to=M
pub async fn diff_schemas(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path((org, vault)): Path<(u64, u64)>,
    Query(params): Query<DiffQuery>,
) -> Result<Json<DiffResponse>> {
    let ledger = require_ledger(&state)?;
    let org_slug = OrganizationSlug::new(org);
    let vault_slug = VaultSlug::new(vault);

    let from_schema = read_stored_schema(ledger, org_slug, vault_slug, params.from)
        .await?
        .ok_or_else(|| CoreError::not_found(format!("schema version {} not found", params.from)))?;

    let to_schema = read_stored_schema(ledger, org_slug, vault_slug, params.to)
        .await?
        .ok_or_else(|| CoreError::not_found(format!("schema version {} not found", params.to)))?;

    let changes = diff_json_objects(&from_schema.definition, &to_schema.definition);

    Ok(Json(DiffResponse { from: params.from, to: params.to, changes }))
}
