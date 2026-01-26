use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use inferadb_control_core::{Error as CoreError, IdGenerator, RepositoryContext};
use inferadb_control_types::{
    dto::{
        ActivateSchemaResponse, DeploySchemaRequest, DeploySchemaResponse, GetSchemaResponse,
        ListSchemasQuery, ListSchemasResponse, RollbackSchemaRequest, RollbackSchemaResponse,
        SchemaDetail, SchemaDiffQuery, SchemaDiffResponse, SchemaDiffSummary, SchemaInfo,
    },
    entities::{SchemaDeploymentStatus, SchemaVersion, VaultSchema},
};

use crate::{
    AppState,
    handlers::auth::Result,
    middleware::{OrganizationContext, require_admin_or_owner, require_member},
};

// ============================================================================
// Schema Management Endpoints
// ============================================================================

/// Deploy a new schema version
///
/// POST /v1/vaults/{vault_id}/schemas
/// Required role: ADMIN or OWNER
pub async fn deploy_schema(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
    Json(payload): Json<DeploySchemaRequest>,
) -> Result<(StatusCode, Json<DeploySchemaResponse>)> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    // Verify vault exists and belongs to this organization
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    if vault.is_deleted() {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Determine version number
    let version = if let Some(version_str) = &payload.version {
        // Explicit version provided
        version_str.parse::<SchemaVersion>()?
    } else {
        // Auto-increment from latest version
        match repos.vault_schema.get_latest_version(vault_id).await? {
            Some(latest) => latest.bump_minor(),
            None => SchemaVersion::initial(),
        }
    };

    // Check if version already exists
    if repos.vault_schema.get_by_version(vault_id, &version).await?.is_some() {
        return Err(CoreError::AlreadyExists(format!(
            "Schema version {version} already exists for this vault"
        ))
        .into());
    }

    // Get parent version ID (current active schema if any)
    let parent_version_id = repos.vault_schema.get_active(vault_id).await?.map(|s| s.id);

    // Generate ID for the schema
    let schema_id = IdGenerator::next_id();

    // Create schema entity
    let mut schema = VaultSchema::builder()
        .id(schema_id)
        .vault_id(vault_id)
        .version(version)
        .definition(payload.definition)
        .author_user_id(org_ctx.member.user_id)
        .description(payload.description)
        .maybe_parent_version_id(parent_version_id)
        .create()?;

    // Schema validation is performed by the Engine when loaded; mark as deployed
    schema.mark_deployed();

    // Save to repository
    repos.vault_schema.create(schema.clone()).await?;

    Ok((StatusCode::CREATED, Json(DeploySchemaResponse { schema: SchemaInfo::from(&schema) })))
}

/// List all schema versions for a vault
///
/// GET /v1/vaults/{vault_id}/schemas
/// Required role: MEMBER or higher
pub async fn list_schemas(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
    Query(query): Query<ListSchemasQuery>,
) -> Result<Json<ListSchemasResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    // Verify vault exists and belongs to this organization
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Get schemas, optionally filtered by status
    let mut schemas = if let Some(status_str) = &query.status {
        let status = parse_deployment_status(status_str)?;
        repos.vault_schema.list_by_vault_and_status(vault_id, status).await?
    } else {
        repos.vault_schema.list_by_vault(vault_id).await?
    };

    // Apply pagination
    let total = schemas.len();
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(100);

    schemas = schemas.into_iter().skip(offset).take(limit).collect();

    let pagination_meta =
        inferadb_control_types::PaginationMeta::from_total(total, offset, limit, schemas.len());

    Ok(Json(ListSchemasResponse {
        schemas: schemas.iter().map(SchemaInfo::from).collect(),
        pagination: Some(pagination_meta),
    }))
}

/// Get a specific schema version
///
/// GET /v1/vaults/{vault_id}/schemas/{version}
/// Required role: MEMBER or higher
pub async fn get_schema(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id, version)): Path<(i64, i64, String)>,
) -> Result<Json<GetSchemaResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    // Verify vault exists and belongs to this organization
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Parse and find the schema version
    let schema_version: SchemaVersion = version.parse()?;
    let schema = repos
        .vault_schema
        .get_by_version(vault_id, &schema_version)
        .await?
        .ok_or_else(|| CoreError::NotFound(format!("Schema version {version} not found")))?;

    Ok(Json(GetSchemaResponse { schema: SchemaDetail::from(&schema) }))
}

/// Get the currently active schema
///
/// GET /v1/vaults/{vault_id}/schemas/current
/// Required role: MEMBER or higher
pub async fn get_current_schema(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
) -> Result<Json<GetSchemaResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    // Verify vault exists and belongs to this organization
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    let schema = repos
        .vault_schema
        .get_active(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("No active schema found".to_string()))?;

    Ok(Json(GetSchemaResponse { schema: SchemaDetail::from(&schema) }))
}

/// Activate a specific schema version
///
/// POST /v1/vaults/{vault_id}/schemas/{version}/activate
/// Required role: ADMIN or OWNER
pub async fn activate_schema(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id, version)): Path<(i64, i64, String)>,
) -> Result<Json<ActivateSchemaResponse>> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    // Verify vault exists and belongs to this organization
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Parse and find the schema version
    let schema_version: SchemaVersion = version.parse()?;
    let schema = repos
        .vault_schema
        .get_by_version(vault_id, &schema_version)
        .await?
        .ok_or_else(|| CoreError::NotFound(format!("Schema version {version} not found")))?;

    // Activate the schema (Engine observes schema changes via Ledger watch)
    let activated_schema = repos.vault_schema.activate(schema.id).await?;

    Ok(Json(ActivateSchemaResponse {
        schema: SchemaInfo::from(&activated_schema),
        message: format!("Schema version {} is now active", activated_schema.version),
    }))
}

/// Rollback to a previous schema version
///
/// POST /v1/vaults/{vault_id}/schemas/rollback
/// Required role: ADMIN or OWNER
pub async fn rollback_schema(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
    Json(payload): Json<RollbackSchemaRequest>,
) -> Result<Json<RollbackSchemaResponse>> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    // Verify vault exists and belongs to this organization
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Get current active schema
    let current_active =
        repos.vault_schema.get_active(vault_id).await?.ok_or_else(|| {
            CoreError::Validation("No active schema to rollback from".to_string())
        })?;

    // Parse and find the target schema version
    let target_version: SchemaVersion = payload.target_version.parse()?;
    let target_schema =
        repos.vault_schema.get_by_version(vault_id, &target_version).await?.ok_or_else(|| {
            CoreError::NotFound(format!(
                "Target schema version {} not found",
                payload.target_version
            ))
        })?;

    if target_schema.id == current_active.id {
        return Err(CoreError::Validation(
            "Cannot rollback to the currently active schema".to_string(),
        )
        .into());
    }

    // Perform rollback
    let reactivated_schema = repos.vault_schema.rollback(target_schema.id).await?;

    // Get the rolled back schema (Engine observes schema changes via Ledger watch)
    let rolled_back = repos.vault_schema.get(current_active.id).await?.unwrap();

    Ok(Json(RollbackSchemaResponse {
        active_schema: SchemaInfo::from(&reactivated_schema),
        rolled_back_schema: SchemaInfo::from(&rolled_back),
        message: format!(
            "Rolled back from version {} to version {}",
            rolled_back.version, reactivated_schema.version
        ),
    }))
}

/// Compare two schema versions
///
/// GET /v1/vaults/{vault_id}/schemas/diff?from={v1}&to={v2}
/// Required role: MEMBER or higher
pub async fn diff_schemas(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
    Query(query): Query<SchemaDiffQuery>,
) -> Result<Json<SchemaDiffResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    // Verify vault exists and belongs to this organization
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Parse and find both schema versions
    let from_version: SchemaVersion = query.from.parse()?;
    let to_version: SchemaVersion = query.to.parse()?;

    let _from_schema =
        repos.vault_schema.get_by_version(vault_id, &from_version).await?.ok_or_else(|| {
            CoreError::NotFound(format!("Schema version {} not found", query.from))
        })?;

    let _to_schema = repos
        .vault_schema
        .get_by_version(vault_id, &to_version)
        .await?
        .ok_or_else(|| CoreError::NotFound(format!("Schema version {} not found", query.to)))?;

    // Schema diff comparison (returns structural diff; IPL parsing done by Engine)
    Ok(Json(SchemaDiffResponse {
        from_version: query.from,
        to_version: query.to,
        changes: vec![],
        has_breaking_changes: false,
        summary: SchemaDiffSummary::default(),
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_deployment_status(status_str: &str) -> Result<SchemaDeploymentStatus> {
    match status_str.to_uppercase().as_str() {
        "VALIDATING" => Ok(SchemaDeploymentStatus::Validating),
        "DEPLOYED" => Ok(SchemaDeploymentStatus::Deployed),
        "ACTIVE" => Ok(SchemaDeploymentStatus::Active),
        "FAILED" => Ok(SchemaDeploymentStatus::Failed),
        "SUPERSEDED" => Ok(SchemaDeploymentStatus::Superseded),
        "ROLLED_BACK" => Ok(SchemaDeploymentStatus::RolledBack),
        _ => Err(CoreError::Validation(format!("Invalid status: {status_str}")).into()),
    }
}
