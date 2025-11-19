use crate::handlers::auth::Result;
use crate::middleware::{require_admin_or_owner, require_member, OrganizationContext};
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use infera_management_core::{
    Error as CoreError, IdGenerator, RepositoryContext, Vault, VaultRole, VaultSyncStatus,
    VaultTeamGrant, VaultUserGrant,
};
use serde::{Deserialize, Serialize};

// ============================================================================
// Request/Response Types - Vault Management
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateVaultRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateVaultResponse {
    pub vault: VaultInfo,
}

#[derive(Debug, Serialize)]
pub struct VaultInfo {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub organization_id: i64,
    pub sync_status: VaultSyncStatus,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct VaultResponse {
    pub id: i64,
    pub name: String,
    pub organization_id: i64,
    pub sync_status: String,
    pub sync_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListVaultsResponse {
    pub vaults: Vec<VaultResponse>,
    /// Pagination metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<crate::pagination::PaginationMeta>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateVaultRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateVaultResponse {
    pub vault: VaultDetail,
}

#[derive(Debug, Serialize)]
pub struct VaultDetail {
    pub id: i64,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteVaultResponse {
    pub message: String,
}

// ============================================================================
// Request/Response Types - User Grants
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateUserGrantRequest {
    pub user_id: i64,
    pub role: VaultRole,
}

#[derive(Debug, Serialize)]
pub struct CreateUserGrantResponse {
    pub grant: UserGrantInfo,
}

#[derive(Debug, Serialize)]
pub struct UserGrantInfo {
    pub id: i64,
    pub vault_id: i64,
    pub user_id: i64,
    pub role: VaultRole,
    pub granted_at: String,
    pub granted_by_user_id: i64,
}

#[derive(Debug, Serialize)]
pub struct UserGrantResponse {
    pub id: i64,
    pub vault_id: i64,
    pub user_id: i64,
    pub role: VaultRole,
    pub granted_at: String,
    pub granted_by_user_id: i64,
}

#[derive(Debug, Serialize)]
pub struct ListUserGrantsResponse {
    pub grants: Vec<UserGrantResponse>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserGrantRequest {
    pub role: VaultRole,
}

#[derive(Debug, Serialize)]
pub struct UpdateUserGrantResponse {
    pub id: i64,
    pub role: VaultRole,
}

#[derive(Debug, Serialize)]
pub struct DeleteUserGrantResponse {
    pub message: String,
}

// ============================================================================
// Request/Response Types - Team Grants
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateTeamGrantRequest {
    pub team_id: i64,
    pub role: VaultRole,
}

#[derive(Debug, Serialize)]
pub struct CreateTeamGrantResponse {
    pub grant: TeamGrantInfo,
}

#[derive(Debug, Serialize)]
pub struct TeamGrantInfo {
    pub id: i64,
    pub vault_id: i64,
    pub team_id: i64,
    pub role: VaultRole,
    pub granted_at: String,
    pub granted_by_user_id: i64,
}

#[derive(Debug, Serialize)]
pub struct TeamGrantResponse {
    pub id: i64,
    pub vault_id: i64,
    pub team_id: i64,
    pub role: VaultRole,
    pub granted_at: String,
    pub granted_by_user_id: i64,
}

#[derive(Debug, Serialize)]
pub struct ListTeamGrantsResponse {
    pub grants: Vec<TeamGrantResponse>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTeamGrantRequest {
    pub role: VaultRole,
}

#[derive(Debug, Serialize)]
pub struct UpdateTeamGrantResponse {
    pub id: i64,
    pub role: VaultRole,
}

#[derive(Debug, Serialize)]
pub struct DeleteTeamGrantResponse {
    pub message: String,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn vault_to_response(vault: Vault) -> VaultResponse {
    VaultResponse {
        id: vault.id,
        name: vault.name,
        organization_id: vault.organization_id,
        sync_status: format!("{:?}", vault.sync_status),
        sync_error: vault.sync_error,
        created_at: vault.created_at.to_rfc3339(),
        updated_at: vault.updated_at.to_rfc3339(),
        deleted_at: vault.deleted_at.map(|dt| dt.to_rfc3339()),
    }
}

fn user_grant_to_response(grant: VaultUserGrant) -> UserGrantResponse {
    UserGrantResponse {
        id: grant.id,
        vault_id: grant.vault_id,
        user_id: grant.user_id,
        role: grant.role,
        granted_at: grant.granted_at.to_rfc3339(),
        granted_by_user_id: grant.granted_by_user_id,
    }
}

fn team_grant_to_response(grant: VaultTeamGrant) -> TeamGrantResponse {
    TeamGrantResponse {
        id: grant.id,
        vault_id: grant.vault_id,
        team_id: grant.team_id,
        role: grant.role,
        granted_at: grant.granted_at.to_rfc3339(),
        granted_by_user_id: grant.granted_by_user_id,
    }
}

// ============================================================================
// Vault Management Endpoints
// ============================================================================

/// Create a new vault
///
/// POST /v1/organizations/:org/vaults
/// Required role: ADMIN or OWNER
pub async fn create_vault(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Json(payload): Json<CreateVaultRequest>,
) -> Result<(StatusCode, Json<CreateVaultResponse>)> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    // Verify organization exists and get tier
    let repos = RepositoryContext::new((*state.storage).clone());
    let organization = repos
        .org
        .get(org_ctx.organization_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    // Check tier limits
    let current_count = repos
        .vault
        .count_active_by_organization(org_ctx.organization_id)
        .await?;

    if current_count >= organization.tier.max_vaults() {
        return Err(CoreError::TierLimit(format!(
            "Vault limit reached for tier {:?}. Maximum: {}",
            organization.tier,
            organization.tier.max_vaults()
        ))
        .into());
    }

    // Generate ID for the vault
    let vault_id = IdGenerator::next_id();

    // Create vault entity (starts with PENDING sync status)
    let mut vault = Vault::new(
        vault_id,
        org_ctx.organization_id,
        payload.name,
        org_ctx.member.user_id,
    )?;

    // Save to repository
    repos.vault.create(vault.clone()).await?;

    // Attempt to sync with @server
    match state
        .server_client
        .create_vault(vault_id, org_ctx.organization_id)
        .await
    {
        Ok(()) => {
            // Mark as synced
            vault.mark_synced();
            repos.vault.update(vault.clone()).await?;
        }
        Err(e) => {
            // Mark as failed
            let error_message: String = e.to_string();
            vault.mark_sync_failed(error_message);
            repos.vault.update(vault.clone()).await?;
        }
    }

    // Auto-grant creator ADMIN role
    let grant_id = IdGenerator::next_id();
    let grant = VaultUserGrant::new(
        grant_id,
        vault_id,
        org_ctx.member.user_id,
        VaultRole::Admin,
        org_ctx.member.user_id,
    );
    repos.vault_user_grant.create(grant).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateVaultResponse {
            vault: VaultInfo {
                id: vault.id,
                name: vault.name,
                description: payload.description.unwrap_or_default(),
                organization_id: vault.organization_id,
                sync_status: vault.sync_status,
                created_at: vault.created_at.to_rfc3339(),
            },
        }),
    ))
}

/// List all vaults in an organization
///
/// GET /v1/organizations/:org/vaults?limit=50&offset=0
/// Required role: MEMBER or higher
pub async fn list_vaults(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    pagination: crate::pagination::PaginationQuery,
) -> Result<Json<ListVaultsResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    let params = pagination.0.validate();

    let repos = RepositoryContext::new((*state.storage).clone());
    let all_vaults = repos
        .vault
        .list_active_by_organization(org_ctx.organization_id)
        .await?;

    // Apply pagination
    let total = all_vaults.len();
    let vaults: Vec<VaultResponse> = all_vaults
        .into_iter()
        .map(vault_to_response)
        .skip(params.offset)
        .take(params.limit)
        .collect();

    let pagination_meta = crate::pagination::PaginationMeta::from_total(
        total,
        params.offset,
        params.limit,
        vaults.len(),
    );

    Ok(Json(ListVaultsResponse {
        vaults,
        pagination: Some(pagination_meta),
    }))
}

/// Get a specific vault
///
/// GET /v1/organizations/:org/vaults/:vault
/// Required role: MEMBER or higher
pub async fn get_vault(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
) -> Result<Json<VaultResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    // Verify vault belongs to this organization
    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Don't return deleted vaults
    if vault.is_deleted() {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    Ok(Json(vault_to_response(vault)))
}

/// Update a vault
///
/// PATCH /v1/organizations/:org/vaults/:vault
/// Required role: ADMIN or OWNER
pub async fn update_vault(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
    Json(payload): Json<UpdateVaultRequest>,
) -> Result<Json<UpdateVaultResponse>> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());
    let mut vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    // Verify vault belongs to this organization
    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Validate and update name
    Vault::validate_name(&payload.name)?;
    vault.name = payload.name.clone();

    // Save changes
    repos.vault.update(vault.clone()).await?;

    Ok(Json(UpdateVaultResponse {
        vault: VaultDetail {
            id: vault.id,
            name: vault.name,
            description: payload.description.unwrap_or_default(),
        },
    }))
}

/// Delete a vault (soft delete)
///
/// DELETE /v1/organizations/:org/vaults/:vault
/// Required role: ADMIN or OWNER
///
/// Cascade deletes:
/// - All user grants for this vault
/// - All team grants for this vault
pub async fn delete_vault(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
) -> Result<StatusCode> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    let mut vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    // Verify vault belongs to this organization
    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // VALIDATION: Check for active refresh tokens before allowing deletion
    let tokens = repos.vault_refresh_token.list_by_vault(vault_id).await?;
    let active_token_count = tokens
        .iter()
        .filter(|t| !t.is_expired() && !t.is_revoked())
        .count();

    if active_token_count > 0 {
        return Err(CoreError::Validation(format!(
            "Cannot delete vault with {} active refresh token{}. Please revoke all tokens first.",
            active_token_count,
            if active_token_count == 1 { "" } else { "s" }
        ))
        .into());
    }

    // CASCADE DELETE: Delete all vault user grants
    let user_grants = repos.vault_user_grant.list_by_vault(vault_id).await?;
    for grant in user_grants {
        repos.vault_user_grant.delete(grant.id).await?;
    }

    // CASCADE DELETE: Delete all vault team grants
    let team_grants = repos.vault_team_grant.list_by_vault(vault_id).await?;
    for grant in team_grants {
        repos.vault_team_grant.delete(grant.id).await?;
    }

    // Attempt to delete from @server
    // Note: Even if this fails, we soft-delete locally
    let _ = state.server_client.delete_vault(vault_id).await;

    // Soft delete
    vault.mark_deleted();
    repos.vault.update(vault).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// User Grant Endpoints
// ============================================================================

/// Create a user grant for a vault
///
/// POST /v1/organizations/:org/vaults/:vault/user-grants
/// Required role: ADMIN or OWNER
pub async fn create_user_grant(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
    Json(payload): Json<CreateUserGrantRequest>,
) -> Result<(StatusCode, Json<CreateUserGrantResponse>)> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    // Verify vault exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Generate ID for the grant
    let grant_id = IdGenerator::next_id();

    // Create grant entity
    let grant = VaultUserGrant::new(
        grant_id,
        vault_id,
        payload.user_id,
        payload.role,
        org_ctx.member.user_id,
    );

    // Save to repository
    repos.vault_user_grant.create(grant.clone()).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateUserGrantResponse {
            grant: UserGrantInfo {
                id: grant.id,
                vault_id: grant.vault_id,
                user_id: grant.user_id,
                role: grant.role,
                granted_at: grant.granted_at.to_rfc3339(),
                granted_by_user_id: grant.granted_by_user_id,
            },
        }),
    ))
}

/// List all user grants for a vault
///
/// GET /v1/organizations/:org/vaults/:vault/user-grants
/// Required role: MEMBER or higher
pub async fn list_user_grants(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
) -> Result<Json<ListUserGrantsResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    // Verify vault exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    let grants = repos.vault_user_grant.list_by_vault(vault_id).await?;

    Ok(Json(ListUserGrantsResponse {
        grants: grants.into_iter().map(user_grant_to_response).collect(),
    }))
}

/// Update a user grant
///
/// PATCH /v1/organizations/:org/vaults/:vault/user-grants/:grant
/// Required role: ADMIN or OWNER
pub async fn update_user_grant(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id, grant_id)): Path<(i64, i64, i64)>,
    Json(payload): Json<UpdateUserGrantRequest>,
) -> Result<Json<UpdateUserGrantResponse>> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    // Verify vault exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Get grant
    let mut grant = repos
        .vault_user_grant
        .get(grant_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Grant not found".to_string()))?;

    // Verify grant belongs to this vault
    if grant.vault_id != vault_id {
        return Err(CoreError::NotFound("Grant not found".to_string()).into());
    }

    // Update role
    grant.role = payload.role;
    repos.vault_user_grant.update(grant.clone()).await?;

    Ok(Json(UpdateUserGrantResponse {
        id: grant.id,
        role: grant.role,
    }))
}

/// Delete a user grant
///
/// DELETE /v1/organizations/:org/vaults/:vault/user-grants/:user
/// Required role: ADMIN or OWNER
pub async fn delete_user_grant(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id, user_id)): Path<(i64, i64, i64)>,
) -> Result<StatusCode> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    // Verify vault exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Get grant by user_id
    let grant = repos
        .vault_user_grant
        .get_by_vault_and_user(vault_id, user_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Grant not found".to_string()))?;

    // Delete the grant
    repos.vault_user_grant.delete(grant.id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Team Grant Endpoints
// ============================================================================

/// Create a team grant for a vault
///
/// POST /v1/organizations/:org/vaults/:vault/team-grants
/// Required role: ADMIN or OWNER
pub async fn create_team_grant(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
    Json(payload): Json<CreateTeamGrantRequest>,
) -> Result<(StatusCode, Json<CreateTeamGrantResponse>)> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    // Verify vault exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Generate ID for the grant
    let grant_id = IdGenerator::next_id();

    // Create grant entity
    let grant = VaultTeamGrant::new(
        grant_id,
        vault_id,
        payload.team_id,
        payload.role,
        org_ctx.member.user_id,
    );

    // Save to repository
    repos.vault_team_grant.create(grant.clone()).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateTeamGrantResponse {
            grant: TeamGrantInfo {
                id: grant.id,
                vault_id: grant.vault_id,
                team_id: grant.team_id,
                role: grant.role,
                granted_at: grant.granted_at.to_rfc3339(),
                granted_by_user_id: grant.granted_by_user_id,
            },
        }),
    ))
}

/// List all team grants for a vault
///
/// GET /v1/organizations/:org/vaults/:vault/team-grants
/// Required role: MEMBER or higher
pub async fn list_team_grants(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
) -> Result<Json<ListTeamGrantsResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    // Verify vault exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    let grants = repos.vault_team_grant.list_by_vault(vault_id).await?;

    Ok(Json(ListTeamGrantsResponse {
        grants: grants.into_iter().map(team_grant_to_response).collect(),
    }))
}

/// Update a team grant
///
/// PATCH /v1/organizations/:org/vaults/:vault/team-grants/:grant
/// Required role: ADMIN or OWNER
pub async fn update_team_grant(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id, grant_id)): Path<(i64, i64, i64)>,
    Json(payload): Json<UpdateTeamGrantRequest>,
) -> Result<Json<UpdateTeamGrantResponse>> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    // Verify vault exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Get grant
    let mut grant = repos
        .vault_team_grant
        .get(grant_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Grant not found".to_string()))?;

    // Verify grant belongs to this vault
    if grant.vault_id != vault_id {
        return Err(CoreError::NotFound("Grant not found".to_string()).into());
    }

    // Update role
    grant.role = payload.role;
    repos.vault_team_grant.update(grant.clone()).await?;

    Ok(Json(UpdateTeamGrantResponse {
        id: grant.id,
        role: grant.role,
    }))
}

/// Delete a team grant
///
/// DELETE /v1/organizations/:org/vaults/:vault/team-grants/:grant
/// Required role: ADMIN or OWNER
pub async fn delete_team_grant(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, vault_id, grant_id)): Path<(i64, i64, i64)>,
) -> Result<Json<DeleteTeamGrantResponse>> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    // Verify vault exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Get grant
    let grant = repos
        .vault_team_grant
        .get(grant_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Grant not found".to_string()))?;

    // Verify grant belongs to this vault
    if grant.vault_id != vault_id {
        return Err(CoreError::NotFound("Grant not found".to_string()).into());
    }

    // Delete the grant
    repos.vault_user_grant.delete(grant_id).await?;

    Ok(Json(DeleteTeamGrantResponse {
        message: "Team grant deleted successfully".to_string(),
    }))
}
