use crate::handlers::auth::Result;
use crate::middleware::{
    require_admin_or_owner, require_member, require_owner, OrganizationContext,
};
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use infera_management_core::{
    Error as CoreError, IdGenerator, OrganizationPermission, OrganizationTeam,
    OrganizationTeamMember, OrganizationTeamPermission, RepositoryContext,
};
use serde::{Deserialize, Serialize};

// ============================================================================
// Request/Response Types - Team Management
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateTeamResponse {
    pub team: TeamInfo,
}

#[derive(Debug, Serialize)]
pub struct TeamInfo {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub organization_id: i64,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct TeamResponse {
    pub id: i64,
    pub name: String,
    pub organization_id: i64,
    pub created_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListTeamsResponse {
    pub teams: Vec<TeamResponse>,
    /// Pagination metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<crate::pagination::PaginationMeta>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTeamRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateTeamResponse {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteTeamResponse {
    pub message: String,
}

// ============================================================================
// Request/Response Types - Team Members
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AddTeamMemberRequest {
    pub user_id: i64,
    #[serde(rename = "is_manager")]
    pub manager: bool,
}

#[derive(Debug, Serialize)]
pub struct AddTeamMemberResponse {
    pub member: TeamMemberInfo,
}

#[derive(Debug, Serialize)]
pub struct TeamMemberInfo {
    pub id: i64,
    pub team_id: i64,
    pub user_id: i64,
    pub is_manager: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct TeamMemberResponse {
    pub id: i64,
    pub team_id: i64,
    pub user_id: i64,
    pub manager: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ListTeamMembersResponse {
    pub members: Vec<TeamMemberResponse>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTeamMemberRequest {
    pub manager: bool,
}

#[derive(Debug, Serialize)]
pub struct UpdateTeamMemberResponse {
    pub id: i64,
    pub manager: bool,
}

#[derive(Debug, Serialize)]
pub struct RemoveTeamMemberResponse {
    pub message: String,
}

// ============================================================================
// Request/Response Types - Team Permissions
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct GrantTeamPermissionRequest {
    pub permission: OrganizationPermission,
}

#[derive(Debug, Serialize)]
pub struct GrantTeamPermissionResponse {
    pub permission: TeamPermissionInfo,
}

#[derive(Debug, Serialize)]
pub struct TeamPermissionInfo {
    pub id: i64,
    pub team_id: i64,
    pub permission: OrganizationPermission,
    pub granted_at: String,
    pub granted_by_user_id: i64,
}

#[derive(Debug, Serialize)]
pub struct TeamPermissionResponse {
    pub id: i64,
    pub team_id: i64,
    pub permission: OrganizationPermission,
    pub granted_at: String,
    pub granted_by_user_id: i64,
}

#[derive(Debug, Serialize)]
pub struct ListTeamPermissionsResponse {
    pub permissions: Vec<TeamPermissionResponse>,
}

#[derive(Debug, Serialize)]
pub struct RevokeTeamPermissionResponse {
    pub message: String,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn team_to_response(team: OrganizationTeam) -> TeamResponse {
    TeamResponse {
        id: team.id,
        name: team.name,
        organization_id: team.organization_id,
        created_at: team.created_at.to_rfc3339(),
        deleted_at: team.deleted_at.map(|dt| dt.to_rfc3339()),
    }
}

fn team_member_to_response(member: OrganizationTeamMember) -> TeamMemberResponse {
    TeamMemberResponse {
        id: member.id,
        team_id: member.team_id,
        user_id: member.user_id,
        manager: member.manager,
        created_at: member.created_at.to_rfc3339(),
    }
}

fn team_permission_to_response(permission: OrganizationTeamPermission) -> TeamPermissionResponse {
    TeamPermissionResponse {
        id: permission.id,
        team_id: permission.team_id,
        permission: permission.permission,
        granted_at: permission.granted_at.to_rfc3339(),
        granted_by_user_id: permission.granted_by_user_id,
    }
}

// ============================================================================
// Team Management Endpoints
// ============================================================================

/// Create a new team
///
/// POST /v1/organizations/:org/teams
/// Required role: ADMIN or OWNER
pub async fn create_team(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Json(payload): Json<CreateTeamRequest>,
) -> Result<(StatusCode, Json<CreateTeamResponse>)> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    // Get organization to check tier limits
    let organization = repos
        .org
        .get(org_ctx.organization_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    // Check tier limits
    let current_count = repos
        .org_team
        .count_active_by_organization(org_ctx.organization_id)
        .await?;

    if current_count >= organization.tier.max_teams() {
        return Err(CoreError::Validation(format!(
            "Team limit reached for tier {:?}. Maximum: {}",
            organization.tier,
            organization.tier.max_teams()
        ))
        .into());
    }

    // Generate ID and create team
    let team_id = IdGenerator::next_id();
    let team = OrganizationTeam::new(team_id, org_ctx.organization_id, payload.name)?;

    // Store team
    repos.org_team.create(team.clone()).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateTeamResponse {
            team: TeamInfo {
                id: team.id,
                name: team.name,
                description: payload.description.unwrap_or_default(),
                organization_id: team.organization_id,
                created_at: team.created_at.to_rfc3339(),
            },
        }),
    ))
}

/// List all teams in an organization
///
/// GET /v1/organizations/:org/teams?limit=50&offset=0
/// Required role: MEMBER (all organization members can view teams)
pub async fn list_teams(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    pagination: crate::pagination::PaginationQuery,
) -> Result<Json<ListTeamsResponse>> {
    // All organization members can view teams
    require_member(&org_ctx)?;

    let params = pagination.0.validate();

    let repos = RepositoryContext::new((*state.storage).clone());
    let all_teams = repos
        .org_team
        .list_active_by_organization(org_ctx.organization_id)
        .await?;

    // Apply pagination
    let total = all_teams.len();
    let teams: Vec<TeamResponse> = all_teams
        .into_iter()
        .map(team_to_response)
        .skip(params.offset)
        .take(params.limit)
        .collect();

    let pagination_meta = crate::pagination::PaginationMeta::from_total(
        total,
        params.offset,
        params.limit,
        teams.len(),
    );

    Ok(Json(ListTeamsResponse {
        teams,
        pagination: Some(pagination_meta),
    }))
}

/// Get team details
///
/// GET /v1/organizations/:org/teams/:team
/// Required role: MEMBER (all organization members)
pub async fn get_team(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org, team_id)): Path<(i64, i64)>,
) -> Result<Json<TeamResponse>> {
    // All organization members can view team details
    require_member(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());
    let team = repos
        .org_team
        .get(team_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team not found".to_string()))?;

    // Verify team belongs to the organization
    if team.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    // Don't return deleted teams
    if team.is_deleted() {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    Ok(Json(team_to_response(team)))
}

/// Update team name
///
/// PATCH /v1/organizations/:org/teams/:team
/// Required role: ADMIN, OWNER, or team manager
pub async fn update_team(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org, team_id)): Path<(i64, i64)>,
    Json(payload): Json<UpdateTeamRequest>,
) -> Result<Json<UpdateTeamResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get team and verify ownership
    let mut team = repos
        .org_team
        .get(team_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team not found".to_string()))?;

    if team.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    if team.is_deleted() {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    // Check authorization: ADMIN/OWNER or team manager
    let is_admin_or_owner = org_ctx.member.role == infera_management_core::OrganizationRole::Admin
        || org_ctx.member.role == infera_management_core::OrganizationRole::Owner;

    let is_team_manager = if !is_admin_or_owner {
        repos
            .org_team_member
            .get_by_team_and_user(team_id, org_ctx.member.user_id)
            .await?
            .map(|m| m.manager)
            .unwrap_or(false)
    } else {
        false
    };

    if !is_admin_or_owner && !is_team_manager {
        return Err(CoreError::Authz(
            "Only team managers or organization admins can update teams".to_string(),
        )
        .into());
    }

    // Update team name
    team.set_name(payload.name)?;
    repos.org_team.update(team.clone()).await?;

    Ok(Json(UpdateTeamResponse {
        id: team.id,
        name: team.name,
    }))
}

/// Delete a team
///
/// DELETE /v1/organizations/:org/teams/:team
/// Required role: ADMIN or OWNER
pub async fn delete_team(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org, team_id)): Path<(i64, i64)>,
) -> Result<Json<DeleteTeamResponse>> {
    // Require admin or owner
    require_admin_or_owner(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    // Get team and verify ownership
    let mut team = repos
        .org_team
        .get(team_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team not found".to_string()))?;

    if team.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    // Soft delete team
    team.mark_deleted();
    repos.org_team.update(team).await?;

    // Delete all team members
    repos.org_team_member.delete_by_team(team_id).await?;

    // Delete all team permissions
    repos.org_team_permission.delete_by_team(team_id).await?;

    Ok(Json(DeleteTeamResponse {
        message: "Team deleted successfully".to_string(),
    }))
}

// ============================================================================
// Team Member Management Endpoints
// ============================================================================

/// Add a member to a team
///
/// POST /v1/organizations/:org/teams/:team/members
/// Required role: ADMIN, OWNER, or team manager
pub async fn add_team_member(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org, team_id)): Path<(i64, i64)>,
    Json(payload): Json<AddTeamMemberRequest>,
) -> Result<(StatusCode, Json<AddTeamMemberResponse>)> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get team and verify ownership
    let team = repos
        .org_team
        .get(team_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team not found".to_string()))?;

    if team.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    if team.is_deleted() {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    // Check authorization: ADMIN/OWNER or team manager
    let is_admin_or_owner = org_ctx.member.role == infera_management_core::OrganizationRole::Admin
        || org_ctx.member.role == infera_management_core::OrganizationRole::Owner;

    let is_team_manager = if !is_admin_or_owner {
        repos
            .org_team_member
            .get_by_team_and_user(team_id, org_ctx.member.user_id)
            .await?
            .map(|m| m.manager)
            .unwrap_or(false)
    } else {
        false
    };

    if !is_admin_or_owner && !is_team_manager {
        return Err(CoreError::Authz(
            "Only team managers or organization admins can add team members".to_string(),
        )
        .into());
    }

    // Verify user is an organization member
    let _target_member = repos
        .org_member
        .get_by_org_and_user(org_ctx.organization_id, payload.user_id)
        .await?
        .ok_or_else(|| {
            CoreError::Validation("User is not a member of this organization".to_string())
        })?;

    // Create team member
    let member_id = IdGenerator::next_id();
    let member = OrganizationTeamMember::new(member_id, team_id, payload.user_id, payload.manager);

    repos.org_team_member.create(member.clone()).await?;

    Ok((
        StatusCode::CREATED,
        Json(AddTeamMemberResponse {
            member: TeamMemberInfo {
                id: member.id,
                team_id: member.team_id,
                user_id: member.user_id,
                is_manager: member.manager,
                created_at: member.created_at.to_rfc3339(),
            },
        }),
    ))
}

/// List team members
///
/// GET /v1/organizations/:org/teams/:team/members
/// Required role: MEMBER (all organization members can view)
pub async fn list_team_members(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org, team_id)): Path<(i64, i64)>,
) -> Result<Json<ListTeamMembersResponse>> {
    // All organization members can view team members
    require_member(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    // Verify team exists and belongs to organization
    let team = repos
        .org_team
        .get(team_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team not found".to_string()))?;

    if team.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    if team.is_deleted() {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    // Get team members
    let members = repos.org_team_member.list_by_team(team_id).await?;

    Ok(Json(ListTeamMembersResponse {
        members: members.into_iter().map(team_member_to_response).collect(),
    }))
}

/// Update team member (change manager flag)
///
/// PATCH /v1/organizations/:org/teams/:team/members/:member
/// Required role: ADMIN, OWNER, or team manager
pub async fn update_team_member(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org, team_id, member_id)): Path<(i64, i64, i64)>,
    Json(payload): Json<UpdateTeamMemberRequest>,
) -> Result<Json<UpdateTeamMemberResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get team and verify ownership
    let team = repos
        .org_team
        .get(team_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team not found".to_string()))?;

    if team.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    if team.is_deleted() {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    // Check authorization: ADMIN/OWNER or team manager
    let is_admin_or_owner = org_ctx.member.role == infera_management_core::OrganizationRole::Admin
        || org_ctx.member.role == infera_management_core::OrganizationRole::Owner;

    let is_team_manager = if !is_admin_or_owner {
        repos
            .org_team_member
            .get_by_team_and_user(team_id, org_ctx.member.user_id)
            .await?
            .map(|m| m.manager)
            .unwrap_or(false)
    } else {
        false
    };

    if !is_admin_or_owner && !is_team_manager {
        return Err(CoreError::Authz(
            "Only team managers or organization admins can update team members".to_string(),
        )
        .into());
    }

    // Get and update member
    let mut member = repos
        .org_team_member
        .get(member_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team member not found".to_string()))?;

    if member.team_id != team_id {
        return Err(CoreError::NotFound("Team member not found".to_string()).into());
    }

    member.set_manager(payload.manager);
    repos.org_team_member.update(member.clone()).await?;

    Ok(Json(UpdateTeamMemberResponse {
        id: member.id,
        manager: member.manager,
    }))
}

/// Remove a member from a team
///
/// DELETE /v1/organizations/:org/teams/:team/members/:member
/// Required role: ADMIN, OWNER, or team manager
pub async fn remove_team_member(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org, team_id, member_id)): Path<(i64, i64, i64)>,
) -> Result<Json<RemoveTeamMemberResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get team and verify ownership
    let team = repos
        .org_team
        .get(team_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team not found".to_string()))?;

    if team.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    if team.is_deleted() {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    // Check authorization: ADMIN/OWNER or team manager
    let is_admin_or_owner = org_ctx.member.role == infera_management_core::OrganizationRole::Admin
        || org_ctx.member.role == infera_management_core::OrganizationRole::Owner;

    let is_team_manager = if !is_admin_or_owner {
        repos
            .org_team_member
            .get_by_team_and_user(team_id, org_ctx.member.user_id)
            .await?
            .map(|m| m.manager)
            .unwrap_or(false)
    } else {
        false
    };

    if !is_admin_or_owner && !is_team_manager {
        return Err(CoreError::Authz(
            "Only team managers or organization admins can remove team members".to_string(),
        )
        .into());
    }

    // Get and delete member
    let member = repos
        .org_team_member
        .get(member_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team member not found".to_string()))?;

    if member.team_id != team_id {
        return Err(CoreError::NotFound("Team member not found".to_string()).into());
    }

    repos.org_team_member.delete(member_id).await?;

    Ok(Json(RemoveTeamMemberResponse {
        message: "Team member removed successfully".to_string(),
    }))
}

// ============================================================================
// Team Permission Management Endpoints
// ============================================================================

/// Grant a permission to a team
///
/// POST /v1/organizations/:org/teams/:team/permissions
/// Required role: OWNER
pub async fn grant_team_permission(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org, team_id)): Path<(i64, i64)>,
    Json(payload): Json<GrantTeamPermissionRequest>,
) -> Result<(StatusCode, Json<GrantTeamPermissionResponse>)> {
    // Only owners can grant permissions
    require_owner(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    // Get team and verify ownership
    let team = repos
        .org_team
        .get(team_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team not found".to_string()))?;

    if team.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    if team.is_deleted() {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    // Create team permission
    let permission_id = IdGenerator::next_id();
    let permission = OrganizationTeamPermission::new(
        permission_id,
        team_id,
        payload.permission,
        org_ctx.member.user_id,
    );

    repos.org_team_permission.create(permission.clone()).await?;

    Ok((
        StatusCode::CREATED,
        Json(GrantTeamPermissionResponse {
            permission: TeamPermissionInfo {
                id: permission.id,
                team_id: permission.team_id,
                permission: permission.permission,
                granted_at: permission.granted_at.to_rfc3339(),
                granted_by_user_id: permission.granted_by_user_id,
            },
        }),
    ))
}

/// List team permissions
///
/// GET /v1/organizations/:org/teams/:team/permissions
/// Required role: ADMIN, OWNER, or team member
pub async fn list_team_permissions(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org, team_id)): Path<(i64, i64)>,
) -> Result<Json<ListTeamPermissionsResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Verify team exists and belongs to organization
    let team = repos
        .org_team
        .get(team_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team not found".to_string()))?;

    if team.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    if team.is_deleted() {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    // Check authorization: ADMIN/OWNER or team member
    let is_admin_or_owner = org_ctx.member.role == infera_management_core::OrganizationRole::Admin
        || org_ctx.member.role == infera_management_core::OrganizationRole::Owner;

    let is_team_member = if !is_admin_or_owner {
        repos
            .org_team_member
            .get_by_team_and_user(team_id, org_ctx.member.user_id)
            .await?
            .is_some()
    } else {
        false
    };

    if !is_admin_or_owner && !is_team_member {
        return Err(CoreError::Authz(
            "Only team members or organization admins can view team permissions".to_string(),
        )
        .into());
    }

    // Get team permissions
    let permissions = repos.org_team_permission.list_by_team(team_id).await?;

    Ok(Json(ListTeamPermissionsResponse {
        permissions: permissions
            .into_iter()
            .map(team_permission_to_response)
            .collect(),
    }))
}

/// Revoke a permission from a team
///
/// DELETE /v1/organizations/:org/teams/:team/permissions/:permission
/// Required role: OWNER
pub async fn revoke_team_permission(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org, team_id, permission_id)): Path<(i64, i64, i64)>,
) -> Result<Json<RevokeTeamPermissionResponse>> {
    // Only owners can revoke permissions
    require_owner(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());

    // Get team and verify ownership
    let team = repos
        .org_team
        .get(team_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team not found".to_string()))?;

    if team.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    if team.is_deleted() {
        return Err(CoreError::NotFound("Team not found".to_string()).into());
    }

    // Get and delete permission
    let permission = repos
        .org_team_permission
        .get(permission_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Team permission not found".to_string()))?;

    if permission.team_id != team_id {
        return Err(CoreError::NotFound("Team permission not found".to_string()).into());
    }

    repos.org_team_permission.delete(permission_id).await?;

    Ok(Json(RevokeTeamPermissionResponse {
        message: "Team permission revoked successfully".to_string(),
    }))
}
