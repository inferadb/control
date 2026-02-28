use serde::{Deserialize, Serialize};

use crate::{OrganizationSlug, entities::OrganizationPermission};

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
    pub id: u64,
    pub name: String,
    pub description: String,
    pub organization: OrganizationSlug,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct TeamResponse {
    pub id: u64,
    pub name: String,
    pub description: String,
    pub organization: OrganizationSlug,
    pub created_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListTeamsResponse {
    pub teams: Vec<TeamResponse>,
    /// Pagination metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<crate::PaginationMeta>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTeamRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateTeamResponse {
    pub team: TeamInfo,
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
    pub user_id: u64,
    #[serde(rename = "is_manager")]
    pub manager: bool,
}

#[derive(Debug, Serialize)]
pub struct AddTeamMemberResponse {
    pub member: TeamMemberInfo,
}

#[derive(Debug, Serialize)]
pub struct TeamMemberInfo {
    pub id: u64,
    pub team_id: u64,
    pub user_id: u64,
    pub is_manager: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct TeamMemberResponse {
    pub id: u64,
    pub team_id: u64,
    pub user_id: u64,
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
    pub id: u64,
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
    pub id: u64,
    pub team_id: u64,
    pub permission: OrganizationPermission,
    pub granted_at: String,
    pub granted_by_user_id: u64,
}

#[derive(Debug, Serialize)]
pub struct TeamPermissionResponse {
    pub id: u64,
    pub team_id: u64,
    pub permission: OrganizationPermission,
    pub granted_at: String,
    pub granted_by_user_id: u64,
}

#[derive(Debug, Serialize)]
pub struct ListTeamPermissionsResponse {
    pub permissions: Vec<TeamPermissionResponse>,
}

#[derive(Debug, Serialize)]
pub struct RevokeTeamPermissionResponse {
    pub message: String,
}
