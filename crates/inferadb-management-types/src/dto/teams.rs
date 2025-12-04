use serde::{Deserialize, Serialize};

use crate::entities::OrganizationPermission;

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
    pub pagination: Option<crate::PaginationMeta>,
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
