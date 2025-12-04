use serde::{Deserialize, Serialize};

use crate::entities::{VaultRole, VaultSyncStatus};

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
    pub pagination: Option<crate::PaginationMeta>,
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
