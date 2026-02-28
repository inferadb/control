use bon::Builder;
use serde::{Deserialize, Serialize};

use crate::{
    OrganizationSlug, VaultSlug,
    entities::{VaultRole, VaultSyncStatus},
};

// ============================================================================
// Request/Response Types - Vault Management
// ============================================================================

#[derive(Debug, Deserialize, Builder)]
#[builder(on(String, into))]
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
    pub id: VaultSlug,
    pub name: String,
    pub description: String,
    pub organization: OrganizationSlug,
    pub sync_status: VaultSyncStatus,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct VaultResponse {
    pub id: VaultSlug,
    pub name: String,
    pub description: String,
    pub organization: OrganizationSlug,
    pub sync_status: VaultSyncStatus,
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
    pub vault: VaultInfo,
}

#[derive(Debug, Serialize)]
pub struct VaultDetail {
    pub id: VaultSlug,
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
    pub user_id: u64,
    pub role: VaultRole,
}

#[derive(Debug, Serialize)]
pub struct CreateUserGrantResponse {
    pub grant: UserGrantResponse,
}

#[derive(Debug, Serialize)]
pub struct UserGrantResponse {
    pub id: u64,
    pub vault: VaultSlug,
    pub user_id: u64,
    pub role: VaultRole,
    pub granted_at: String,
    pub granted_by_user_id: u64,
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
    pub id: u64,
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
    pub team_id: u64,
    pub role: VaultRole,
}

#[derive(Debug, Serialize)]
pub struct CreateTeamGrantResponse {
    pub grant: TeamGrantResponse,
}

#[derive(Debug, Serialize)]
pub struct TeamGrantResponse {
    pub id: u64,
    pub vault: VaultSlug,
    pub team_id: u64,
    pub role: VaultRole,
    pub granted_at: String,
    pub granted_by_user_id: u64,
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
    pub id: u64,
    pub role: VaultRole,
}

#[derive(Debug, Serialize)]
pub struct DeleteTeamGrantResponse {
    pub message: String,
}
