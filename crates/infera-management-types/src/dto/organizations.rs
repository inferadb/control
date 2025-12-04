use serde::{Deserialize, Serialize};

use crate::entities::OrganizationRole;

/// Organization response
#[derive(Debug, Serialize, Deserialize)]
pub struct OrganizationResponse {
    /// Organization ID
    pub id: i64,
    /// Organization name
    pub name: String,
    /// Organization tier
    pub tier: String,
    /// When the organization was created
    pub created_at: String,
    /// Your role in the organization
    pub role: String,
}

/// Request body for creating an organization
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateOrganizationRequest {
    /// Organization name
    pub name: String,
}

/// Response body for organization creation
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateOrganizationResponse {
    /// Created organization
    pub organization: OrganizationResponse,
}

/// Response body for listing organizations
#[derive(Debug, Serialize, Deserialize)]
pub struct ListOrganizationsResponse {
    /// List of organizations the user is a member of
    pub organizations: Vec<OrganizationResponse>,
    /// Pagination metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<crate::PaginationMeta>,
}

/// Response body for getting organization details
#[derive(Debug, Serialize, Deserialize)]
pub struct GetOrganizationResponse {
    /// Organization details
    pub organization: OrganizationResponse,
}

/// Request body for updating an organization
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateOrganizationRequest {
    /// Updated organization name
    pub name: String,
}

/// Response body for organization update
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateOrganizationResponse {
    /// Updated organization
    pub organization: OrganizationResponse,
}

/// Response body for organization deletion
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteOrganizationResponse {
    /// Confirmation message
    pub message: String,
}

/// Response body for organization suspension
#[derive(Debug, Serialize, Deserialize)]
pub struct SuspendOrganizationResponse {
    /// Confirmation message
    pub message: String,
}

/// Response body for organization resumption
#[derive(Debug, Serialize, Deserialize)]
pub struct ResumeOrganizationResponse {
    /// Confirmation message
    pub message: String,
}

// ============================================================================
// Organization Member Management
// ============================================================================

/// Organization member response
#[derive(Debug, Serialize, Deserialize)]
pub struct OrganizationMemberResponse {
    /// Member ID
    pub id: i64,
    /// User ID
    pub user_id: i64,
    /// Member role
    pub role: String,
    /// When the member joined
    pub joined_at: String,
}

/// Response body for listing organization members
#[derive(Debug, Serialize, Deserialize)]
pub struct ListMembersResponse {
    /// List of organization members
    pub members: Vec<OrganizationMemberResponse>,
}

/// Request body for updating a member's role
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateMemberRoleRequest {
    /// New role for the member
    pub role: String,
}

/// Response body for member role update
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateMemberRoleResponse {
    /// Updated member
    pub member: OrganizationMemberResponse,
}

/// Response body for member removal
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveMemberResponse {
    /// Confirmation message
    pub message: String,
}

// ============================================================================
// Organization Invitations
// ============================================================================

/// Invitation response
#[derive(Debug, Serialize, Deserialize)]
pub struct InvitationResponse {
    /// Invitation ID
    pub id: i64,
    /// Email address
    pub email: String,
    /// Role
    pub role: String,
    /// When created
    pub created_at: String,
    /// When expires
    pub expires_at: String,
    /// User who created the invitation
    pub invited_by_user_id: i64,
    /// Invitation token (only included when creating invitation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// Request body for creating an invitation
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInvitationRequest {
    /// Email address to invite
    pub email: String,
    /// Role for the invited user
    pub role: OrganizationRole,
}

/// Response body for invitation creation
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInvitationResponse {
    /// Created invitation
    pub invitation: InvitationResponse,
}

/// Response body for listing invitations
#[derive(Debug, Serialize, Deserialize)]
pub struct ListInvitationsResponse {
    /// Invitations
    pub invitations: Vec<InvitationResponse>,
}

/// Response for accepting an invitation
#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptInvitationRequest {
    /// Invitation token
    pub token: String,
}

/// Response for accepting an invitation
#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptInvitationResponse {
    /// Organization the user joined
    pub organization: OrganizationResponse,
}

/// Response for deleting an invitation
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteInvitationResponse {
    /// Success message
    pub message: String,
}

// ============================================================================
// Ownership Transfer
// ============================================================================

/// Request body for transferring ownership
#[derive(Debug, Serialize, Deserialize)]
pub struct TransferOwnershipRequest {
    /// User ID of the new owner (must be existing member)
    pub new_owner_user_id: i64,
}

/// Response for ownership transfer
#[derive(Debug, Serialize, Deserialize)]
pub struct TransferOwnershipResponse {
    /// Success message
    pub message: String,
}

// ============================================================================
// Server-to-Server Organization Info
// ============================================================================

/// Organization status for server-to-server communication
/// This mirrors the server's OrgStatus enum for compatibility
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationStatus {
    /// Organization is active
    Active,
    /// Organization is suspended
    Suspended,
    /// Organization is deleted
    Deleted,
}

/// Organization information for server-to-server endpoints
/// This response format is specifically for the server API to verify
/// organization status without requiring user session context.
#[derive(Debug, Serialize, Deserialize)]
pub struct OrganizationServerResponse {
    /// Organization ID
    pub id: i64,
    /// Organization name
    pub name: String,
    /// Organization status (Active, Suspended, or Deleted)
    pub status: OrganizationStatus,
}
