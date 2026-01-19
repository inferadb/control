use axum::{
    Extension, Json,
    extract::{Path, State},
};
use inferadb_control_const::limits::{GLOBAL_ORGANIZATION_LIMIT, PER_USER_ORGANIZATION_LIMIT};
use inferadb_control_core::{IdGenerator, RepositoryContext, error::Error as CoreError};
use inferadb_control_types::{
    dto::{
        AcceptInvitationRequest, AcceptInvitationResponse, CreateInvitationRequest,
        CreateInvitationResponse, CreateOrganizationRequest, CreateOrganizationResponse,
        DeleteInvitationResponse, DeleteOrganizationResponse, GetOrganizationResponse,
        InvitationResponse, ListInvitationsResponse, ListMembersResponse,
        ListOrganizationsResponse, OrganizationMemberResponse, OrganizationResponse,
        OrganizationServerResponse, OrganizationStatus, RemoveMemberResponse,
        ResumeOrganizationResponse, SuspendOrganizationResponse, UpdateMemberRoleRequest,
        UpdateMemberRoleResponse, UpdateOrganizationRequest, UpdateOrganizationResponse,
    },
    entities::{
        Organization, OrganizationInvitation, OrganizationMember, OrganizationRole,
        OrganizationTier,
    },
};

use crate::{
    handlers::auth::{AppState, Result},
    middleware::{OrganizationContext, SessionContext, engine_auth::EngineContext},
};

/// Create a new organization
///
/// POST /v1/organizations
///
/// Creates a new organization with the authenticated user as owner.
/// Requires verified email and enforces per-user and global limits.
pub async fn create_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Json(payload): Json<CreateOrganizationRequest>,
) -> Result<Json<CreateOrganizationResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Validate organization name
    Organization::validate_name(&payload.name)?;

    // Check if user has a verified email
    let user_emails = repos.user_email.get_user_emails(ctx.user_id).await?;
    let has_verified_email = user_emails.iter().any(|e| e.verified_at.is_some());

    if !has_verified_email {
        return Err(CoreError::Validation(
            "You must verify your email before creating an organization".to_string(),
        )
        .into());
    }

    // Check per-user organization limit
    let user_org_count = repos.org_member.get_user_organization_count(ctx.user_id).await?;

    if user_org_count >= PER_USER_ORGANIZATION_LIMIT {
        return Err(CoreError::TierLimit(format!(
            "You have reached the maximum number of organizations ({})",
            PER_USER_ORGANIZATION_LIMIT
        ))
        .into());
    }

    // Check global organization limit
    let total_org_count = repos.org.get_total_count().await?;

    if total_org_count >= GLOBAL_ORGANIZATION_LIMIT {
        return Err(CoreError::TierLimit(
            "Global organization limit reached. Please contact support.".to_string(),
        )
        .into());
    }

    // Generate IDs
    let org_id = IdGenerator::next_id();
    let member_id = IdGenerator::next_id();

    // Create organization with TIER_DEV_V1
    let organization = Organization::new(org_id, payload.name, OrganizationTier::TierDevV1)?;

    // Create organization
    repos.org.create(organization.clone()).await?;

    // Create organization member (owner role)
    let member = OrganizationMember::new(member_id, org_id, ctx.user_id, OrganizationRole::Owner);

    // Create member
    repos.org_member.create(member).await?;

    Ok(Json(CreateOrganizationResponse {
        organization: OrganizationResponse {
            id: organization.id,
            name: organization.name,
            tier: tier_to_string(&organization.tier),
            created_at: organization.created_at.to_rfc3339(),
            role: role_to_string(&OrganizationRole::Owner),
        },
    }))
}

/// Convert OrganizationTier to string
fn tier_to_string(tier: &OrganizationTier) -> String {
    match tier {
        OrganizationTier::TierDevV1 => "TIER_DEV_V1".to_string(),
        OrganizationTier::TierProV1 => "TIER_PRO_V1".to_string(),
        OrganizationTier::TierMaxV1 => "TIER_MAX_V1".to_string(),
    }
}

/// Convert OrganizationRole to string
fn role_to_string(role: &OrganizationRole) -> String {
    match role {
        OrganizationRole::Member => "MEMBER".to_string(),
        OrganizationRole::Admin => "ADMIN".to_string(),
        OrganizationRole::Owner => "OWNER".to_string(),
    }
}

/// List organizations
///
/// GET /v1/organizations?limit=50&offset=0
///
/// Returns organizations the authenticated user is a member of, with pagination support.
pub async fn list_organizations(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    pagination: crate::pagination::PaginationQuery,
) -> Result<Json<ListOrganizationsResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());
    let params = pagination.0.validate();

    // Get all memberships for the user
    let memberships = repos.org_member.get_by_user(ctx.user_id).await?;

    // Fetch organization details for each membership
    let mut all_organizations = Vec::new();
    for member in memberships {
        if let Some(org) = repos.org.get(member.organization_id).await? {
            // Skip deleted organizations
            if org.is_deleted() {
                continue;
            }

            all_organizations.push(OrganizationResponse {
                id: org.id,
                name: org.name,
                tier: tier_to_string(&org.tier),
                created_at: org.created_at.to_rfc3339(),
                role: role_to_string(&member.role),
            });
        }
    }

    // Apply pagination
    let total = all_organizations.len();
    let organizations: Vec<OrganizationResponse> =
        all_organizations.into_iter().skip(params.offset).take(params.limit).collect();

    let pagination_meta = inferadb_control_types::PaginationMeta::from_total(
        total,
        params.offset,
        params.limit,
        organizations.len(),
    );

    Ok(Json(ListOrganizationsResponse { organizations, pagination: Some(pagination_meta) }))
}

/// Get organization details
///
/// GET /v1/organizations/:org
///
/// Returns details of a specific organization. User must be a member.
pub async fn get_organization(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
) -> Result<Json<GetOrganizationResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get organization
    let org = repos
        .org
        .get(org_ctx.organization_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    // Check if deleted
    if org.is_deleted() {
        return Err(CoreError::NotFound("Organization not found".to_string()).into());
    }

    Ok(Json(GetOrganizationResponse {
        organization: OrganizationResponse {
            id: org.id,
            name: org.name,
            tier: tier_to_string(&org.tier),
            created_at: org.created_at.to_rfc3339(),
            role: role_to_string(&org_ctx.member.role),
        },
    }))
}

/// Get organization by ID (engine-to-control endpoint)
///
/// GET /v1/organizations/:org
/// Auth: Session or Engine JWT (dual authentication)
///
/// This endpoint is used by the Engine to verify organization status.
/// Unlike `get_organization`, this does not require organization context
/// and returns minimal information (no user role).
///
/// Returns organization status as Active, Suspended, or Deleted.
/// Currently only Active and Deleted states are implemented.
pub async fn get_organization_by_id(
    State(state): State<AppState>,
    Path(org_id): Path<i64>,
) -> Result<Json<OrganizationServerResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get organization
    let org = repos
        .org
        .get(org_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    // Determine status: Deleted > Suspended > Active
    let status = if org.is_deleted() {
        OrganizationStatus::Deleted
    } else if org.is_suspended() {
        OrganizationStatus::Suspended
    } else {
        OrganizationStatus::Active
    };

    Ok(Json(OrganizationServerResponse { id: org.id, name: org.name, status }))
}

/// Get organization (privileged engine-to-control endpoint)
///
/// GET /internal/v1/organizations/:org
///
/// Returns organization details for engine-to-control authentication.
/// No membership or permission checks - any valid engine JWT can access.
pub async fn get_organization_privileged(
    State(state): State<AppState>,
    Path(org_id): Path<i64>,
    Extension(_engine_ctx): Extension<EngineContext>,
) -> Result<Json<OrganizationServerResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get organization
    let org = repos
        .org
        .get(org_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    // Determine status: Deleted > Suspended > Active
    let status = if org.is_deleted() {
        OrganizationStatus::Deleted
    } else if org.is_suspended() {
        OrganizationStatus::Suspended
    } else {
        OrganizationStatus::Active
    };

    let response = OrganizationServerResponse { id: org.id, name: org.name, status };

    Ok(Json(response))
}

/// Update organization
///
/// PATCH /v1/organizations/:org
///
/// Updates organization details. Requires admin or owner role.
pub async fn update_organization(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Json(payload): Json<UpdateOrganizationRequest>,
) -> Result<Json<UpdateOrganizationResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Require admin or owner
    crate::middleware::require_admin_or_owner(&org_ctx)?;

    // Get organization
    let mut org = repos
        .org
        .get(org_ctx.organization_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    // Check if deleted
    if org.is_deleted() {
        return Err(CoreError::NotFound("Organization not found".to_string()).into());
    }

    // Update name
    org.set_name(payload.name)?;
    repos.org.update(org.clone()).await?;

    Ok(Json(UpdateOrganizationResponse {
        organization: OrganizationResponse {
            id: org.id,
            name: org.name,
            tier: tier_to_string(&org.tier),
            created_at: org.created_at.to_rfc3339(),
            role: role_to_string(&org_ctx.member.role),
        },
    }))
}

/// Delete organization
///
/// DELETE /v1/organizations/:org
///
/// Soft-deletes an organization and cascades to all related resources.
/// Requires owner role.
///
/// Cascade deletes:
/// - All teams (and their members/permissions)
/// - All vaults (and their grants)
/// - All organization members
/// - All pending invitations
pub async fn delete_organization(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
) -> Result<Json<DeleteOrganizationResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Require owner
    crate::middleware::require_owner(&org_ctx)?;

    // VALIDATION: Check for active vaults before allowing deletion
    let vaults = repos.vault.list_by_organization(org_ctx.organization_id).await?;
    let active_vault_count = vaults.iter().filter(|v| !v.is_deleted()).count();

    if active_vault_count > 0 {
        return Err(CoreError::Validation(format!(
            "Cannot delete organization with {} active vault{}. Please delete all vaults first.",
            active_vault_count,
            if active_vault_count == 1 { "" } else { "s" }
        ))
        .into());
    }

    // CASCADE DELETE: Delete all teams first (and their members/permissions)
    let teams = repos.org_team.list_by_organization(org_ctx.organization_id).await?;
    for team in teams {
        if !team.is_deleted() {
            // Delete team members
            repos.org_team_member.delete_by_team(team.id).await?;
            // Delete team permissions
            repos.org_team_permission.delete_by_team(team.id).await?;
            // Soft delete team
            repos.org_team.delete(team.id).await?;
        }
    }

    // NOTE: Vaults must be deleted manually before organization deletion
    // This is enforced by the validation check above

    // CASCADE DELETE: Delete all organization members
    let members = repos.org_member.get_by_organization(org_ctx.organization_id).await?;
    for member in members {
        repos.org_member.delete(member.id).await?;
    }

    // CASCADE DELETE: Delete all pending invitations
    let invitations = repos.org_invitation.list_by_organization(org_ctx.organization_id).await?;
    for invitation in invitations {
        repos.org_invitation.delete(invitation.id).await?;
    }

    // Finally, soft delete the organization
    repos.org.delete(org_ctx.organization_id).await?;

    Ok(Json(DeleteOrganizationResponse {
        message: "Organization deleted successfully".to_string(),
    }))
}

/// Suspend organization
///
/// POST /v1/organizations/:org/suspend
///
/// Suspends an organization, blocking all API access for that organization.
/// Requires owner role.
pub async fn suspend_organization(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
) -> Result<Json<SuspendOrganizationResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Require owner
    crate::middleware::require_owner(&org_ctx)?;

    // Get organization
    let mut org = repos
        .org
        .get(org_ctx.organization_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    // Check if deleted
    if org.is_deleted() {
        return Err(CoreError::NotFound("Organization not found".to_string()).into());
    }

    // Check if already suspended
    if org.is_suspended() {
        return Err(CoreError::Validation("Organization is already suspended".to_string()).into());
    }

    // Suspend the organization
    org.suspend();
    repos.org.update(org).await?;

    Ok(Json(SuspendOrganizationResponse {
        message: "Organization suspended successfully".to_string(),
    }))
}

/// Resume organization
///
/// POST /v1/organizations/:org/resume
///
/// Resumes a suspended organization, restoring API access.
/// Requires owner role.
pub async fn resume_organization(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
) -> Result<Json<ResumeOrganizationResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Require owner
    crate::middleware::require_owner(&org_ctx)?;

    // Get organization
    let mut org = repos
        .org
        .get(org_ctx.organization_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    // Check if deleted
    if org.is_deleted() {
        return Err(CoreError::NotFound("Organization not found".to_string()).into());
    }

    // Check if not suspended
    if !org.is_suspended() {
        return Err(CoreError::Validation("Organization is not suspended".to_string()).into());
    }

    // Resume the organization
    org.resume();
    repos.org.update(org).await?;

    Ok(Json(ResumeOrganizationResponse {
        message: "Organization resumed successfully".to_string(),
    }))
}

// ============================================================================
// Organization Member Management
// ============================================================================

/// List organization members
///
/// GET /v1/organizations/:org/members
///
/// Returns all members of an organization. User must be a member.
pub async fn list_members(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
) -> Result<Json<ListMembersResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get all members
    let members = repos.org_member.get_by_organization(org_ctx.organization_id).await?;

    let member_responses: Vec<OrganizationMemberResponse> = members
        .into_iter()
        .map(|m| OrganizationMemberResponse {
            id: m.id,
            user_id: m.user_id,
            role: role_to_string(&m.role),
            joined_at: m.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(ListMembersResponse { members: member_responses }))
}

/// Update organization member's role
///
/// PATCH /v1/organizations/:org/members/:member
///
/// Updates a member's role. Requires admin or owner role.
/// Cannot demote the last owner.
pub async fn update_member_role(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, member_id)): Path<(i64, i64)>,
    Json(payload): Json<UpdateMemberRoleRequest>,
) -> Result<Json<UpdateMemberRoleResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Require admin or owner
    crate::middleware::require_admin_or_owner(&org_ctx)?;

    // Get the target member
    let mut target_member = repos
        .org_member
        .get(member_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Member not found".to_string()))?;

    // Verify the member belongs to this organization
    if target_member.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Member not found in this organization".to_string()).into());
    }

    // Parse new role
    let new_role = match payload.role.as_str() {
        "MEMBER" => OrganizationRole::Member,
        "ADMIN" => OrganizationRole::Admin,
        "OWNER" => OrganizationRole::Owner,
        _ => {
            return Err(CoreError::Validation(format!(
                "Invalid role '{}'. Must be MEMBER, ADMIN, or OWNER",
                payload.role
            ))
            .into());
        },
    };

    // Only owners can promote someone to OWNER
    if new_role == OrganizationRole::Owner && org_ctx.member.role != OrganizationRole::Owner {
        return Err(
            CoreError::Authz("Only owners can promote members to OWNER role".to_string()).into()
        );
    }

    // If demoting from owner, check if there are other owners
    if target_member.role == OrganizationRole::Owner && new_role != OrganizationRole::Owner {
        let owner_count = repos.org_member.count_owners(org_ctx.organization_id).await?;
        if owner_count <= 1 {
            return Err(CoreError::Validation(
                "Cannot demote the last owner. Promote another member to OWNER first.".to_string(),
            )
            .into());
        }
    }

    // Update role
    target_member.set_role(new_role);
    repos.org_member.update(target_member.clone()).await?;

    Ok(Json(UpdateMemberRoleResponse {
        member: OrganizationMemberResponse {
            id: target_member.id,
            user_id: target_member.user_id,
            role: role_to_string(&target_member.role),
            joined_at: target_member.created_at.to_rfc3339(),
        },
    }))
}

/// Remove organization member
///
/// DELETE /v1/organizations/:org/members/:member
///
/// Removes a member from the organization. Requires admin or owner role.
/// Cannot remove the last owner.
pub async fn remove_member(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, member_id)): Path<(i64, i64)>,
) -> Result<Json<RemoveMemberResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Require admin or owner
    crate::middleware::require_admin_or_owner(&org_ctx)?;

    // Get the target member
    let target_member = repos
        .org_member
        .get(member_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Member not found".to_string()))?;

    // Verify the member belongs to this organization
    if target_member.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Member not found in this organization".to_string()).into());
    }

    // If removing an owner, check if there are other owners
    if target_member.role == OrganizationRole::Owner {
        let owner_count = repos.org_member.count_owners(org_ctx.organization_id).await?;
        if owner_count <= 1 {
            return Err(CoreError::Validation(
                "Cannot remove the last owner. Transfer ownership first or delete the organization."
                    .to_string(),
            )
            .into());
        }
    }

    // Remove member
    repos.org_member.delete(member_id).await?;

    Ok(Json(RemoveMemberResponse { message: "Member removed successfully".to_string() }))
}

/// Leave an organization (remove self)
///
/// DELETE /v1/organizations/:org/members/self
///
/// Allows any member to remove themselves from an organization.
/// Owners cannot leave if they are the last owner - they must first
/// promote another member to owner or delete the organization.
pub async fn leave_organization(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
) -> Result<Json<RemoveMemberResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // If the user is an owner, check if there are other owners
    if org_ctx.member.role == OrganizationRole::Owner {
        let owner_count = repos.org_member.count_owners(org_ctx.organization_id).await?;
        if owner_count <= 1 {
            return Err(CoreError::Validation(
                "Cannot leave as the last owner. Promote another member to owner first or delete the organization."
                    .to_string(),
            )
            .into());
        }
    }

    // Remove self from organization
    repos.org_member.delete(org_ctx.member.id).await?;

    Ok(Json(RemoveMemberResponse { message: "You have left the organization".to_string() }))
}

// ============================================================================
// Organization Invitations
// ============================================================================

fn invitation_to_response(invitation: OrganizationInvitation) -> InvitationResponse {
    InvitationResponse {
        id: invitation.id,
        email: invitation.email,
        role: format!("{:?}", invitation.role).to_uppercase(),
        created_at: invitation.created_at.to_rfc3339(),
        expires_at: invitation.expires_at.to_rfc3339(),
        invited_by_user_id: invitation.invited_by_user_id,
        token: None, // Token not included by default
    }
}

/// Create a new organization invitation
///
/// POST /v1/organizations/:org/invitations
///
/// Invite a user to join an organization by email. Requires ADMIN or OWNER role.
pub async fn create_invitation(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Json(payload): Json<CreateInvitationRequest>,
) -> Result<Json<CreateInvitationResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Require admin or owner
    crate::middleware::require_admin_or_owner(&org_ctx)?;

    // Validate email
    OrganizationInvitation::validate_email(&payload.email)?;

    // Get organization to check member limits
    let org = repos
        .org
        .get(org_ctx.organization_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    // Check member count against tier limit
    let member_count = repos.org_member.count_by_organization(org_ctx.organization_id).await?;

    if member_count >= org.tier.max_members() {
        return Err(CoreError::TierLimit(format!(
            "Organization has reached the maximum number of members ({}) for tier {:?}",
            org.tier.max_members(),
            org.tier
        ))
        .into());
    }

    // Check if user with this email already exists and is a member
    if let Some(existing_email) = repos.user_email.get_by_email(&payload.email).await? {
        if repos
            .org_member
            .get_by_org_and_user(org_ctx.organization_id, existing_email.user_id)
            .await?
            .is_some()
        {
            return Err(CoreError::AlreadyExists(
                "User is already a member of this organization".to_string(),
            )
            .into());
        }
    }

    // Check for existing invitation
    if repos.org_invitation.exists_for_email_in_org(&payload.email, org_ctx.organization_id).await?
    {
        return Err(CoreError::AlreadyExists(
            "An invitation for this email already exists".to_string(),
        )
        .into());
    }

    // Generate invitation
    let invitation_id = IdGenerator::next_id();
    let token = OrganizationInvitation::generate_token()?;
    let invitation = OrganizationInvitation::new(
        invitation_id,
        org_ctx.organization_id,
        org_ctx.member.user_id,
        payload.email,
        payload.role,
        token.clone(),
    )?;

    // Create invitation
    repos.org_invitation.create(invitation.clone()).await?;

    // Convert to response and include token
    let mut invitation_response = invitation_to_response(invitation);
    invitation_response.token = Some(token);

    Ok(Json(CreateInvitationResponse { invitation: invitation_response }))
}

/// List organization invitations
///
/// GET /v1/organizations/:org/invitations
///
/// List all pending invitations for an organization. Requires ADMIN or OWNER role.
pub async fn list_invitations(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
) -> Result<Json<ListInvitationsResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Require admin or owner
    crate::middleware::require_admin_or_owner(&org_ctx)?;

    let invitations = repos.org_invitation.list_by_organization(org_ctx.organization_id).await?;

    Ok(Json(ListInvitationsResponse {
        invitations: invitations.into_iter().map(invitation_to_response).collect(),
    }))
}

/// Delete an organization invitation
///
/// DELETE /v1/organizations/:org/invitations/:invitation
///
/// Revoke a pending invitation. Requires ADMIN or OWNER role.
pub async fn delete_invitation(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, invitation_id)): Path<(i64, i64)>,
) -> Result<Json<DeleteInvitationResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Require admin or owner
    crate::middleware::require_admin_or_owner(&org_ctx)?;

    // Verify invitation belongs to this organization
    let invitation: OrganizationInvitation = repos
        .org_invitation
        .get(invitation_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Invitation not found".to_string()))?;

    if invitation.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Invitation not found".to_string()).into());
    }

    // Delete invitation
    repos.org_invitation.delete(invitation_id).await?;

    Ok(Json(DeleteInvitationResponse { message: "Invitation deleted successfully".to_string() }))
}

/// Accept an organization invitation
///
/// POST /v1/organizations/invitations/accept
///
/// Accept an invitation to join an organization using the invitation token.
pub async fn accept_invitation(
    State(state): State<AppState>,
    Extension(ctx): Extension<SessionContext>,
    Json(payload): Json<AcceptInvitationRequest>,
) -> Result<Json<AcceptInvitationResponse>> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Validate token format
    OrganizationInvitation::validate_token(&payload.token)?;

    // Get invitation by token
    let invitation: OrganizationInvitation = repos
        .org_invitation
        .get_by_token(&payload.token)
        .await?
        .ok_or_else(|| CoreError::NotFound("Invalid or expired invitation".to_string()))?;

    // Check if invitation has expired
    if invitation.is_expired() {
        // Clean up expired invitation
        repos.org_invitation.delete(invitation.id).await?;
        return Err(CoreError::NotFound("Invalid or expired invitation".to_string()).into());
    }

    // Get user's email to verify it matches
    let user_emails = repos.user_email.get_user_emails(ctx.user_id).await?;
    let has_matching_email =
        user_emails.iter().any(|e| e.email.to_lowercase() == invitation.email.to_lowercase());

    if !has_matching_email {
        return Err(CoreError::Validation(
            "This invitation was sent to a different email address".to_string(),
        )
        .into());
    }

    // Check if user is already a member
    if repos
        .org_member
        .get_by_org_and_user(invitation.organization_id, ctx.user_id)
        .await?
        .is_some()
    {
        // Delete invitation and return success
        repos.org_invitation.delete(invitation.id).await?;
        return Err(CoreError::AlreadyExists(
            "You are already a member of this organization".to_string(),
        )
        .into());
    }

    // Check organization member limit
    let org = repos
        .org
        .get(invitation.organization_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    let member_count = repos.org_member.count_by_organization(invitation.organization_id).await?;
    if member_count >= org.tier.max_members() {
        return Err(CoreError::TierLimit(
            "Organization has reached the maximum number of members".to_string(),
        )
        .into());
    }

    // Create organization member
    let member_id = IdGenerator::next_id();
    let member = OrganizationMember::new(
        member_id,
        invitation.organization_id,
        ctx.user_id,
        invitation.role,
    );
    repos.org_member.create(member).await?;

    // Delete invitation
    repos.org_invitation.delete(invitation.id).await?;

    // Return organization details
    let org_response = OrganizationResponse {
        id: org.id,
        name: org.name,
        tier: format!("{:?}", org.tier).to_uppercase(),
        created_at: org.created_at.to_rfc3339(),
        role: format!("{:?}", invitation.role).to_uppercase(),
    };

    Ok(Json(AcceptInvitationResponse { organization: org_response }))
}
