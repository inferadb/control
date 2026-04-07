//! Organization, membership, and invitation management handlers.
//!
//! All operations delegate to Ledger SDK via the service layer.
//! Organization state (members, invitations, tiers) is owned by Ledger.

use std::time::Instant;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use inferadb_control_const::duration::{INVITATION_EXPIRY_DAYS, INVITATION_EXPIRY_HOURS};
use inferadb_control_core::SdkResultExt;
use inferadb_ledger_sdk::{
    InvitationStatus, InviteSlug, OrganizationMemberRole, OrganizationSlug, OrganizationTier,
    Region, UserSlug,
};
use serde::{Deserialize, Serialize};

use super::common::{
    CursorPaginationQuery, MessageResponse, encode_page_token, require_ledger,
    system_time_to_rfc3339, validate_email, validate_name, verify_org_membership_from_claims,
};
use crate::{
    handlers::state::{AppState, Result},
    middleware::UserClaims,
};

// ── Request Types ─────────────────────────────────────────────────────

/// Request body for creating an organization.
#[derive(Debug, Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
}

/// Request body for updating an organization.
#[derive(Debug, Deserialize)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
}

/// Organization member role input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationRoleInput {
    /// Full management access to the organization.
    Admin,
    /// Standard member with limited privileges.
    Member,
}

impl OrganizationRoleInput {
    /// Converts to the Ledger SDK role type.
    fn to_sdk_role(&self) -> OrganizationMemberRole {
        match self {
            Self::Admin => OrganizationMemberRole::Admin,
            Self::Member => OrganizationMemberRole::Member,
        }
    }
}

/// Request body for updating a member's role.
#[derive(Debug, Deserialize)]
pub struct UpdateMemberRoleRequest {
    pub role: OrganizationRoleInput,
}

/// Request body for creating an invitation.
#[derive(Debug, Deserialize)]
pub struct CreateInvitationRequest {
    pub email: String,
    pub role: Option<OrganizationRoleInput>,
}

// ── Response Types ────────────────────────────────────────────────────

/// Organization summary.
#[derive(Debug, Serialize)]
pub struct OrganizationResponse {
    /// Organization slug identifier.
    pub slug: u64,
    /// Display name.
    pub name: String,
    /// Data residency region (e.g., `"us-east-va"`).
    pub region: String,
    /// Organization status (e.g., `"active"`, `"deleted"`).
    pub status: String,
    /// Subscription tier (e.g., `"free"`, `"pro"`).
    pub tier: String,
}

/// Wrapper for a single organization.
#[derive(Debug, Serialize)]
pub struct SingleOrganizationResponse {
    pub organization: OrganizationResponse,
}

/// Paginated list of organizations.
#[derive(Debug, Serialize)]
pub struct ListOrganizationsResponse {
    pub organizations: Vec<OrganizationResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// Response confirming organization deletion.
#[derive(Debug, Serialize)]
pub struct DeleteOrganizationResponse {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
}

/// Organization member summary.
#[derive(Debug, Serialize)]
pub struct MemberResponse {
    /// User slug identifier.
    pub user: u64,
    /// Member role (e.g., `"admin"`, `"member"`).
    pub role: String,
    /// RFC 3339 timestamp of when the user joined the organization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub joined_at: Option<String>,
}

/// Paginated list of members.
#[derive(Debug, Serialize)]
pub struct ListMembersResponse {
    pub members: Vec<MemberResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// Response containing an updated organization member.
#[derive(Debug, Serialize)]
pub struct UpdateMemberRoleResponse {
    pub member: MemberResponse,
}

/// Invitation response (admin view).
#[derive(Debug, Serialize)]
pub struct InvitationResponse {
    /// Invitation slug identifier.
    pub slug: u64,
    /// Organization the invitation is for.
    pub organization: u64,
    /// User slug of the person who sent the invitation.
    pub inviter: u64,
    /// Email address of the invitee.
    pub invitee_email: String,
    /// Role the invitee will receive (e.g., `"admin"`, `"member"`).
    pub role: String,
    /// Invitation status (e.g., `"pending"`, `"accepted"`, `"revoked"`).
    pub status: String,
    /// RFC 3339 timestamp of when the invitation was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// RFC 3339 timestamp of when the invitation expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Invitation token (omitted in list responses for security).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// Paginated list of invitations (admin view).
#[derive(Debug, Serialize)]
pub struct ListInvitationsResponse {
    pub invitations: Vec<InvitationResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// Received invitation response (user view).
#[derive(Debug, Serialize)]
pub struct ReceivedInvitationResponse {
    /// Invitation slug identifier.
    pub slug: u64,
    /// Organization slug.
    pub organization: u64,
    /// Organization display name.
    pub organization_name: String,
    /// Role offered (e.g., `"admin"`, `"member"`).
    pub role: String,
    /// Invitation status (e.g., `"pending"`, `"accepted"`).
    pub status: String,
    /// RFC 3339 creation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// RFC 3339 expiration timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Paginated list of received invitations.
#[derive(Debug, Serialize)]
pub struct ListReceivedInvitationsResponse {
    pub invitations: Vec<ReceivedInvitationResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Converts a Ledger [`OrganizationInfo`](inferadb_ledger_sdk::OrganizationInfo) to an API
/// response.
fn org_info_to_response(info: &inferadb_ledger_sdk::OrganizationInfo) -> OrganizationResponse {
    OrganizationResponse {
        slug: info.slug.value(),
        name: info.name.clone(),
        region: info.region.to_string(),
        status: info.status.to_string(),
        tier: info.tier.to_string(),
    }
}

/// Converts a Ledger [`OrganizationMemberInfo`](inferadb_ledger_sdk::OrganizationMemberInfo) to an
/// API response.
fn member_info_to_response(info: &inferadb_ledger_sdk::OrganizationMemberInfo) -> MemberResponse {
    MemberResponse {
        user: info.user.value(),
        role: info.role.to_string(),
        joined_at: system_time_to_rfc3339(&info.joined_at),
    }
}

/// Converts a Ledger [`InvitationInfo`](inferadb_ledger_sdk::InvitationInfo) to an API response.
fn invitation_info_to_response(info: &inferadb_ledger_sdk::InvitationInfo) -> InvitationResponse {
    InvitationResponse {
        slug: info.slug.value(),
        organization: info.organization.value(),
        inviter: info.inviter.value(),
        invitee_email: info.invitee_email.clone(),
        role: info.role.to_string(),
        status: info.status.to_string(),
        created_at: system_time_to_rfc3339(&info.created_at),
        expires_at: system_time_to_rfc3339(&info.expires_at),
        token: None,
    }
}

/// Converts a Ledger [`ReceivedInvitationInfo`](inferadb_ledger_sdk::ReceivedInvitationInfo) to an
/// API response.
fn received_info_to_response(
    info: &inferadb_ledger_sdk::ReceivedInvitationInfo,
) -> ReceivedInvitationResponse {
    ReceivedInvitationResponse {
        slug: info.slug.value(),
        organization: info.organization.value(),
        organization_name: info.organization_name.clone(),
        role: info.role.to_string(),
        status: info.status.to_string(),
        created_at: system_time_to_rfc3339(&info.created_at),
        expires_at: system_time_to_rfc3339(&info.expires_at),
    }
}

// ── Organization Handlers ─────────────────────────────────────────────

/// POST /control/v1/organizations
///
/// Creates a new organization with the authenticated user as admin.
/// Uses default region (US_EAST_VA) and tier (Free).
pub async fn create_organization(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Json(payload): Json<CreateOrganizationRequest>,
) -> Result<(StatusCode, Json<SingleOrganizationResponse>)> {
    validate_name(&payload.name)?;
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let info = ledger
        .create_organization(
            &payload.name,
            Region::US_EAST_VA,
            claims.user_slug,
            OrganizationTier::Free,
        )
        .await
        .map_sdk_err_instrumented("create_organization", start)?;

    Ok((
        StatusCode::CREATED,
        Json(SingleOrganizationResponse { organization: org_info_to_response(&info) }),
    ))
}

/// GET /control/v1/organizations
///
/// Lists organizations the authenticated user belongs to, with cursor-based pagination.
pub async fn list_organizations(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Query(pagination): Query<CursorPaginationQuery>,
) -> Result<Json<ListOrganizationsResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let (orgs, next_token) = ledger
        .list_organizations(
            claims.user_slug,
            pagination.validated_page_size(),
            pagination.decoded_page_token(),
        )
        .await
        .map_sdk_err_instrumented("list_organizations", start)?;

    Ok(Json(ListOrganizationsResponse {
        organizations: orgs.iter().map(org_info_to_response).collect(),
        next_page_token: encode_page_token(&next_token),
    }))
}

/// GET /control/v1/organizations/{org}
///
/// Returns details of a specific organization. Caller must be a member.
pub async fn get_organization(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
) -> Result<Json<SingleOrganizationResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let info = ledger
        .get_organization(OrganizationSlug::new(org), claims.user_slug)
        .await
        .map_sdk_err_instrumented("get_organization", start)?;

    Ok(Json(SingleOrganizationResponse { organization: org_info_to_response(&info) }))
}

/// PATCH /control/v1/organizations/{org}
///
/// Updates organization details. Ledger enforces role requirements.
pub async fn update_organization(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Json(payload): Json<UpdateOrganizationRequest>,
) -> Result<Json<SingleOrganizationResponse>> {
    if let Some(ref name) = payload.name {
        validate_name(name)?;
    }
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let info = ledger
        .update_organization(OrganizationSlug::new(org), claims.user_slug, payload.name)
        .await
        .map_sdk_err_instrumented("update_organization", start)?;

    Ok(Json(SingleOrganizationResponse { organization: org_info_to_response(&info) }))
}

/// DELETE /control/v1/organizations/{org}
///
/// Soft-deletes an organization. Ledger handles cascade deletion and
/// enforces that no active vaults remain.
pub async fn delete_organization(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
) -> Result<Json<DeleteOrganizationResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let delete_info = ledger
        .delete_organization(OrganizationSlug::new(org), claims.user_slug)
        .await
        .map_sdk_err_instrumented("delete_organization", start)?;

    Ok(Json(DeleteOrganizationResponse {
        message: "Organization deleted successfully".to_string(),
        retention_days: Some(delete_info.retention_days),
    }))
}

// ── Membership Handlers ───────────────────────────────────────────────

/// GET /control/v1/organizations/{org}/members
///
/// Lists members of an organization with cursor-based pagination.
pub async fn list_members(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Query(pagination): Query<CursorPaginationQuery>,
) -> Result<Json<ListMembersResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let (members, next_token) = ledger
        .list_organization_members(
            OrganizationSlug::new(org),
            claims.user_slug,
            pagination.validated_page_size(),
            pagination.decoded_page_token(),
        )
        .await
        .map_sdk_err_instrumented("list_members", start)?;

    Ok(Json(ListMembersResponse {
        members: members.iter().map(member_info_to_response).collect(),
        next_page_token: encode_page_token(&next_token),
    }))
}

/// PATCH /control/v1/organizations/{org}/members/{member}
///
/// Updates a member's role. Ledger enforces permission checks (admin/owner required).
pub async fn update_member_role(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, member)): Path<(u64, u64)>,
    Json(payload): Json<UpdateMemberRoleRequest>,
) -> Result<Json<UpdateMemberRoleResponse>> {
    let ledger = require_ledger(&state)?;

    let role = payload.role.to_sdk_role();

    let start = Instant::now();
    let updated = ledger
        .update_organization_member_role(
            OrganizationSlug::new(org),
            claims.user_slug,
            UserSlug::new(member),
            role,
        )
        .await
        .map_sdk_err_instrumented("update_member_role", start)?;

    Ok(Json(UpdateMemberRoleResponse { member: member_info_to_response(&updated) }))
}

/// DELETE /control/v1/organizations/{org}/members/{member}
///
/// Removes a member from the organization. Ledger enforces permission checks.
pub async fn remove_member(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, member)): Path<(u64, u64)>,
) -> Result<Json<MessageResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    ledger
        .remove_organization_member(
            OrganizationSlug::new(org),
            claims.user_slug,
            UserSlug::new(member),
        )
        .await
        .map_sdk_err_instrumented("remove_member", start)?;

    // Invalidate cached membership so vault/schema access is revoked immediately.
    state.org_membership_cache.invalidate(member, org).await;

    Ok(Json(MessageResponse { message: "Member removed successfully".to_string() }))
}

/// DELETE /control/v1/organizations/{org}/members/me
///
/// Removes the authenticated user from the organization (leave).
/// Ledger enforces last-owner protection.
pub async fn leave_organization(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
) -> Result<Json<MessageResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    ledger
        .remove_organization_member(OrganizationSlug::new(org), claims.user_slug, claims.user_slug)
        .await
        .map_sdk_err_instrumented("remove_member", start)?;

    // Invalidate cached membership so vault/schema access is revoked immediately.
    state.org_membership_cache.invalidate(claims.user_slug.value(), org).await;

    Ok(Json(MessageResponse { message: "You have left the organization".to_string() }))
}

// ── Invitation Handlers ───────────────────────────────────────────────

/// POST /control/v1/organizations/{org}/invitations
///
/// Creates an invitation to join the organization. Ledger enforces role
/// and member-limit checks. If the email service is configured, sends an
/// invitation email.
pub async fn create_invitation(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Json(payload): Json<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<InvitationResponse>)> {
    validate_email(&payload.email)?;
    let ledger = require_ledger(&state)?;

    let role = payload
        .role
        .as_ref()
        .map(OrganizationRoleInput::to_sdk_role)
        .unwrap_or(OrganizationMemberRole::Member);

    let start = Instant::now();
    let created = ledger
        .create_organization_invite(
            OrganizationSlug::new(org),
            claims.user_slug,
            &payload.email,
            role,
            INVITATION_EXPIRY_HOURS,
            None,
        )
        .await
        .map_sdk_err_instrumented("create_invite", start)?;

    // Attempt to send invitation email if the email service is configured.
    if let Some(email_svc) = &state.email_service {
        // Fetch org name and inviter name concurrently for the email template.
        let start = Instant::now();
        let (org_result, inviter_result) = tokio::join!(
            ledger.get_organization(OrganizationSlug::new(org), claims.user_slug),
            ledger.get_user(claims.user_slug),
        );
        let org_info = org_result.map_sdk_err_instrumented("get_organization", start);
        let inviter_info = inviter_result.map_sdk_err_instrumented("get_user", start);

        let org_name = org_info.as_ref().map(|o| o.name.as_str()).unwrap_or("the organization");

        let inviter_name =
            inviter_info.as_ref().map(|u| u.name.as_str()).unwrap_or("A team member");

        let frontend_url = &state.config.frontend_url;
        let invite_link = format!("{frontend_url}/invitations/accept?token={}", created.token);

        let template = inferadb_control_core::InvitationEmailTemplate {
            invitee_email: payload.email.clone(),
            organization_name: org_name.to_string(),
            inviter_name: inviter_name.to_string(),
            role: role.to_string(),
            invitation_link: invite_link,
            invitation_token: created.token.clone(),
            expires_in: format!("{INVITATION_EXPIRY_DAYS} days"),
        };

        use inferadb_control_core::EmailTemplate;
        let _ = email_svc
            .send_email(
                &payload.email,
                &template.subject(),
                &template.html_body(),
                &template.text_body(),
            )
            .await;
    }

    Ok((
        StatusCode::CREATED,
        Json(InvitationResponse {
            slug: created.slug.value(),
            organization: org,
            inviter: claims.user_slug.value(),
            invitee_email: payload.email,
            role: role.to_string(),
            status: created.status.to_string(),
            created_at: system_time_to_rfc3339(&created.created_at),
            expires_at: system_time_to_rfc3339(&created.expires_at),
            token: None,
        }),
    ))
}

/// GET /control/v1/organizations/{org}/invitations
///
/// Lists invitations for an organization (admin view) with cursor-based pagination.
pub async fn list_invitations(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Query(pagination): Query<CursorPaginationQuery>,
) -> Result<Json<ListInvitationsResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let page = ledger
        .list_organization_invites(
            OrganizationSlug::new(org),
            claims.user_slug,
            None::<InvitationStatus>,
            pagination.decoded_page_token(),
            pagination.validated_page_size(),
        )
        .await
        .map_sdk_err_instrumented("list_invites", start)?;

    Ok(Json(ListInvitationsResponse {
        invitations: page.invitations.iter().map(invitation_info_to_response).collect(),
        next_page_token: encode_page_token(&page.next_page_token),
    }))
}

/// DELETE /control/v1/organizations/{org}/invitations/{invitation}
///
/// Revokes a pending invitation. Verifies org membership before revoking
/// to ensure the invitation belongs to the specified organization.
pub async fn delete_invitation(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, invite)): Path<(u64, u64)>,
) -> Result<Json<MessageResponse>> {
    let ledger = require_ledger(&state)?;

    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let start = Instant::now();
    ledger
        .revoke_organization_invite(InviteSlug::new(invite), claims.user_slug)
        .await
        .map_sdk_err_instrumented("revoke_invite", start)?;

    Ok(Json(MessageResponse { message: "Invitation revoked successfully".to_string() }))
}

/// POST /control/v1/users/me/invitations/{invitation}/accept
///
/// Accepts a pending invitation, adding the user to the organization.
pub async fn accept_invitation(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(invite): Path<u64>,
) -> Result<Json<ReceivedInvitationResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let info = ledger
        .accept_invitation(InviteSlug::new(invite), claims.user_slug)
        .await
        .map_sdk_err_instrumented("accept_invitation", start)?;

    Ok(Json(received_info_to_response(&info)))
}

/// GET /control/v1/users/me/invitations
///
/// Lists invitations received by the authenticated user.
pub async fn list_received_invitations(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Query(pagination): Query<CursorPaginationQuery>,
) -> Result<Json<ListReceivedInvitationsResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let page = ledger
        .list_received_invitations(
            claims.user_slug,
            None::<InvitationStatus>,
            pagination.decoded_page_token(),
            pagination.validated_page_size(),
        )
        .await
        .map_sdk_err_instrumented("list_received", start)?;

    Ok(Json(ListReceivedInvitationsResponse {
        invitations: page.invitations.iter().map(received_info_to_response).collect(),
        next_page_token: encode_page_token(&page.next_page_token),
    }))
}

/// POST /control/v1/users/me/invitations/{invitation}/decline
///
/// Declines a pending invitation.
pub async fn decline_invitation(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(invite): Path<u64>,
) -> Result<Json<ReceivedInvitationResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let info = ledger
        .decline_invitation(InviteSlug::new(invite), claims.user_slug)
        .await
        .map_sdk_err_instrumented("decline_invitation", start)?;

    Ok(Json(received_info_to_response(&info)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::SystemTime;

    use inferadb_ledger_sdk::{
        InvitationStatus, InviteSlug, OrganizationMemberRole, OrganizationSlug, OrganizationStatus,
        OrganizationTier, Region, UserSlug,
    };

    use super::*;

    fn sample_org_info() -> inferadb_ledger_sdk::OrganizationInfo {
        inferadb_ledger_sdk::OrganizationInfo {
            slug: OrganizationSlug::new(100),
            name: "Acme Corp".to_string(),
            region: Region::US_EAST_VA,
            member_nodes: vec![],
            config_version: 1,
            status: OrganizationStatus::Active,
            tier: OrganizationTier::Free,
            members: vec![],
        }
    }

    fn sample_member_info() -> inferadb_ledger_sdk::OrganizationMemberInfo {
        inferadb_ledger_sdk::OrganizationMemberInfo {
            user: UserSlug::new(42),
            role: OrganizationMemberRole::Admin,
            joined_at: Some(SystemTime::now()),
        }
    }

    fn sample_invitation_info() -> inferadb_ledger_sdk::InvitationInfo {
        inferadb_ledger_sdk::InvitationInfo {
            slug: InviteSlug::new(200),
            organization: OrganizationSlug::new(100),
            inviter: UserSlug::new(42),
            invitee_email: "guest@example.com".to_string(),
            role: OrganizationMemberRole::Member,
            team: None,
            status: InvitationStatus::Pending,
            created_at: Some(SystemTime::now()),
            expires_at: Some(SystemTime::now()),
            resolved_at: None,
        }
    }

    fn sample_received_info() -> inferadb_ledger_sdk::ReceivedInvitationInfo {
        inferadb_ledger_sdk::ReceivedInvitationInfo {
            slug: InviteSlug::new(300),
            organization: OrganizationSlug::new(100),
            organization_name: "Acme Corp".to_string(),
            role: OrganizationMemberRole::Member,
            team: None,
            status: InvitationStatus::Pending,
            created_at: Some(SystemTime::now()),
            expires_at: Some(SystemTime::now()),
        }
    }

    // ── org_info_to_response ─────────────────────────────────────────

    #[test]
    fn test_org_info_to_response_maps_all_fields() {
        let resp = org_info_to_response(&sample_org_info());

        assert_eq!(resp.slug, 100);
        assert_eq!(resp.name, "Acme Corp");
        assert_eq!(resp.region, "us-east-va");
        assert_eq!(resp.status, "active");
        assert_eq!(resp.tier, "free");
    }

    // ── member_info_to_response ──────────────────────────────────────

    #[test]
    fn test_member_info_to_response_maps_user_and_role() {
        let resp = member_info_to_response(&sample_member_info());
        assert_eq!(resp.user, 42);
        assert_eq!(resp.role, "admin");
    }

    #[test]
    fn test_member_info_to_response_with_joined_at_returns_some() {
        let resp = member_info_to_response(&sample_member_info());
        assert!(resp.joined_at.is_some());
    }

    #[test]
    fn test_member_info_to_response_without_joined_at_returns_none() {
        let mut info = sample_member_info();
        info.joined_at = None;
        let resp = member_info_to_response(&info);
        assert!(resp.joined_at.is_none());
    }

    // ── invitation_info_to_response ──────────────────────────────────

    #[test]
    fn test_invitation_info_to_response_maps_all_fields() {
        let resp = invitation_info_to_response(&sample_invitation_info());
        assert_eq!(resp.slug, 200);
        assert_eq!(resp.organization, 100);
        assert_eq!(resp.inviter, 42);
        assert_eq!(resp.invitee_email, "guest@example.com");
        assert_eq!(resp.role, "member");
        assert_eq!(resp.status, "pending");
        assert!(resp.created_at.is_some());
        assert!(resp.expires_at.is_some());
    }

    #[test]
    fn test_invitation_info_to_response_token_always_none() {
        let resp = invitation_info_to_response(&sample_invitation_info());
        assert!(resp.token.is_none());
    }

    // ── received_info_to_response ────────────────────────────────────

    #[test]
    fn test_received_info_to_response_maps_all_fields() {
        let resp = received_info_to_response(&sample_received_info());
        assert_eq!(resp.slug, 300);
        assert_eq!(resp.organization, 100);
        assert_eq!(resp.organization_name, "Acme Corp");
        assert_eq!(resp.role, "member");
        assert_eq!(resp.status, "pending");
        assert!(resp.created_at.is_some());
        assert!(resp.expires_at.is_some());
    }

    #[test]
    fn test_received_info_to_response_no_timestamps_returns_none() {
        let mut info = sample_received_info();
        info.created_at = None;
        info.expires_at = None;
        let resp = received_info_to_response(&info);
        assert!(resp.created_at.is_none());
        assert!(resp.expires_at.is_none());
    }

    // ── OrganizationRoleInput ────────────────────────────────────────

    #[test]
    fn test_role_input_admin_to_sdk_role() {
        assert!(matches!(
            OrganizationRoleInput::Admin.to_sdk_role(),
            OrganizationMemberRole::Admin
        ));
    }

    #[test]
    fn test_role_input_member_to_sdk_role() {
        assert!(matches!(
            OrganizationRoleInput::Member.to_sdk_role(),
            OrganizationMemberRole::Member
        ));
    }

    #[test]
    fn test_role_input_deserializes_from_json() {
        let admin: OrganizationRoleInput = serde_json::from_str(r#""admin""#).unwrap();
        assert!(matches!(admin.to_sdk_role(), OrganizationMemberRole::Admin));

        let member: OrganizationRoleInput = serde_json::from_str(r#""member""#).unwrap();
        assert!(matches!(member.to_sdk_role(), OrganizationMemberRole::Member));
    }

    // ── Request deserialization ──────────────────────────────────────

    #[test]
    fn test_create_organization_request_deserializes() {
        let json = r#"{"name": "My Org"}"#;
        let req: CreateOrganizationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "My Org");
    }

    #[test]
    fn test_update_organization_request_deserializes_with_name() {
        let json = r#"{"name": "New Name"}"#;
        let req: UpdateOrganizationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("New Name"));
    }

    #[test]
    fn test_update_organization_request_deserializes_empty_body() {
        let json = r#"{}"#;
        let req: UpdateOrganizationRequest = serde_json::from_str(json).unwrap();
        assert!(req.name.is_none());
    }

    #[test]
    fn test_create_invitation_request_deserializes_with_role() {
        let json = r#"{"email": "user@example.com", "role": "admin"}"#;
        let req: CreateInvitationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.email, "user@example.com");
        assert!(req.role.is_some());
    }

    #[test]
    fn test_create_invitation_request_deserializes_without_role() {
        let json = r#"{"email": "user@example.com"}"#;
        let req: CreateInvitationRequest = serde_json::from_str(json).unwrap();
        assert!(req.role.is_none());
    }

    #[test]
    fn test_update_member_role_request_deserializes() {
        let json = r#"{"role": "admin"}"#;
        let req: UpdateMemberRoleRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(req.role.to_sdk_role(), OrganizationMemberRole::Admin));
    }

    // ── Response serialization ──────────────────────────────────────

    #[test]
    fn test_delete_organization_response_with_retention_serializes() {
        let resp = DeleteOrganizationResponse {
            message: "Organization deleted successfully".to_string(),
            retention_days: Some(30),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["message"], "Organization deleted successfully");
        assert_eq!(json["retention_days"], 30);
    }

    #[test]
    fn test_delete_organization_response_without_retention_omits_field() {
        let resp =
            DeleteOrganizationResponse { message: "deleted".to_string(), retention_days: None };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("retention_days").is_none());
    }

    #[test]
    fn test_list_organizations_response_no_token_omits_field() {
        let resp = ListOrganizationsResponse { organizations: vec![], next_page_token: None };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("next_page_token").is_none());
    }

    #[test]
    fn test_invitation_response_none_optionals_omitted() {
        let resp = InvitationResponse {
            slug: 1,
            organization: 2,
            inviter: 3,
            invitee_email: "a@b.com".to_string(),
            role: "member".to_string(),
            status: "pending".to_string(),
            created_at: None,
            expires_at: None,
            token: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("created_at").is_none());
        assert!(json.get("expires_at").is_none());
        assert!(json.get("token").is_none());
    }

    #[test]
    fn test_received_invitation_response_serializes_all_fields() {
        let resp = ReceivedInvitationResponse {
            slug: 10,
            organization: 20,
            organization_name: "Org".to_string(),
            role: "admin".to_string(),
            status: "accepted".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
            expires_at: Some("2026-02-01T00:00:00Z".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["slug"], 10);
        assert_eq!(json["organization_name"], "Org");
        assert_eq!(json["created_at"], "2026-01-01T00:00:00Z");
    }

    #[test]
    fn test_list_members_response_no_token_omits_field() {
        let resp = ListMembersResponse { members: vec![], next_page_token: None };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("next_page_token").is_none());
    }

    #[test]
    fn test_list_invitations_response_no_token_omits_field() {
        let resp = ListInvitationsResponse { invitations: vec![], next_page_token: None };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("next_page_token").is_none());
    }

    #[test]
    fn test_list_received_invitations_response_no_token_omits_field() {
        let resp = ListReceivedInvitationsResponse { invitations: vec![], next_page_token: None };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("next_page_token").is_none());
    }
}
