//! Organization, membership, and invitation management handlers.
//!
//! All operations delegate to Ledger SDK via the service layer.
//! Organization state (members, invitations, tiers) is owned by Ledger.

use std::time::Instant;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use inferadb_control_core::SdkResultExt;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{
    InvitationStatus, InviteSlug, OrganizationMemberRole, OrganizationSlug, OrganizationTier,
    Region, UserSlug,
};
use serde::{Deserialize, Serialize};

use super::common::{
    CursorPaginationQuery, MessageResponse, encode_page_token, require_ledger,
    system_time_to_rfc3339,
};
use crate::{
    handlers::auth::{AppState, Result},
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

/// Request body for updating a member's role.
#[derive(Debug, Deserialize)]
pub struct UpdateMemberRoleRequest {
    pub role: String,
}

/// Request body for creating an invitation.
#[derive(Debug, Deserialize)]
pub struct CreateInvitationRequest {
    pub email: String,
    pub role: Option<String>,
}

// ── Response Types ────────────────────────────────────────────────────

/// Organization summary response.
#[derive(Debug, Serialize)]
pub struct OrganizationResponse {
    pub slug: u64,
    pub name: String,
    pub region: String,
    pub status: String,
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

/// Delete organization response.
#[derive(Debug, Serialize)]
pub struct DeleteOrganizationResponse {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
}

/// Organization member response.
#[derive(Debug, Serialize)]
pub struct MemberResponse {
    pub user: u64,
    pub role: String,
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

/// Updated member response wrapper.
#[derive(Debug, Serialize)]
pub struct UpdateMemberRoleResponse {
    pub member: MemberResponse,
}

/// Invitation response (admin view).
#[derive(Debug, Serialize)]
pub struct InvitationResponse {
    pub slug: u64,
    pub organization: u64,
    pub inviter: u64,
    pub invitee_email: String,
    pub role: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
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
    pub slug: u64,
    pub organization: u64,
    pub organization_name: String,
    pub role: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
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

fn parse_member_role(s: &str) -> std::result::Result<OrganizationMemberRole, CoreError> {
    match s.to_lowercase().as_str() {
        "admin" => Ok(OrganizationMemberRole::Admin),
        "member" => Ok(OrganizationMemberRole::Member),
        _ => Err(CoreError::validation(format!("Invalid role '{s}'. Must be 'admin' or 'member'"))),
    }
}

fn org_info_to_response(info: &inferadb_ledger_sdk::OrganizationInfo) -> OrganizationResponse {
    OrganizationResponse {
        slug: info.slug.value(),
        name: info.name.clone(),
        region: info.region.to_string(),
        status: info.status.to_string(),
        tier: info.tier.to_string(),
    }
}

fn member_info_to_response(info: &inferadb_ledger_sdk::OrganizationMemberInfo) -> MemberResponse {
    MemberResponse {
        user: info.user.value(),
        role: info.role.to_string(),
        joined_at: system_time_to_rfc3339(&info.joined_at),
    }
}

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

/// POST /v1/organizations
///
/// Creates a new organization with the authenticated user as admin.
/// Uses default region (US_EAST_VA) and tier (Free).
pub async fn create_organization(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Json(payload): Json<CreateOrganizationRequest>,
) -> Result<Json<SingleOrganizationResponse>> {
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

    Ok(Json(SingleOrganizationResponse { organization: org_info_to_response(&info) }))
}

/// GET /v1/organizations
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

/// GET /v1/organizations/:org
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

/// PATCH /v1/organizations/:org
///
/// Updates organization details. Ledger enforces role requirements.
pub async fn update_organization(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Json(payload): Json<UpdateOrganizationRequest>,
) -> Result<Json<SingleOrganizationResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let info = ledger
        .update_organization(OrganizationSlug::new(org), claims.user_slug, payload.name)
        .await
        .map_sdk_err_instrumented("update_organization", start)?;

    Ok(Json(SingleOrganizationResponse { organization: org_info_to_response(&info) }))
}

/// DELETE /v1/organizations/:org
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

/// GET /v1/organizations/:org/members
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

/// PATCH /v1/organizations/:org/members/:member
///
/// Updates a member's role. Ledger enforces permission checks (admin/owner required).
pub async fn update_member_role(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, member)): Path<(u64, u64)>,
    Json(payload): Json<UpdateMemberRoleRequest>,
) -> Result<Json<UpdateMemberRoleResponse>> {
    let ledger = require_ledger(&state)?;

    let role = parse_member_role(&payload.role)?;

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

/// DELETE /v1/organizations/:org/members/:member
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

    Ok(Json(MessageResponse { message: "Member removed successfully".to_string() }))
}

/// DELETE /v1/organizations/:org/members/self
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

    Ok(Json(MessageResponse { message: "You have left the organization".to_string() }))
}

// ── Invitation Handlers ───────────────────────────────────────────────

/// Default invitation TTL in hours (7 days).
const DEFAULT_INVITE_TTL_HOURS: u32 = 168;

/// POST /v1/organizations/:org/invitations
///
/// Creates an invitation to join the organization. Ledger enforces role
/// and member-limit checks. If the email service is configured, sends an
/// invitation email.
pub async fn create_invitation(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Json(payload): Json<CreateInvitationRequest>,
) -> Result<Json<InvitationResponse>> {
    let ledger = require_ledger(&state)?;

    let role = match payload.role.as_deref() {
        Some(r) => parse_member_role(r)?,
        None => OrganizationMemberRole::Member,
    };

    let start = Instant::now();
    let created = ledger
        .create_organization_invite(
            OrganizationSlug::new(org),
            claims.user_slug,
            &payload.email,
            role,
            DEFAULT_INVITE_TTL_HOURS,
            None,
        )
        .await
        .map_sdk_err_instrumented("create_invite", start)?;

    // Attempt to send invitation email if the email service is configured.
    if let Some(email_svc) = &state.email_service {
        // Fetch org name for the email template.
        let start = Instant::now();
        let org_info = ledger
            .get_organization(OrganizationSlug::new(org), claims.user_slug)
            .await
            .map_sdk_err_instrumented("get_organization", start);

        let org_name = org_info.as_ref().map(|o| o.name.as_str()).unwrap_or("the organization");

        // Fetch inviter name for the email template.
        let start = Instant::now();
        let inviter_info =
            ledger.get_user(claims.user_slug).await.map_sdk_err_instrumented("get_user", start);

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
            expires_in: format!("{} days", DEFAULT_INVITE_TTL_HOURS / 24),
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

    Ok(Json(InvitationResponse {
        slug: created.slug.value(),
        organization: org,
        inviter: claims.user_slug.value(),
        invitee_email: payload.email,
        role: role.to_string(),
        status: created.status.to_string(),
        created_at: system_time_to_rfc3339(&created.created_at),
        expires_at: system_time_to_rfc3339(&created.expires_at),
        token: None,
    }))
}

/// GET /v1/organizations/:org/invitations
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

/// DELETE /v1/organizations/:org/invitations/:invite
///
/// Revokes a pending invitation. Ledger enforces admin/owner permission.
pub async fn delete_invitation(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, invite)): Path<(u64, u64)>,
) -> Result<Json<MessageResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    ledger
        .revoke_organization_invite(InviteSlug::new(invite), claims.user_slug)
        .await
        .map_sdk_err_instrumented("revoke_invite", start)?;

    Ok(Json(MessageResponse { message: "Invitation revoked successfully".to_string() }))
}

/// POST /v1/users/me/invitations/{invitation}/accept
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

/// GET /v1/invitations/received
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

/// POST /v1/invitations/:invite/decline
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
