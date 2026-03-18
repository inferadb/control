//! Organization invitation service wrapping Ledger SDK invitation operations.

use inferadb_control_types::error::Result;
use inferadb_ledger_sdk::{
    InvitationCreated, InvitationInfo, InvitationPage, InvitationStatus, LedgerClient,
    OrganizationMemberRole, ReceivedInvitationInfo, ReceivedInvitationPage,
};
use inferadb_ledger_types::{InviteSlug, OrganizationSlug, TeamSlug, UserSlug};

use super::error::SdkResultExt;

/// Creates an organization invitation for the given email address.
pub async fn create_invite(
    ledger: &LedgerClient,
    org: OrganizationSlug,
    caller: UserSlug,
    email: &str,
    role: OrganizationMemberRole,
    ttl_hours: u32,
    team: Option<TeamSlug>,
) -> Result<InvitationCreated> {
    ledger.create_organization_invite(org, caller, email, role, ttl_hours, team).await.map_sdk_err()
}

/// Lists invitations for an organization (admin view) with optional status filter.
pub async fn list_invites(
    ledger: &LedgerClient,
    org: OrganizationSlug,
    caller: UserSlug,
    status_filter: Option<InvitationStatus>,
    page_token: Option<Vec<u8>>,
    page_size: u32,
) -> Result<InvitationPage> {
    ledger
        .list_organization_invites(org, caller, status_filter, page_token, page_size)
        .await
        .map_sdk_err()
}

/// Gets a single invitation by slug (admin view).
pub async fn get_invite(
    ledger: &LedgerClient,
    slug: InviteSlug,
    caller: UserSlug,
) -> Result<InvitationInfo> {
    ledger.get_organization_invite(slug, caller).await.map_sdk_err()
}

/// Revokes a pending invitation (admin operation).
pub async fn revoke_invite(
    ledger: &LedgerClient,
    slug: InviteSlug,
    caller: UserSlug,
) -> Result<InvitationInfo> {
    ledger.revoke_organization_invite(slug, caller).await.map_sdk_err()
}

/// Lists invitations received by the authenticated user.
pub async fn list_received(
    ledger: &LedgerClient,
    user: UserSlug,
    status_filter: Option<InvitationStatus>,
    page_token: Option<Vec<u8>>,
    page_size: u32,
) -> Result<ReceivedInvitationPage> {
    ledger.list_received_invitations(user, status_filter, page_token, page_size).await.map_sdk_err()
}

/// Gets details of a specific invitation for the authenticated user.
pub async fn get_invitation_details(
    ledger: &LedgerClient,
    slug: InviteSlug,
    user: UserSlug,
) -> Result<ReceivedInvitationInfo> {
    ledger.get_invitation_details(slug, user).await.map_sdk_err()
}

/// Accepts a pending invitation, adding the user to the organization.
pub async fn accept_invitation(
    ledger: &LedgerClient,
    slug: InviteSlug,
    acceptor: UserSlug,
) -> Result<InvitationInfo> {
    ledger.accept_invitation(slug, acceptor).await.map_sdk_err()
}

/// Declines a pending invitation.
pub async fn decline_invitation(
    ledger: &LedgerClient,
    slug: InviteSlug,
    user: UserSlug,
) -> Result<ReceivedInvitationInfo> {
    ledger.decline_invitation(slug, user).await.map_sdk_err()
}
