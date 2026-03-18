//! Organization membership service wrapping Ledger SDK membership operations.

use inferadb_control_types::error::Result;
use inferadb_ledger_sdk::{LedgerClient, OrganizationMemberInfo, OrganizationMemberRole};
use inferadb_ledger_types::{OrganizationSlug, UserSlug};

use super::error::SdkResultExt;

/// Lists members of an organization with cursor-based pagination.
pub async fn list_members(
    ledger: &LedgerClient,
    org: OrganizationSlug,
    caller: UserSlug,
    page_size: u32,
    page_token: Option<Vec<u8>>,
) -> Result<(Vec<OrganizationMemberInfo>, Option<Vec<u8>>)> {
    ledger.list_organization_members(org, caller, page_size, page_token).await.map_sdk_err()
}

/// Updates a member's role within an organization.
pub async fn update_member_role(
    ledger: &LedgerClient,
    org: OrganizationSlug,
    user: UserSlug,
    target: UserSlug,
    role: OrganizationMemberRole,
) -> Result<OrganizationMemberInfo> {
    ledger.update_organization_member_role(org, user, target, role).await.map_sdk_err()
}

/// Removes a member from an organization.
pub async fn remove_member(
    ledger: &LedgerClient,
    org: OrganizationSlug,
    user: UserSlug,
    target: UserSlug,
) -> Result<()> {
    ledger.remove_organization_member(org, user, target).await.map_sdk_err()
}
