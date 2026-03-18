//! Organization management service wrapping Ledger SDK organization operations.

use inferadb_control_types::error::Result;
use inferadb_ledger_sdk::{
    LedgerClient, OrganizationDeleteInfo, OrganizationInfo, OrganizationTier, Region,
};
use inferadb_ledger_types::{OrganizationSlug, UserSlug};

use super::error::SdkResultExt;

/// Creates a new organization with the given name, region, initial admin, and tier.
pub async fn create_organization(
    ledger: &LedgerClient,
    name: &str,
    region: Region,
    admin: UserSlug,
    tier: OrganizationTier,
) -> Result<OrganizationInfo> {
    ledger.create_organization(name, region, admin, tier).await.map_sdk_err()
}

/// Gets organization details by slug. The caller must be a member.
pub async fn get_organization(
    ledger: &LedgerClient,
    slug: OrganizationSlug,
    user: UserSlug,
) -> Result<OrganizationInfo> {
    ledger.get_organization(slug, user).await.map_sdk_err()
}

/// Lists organizations visible to the caller with cursor-based pagination.
pub async fn list_organizations(
    ledger: &LedgerClient,
    caller: UserSlug,
    page_size: u32,
    page_token: Option<Vec<u8>>,
) -> Result<(Vec<OrganizationInfo>, Option<Vec<u8>>)> {
    ledger.list_organizations(caller, page_size, page_token).await.map_sdk_err()
}

/// Updates an organization's mutable fields. Currently supports renaming.
pub async fn update_organization(
    ledger: &LedgerClient,
    slug: OrganizationSlug,
    user: UserSlug,
    name: Option<String>,
) -> Result<OrganizationInfo> {
    ledger.update_organization(slug, user, name).await.map_sdk_err()
}

/// Soft-deletes an organization. Fails if it still contains active vaults.
pub async fn delete_organization(
    ledger: &LedgerClient,
    slug: OrganizationSlug,
    user: UserSlug,
) -> Result<OrganizationDeleteInfo> {
    ledger.delete_organization(slug, user).await.map_sdk_err()
}
