//! Vault management service wrapping Ledger SDK vault operations.

use inferadb_control_types::error::Result;
use inferadb_ledger_sdk::{LedgerClient, VaultInfo, token::TokenPair};
use inferadb_ledger_types::{AppSlug, OrganizationSlug, VaultSlug};

use super::error::SdkResultExt;

/// Creates a new vault in an organization.
pub async fn create_vault(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
) -> Result<VaultInfo> {
    ledger.create_vault(organization).await.map_sdk_err()
}

/// Gets vault details by organization and vault slug.
pub async fn get_vault(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    vault: VaultSlug,
) -> Result<VaultInfo> {
    ledger.get_vault(organization, vault).await.map_sdk_err()
}

/// Lists vaults with cursor-based pagination.
pub async fn list_vaults(
    ledger: &LedgerClient,
    page_size: u32,
    page_token: Option<Vec<u8>>,
) -> Result<(Vec<VaultInfo>, Option<Vec<u8>>)> {
    ledger.list_vaults(page_size, page_token).await.map_sdk_err()
}

/// Updates vault metadata. Currently supports retention policy changes.
///
/// Note: The Ledger SDK `update_vault` requires
/// `inferadb_ledger_proto::proto::BlockRetentionPolicy` which is not exposed to the Control crate.
/// This wrapper is a placeholder until the SDK exposes a higher-level retention policy type.
pub async fn update_vault(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    vault: VaultSlug,
) -> Result<()> {
    ledger.update_vault(organization, vault, None).await.map_sdk_err()
}

/// Creates a vault access token for an app.
pub async fn create_vault_token(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    app: AppSlug,
    vault: VaultSlug,
    scopes: &[String],
) -> Result<TokenPair> {
    ledger.create_vault_token(organization, app, vault, scopes).await.map_sdk_err()
}

/// Revokes all sessions for an app. Returns the number of sessions revoked.
pub async fn revoke_all_app_sessions(ledger: &LedgerClient, app: AppSlug) -> Result<u64> {
    ledger.revoke_all_app_sessions(app).await.map_sdk_err()
}
