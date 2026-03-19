//! Vault management service wrapping Ledger SDK vault operations.

use inferadb_control_types::error::Result;
use inferadb_ledger_sdk::{LedgerClient, Operation, VaultInfo, token::TokenPair};
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

/// Reads an entity value by key from a vault's entity store.
pub async fn read_entity(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    vault: VaultSlug,
    key: &str,
) -> Result<Option<Vec<u8>>> {
    ledger.read(organization, Some(vault), key, None, None).await.map_sdk_err()
}

/// Writes an entity value by key to a vault's entity store.
pub async fn write_entity(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    vault: VaultSlug,
    key: &str,
    value: Vec<u8>,
) -> Result<()> {
    let ops = vec![Operation::set_entity(key, value, None, None)];
    ledger.write(organization, Some(vault), ops, None).await.map_sdk_err()?;
    Ok(())
}

/// Deletes an entity by key from a vault's entity store.
pub async fn delete_entity_key(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    vault: VaultSlug,
    key: &str,
) -> Result<()> {
    let ops = vec![Operation::delete_entity(key)];
    ledger.write(organization, Some(vault), ops, None).await.map_sdk_err()?;
    Ok(())
}
