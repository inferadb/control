use inferadb_control_storage::{StorageBackend, to_storage_range};
use inferadb_control_types::{
    OrganizationSlug, VaultSlug,
    entities::{Vault, VaultTeamGrant, VaultUserGrant},
    error::{Error, Result},
};

/// Repository for Vault entity operations
///
/// Key schema:
/// - vault:{id} -> Vault data
/// - vault:org:{organization}:{idx} -> vault (for org listing)
/// - vault:name:{organization}:{name_lowercase} -> vault (for duplicate name checking)
/// - vault:org_active_count:{organization} -> u64 (active vault count per org)
pub struct VaultRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> VaultRepository<S> {
    /// Create a new vault repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for vault by ID
    fn vault_key(id: VaultSlug) -> Vec<u8> {
        format!("vault:{id}").into_bytes()
    }

    /// Generate key for vault by organization index
    fn vault_org_index_key(organization: OrganizationSlug, idx: VaultSlug) -> Vec<u8> {
        format!("vault:org:{organization}:{idx}").into_bytes()
    }

    /// Generate key for vault by name (for duplicate checking)
    fn vault_name_index_key(organization: OrganizationSlug, name: &str) -> Vec<u8> {
        format!("vault:name:{}:{}", organization, name.to_lowercase()).into_bytes()
    }

    /// Key for per-organization active vault count
    fn org_active_count_key(organization: OrganizationSlug) -> Vec<u8> {
        format!("vault:org_active_count:{organization}").into_bytes()
    }

    /// Read the raw active count from storage, returning None if uninitialized or corrupt
    async fn get_raw_active_count(&self, organization: OrganizationSlug) -> Result<Option<u64>> {
        let key = Self::org_active_count_key(organization);
        let data = self.storage.get(&key).await?;
        match data {
            Some(bytes) if bytes.len() == 8 => Ok(Some(super::parse_u64_id(&bytes)?)),
            _ => Ok(None),
        }
    }

    /// Recount active vaults by scanning all entities and update the counter
    async fn recount_active(&self, organization: OrganizationSlug) -> Result<usize> {
        let active = self.list_active_by_organization(organization).await?;
        let count = active.len();
        self.storage
            .set(Self::org_active_count_key(organization), (count as u64).to_le_bytes().to_vec())
            .await?;
        Ok(count)
    }

    /// Create a new vault
    pub async fn create(&self, vault: Vault) -> Result<()> {
        // Serialize vault
        let vault_data = serde_json::to_vec(&vault)
            .map_err(|e| Error::internal(format!("Failed to serialize vault: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self.storage.transaction().await?;

        // Check for duplicate name within organization
        let name_key = Self::vault_name_index_key(vault.organization, &vault.name);
        if self.storage.get(&name_key).await?.is_some() {
            return Err(Error::already_exists(format!(
                "A vault named '{}' already exists in this organization",
                vault.name
            )));
        }

        // Store vault record
        txn.set(Self::vault_key(vault.id), vault_data.clone());

        // Store organization index
        txn.set(
            Self::vault_org_index_key(vault.organization, vault.id),
            vault.id.value().to_le_bytes().to_vec(),
        );

        // Store name index
        txn.set(name_key, vault.id.value().to_le_bytes().to_vec());

        // Increment active count for the organization
        let active_count_key = Self::org_active_count_key(vault.organization);
        let current_active = self.get_raw_active_count(vault.organization).await?.unwrap_or(0);
        txn.set(active_count_key, (current_active + 1).to_le_bytes().to_vec());

        // Commit transaction
        txn.commit().await?;

        Ok(())
    }

    /// Get a vault by ID
    pub async fn get(&self, id: VaultSlug) -> Result<Option<Vault>> {
        let key = Self::vault_key(id);
        let data = self.storage.get(&key).await?;

        match data {
            Some(bytes) => {
                let vault: Vault = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::internal(format!("Failed to deserialize vault: {e}")))?;
                Ok(Some(vault))
            },
            None => Ok(None),
        }
    }

    /// List all vaults for an organization (including soft-deleted)
    pub async fn list_by_organization(&self, organization: OrganizationSlug) -> Result<Vec<Vault>> {
        let prefix = format!("vault:org:{organization}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault:org:{organization}~").into_bytes();

        let kvs = self.storage.get_range(to_storage_range(start..end)).await?;

        let mut vaults = Vec::new();
        for kv in kvs {
            let Ok(raw_id) = super::parse_u64_id(&kv.value) else { continue };
            if let Some(vault) = self.get(VaultSlug::from(raw_id)).await? {
                vaults.push(vault);
            }
        }

        Ok(vaults)
    }

    /// List active (non-deleted) vaults for an organization
    pub async fn list_active_by_organization(
        &self,
        organization: OrganizationSlug,
    ) -> Result<Vec<Vault>> {
        let all_vaults = self.list_by_organization(organization).await?;
        Ok(all_vaults.into_iter().filter(|v| !v.is_deleted()).collect())
    }

    /// Update a vault
    pub async fn update(&self, vault: Vault) -> Result<()> {
        // Get the existing vault to clean up old indexes if name changed
        let existing = self
            .get(vault.id)
            .await?
            .ok_or_else(|| Error::not_found(format!("Vault {} not found", vault.id)))?;

        // Detect soft-delete and undelete transitions
        let soft_delete_transition = !existing.is_deleted() && vault.is_deleted();
        let undelete_transition = existing.is_deleted() && !vault.is_deleted();

        // Serialize updated vault
        let vault_data = serde_json::to_vec(&vault)
            .map_err(|e| Error::internal(format!("Failed to serialize vault: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self.storage.transaction().await?;

        // If name changed, update name index
        if existing.name != vault.name {
            // Delete old name index
            txn.delete(Self::vault_name_index_key(existing.organization, &existing.name));

            // Check for duplicate new name
            let new_name_key = Self::vault_name_index_key(vault.organization, &vault.name);
            if self.storage.get(&new_name_key).await?.is_some() {
                return Err(Error::already_exists(format!(
                    "A vault named '{}' already exists in this organization",
                    vault.name
                )));
            }

            // Store new name index
            txn.set(new_name_key, vault.id.value().to_le_bytes().to_vec());
        }

        // Adjust active count on soft-delete or undelete transitions
        if soft_delete_transition {
            let active_count_key = Self::org_active_count_key(vault.organization);
            let current_active = self.get_raw_active_count(vault.organization).await?.unwrap_or(0);
            if current_active > 0 {
                txn.set(active_count_key, (current_active - 1).to_le_bytes().to_vec());
            }
        } else if undelete_transition {
            let active_count_key = Self::org_active_count_key(vault.organization);
            let current_active = self.get_raw_active_count(vault.organization).await?.unwrap_or(0);
            txn.set(active_count_key, (current_active + 1).to_le_bytes().to_vec());
        }

        // Update vault record
        txn.set(Self::vault_key(vault.id), vault_data);

        // Commit transaction
        txn.commit().await?;

        Ok(())
    }

    /// Delete a vault (removes all indexes)
    pub async fn delete(&self, id: VaultSlug) -> Result<()> {
        // Get the vault first to clean up indexes
        let vault =
            self.get(id).await?.ok_or_else(|| Error::not_found(format!("Vault {id} not found")))?;

        // Use transaction for atomicity
        let mut txn = self.storage.transaction().await?;

        // Delete vault record
        txn.delete(Self::vault_key(id));

        // Delete organization index
        txn.delete(Self::vault_org_index_key(vault.organization, vault.id));

        // Delete name index
        txn.delete(Self::vault_name_index_key(vault.organization, &vault.name));

        // Decrement active count if the vault was not soft-deleted
        if !vault.is_deleted() {
            let active_count_key = Self::org_active_count_key(vault.organization);
            let current_active = self.get_raw_active_count(vault.organization).await?.unwrap_or(0);
            if current_active > 0 {
                txn.set(active_count_key, (current_active - 1).to_le_bytes().to_vec());
            }
        }

        // Commit transaction
        txn.commit().await?;

        Ok(())
    }

    /// Count vaults in an organization by counting index keys
    pub async fn count_by_organization(&self, organization: OrganizationSlug) -> Result<usize> {
        let start = format!("vault:org:{organization}:").into_bytes();
        let end = format!("vault:org:{organization}~").into_bytes();
        let kvs = self.storage.get_range(to_storage_range(start..end)).await?;
        Ok(kvs.len())
    }

    /// Count active (non-deleted) vaults in an organization using maintained counter
    ///
    /// Reads from a counter key maintained during create, update (soft-delete/undelete),
    /// and delete operations. Under concurrent writes, the counter is eventually consistent:
    /// reads outside the transaction may observe stale values, but self-healing on the next
    /// read corrects any drift.
    pub async fn count_active_by_organization(
        &self,
        organization: OrganizationSlug,
    ) -> Result<usize> {
        match self.get_raw_active_count(organization).await? {
            Some(count) => Ok(count as usize),
            _ => self.recount_active(organization).await,
        }
    }
}

/// Repository for VaultUserGrant entity operations
///
/// Key schema:
/// - vault_user_grant:{id} -> VaultUserGrant data
/// - vault_user_grant:vault:{vault}:{user_id} -> grant_id (for unique constraint)
/// - vault_user_grant:user:{user_id}:{vault} -> grant_id (for user's vaults lookup)
pub struct VaultUserGrantRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> VaultUserGrantRepository<S> {
    /// Create a new vault user grant repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for grant by ID
    fn grant_key(id: u64) -> Vec<u8> {
        format!("vault_user_grant:{id}").into_bytes()
    }

    /// Generate key for vault-user unique constraint
    fn vault_user_index_key(vault: VaultSlug, user_id: u64) -> Vec<u8> {
        format!("vault_user_grant:vault:{vault}:{user_id}").into_bytes()
    }

    /// Generate key for user's vault grants
    fn user_vault_index_key(user_id: u64, vault: VaultSlug) -> Vec<u8> {
        format!("vault_user_grant:user:{user_id}:{vault}").into_bytes()
    }

    /// Create a new user grant
    pub async fn create(&self, grant: VaultUserGrant) -> Result<()> {
        // Serialize grant
        let grant_data = serde_json::to_vec(&grant)
            .map_err(|e| Error::internal(format!("Failed to serialize grant: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self.storage.transaction().await?;

        // Check for duplicate grant (vault, user_id unique)
        let unique_key = Self::vault_user_index_key(grant.vault, grant.user_id);
        if self.storage.get(&unique_key).await?.is_some() {
            return Err(Error::already_exists("User already has access to this vault".to_string()));
        }

        // Store grant record
        txn.set(Self::grant_key(grant.id), grant_data.clone());

        // Store vault-user index
        txn.set(unique_key, grant.id.to_le_bytes().to_vec());

        // Store user-vault index
        txn.set(
            Self::user_vault_index_key(grant.user_id, grant.vault),
            grant.id.to_le_bytes().to_vec(),
        );

        // Commit transaction
        txn.commit().await?;

        Ok(())
    }

    /// Get a grant by ID
    pub async fn get(&self, id: u64) -> Result<Option<VaultUserGrant>> {
        let key = Self::grant_key(id);
        let data = self.storage.get(&key).await?;

        match data {
            Some(bytes) => {
                let grant: VaultUserGrant = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::internal(format!("Failed to deserialize grant: {e}")))?;
                Ok(Some(grant))
            },
            None => Ok(None),
        }
    }

    /// Get a grant by vault and user
    pub async fn get_by_vault_and_user(
        &self,
        vault: VaultSlug,
        user_id: u64,
    ) -> Result<Option<VaultUserGrant>> {
        let index_key = Self::vault_user_index_key(vault, user_id);
        let data = self.storage.get(&index_key).await?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::internal("Invalid grant index data".to_string()));
                }
                let id = super::parse_u64_id(&bytes)?;
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// List all grants for a vault
    pub async fn list_by_vault(&self, vault: VaultSlug) -> Result<Vec<VaultUserGrant>> {
        let prefix = format!("vault_user_grant:vault:{vault}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_user_grant:vault:{vault}~").into_bytes();

        let kvs = self.storage.get_range(to_storage_range(start..end)).await?;

        let mut grants = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_u64_id(&kv.value) else { continue };
            if let Some(grant) = self.get(id).await? {
                grants.push(grant);
            }
        }

        Ok(grants)
    }

    /// List all grants for a user
    pub async fn list_by_user(&self, user_id: u64) -> Result<Vec<VaultUserGrant>> {
        let prefix = format!("vault_user_grant:user:{user_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_user_grant:user:{user_id}~").into_bytes();

        let kvs = self.storage.get_range(to_storage_range(start..end)).await?;

        let mut grants = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_u64_id(&kv.value) else { continue };
            if let Some(grant) = self.get(id).await? {
                grants.push(grant);
            }
        }

        Ok(grants)
    }

    /// Update a grant (typically for role changes)
    pub async fn update(&self, grant: VaultUserGrant) -> Result<()> {
        // Verify grant exists
        self.get(grant.id)
            .await?
            .ok_or_else(|| Error::not_found(format!("Grant {} not found", grant.id)))?;

        // Serialize updated grant
        let grant_data = serde_json::to_vec(&grant)
            .map_err(|e| Error::internal(format!("Failed to serialize grant: {e}")))?;

        // Update grant record
        self.storage.set(Self::grant_key(grant.id), grant_data).await?;

        Ok(())
    }

    /// Delete a grant
    pub async fn delete(&self, id: u64) -> Result<()> {
        // Get the grant first to clean up indexes
        let grant =
            self.get(id).await?.ok_or_else(|| Error::not_found(format!("Grant {id} not found")))?;

        // Use transaction for atomicity
        let mut txn = self.storage.transaction().await?;

        // Delete grant record
        txn.delete(Self::grant_key(id));

        // Delete vault-user index
        txn.delete(Self::vault_user_index_key(grant.vault, grant.user_id));

        // Delete user-vault index
        txn.delete(Self::user_vault_index_key(grant.user_id, grant.vault));

        // Commit transaction
        txn.commit().await?;

        Ok(())
    }
}

/// Repository for VaultTeamGrant entity operations
///
/// Key schema:
/// - vault_team_grant:{id} -> VaultTeamGrant data
/// - vault_team_grant:vault:{vault}:{team_id} -> grant_id (for unique constraint)
/// - vault_team_grant:team:{team_id}:{vault} -> grant_id (for team's vaults lookup)
pub struct VaultTeamGrantRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> VaultTeamGrantRepository<S> {
    /// Create a new vault team grant repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for grant by ID
    fn grant_key(id: u64) -> Vec<u8> {
        format!("vault_team_grant:{id}").into_bytes()
    }

    /// Generate key for vault-team unique constraint
    fn vault_team_index_key(vault: VaultSlug, team_id: u64) -> Vec<u8> {
        format!("vault_team_grant:vault:{vault}:{team_id}").into_bytes()
    }

    /// Generate key for team's vault grants
    fn team_vault_index_key(team_id: u64, vault: VaultSlug) -> Vec<u8> {
        format!("vault_team_grant:team:{team_id}:{vault}").into_bytes()
    }

    /// Create a new team grant
    pub async fn create(&self, grant: VaultTeamGrant) -> Result<()> {
        // Serialize grant
        let grant_data = serde_json::to_vec(&grant)
            .map_err(|e| Error::internal(format!("Failed to serialize grant: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self.storage.transaction().await?;

        // Check for duplicate grant (vault, team_id unique)
        let unique_key = Self::vault_team_index_key(grant.vault, grant.team_id);
        if self.storage.get(&unique_key).await?.is_some() {
            return Err(Error::already_exists("Team already has access to this vault".to_string()));
        }

        // Store grant record
        txn.set(Self::grant_key(grant.id), grant_data.clone());

        // Store vault-team index
        txn.set(unique_key, grant.id.to_le_bytes().to_vec());

        // Store team-vault index
        txn.set(
            Self::team_vault_index_key(grant.team_id, grant.vault),
            grant.id.to_le_bytes().to_vec(),
        );

        // Commit transaction
        txn.commit().await?;

        Ok(())
    }

    /// Get a grant by ID
    pub async fn get(&self, id: u64) -> Result<Option<VaultTeamGrant>> {
        let key = Self::grant_key(id);
        let data = self.storage.get(&key).await?;

        match data {
            Some(bytes) => {
                let grant: VaultTeamGrant = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::internal(format!("Failed to deserialize grant: {e}")))?;
                Ok(Some(grant))
            },
            None => Ok(None),
        }
    }

    /// Get a grant by vault and team
    pub async fn get_by_vault_and_team(
        &self,
        vault: VaultSlug,
        team_id: u64,
    ) -> Result<Option<VaultTeamGrant>> {
        let index_key = Self::vault_team_index_key(vault, team_id);
        let data = self.storage.get(&index_key).await?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::internal("Invalid grant index data".to_string()));
                }
                let id = super::parse_u64_id(&bytes)?;
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// List all grants for a vault
    pub async fn list_by_vault(&self, vault: VaultSlug) -> Result<Vec<VaultTeamGrant>> {
        let prefix = format!("vault_team_grant:vault:{vault}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_team_grant:vault:{vault}~").into_bytes();

        let kvs = self.storage.get_range(to_storage_range(start..end)).await?;

        let mut grants = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_u64_id(&kv.value) else { continue };
            if let Some(grant) = self.get(id).await? {
                grants.push(grant);
            }
        }

        Ok(grants)
    }

    /// List all grants for a team
    pub async fn list_by_team(&self, team_id: u64) -> Result<Vec<VaultTeamGrant>> {
        let prefix = format!("vault_team_grant:team:{team_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_team_grant:team:{team_id}~").into_bytes();

        let kvs = self.storage.get_range(to_storage_range(start..end)).await?;

        let mut grants = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_u64_id(&kv.value) else { continue };
            if let Some(grant) = self.get(id).await? {
                grants.push(grant);
            }
        }

        Ok(grants)
    }

    /// Update a grant (typically for role changes)
    pub async fn update(&self, grant: VaultTeamGrant) -> Result<()> {
        // Verify grant exists
        self.get(grant.id)
            .await?
            .ok_or_else(|| Error::not_found(format!("Grant {} not found", grant.id)))?;

        // Serialize updated grant
        let grant_data = serde_json::to_vec(&grant)
            .map_err(|e| Error::internal(format!("Failed to serialize grant: {e}")))?;

        // Update grant record
        self.storage.set(Self::grant_key(grant.id), grant_data).await?;

        Ok(())
    }

    /// Delete a grant
    pub async fn delete(&self, id: u64) -> Result<()> {
        // Get the grant first to clean up indexes
        let grant =
            self.get(id).await?.ok_or_else(|| Error::not_found(format!("Grant {id} not found")))?;

        // Use transaction for atomicity
        let mut txn = self.storage.transaction().await?;

        // Delete grant record
        txn.delete(Self::grant_key(id));

        // Delete vault-team index
        txn.delete(Self::vault_team_index_key(grant.vault, grant.team_id));

        // Delete team-vault index
        txn.delete(Self::team_vault_index_key(grant.team_id, grant.vault));

        // Commit transaction
        txn.commit().await?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_control_storage::MemoryBackend;
    use inferadb_control_types::entities::{VaultRole, VaultSyncStatus};

    use super::*;

    fn create_test_vault_repo() -> VaultRepository<MemoryBackend> {
        VaultRepository::new(MemoryBackend::new())
    }

    fn create_test_user_grant_repo() -> VaultUserGrantRepository<MemoryBackend> {
        VaultUserGrantRepository::new(MemoryBackend::new())
    }

    fn create_test_team_grant_repo() -> VaultTeamGrantRepository<MemoryBackend> {
        VaultTeamGrantRepository::new(MemoryBackend::new())
    }

    fn create_test_vault(id: u64, organization: u64, name: &str) -> Result<Vault> {
        Vault::builder()
            .id(VaultSlug::from(id))
            .organization(OrganizationSlug::from(organization))
            .name(name.to_string())
            .created_by_user_id(999_u64)
            .create()
    }

    fn v(id: u64) -> VaultSlug {
        VaultSlug::from(id)
    }

    fn o(id: u64) -> OrganizationSlug {
        OrganizationSlug::from(id)
    }

    #[tokio::test]
    async fn test_create_and_get_vault() {
        let repo = create_test_vault_repo();
        let vault = create_test_vault(1, 100, "Test Vault").unwrap();

        repo.create(vault.clone()).await.unwrap();

        let retrieved = repo.get(v(1)).await.unwrap();
        assert_eq!(retrieved, Some(vault));
    }

    #[tokio::test]
    async fn test_duplicate_vault_name_rejected() {
        let repo = create_test_vault_repo();
        let vault1 = create_test_vault(1, 100, "Test Vault").unwrap();
        let vault2 = create_test_vault(2, 100, "Test Vault").unwrap();

        repo.create(vault1).await.unwrap();

        let result = repo.create(vault2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists { .. }));
    }

    #[tokio::test]
    async fn test_list_by_organization() {
        let repo = create_test_vault_repo();
        let vault1 = create_test_vault(1, 100, "Vault 1").unwrap();
        let vault2 = create_test_vault(2, 100, "Vault 2").unwrap();
        let vault3 = create_test_vault(3, 200, "Vault 3").unwrap();

        repo.create(vault1).await.unwrap();
        repo.create(vault2).await.unwrap();
        repo.create(vault3).await.unwrap();

        let org_100_vaults = repo.list_by_organization(o(100)).await.unwrap();
        assert_eq!(org_100_vaults.len(), 2);

        let org_200_vaults = repo.list_by_organization(o(200)).await.unwrap();
        assert_eq!(org_200_vaults.len(), 1);
    }

    #[tokio::test]
    async fn test_update_vault() {
        let repo = create_test_vault_repo();
        let mut vault = create_test_vault(1, 100, "Original Name").unwrap();

        repo.create(vault.clone()).await.unwrap();

        vault.name = "Updated Name".to_string();
        vault.mark_synced();
        repo.update(vault.clone()).await.unwrap();

        let retrieved = repo.get(v(1)).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "Updated Name");
        assert_eq!(retrieved.sync_status, VaultSyncStatus::Synced);
    }

    #[tokio::test]
    async fn test_soft_delete_vault() {
        let repo = create_test_vault_repo();
        let mut vault = create_test_vault(1, 100, "Test Vault").unwrap();

        repo.create(vault.clone()).await.unwrap();

        vault.mark_deleted();
        repo.update(vault).await.unwrap();

        let retrieved = repo.get(v(1)).await.unwrap().unwrap();
        assert!(retrieved.is_deleted());

        // Should not be in active list
        let active = repo.list_active_by_organization(o(100)).await.unwrap();
        assert_eq!(active.len(), 0);

        // Still in full list
        let all = repo.list_by_organization(o(100)).await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_vault() {
        let repo = create_test_vault_repo();
        let vault = create_test_vault(1, 100, "Test Vault").unwrap();

        repo.create(vault).await.unwrap();
        assert!(repo.get(v(1)).await.unwrap().is_some());

        repo.delete(v(1)).await.unwrap();
        assert!(repo.get(v(1)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_active_count_tracks_create() {
        let repo = create_test_vault_repo();
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 0);

        let vault1 = create_test_vault(1, 100, "Vault 1").unwrap();
        repo.create(vault1).await.unwrap();
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 1);

        let vault2 = create_test_vault(2, 100, "Vault 2").unwrap();
        repo.create(vault2).await.unwrap();
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 2);

        // Different org should be independent
        let vault3 = create_test_vault(3, 200, "Vault 3").unwrap();
        repo.create(vault3).await.unwrap();
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 2);
        assert_eq!(repo.count_active_by_organization(o(200)).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_active_count_tracks_soft_delete() {
        let repo = create_test_vault_repo();
        let vault1 = create_test_vault(1, 100, "Vault 1").unwrap();
        let mut vault2 = create_test_vault(2, 100, "Vault 2").unwrap();
        let vault3 = create_test_vault(3, 100, "Vault 3").unwrap();

        repo.create(vault1).await.unwrap();
        repo.create(vault2.clone()).await.unwrap();
        repo.create(vault3).await.unwrap();

        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 3);
        assert_eq!(repo.count_by_organization(o(100)).await.unwrap(), 3);

        // Soft delete one vault
        vault2.mark_deleted();
        repo.update(vault2).await.unwrap();

        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 2);
        // Total count (index key count) still includes soft-deleted
        assert_eq!(repo.count_by_organization(o(100)).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_active_count_tracks_hard_delete() {
        let repo = create_test_vault_repo();
        let vault1 = create_test_vault(1, 100, "Vault 1").unwrap();
        let vault2 = create_test_vault(2, 100, "Vault 2").unwrap();

        repo.create(vault1).await.unwrap();
        repo.create(vault2).await.unwrap();
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 2);

        // Hard delete
        repo.delete(v(1)).await.unwrap();
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 1);
        assert_eq!(repo.count_by_organization(o(100)).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_active_count_hard_delete_of_soft_deleted_does_not_double_decrement() {
        let repo = create_test_vault_repo();
        let mut vault = create_test_vault(1, 100, "Vault 1").unwrap();
        repo.create(vault.clone()).await.unwrap();
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 1);

        // Soft delete first
        vault.mark_deleted();
        repo.update(vault).await.unwrap();
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 0);

        // Then hard delete — should not decrement below 0
        repo.delete(v(1)).await.unwrap();
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_active_count_self_heals_on_missing_counter() {
        let repo = create_test_vault_repo();

        // Create vaults without counter (simulating migration from old data)
        let vault1 = create_test_vault(1, 100, "Vault 1").unwrap();
        let vault2 = create_test_vault(2, 100, "Vault 2").unwrap();
        repo.create(vault1).await.unwrap();
        repo.create(vault2).await.unwrap();

        // Delete the counter key to simulate pre-existing data
        repo.storage
            .delete(&VaultRepository::<MemoryBackend>::org_active_count_key(o(100)))
            .await
            .unwrap();

        // Should self-heal by recounting
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_active_count_tracks_undelete() {
        let repo = create_test_vault_repo();
        let mut vault = create_test_vault(1, 100, "Vault 1").unwrap();
        repo.create(vault.clone()).await.unwrap();
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 1);

        // Soft delete
        vault.mark_deleted();
        repo.update(vault.clone()).await.unwrap();
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 0);

        // Undelete by clearing deleted_at
        vault.deleted_at = None;
        repo.update(vault).await.unwrap();
        assert_eq!(repo.count_active_by_organization(o(100)).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_create_user_grant() {
        let repo = create_test_user_grant_repo();
        let grant = VaultUserGrant::new(1, v(100), 200, VaultRole::Reader, 999);

        repo.create(grant.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert_eq!(retrieved, Some(grant));
    }

    #[tokio::test]
    async fn test_duplicate_user_grant_rejected() {
        let repo = create_test_user_grant_repo();
        let grant1 = VaultUserGrant::new(1, v(100), 200, VaultRole::Reader, 999);
        let grant2 = VaultUserGrant::new(2, v(100), 200, VaultRole::Writer, 999);

        repo.create(grant1).await.unwrap();

        let result = repo.create(grant2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists { .. }));
    }

    #[tokio::test]
    async fn test_get_user_grant_by_vault_and_user() {
        let repo = create_test_user_grant_repo();
        let grant = VaultUserGrant::new(1, v(100), 200, VaultRole::Reader, 999);

        repo.create(grant.clone()).await.unwrap();

        let retrieved = repo.get_by_vault_and_user(v(100), 200).await.unwrap();
        assert_eq!(retrieved, Some(grant));
    }

    #[tokio::test]
    async fn test_list_user_grants_by_vault() {
        let repo = create_test_user_grant_repo();
        let grant1 = VaultUserGrant::new(1, v(100), 200, VaultRole::Reader, 999);
        let grant2 = VaultUserGrant::new(2, v(100), 201, VaultRole::Writer, 999);
        let grant3 = VaultUserGrant::new(3, v(101), 200, VaultRole::Admin, 999);

        repo.create(grant1).await.unwrap();
        repo.create(grant2).await.unwrap();
        repo.create(grant3).await.unwrap();

        let vault_100_grants = repo.list_by_vault(v(100)).await.unwrap();
        assert_eq!(vault_100_grants.len(), 2);

        let vault_101_grants = repo.list_by_vault(v(101)).await.unwrap();
        assert_eq!(vault_101_grants.len(), 1);
    }

    #[tokio::test]
    async fn test_list_user_grants_by_user() {
        let repo = create_test_user_grant_repo();
        let grant1 = VaultUserGrant::new(1, v(100), 200, VaultRole::Reader, 999);
        let grant2 = VaultUserGrant::new(2, v(101), 200, VaultRole::Writer, 999);
        let grant3 = VaultUserGrant::new(3, v(100), 201, VaultRole::Admin, 999);

        repo.create(grant1).await.unwrap();
        repo.create(grant2).await.unwrap();
        repo.create(grant3).await.unwrap();

        let user_200_grants = repo.list_by_user(200).await.unwrap();
        assert_eq!(user_200_grants.len(), 2);

        let user_201_grants = repo.list_by_user(201).await.unwrap();
        assert_eq!(user_201_grants.len(), 1);
    }

    #[tokio::test]
    async fn test_update_user_grant() {
        let repo = create_test_user_grant_repo();
        let mut grant = VaultUserGrant::new(1, v(100), 200, VaultRole::Reader, 999);

        repo.create(grant.clone()).await.unwrap();

        grant.role = VaultRole::Writer;
        repo.update(grant.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert_eq!(retrieved.role, VaultRole::Writer);
    }

    #[tokio::test]
    async fn test_delete_user_grant() {
        let repo = create_test_user_grant_repo();
        let grant = VaultUserGrant::new(1, v(100), 200, VaultRole::Reader, 999);

        repo.create(grant).await.unwrap();
        assert!(repo.get(1).await.unwrap().is_some());

        repo.delete(1).await.unwrap();
        assert!(repo.get(1).await.unwrap().is_none());
        assert!(repo.get_by_vault_and_user(v(100), 200).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_create_team_grant() {
        let repo = create_test_team_grant_repo();
        let grant = VaultTeamGrant::new(1, v(100), 300, VaultRole::Reader, 999);

        repo.create(grant.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert_eq!(retrieved, Some(grant));
    }

    #[tokio::test]
    async fn test_duplicate_team_grant_rejected() {
        let repo = create_test_team_grant_repo();
        let grant1 = VaultTeamGrant::new(1, v(100), 300, VaultRole::Reader, 999);
        let grant2 = VaultTeamGrant::new(2, v(100), 300, VaultRole::Writer, 999);

        repo.create(grant1).await.unwrap();

        let result = repo.create(grant2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists { .. }));
    }

    #[tokio::test]
    async fn test_list_team_grants_by_vault() {
        let repo = create_test_team_grant_repo();
        let grant1 = VaultTeamGrant::new(1, v(100), 300, VaultRole::Reader, 999);
        let grant2 = VaultTeamGrant::new(2, v(100), 301, VaultRole::Writer, 999);
        let grant3 = VaultTeamGrant::new(3, v(101), 300, VaultRole::Admin, 999);

        repo.create(grant1).await.unwrap();
        repo.create(grant2).await.unwrap();
        repo.create(grant3).await.unwrap();

        let vault_100_grants = repo.list_by_vault(v(100)).await.unwrap();
        assert_eq!(vault_100_grants.len(), 2);

        let vault_101_grants = repo.list_by_vault(v(101)).await.unwrap();
        assert_eq!(vault_101_grants.len(), 1);
    }

    #[tokio::test]
    async fn test_list_team_grants_by_team() {
        let repo = create_test_team_grant_repo();
        let grant1 = VaultTeamGrant::new(1, v(100), 300, VaultRole::Reader, 999);
        let grant2 = VaultTeamGrant::new(2, v(101), 300, VaultRole::Writer, 999);
        let grant3 = VaultTeamGrant::new(3, v(100), 301, VaultRole::Admin, 999);

        repo.create(grant1).await.unwrap();
        repo.create(grant2).await.unwrap();
        repo.create(grant3).await.unwrap();

        let team_300_grants = repo.list_by_team(300).await.unwrap();
        assert_eq!(team_300_grants.len(), 2);

        let team_301_grants = repo.list_by_team(301).await.unwrap();
        assert_eq!(team_301_grants.len(), 1);
    }
}
