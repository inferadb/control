use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::{Vault, VaultTeamGrant, VaultUserGrant},
    error::{Error, Result},
};

/// Repository for Vault entity operations
///
/// Key schema:
/// - vault:{id} -> Vault data
/// - vault:org:{org_id}:{idx} -> vault_id (for org listing)
/// - vault:name:{org_id}:{name_lowercase} -> vault_id (for duplicate name checking)
pub struct VaultRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> VaultRepository<S> {
    /// Create a new vault repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for vault by ID
    fn vault_key(id: i64) -> Vec<u8> {
        format!("vault:{id}").into_bytes()
    }

    /// Generate key for vault by organization index
    fn vault_org_index_key(org_id: i64, idx: i64) -> Vec<u8> {
        format!("vault:org:{org_id}:{idx}").into_bytes()
    }

    /// Generate key for vault by name (for duplicate checking)
    fn vault_name_index_key(org_id: i64, name: &str) -> Vec<u8> {
        format!("vault:name:{}:{}", org_id, name.to_lowercase()).into_bytes()
    }

    /// Create a new vault
    pub async fn create(&self, vault: Vault) -> Result<()> {
        // Serialize vault
        let vault_data = serde_json::to_vec(&vault)
            .map_err(|e| Error::Internal(format!("Failed to serialize vault: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Check for duplicate name within organization
        let name_key = Self::vault_name_index_key(vault.organization_id, &vault.name);
        if self
            .storage
            .get(&name_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to check duplicate vault name: {e}")))?
            .is_some()
        {
            return Err(Error::AlreadyExists(format!(
                "A vault named '{}' already exists in this organization",
                vault.name
            )));
        }

        // Store vault record
        txn.set(Self::vault_key(vault.id), vault_data.clone());

        // Store organization index
        txn.set(
            Self::vault_org_index_key(vault.organization_id, vault.id),
            vault.id.to_le_bytes().to_vec(),
        );

        // Store name index
        txn.set(name_key, vault.id.to_le_bytes().to_vec());

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit vault creation: {e}")))?;

        Ok(())
    }

    /// Get a vault by ID
    pub async fn get(&self, id: i64) -> Result<Option<Vault>> {
        let key = Self::vault_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get vault: {e}")))?;

        match data {
            Some(bytes) => {
                let vault: Vault = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("Failed to deserialize vault: {e}")))?;
                Ok(Some(vault))
            },
            None => Ok(None),
        }
    }

    /// List all vaults for an organization (including soft-deleted)
    pub async fn list_by_organization(&self, org_id: i64) -> Result<Vec<Vault>> {
        let prefix = format!("vault:org:{org_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault:org:{org_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get organization vaults: {e}")))?;

        let mut vaults = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(vault) = self.get(id).await? {
                vaults.push(vault);
            }
        }

        Ok(vaults)
    }

    /// List active (non-deleted) vaults for an organization
    pub async fn list_active_by_organization(&self, org_id: i64) -> Result<Vec<Vault>> {
        let all_vaults = self.list_by_organization(org_id).await?;
        Ok(all_vaults.into_iter().filter(|v| !v.is_deleted()).collect())
    }

    /// Update a vault
    pub async fn update(&self, vault: Vault) -> Result<()> {
        // Get the existing vault to clean up old indexes if name changed
        let existing = self
            .get(vault.id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Vault {} not found", vault.id)))?;

        // Serialize updated vault
        let vault_data = serde_json::to_vec(&vault)
            .map_err(|e| Error::Internal(format!("Failed to serialize vault: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // If name changed, update name index
        if existing.name != vault.name {
            // Delete old name index
            txn.delete(Self::vault_name_index_key(existing.organization_id, &existing.name));

            // Check for duplicate new name
            let new_name_key = Self::vault_name_index_key(vault.organization_id, &vault.name);
            if self
                .storage
                .get(&new_name_key)
                .await
                .map_err(|e| Error::Internal(format!("Failed to check duplicate vault name: {e}")))?
                .is_some()
            {
                return Err(Error::AlreadyExists(format!(
                    "A vault named '{}' already exists in this organization",
                    vault.name
                )));
            }

            // Store new name index
            txn.set(new_name_key, vault.id.to_le_bytes().to_vec());
        }

        // Update vault record
        txn.set(Self::vault_key(vault.id), vault_data);

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit vault update: {e}")))?;

        Ok(())
    }

    /// Delete a vault (removes all indexes)
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get the vault first to clean up indexes
        let vault =
            self.get(id).await?.ok_or_else(|| Error::NotFound(format!("Vault {id} not found")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Delete vault record
        txn.delete(Self::vault_key(id));

        // Delete organization index
        txn.delete(Self::vault_org_index_key(vault.organization_id, vault.id));

        // Delete name index
        txn.delete(Self::vault_name_index_key(vault.organization_id, &vault.name));

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit vault deletion: {e}")))?;

        Ok(())
    }

    /// Count vaults in an organization
    pub async fn count_by_organization(&self, org_id: i64) -> Result<usize> {
        let vaults = self.list_by_organization(org_id).await?;
        Ok(vaults.len())
    }

    /// Count active (non-deleted) vaults in an organization
    pub async fn count_active_by_organization(&self, org_id: i64) -> Result<usize> {
        let vaults = self.list_active_by_organization(org_id).await?;
        Ok(vaults.len())
    }
}

/// Repository for VaultUserGrant entity operations
///
/// Key schema:
/// - vault_user_grant:{id} -> VaultUserGrant data
/// - vault_user_grant:vault:{vault_id}:{user_id} -> grant_id (for unique constraint)
/// - vault_user_grant:user:{user_id}:{vault_id} -> grant_id (for user's vaults lookup)
pub struct VaultUserGrantRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> VaultUserGrantRepository<S> {
    /// Create a new vault user grant repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for grant by ID
    fn grant_key(id: i64) -> Vec<u8> {
        format!("vault_user_grant:{id}").into_bytes()
    }

    /// Generate key for vault-user unique constraint
    fn vault_user_index_key(vault_id: i64, user_id: i64) -> Vec<u8> {
        format!("vault_user_grant:vault:{vault_id}:{user_id}").into_bytes()
    }

    /// Generate key for user's vault grants
    fn user_vault_index_key(user_id: i64, vault_id: i64) -> Vec<u8> {
        format!("vault_user_grant:user:{user_id}:{vault_id}").into_bytes()
    }

    /// Create a new user grant
    pub async fn create(&self, grant: VaultUserGrant) -> Result<()> {
        // Serialize grant
        let grant_data = serde_json::to_vec(&grant)
            .map_err(|e| Error::Internal(format!("Failed to serialize grant: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Check for duplicate grant (vault_id, user_id unique)
        let unique_key = Self::vault_user_index_key(grant.vault_id, grant.user_id);
        if self
            .storage
            .get(&unique_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to check duplicate grant: {e}")))?
            .is_some()
        {
            return Err(Error::AlreadyExists("User already has access to this vault".to_string()));
        }

        // Store grant record
        txn.set(Self::grant_key(grant.id), grant_data.clone());

        // Store vault-user index
        txn.set(unique_key, grant.id.to_le_bytes().to_vec());

        // Store user-vault index
        txn.set(
            Self::user_vault_index_key(grant.user_id, grant.vault_id),
            grant.id.to_le_bytes().to_vec(),
        );

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit user grant creation: {e}")))?;

        Ok(())
    }

    /// Get a grant by ID
    pub async fn get(&self, id: i64) -> Result<Option<VaultUserGrant>> {
        let key = Self::grant_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get grant: {e}")))?;

        match data {
            Some(bytes) => {
                let grant: VaultUserGrant = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("Failed to deserialize grant: {e}")))?;
                Ok(Some(grant))
            },
            None => Ok(None),
        }
    }

    /// Get a grant by vault and user
    pub async fn get_by_vault_and_user(
        &self,
        vault_id: i64,
        user_id: i64,
    ) -> Result<Option<VaultUserGrant>> {
        let index_key = Self::vault_user_index_key(vault_id, user_id);
        let data = self
            .storage
            .get(&index_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get grant by vault/user: {e}")))?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::Internal("Invalid grant index data".to_string()));
                }
                let id = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// List all grants for a vault
    pub async fn list_by_vault(&self, vault_id: i64) -> Result<Vec<VaultUserGrant>> {
        let prefix = format!("vault_user_grant:vault:{vault_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_user_grant:vault:{vault_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get vault grants: {e}")))?;

        let mut grants = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(grant) = self.get(id).await? {
                grants.push(grant);
            }
        }

        Ok(grants)
    }

    /// List all grants for a user
    pub async fn list_by_user(&self, user_id: i64) -> Result<Vec<VaultUserGrant>> {
        let prefix = format!("vault_user_grant:user:{user_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_user_grant:user:{user_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get user grants: {e}")))?;

        let mut grants = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
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
            .ok_or_else(|| Error::NotFound(format!("Grant {} not found", grant.id)))?;

        // Serialize updated grant
        let grant_data = serde_json::to_vec(&grant)
            .map_err(|e| Error::Internal(format!("Failed to serialize grant: {e}")))?;

        // Update grant record
        self.storage
            .set(Self::grant_key(grant.id), grant_data)
            .await
            .map_err(|e| Error::Internal(format!("Failed to update grant: {e}")))?;

        Ok(())
    }

    /// Delete a grant
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get the grant first to clean up indexes
        let grant =
            self.get(id).await?.ok_or_else(|| Error::NotFound(format!("Grant {id} not found")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Delete grant record
        txn.delete(Self::grant_key(id));

        // Delete vault-user index
        txn.delete(Self::vault_user_index_key(grant.vault_id, grant.user_id));

        // Delete user-vault index
        txn.delete(Self::user_vault_index_key(grant.user_id, grant.vault_id));

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit grant deletion: {e}")))?;

        Ok(())
    }
}

/// Repository for VaultTeamGrant entity operations
///
/// Key schema:
/// - vault_team_grant:{id} -> VaultTeamGrant data
/// - vault_team_grant:vault:{vault_id}:{team_id} -> grant_id (for unique constraint)
/// - vault_team_grant:team:{team_id}:{vault_id} -> grant_id (for team's vaults lookup)
pub struct VaultTeamGrantRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> VaultTeamGrantRepository<S> {
    /// Create a new vault team grant repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for grant by ID
    fn grant_key(id: i64) -> Vec<u8> {
        format!("vault_team_grant:{id}").into_bytes()
    }

    /// Generate key for vault-team unique constraint
    fn vault_team_index_key(vault_id: i64, team_id: i64) -> Vec<u8> {
        format!("vault_team_grant:vault:{vault_id}:{team_id}").into_bytes()
    }

    /// Generate key for team's vault grants
    fn team_vault_index_key(team_id: i64, vault_id: i64) -> Vec<u8> {
        format!("vault_team_grant:team:{team_id}:{vault_id}").into_bytes()
    }

    /// Create a new team grant
    pub async fn create(&self, grant: VaultTeamGrant) -> Result<()> {
        // Serialize grant
        let grant_data = serde_json::to_vec(&grant)
            .map_err(|e| Error::Internal(format!("Failed to serialize grant: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Check for duplicate grant (vault_id, team_id unique)
        let unique_key = Self::vault_team_index_key(grant.vault_id, grant.team_id);
        if self
            .storage
            .get(&unique_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to check duplicate grant: {e}")))?
            .is_some()
        {
            return Err(Error::AlreadyExists("Team already has access to this vault".to_string()));
        }

        // Store grant record
        txn.set(Self::grant_key(grant.id), grant_data.clone());

        // Store vault-team index
        txn.set(unique_key, grant.id.to_le_bytes().to_vec());

        // Store team-vault index
        txn.set(
            Self::team_vault_index_key(grant.team_id, grant.vault_id),
            grant.id.to_le_bytes().to_vec(),
        );

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit team grant creation: {e}")))?;

        Ok(())
    }

    /// Get a grant by ID
    pub async fn get(&self, id: i64) -> Result<Option<VaultTeamGrant>> {
        let key = Self::grant_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get grant: {e}")))?;

        match data {
            Some(bytes) => {
                let grant: VaultTeamGrant = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("Failed to deserialize grant: {e}")))?;
                Ok(Some(grant))
            },
            None => Ok(None),
        }
    }

    /// Get a grant by vault and team
    pub async fn get_by_vault_and_team(
        &self,
        vault_id: i64,
        team_id: i64,
    ) -> Result<Option<VaultTeamGrant>> {
        let index_key = Self::vault_team_index_key(vault_id, team_id);
        let data = self
            .storage
            .get(&index_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get grant by vault/team: {e}")))?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::Internal("Invalid grant index data".to_string()));
                }
                let id = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// List all grants for a vault
    pub async fn list_by_vault(&self, vault_id: i64) -> Result<Vec<VaultTeamGrant>> {
        let prefix = format!("vault_team_grant:vault:{vault_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_team_grant:vault:{vault_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get vault grants: {e}")))?;

        let mut grants = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(grant) = self.get(id).await? {
                grants.push(grant);
            }
        }

        Ok(grants)
    }

    /// List all grants for a team
    pub async fn list_by_team(&self, team_id: i64) -> Result<Vec<VaultTeamGrant>> {
        let prefix = format!("vault_team_grant:team:{team_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_team_grant:team:{team_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get team grants: {e}")))?;

        let mut grants = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
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
            .ok_or_else(|| Error::NotFound(format!("Grant {} not found", grant.id)))?;

        // Serialize updated grant
        let grant_data = serde_json::to_vec(&grant)
            .map_err(|e| Error::Internal(format!("Failed to serialize grant: {e}")))?;

        // Update grant record
        self.storage
            .set(Self::grant_key(grant.id), grant_data)
            .await
            .map_err(|e| Error::Internal(format!("Failed to update grant: {e}")))?;

        Ok(())
    }

    /// Delete a grant
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get the grant first to clean up indexes
        let grant =
            self.get(id).await?.ok_or_else(|| Error::NotFound(format!("Grant {id} not found")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Delete grant record
        txn.delete(Self::grant_key(id));

        // Delete vault-team index
        txn.delete(Self::vault_team_index_key(grant.vault_id, grant.team_id));

        // Delete team-vault index
        txn.delete(Self::team_vault_index_key(grant.team_id, grant.vault_id));

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit grant deletion: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use inferadb_control_storage::Backend;
    use inferadb_control_types::entities::{VaultRole, VaultSyncStatus};

    use super::*;

    fn create_test_vault_repo() -> VaultRepository<Backend> {
        VaultRepository::new(Backend::memory())
    }

    fn create_test_user_grant_repo() -> VaultUserGrantRepository<Backend> {
        VaultUserGrantRepository::new(Backend::memory())
    }

    fn create_test_team_grant_repo() -> VaultTeamGrantRepository<Backend> {
        VaultTeamGrantRepository::new(Backend::memory())
    }

    fn create_test_vault(id: i64, org_id: i64, name: &str) -> Result<Vault> {
        Vault::builder()
            .id(id)
            .organization_id(org_id)
            .name(name.to_string())
            .created_by_user_id(999)
            .build()
    }

    #[tokio::test]
    async fn test_create_and_get_vault() {
        let repo = create_test_vault_repo();
        let vault = create_test_vault(1, 100, "Test Vault").unwrap();

        repo.create(vault.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
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
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists(_)));
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

        let org_100_vaults = repo.list_by_organization(100).await.unwrap();
        assert_eq!(org_100_vaults.len(), 2);

        let org_200_vaults = repo.list_by_organization(200).await.unwrap();
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

        let retrieved = repo.get(1).await.unwrap().unwrap();
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

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert!(retrieved.is_deleted());

        // Should not be in active list
        let active = repo.list_active_by_organization(100).await.unwrap();
        assert_eq!(active.len(), 0);

        // Still in full list
        let all = repo.list_by_organization(100).await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_vault() {
        let repo = create_test_vault_repo();
        let vault = create_test_vault(1, 100, "Test Vault").unwrap();

        repo.create(vault).await.unwrap();
        assert!(repo.get(1).await.unwrap().is_some());

        repo.delete(1).await.unwrap();
        assert!(repo.get(1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_create_user_grant() {
        let repo = create_test_user_grant_repo();
        let grant = VaultUserGrant::new(1, 100, 200, VaultRole::Reader, 999);

        repo.create(grant.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert_eq!(retrieved, Some(grant));
    }

    #[tokio::test]
    async fn test_duplicate_user_grant_rejected() {
        let repo = create_test_user_grant_repo();
        let grant1 = VaultUserGrant::new(1, 100, 200, VaultRole::Reader, 999);
        let grant2 = VaultUserGrant::new(2, 100, 200, VaultRole::Writer, 999);

        repo.create(grant1).await.unwrap();

        let result = repo.create(grant2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn test_get_user_grant_by_vault_and_user() {
        let repo = create_test_user_grant_repo();
        let grant = VaultUserGrant::new(1, 100, 200, VaultRole::Reader, 999);

        repo.create(grant.clone()).await.unwrap();

        let retrieved = repo.get_by_vault_and_user(100, 200).await.unwrap();
        assert_eq!(retrieved, Some(grant));
    }

    #[tokio::test]
    async fn test_list_user_grants_by_vault() {
        let repo = create_test_user_grant_repo();
        let grant1 = VaultUserGrant::new(1, 100, 200, VaultRole::Reader, 999);
        let grant2 = VaultUserGrant::new(2, 100, 201, VaultRole::Writer, 999);
        let grant3 = VaultUserGrant::new(3, 101, 200, VaultRole::Admin, 999);

        repo.create(grant1).await.unwrap();
        repo.create(grant2).await.unwrap();
        repo.create(grant3).await.unwrap();

        let vault_100_grants = repo.list_by_vault(100).await.unwrap();
        assert_eq!(vault_100_grants.len(), 2);

        let vault_101_grants = repo.list_by_vault(101).await.unwrap();
        assert_eq!(vault_101_grants.len(), 1);
    }

    #[tokio::test]
    async fn test_list_user_grants_by_user() {
        let repo = create_test_user_grant_repo();
        let grant1 = VaultUserGrant::new(1, 100, 200, VaultRole::Reader, 999);
        let grant2 = VaultUserGrant::new(2, 101, 200, VaultRole::Writer, 999);
        let grant3 = VaultUserGrant::new(3, 100, 201, VaultRole::Admin, 999);

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
        let mut grant = VaultUserGrant::new(1, 100, 200, VaultRole::Reader, 999);

        repo.create(grant.clone()).await.unwrap();

        grant.role = VaultRole::Writer;
        repo.update(grant.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert_eq!(retrieved.role, VaultRole::Writer);
    }

    #[tokio::test]
    async fn test_delete_user_grant() {
        let repo = create_test_user_grant_repo();
        let grant = VaultUserGrant::new(1, 100, 200, VaultRole::Reader, 999);

        repo.create(grant).await.unwrap();
        assert!(repo.get(1).await.unwrap().is_some());

        repo.delete(1).await.unwrap();
        assert!(repo.get(1).await.unwrap().is_none());
        assert!(repo.get_by_vault_and_user(100, 200).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_create_team_grant() {
        let repo = create_test_team_grant_repo();
        let grant = VaultTeamGrant::new(1, 100, 300, VaultRole::Reader, 999);

        repo.create(grant.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert_eq!(retrieved, Some(grant));
    }

    #[tokio::test]
    async fn test_duplicate_team_grant_rejected() {
        let repo = create_test_team_grant_repo();
        let grant1 = VaultTeamGrant::new(1, 100, 300, VaultRole::Reader, 999);
        let grant2 = VaultTeamGrant::new(2, 100, 300, VaultRole::Writer, 999);

        repo.create(grant1).await.unwrap();

        let result = repo.create(grant2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn test_list_team_grants_by_vault() {
        let repo = create_test_team_grant_repo();
        let grant1 = VaultTeamGrant::new(1, 100, 300, VaultRole::Reader, 999);
        let grant2 = VaultTeamGrant::new(2, 100, 301, VaultRole::Writer, 999);
        let grant3 = VaultTeamGrant::new(3, 101, 300, VaultRole::Admin, 999);

        repo.create(grant1).await.unwrap();
        repo.create(grant2).await.unwrap();
        repo.create(grant3).await.unwrap();

        let vault_100_grants = repo.list_by_vault(100).await.unwrap();
        assert_eq!(vault_100_grants.len(), 2);

        let vault_101_grants = repo.list_by_vault(101).await.unwrap();
        assert_eq!(vault_101_grants.len(), 1);
    }

    #[tokio::test]
    async fn test_list_team_grants_by_team() {
        let repo = create_test_team_grant_repo();
        let grant1 = VaultTeamGrant::new(1, 100, 300, VaultRole::Reader, 999);
        let grant2 = VaultTeamGrant::new(2, 101, 300, VaultRole::Writer, 999);
        let grant3 = VaultTeamGrant::new(3, 100, 301, VaultRole::Admin, 999);

        repo.create(grant1).await.unwrap();
        repo.create(grant2).await.unwrap();
        repo.create(grant3).await.unwrap();

        let team_300_grants = repo.list_by_team(300).await.unwrap();
        assert_eq!(team_300_grants.len(), 2);

        let team_301_grants = repo.list_by_team(301).await.unwrap();
        assert_eq!(team_301_grants.len(), 1);
    }
}
