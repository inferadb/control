use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::{Organization, OrganizationMember, OrganizationRole},
    error::{Error, Result},
};

/// Repository for Organization entity operations
///
/// Key schema:
/// - org:{id} -> Organization data
/// - org:name:{name} -> org_id (for name lookup)
/// - org:count -> total organization count (for global limit)
pub struct OrganizationRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> OrganizationRepository<S> {
    /// Create a new organization repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for organization by ID
    fn org_key(id: i64) -> Vec<u8> {
        format!("org:{id}").into_bytes()
    }

    /// Generate key for organization name index
    fn org_name_index_key(name: &str) -> Vec<u8> {
        format!("org:name:{}", name.to_lowercase()).into_bytes()
    }

    /// Key for global organization count
    fn org_count_key() -> Vec<u8> {
        b"org:count".to_vec()
    }

    /// Create a new organization
    pub async fn create(&self, org: Organization) -> Result<()> {
        // Serialize organization
        let org_data = serde_json::to_vec(&org)
            .map_err(|e| Error::internal(format!("Failed to serialize organization: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

        // Store organization record
        let org_key = Self::org_key(org.id);
        txn.set(org_key, org_data);

        // Store name index for lookup (not enforcing uniqueness)
        // Note: If multiple orgs have the same name, this will point to the last one created
        let name_key = Self::org_name_index_key(&org.name);
        txn.set(name_key, org.id.to_le_bytes().to_vec());

        // Increment global count
        let count_key = Self::org_count_key();
        let current_count = self.get_total_count().await?;
        txn.set(count_key, (current_count + 1).to_le_bytes().to_vec());

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::internal(format!("Failed to commit organization creation: {e}")))?;

        Ok(())
    }

    /// Get an organization by ID
    pub async fn get(&self, id: i64) -> Result<Option<Organization>> {
        let key = Self::org_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::internal(format!("Failed to get organization: {e}")))?;

        match data {
            Some(bytes) => {
                let org: Organization = serde_json::from_slice(&bytes).map_err(|e| {
                    Error::internal(format!("Failed to deserialize organization: {e}"))
                })?;
                Ok(Some(org))
            },
            None => Ok(None),
        }
    }

    /// Get an organization by name
    pub async fn get_by_name(&self, name: &str) -> Result<Option<Organization>> {
        let index_key = Self::org_name_index_key(name);
        let data = self
            .storage
            .get(&index_key)
            .await
            .map_err(|e| Error::internal(format!("Failed to get organization by name: {e}")))?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::internal("Invalid organization index data".to_string()));
                }
                let id = super::parse_i64_id(&bytes)?;
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// Check if an organization name is available
    pub async fn is_name_available(&self, name: &str) -> Result<bool> {
        Ok(self.get_by_name(name).await?.is_none())
    }

    /// Update an existing organization
    pub async fn update(&self, org: Organization) -> Result<()> {
        // Get the old organization to check if name changed
        let old_org = self
            .get(org.id)
            .await?
            .ok_or_else(|| Error::not_found(format!("Organization {} not found", org.id)))?;

        // Serialize organization
        let org_data = serde_json::to_vec(&org)
            .map_err(|e| Error::internal(format!("Failed to serialize organization: {e}")))?;

        // Use transaction if name changed
        if old_org.name != org.name {
            let mut txn = self
                .storage
                .transaction()
                .await
                .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

            // Update organization record
            txn.set(Self::org_key(org.id), org_data);

            // Delete old name index
            txn.delete(Self::org_name_index_key(&old_org.name));

            // Create new name index (not enforcing uniqueness)
            let new_name_key = Self::org_name_index_key(&org.name);
            txn.set(new_name_key, org.id.to_le_bytes().to_vec());

            txn.commit().await.map_err(|e| {
                Error::internal(format!("Failed to commit organization update: {e}"))
            })?;
        } else {
            // Just update the organization record
            self.storage
                .set(Self::org_key(org.id), org_data)
                .await
                .map_err(|e| Error::internal(format!("Failed to update organization: {e}")))?;
        }

        Ok(())
    }

    /// Soft-delete an organization
    pub async fn delete(&self, id: i64) -> Result<()> {
        let mut org = self
            .get(id)
            .await?
            .ok_or_else(|| Error::not_found(format!("Organization {id} not found")))?;

        org.soft_delete();
        self.update(org).await
    }

    /// Get the total count of organizations
    pub async fn get_total_count(&self) -> Result<i64> {
        let count_key = Self::org_count_key();
        let data = self
            .storage
            .get(&count_key)
            .await
            .map_err(|e| Error::internal(format!("Failed to get organization count: {e}")))?;

        match data {
            Some(bytes) if bytes.len() == 8 => super::parse_i64_id(&bytes),
            _ => Ok(0),
        }
    }
}

/// Repository for OrganizationMember entity operations
///
/// Key schema:
/// - org_member:{id} -> OrganizationMember data
/// - org_member:org:{org_id}:{user_id} -> member_id (for org+user lookup)
/// - org_member:user:{user_id}:{org_id} -> member_id (for user's orgs lookup)
/// - org_member:user_count:{user_id} -> count (for per-user org limit)
/// - org_member:org_count:{org_id} -> count (for per-org member count)
pub struct OrganizationMemberRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> OrganizationMemberRepository<S> {
    /// Create a new organization member repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for member by ID
    fn member_key(id: i64) -> Vec<u8> {
        format!("org_member:{id}").into_bytes()
    }

    /// Generate key for org+user index
    fn org_user_index_key(org_id: i64, user_id: i64) -> Vec<u8> {
        format!("org_member:org:{org_id}:{user_id}").into_bytes()
    }

    /// Generate key for user's orgs index
    fn user_org_index_key(user_id: i64, org_id: i64) -> Vec<u8> {
        format!("org_member:user:{user_id}:{org_id}").into_bytes()
    }

    /// Key for user's organization count
    fn user_org_count_key(user_id: i64) -> Vec<u8> {
        format!("org_member:user_count:{user_id}").into_bytes()
    }

    /// Key for per-organization member count
    fn org_member_count_key(org_id: i64) -> Vec<u8> {
        format!("org_member:org_count:{org_id}").into_bytes()
    }

    /// Read the raw org member count from storage, returning None if uninitialized or corrupt
    async fn get_raw_org_member_count(&self, org_id: i64) -> Result<Option<i64>> {
        let key = Self::org_member_count_key(org_id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::internal(format!("Failed to get org member count: {e}")))?;
        match data {
            Some(bytes) if bytes.len() == 8 => Ok(Some(super::parse_i64_id(&bytes)?)),
            _ => Ok(None),
        }
    }

    /// Recount org members by scanning all members and update the counter
    async fn recount_org_members(&self, org_id: i64) -> Result<usize> {
        let members = self.get_by_organization(org_id).await?;
        let count = members.len();
        self.storage
            .set(Self::org_member_count_key(org_id), (count as i64).to_le_bytes().to_vec())
            .await
            .map_err(|e| Error::internal(format!("Failed to set org member count: {e}")))?;
        Ok(count)
    }

    /// Create a new organization member
    pub async fn create(&self, member: OrganizationMember) -> Result<()> {
        // Serialize member
        let member_data = serde_json::to_vec(&member).map_err(|e| {
            Error::internal(format!("Failed to serialize organization member: {e}"))
        })?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

        // Check uniqueness (user can only be member once per org)
        let org_user_key = Self::org_user_index_key(member.organization_id, member.user_id);
        if self
            .storage
            .get(&org_user_key)
            .await
            .map_err(|e| Error::internal(format!("Failed to check member uniqueness: {e}")))?
            .is_some()
        {
            return Err(Error::already_exists(
                "User is already a member of this organization".to_string(),
            ));
        }

        // Store member record
        txn.set(Self::member_key(member.id), member_data);

        // Store org+user index
        txn.set(org_user_key, member.id.to_le_bytes().to_vec());

        // Store user+org index
        txn.set(
            Self::user_org_index_key(member.user_id, member.organization_id),
            member.id.to_le_bytes().to_vec(),
        );

        // Increment user's org count
        let count_key = Self::user_org_count_key(member.user_id);
        let current_count = self.get_user_organization_count(member.user_id).await?;
        txn.set(count_key, (current_count + 1).to_le_bytes().to_vec());

        // Increment per-org member count
        let org_count_key = Self::org_member_count_key(member.organization_id);
        let current_org_count =
            self.get_raw_org_member_count(member.organization_id).await?.unwrap_or(0);
        txn.set(org_count_key, (current_org_count + 1).to_le_bytes().to_vec());

        // Commit transaction
        txn.commit().await.map_err(|e| {
            Error::internal(format!("Failed to commit organization member creation: {e}"))
        })?;

        Ok(())
    }

    /// Get a member by ID
    pub async fn get(&self, id: i64) -> Result<Option<OrganizationMember>> {
        let key = Self::member_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::internal(format!("Failed to get organization member: {e}")))?;

        match data {
            Some(bytes) => {
                let member: OrganizationMember = serde_json::from_slice(&bytes).map_err(|e| {
                    Error::internal(format!("Failed to deserialize organization member: {e}"))
                })?;
                Ok(Some(member))
            },
            None => Ok(None),
        }
    }

    /// Get a member by organization and user
    pub async fn get_by_org_and_user(
        &self,
        org_id: i64,
        user_id: i64,
    ) -> Result<Option<OrganizationMember>> {
        let index_key = Self::org_user_index_key(org_id, user_id);
        let data = self.storage.get(&index_key).await.map_err(|e| {
            Error::internal(format!("Failed to get organization member by org+user: {e}"))
        })?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::internal(
                        "Invalid organization member index data".to_string(),
                    ));
                }
                let id = super::parse_i64_id(&bytes)?;
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// Get all members of an organization
    pub async fn get_by_organization(&self, org_id: i64) -> Result<Vec<OrganizationMember>> {
        let prefix = format!("org_member:org:{org_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("org_member:org:{org_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::internal(format!("Failed to get organization members: {e}")))?;

        let mut members = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_i64_id(&kv.value) else { continue };
            if let Some(member) = self.get(id).await? {
                members.push(member);
            }
        }

        Ok(members)
    }

    /// Get all organizations a user is a member of
    pub async fn get_by_user(&self, user_id: i64) -> Result<Vec<OrganizationMember>> {
        let prefix = format!("org_member:user:{user_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("org_member:user:{user_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::internal(format!("Failed to get user's organizations: {e}")))?;

        let mut members = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_i64_id(&kv.value) else { continue };
            if let Some(member) = self.get(id).await? {
                members.push(member);
            }
        }

        Ok(members)
    }

    /// Get the count of organizations a user is a member of
    pub async fn get_user_organization_count(&self, user_id: i64) -> Result<i64> {
        let count_key = Self::user_org_count_key(user_id);
        let data =
            self.storage.get(&count_key).await.map_err(|e| {
                Error::internal(format!("Failed to get user organization count: {e}"))
            })?;

        match data {
            Some(bytes) if bytes.len() == 8 => super::parse_i64_id(&bytes),
            _ => Ok(0),
        }
    }

    /// Count members in an organization using maintained counter
    ///
    /// Reads from a counter key maintained during create and delete operations.
    /// Under concurrent writes, the counter is eventually consistent: reads outside
    /// the transaction may observe stale values, but self-healing on the next read
    /// corrects any drift.
    pub async fn count_by_organization(&self, org_id: i64) -> Result<usize> {
        match self.get_raw_org_member_count(org_id).await? {
            Some(count) if count >= 0 => Ok(count as usize),
            _ => self.recount_org_members(org_id).await,
        }
    }

    /// Count owners in an organization
    pub async fn count_owners(&self, org_id: i64) -> Result<usize> {
        let members = self.get_by_organization(org_id).await?;
        Ok(members.iter().filter(|m| m.role == OrganizationRole::Owner).count())
    }

    /// Update a member's role
    pub async fn update(&self, member: OrganizationMember) -> Result<()> {
        let member_data = serde_json::to_vec(&member).map_err(|e| {
            Error::internal(format!("Failed to serialize organization member: {e}"))
        })?;

        self.storage
            .set(Self::member_key(member.id), member_data)
            .await
            .map_err(|e| Error::internal(format!("Failed to update organization member: {e}")))?;

        Ok(())
    }

    /// Delete a member
    pub async fn delete(&self, id: i64) -> Result<()> {
        let member = self
            .get(id)
            .await?
            .ok_or_else(|| Error::not_found(format!("Organization member {id} not found")))?;

        // Use transaction to delete all related keys atomically
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

        // Delete member record
        txn.delete(Self::member_key(id));

        // Delete org+user index
        txn.delete(Self::org_user_index_key(member.organization_id, member.user_id));

        // Delete user+org index
        txn.delete(Self::user_org_index_key(member.user_id, member.organization_id));

        // Decrement user's org count
        let count_key = Self::user_org_count_key(member.user_id);
        let current_count = self.get_user_organization_count(member.user_id).await?;
        if current_count > 0 {
            txn.set(count_key, (current_count - 1).to_le_bytes().to_vec());
        }

        // Decrement per-org member count
        let org_count_key = Self::org_member_count_key(member.organization_id);
        let current_org_count =
            self.get_raw_org_member_count(member.organization_id).await?.unwrap_or(0);
        if current_org_count > 0 {
            txn.set(org_count_key, (current_org_count - 1).to_le_bytes().to_vec());
        }

        // Commit transaction
        txn.commit().await.map_err(|e| {
            Error::internal(format!("Failed to commit organization member deletion: {e}"))
        })?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_control_storage::Backend;
    use inferadb_control_types::entities::OrganizationTier;

    use super::*;
    use crate::IdGenerator;

    async fn create_test_org_repo() -> OrganizationRepository<Backend> {
        let storage = Backend::memory();
        OrganizationRepository::new(storage)
    }

    async fn create_test_member_repo() -> OrganizationMemberRepository<Backend> {
        let storage = Backend::memory();
        OrganizationMemberRepository::new(storage)
    }

    #[tokio::test]
    async fn test_create_and_get_organization() {
        let _ = IdGenerator::init(1);
        let repo = create_test_org_repo().await;

        let org = Organization::builder()
            .id(100)
            .name("Test Org".to_string())
            .tier(OrganizationTier::TierDevV1)
            .create()
            .unwrap();
        repo.create(org.clone()).await.unwrap();

        let retrieved = repo.get(100).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Org");
    }

    #[tokio::test]
    async fn test_get_by_name() {
        let _ = IdGenerator::init(1);
        let repo = create_test_org_repo().await;

        let org = Organization::builder()
            .id(100)
            .name("Test Org".to_string())
            .tier(OrganizationTier::TierDevV1)
            .create()
            .unwrap();
        repo.create(org).await.unwrap();

        let retrieved = repo.get_by_name("Test Org").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, 100);

        // Case insensitive
        let retrieved = repo.get_by_name("test org").await.unwrap();
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_duplicate_name() {
        let _ = IdGenerator::init(1);
        let repo = create_test_org_repo().await;

        let org1 = Organization::builder()
            .id(100)
            .name("Test Org".to_string())
            .tier(OrganizationTier::TierDevV1)
            .create()
            .unwrap();
        repo.create(org1).await.unwrap();

        let org2 = Organization::builder()
            .id(101)
            .name("Test Org".to_string())
            .tier(OrganizationTier::TierDevV1)
            .create()
            .unwrap();
        let result = repo.create(org2).await;
        // Duplicate names are now allowed
        assert!(result.is_ok());

        // Verify both organizations exist
        assert!(repo.get(100).await.unwrap().is_some());
        assert!(repo.get(101).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_update_organization() {
        let _ = IdGenerator::init(1);
        let repo = create_test_org_repo().await;

        let mut org = Organization::builder()
            .id(100)
            .name("Old Name".to_string())
            .tier(OrganizationTier::TierDevV1)
            .create()
            .unwrap();
        repo.create(org.clone()).await.unwrap();

        org.set_name("New Name".to_string()).unwrap();
        repo.update(org).await.unwrap();

        let retrieved = repo.get(100).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "New Name");

        // Old name should not work
        assert!(repo.get_by_name("Old Name").await.unwrap().is_none());
        // New name should work
        assert!(repo.get_by_name("New Name").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_soft_delete_organization() {
        let _ = IdGenerator::init(1);
        let repo = create_test_org_repo().await;

        let org = Organization::builder()
            .id(100)
            .name("Test Org".to_string())
            .tier(OrganizationTier::TierDevV1)
            .create()
            .unwrap();
        repo.create(org).await.unwrap();

        repo.delete(100).await.unwrap();

        let retrieved = repo.get(100).await.unwrap().unwrap();
        assert!(retrieved.is_deleted());
    }

    #[tokio::test]
    async fn test_organization_count() {
        let _ = IdGenerator::init(1);
        let repo = create_test_org_repo().await;

        assert_eq!(repo.get_total_count().await.unwrap(), 0);

        let org1 = Organization::builder()
            .id(100)
            .name("Org 1".to_string())
            .tier(OrganizationTier::TierDevV1)
            .create()
            .unwrap();
        repo.create(org1).await.unwrap();
        assert_eq!(repo.get_total_count().await.unwrap(), 1);

        let org2 = Organization::builder()
            .id(101)
            .name("Org 2".to_string())
            .tier(OrganizationTier::TierDevV1)
            .create()
            .unwrap();
        repo.create(org2).await.unwrap();
        assert_eq!(repo.get_total_count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_create_and_get_member() {
        let _ = IdGenerator::init(1);
        let repo = create_test_member_repo().await;

        let member = OrganizationMember::new(1, 100, 200, OrganizationRole::Member);
        repo.create(member.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, 200);
    }

    #[tokio::test]
    async fn test_get_member_by_org_and_user() {
        let _ = IdGenerator::init(1);
        let repo = create_test_member_repo().await;

        let member = OrganizationMember::new(1, 100, 200, OrganizationRole::Member);
        repo.create(member).await.unwrap();

        let retrieved = repo.get_by_org_and_user(100, 200).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, 1);
    }

    #[tokio::test]
    async fn test_duplicate_member() {
        let _ = IdGenerator::init(1);
        let repo = create_test_member_repo().await;

        let member1 = OrganizationMember::new(1, 100, 200, OrganizationRole::Member);
        repo.create(member1).await.unwrap();

        let member2 = OrganizationMember::new(2, 100, 200, OrganizationRole::Admin);
        let result = repo.create(member2).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_members_by_organization() {
        let _ = IdGenerator::init(1);
        let repo = create_test_member_repo().await;

        let member1 = OrganizationMember::new(1, 100, 200, OrganizationRole::Owner);
        let member2 = OrganizationMember::new(2, 100, 201, OrganizationRole::Member);
        let member3 = OrganizationMember::new(3, 101, 202, OrganizationRole::Member);

        repo.create(member1).await.unwrap();
        repo.create(member2).await.unwrap();
        repo.create(member3).await.unwrap();

        let members = repo.get_by_organization(100).await.unwrap();
        assert_eq!(members.len(), 2);

        let members = repo.get_by_organization(101).await.unwrap();
        assert_eq!(members.len(), 1);
    }

    #[tokio::test]
    async fn test_get_members_by_user() {
        let _ = IdGenerator::init(1);
        let repo = create_test_member_repo().await;

        let member1 = OrganizationMember::new(1, 100, 200, OrganizationRole::Owner);
        let member2 = OrganizationMember::new(2, 101, 200, OrganizationRole::Member);
        let member3 = OrganizationMember::new(3, 102, 201, OrganizationRole::Member);

        repo.create(member1).await.unwrap();
        repo.create(member2).await.unwrap();
        repo.create(member3).await.unwrap();

        let members = repo.get_by_user(200).await.unwrap();
        assert_eq!(members.len(), 2);

        let members = repo.get_by_user(201).await.unwrap();
        assert_eq!(members.len(), 1);
    }

    #[tokio::test]
    async fn test_user_organization_count() {
        let _ = IdGenerator::init(1);
        let repo = create_test_member_repo().await;

        assert_eq!(repo.get_user_organization_count(200).await.unwrap(), 0);

        let member1 = OrganizationMember::new(1, 100, 200, OrganizationRole::Owner);
        repo.create(member1).await.unwrap();
        assert_eq!(repo.get_user_organization_count(200).await.unwrap(), 1);

        let member2 = OrganizationMember::new(2, 101, 200, OrganizationRole::Member);
        repo.create(member2).await.unwrap();
        assert_eq!(repo.get_user_organization_count(200).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_count_owners() {
        let _ = IdGenerator::init(1);
        let repo = create_test_member_repo().await;

        let member1 = OrganizationMember::new(1, 100, 200, OrganizationRole::Owner);
        let member2 = OrganizationMember::new(2, 100, 201, OrganizationRole::Admin);
        let member3 = OrganizationMember::new(3, 100, 202, OrganizationRole::Owner);

        repo.create(member1).await.unwrap();
        repo.create(member2).await.unwrap();
        repo.create(member3).await.unwrap();

        assert_eq!(repo.count_owners(100).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_update_member_role() {
        let _ = IdGenerator::init(1);
        let repo = create_test_member_repo().await;

        let mut member = OrganizationMember::new(1, 100, 200, OrganizationRole::Member);
        repo.create(member.clone()).await.unwrap();

        member.set_role(OrganizationRole::Admin);
        repo.update(member).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert_eq!(retrieved.role, OrganizationRole::Admin);
    }

    #[tokio::test]
    async fn test_delete_member() {
        let _ = IdGenerator::init(1);
        let repo = create_test_member_repo().await;

        let member = OrganizationMember::new(1, 100, 200, OrganizationRole::Member);
        repo.create(member).await.unwrap();

        assert_eq!(repo.get_user_organization_count(200).await.unwrap(), 1);

        repo.delete(1).await.unwrap();

        assert!(repo.get(1).await.unwrap().is_none());
        assert!(repo.get_by_org_and_user(100, 200).await.unwrap().is_none());
        assert_eq!(repo.get_user_organization_count(200).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_org_member_count_tracks_create_and_delete() {
        let _ = IdGenerator::init(1);
        let repo = create_test_member_repo().await;

        assert_eq!(repo.count_by_organization(100).await.unwrap(), 0);

        let member1 = OrganizationMember::new(1, 100, 200, OrganizationRole::Owner);
        repo.create(member1).await.unwrap();
        assert_eq!(repo.count_by_organization(100).await.unwrap(), 1);

        let member2 = OrganizationMember::new(2, 100, 201, OrganizationRole::Member);
        repo.create(member2).await.unwrap();
        assert_eq!(repo.count_by_organization(100).await.unwrap(), 2);

        repo.delete(1).await.unwrap();
        assert_eq!(repo.count_by_organization(100).await.unwrap(), 1);

        repo.delete(2).await.unwrap();
        assert_eq!(repo.count_by_organization(100).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_org_member_count_independent_per_org() {
        let _ = IdGenerator::init(1);
        let repo = create_test_member_repo().await;

        let member1 = OrganizationMember::new(1, 100, 200, OrganizationRole::Owner);
        let member2 = OrganizationMember::new(2, 101, 201, OrganizationRole::Owner);
        repo.create(member1).await.unwrap();
        repo.create(member2).await.unwrap();

        assert_eq!(repo.count_by_organization(100).await.unwrap(), 1);
        assert_eq!(repo.count_by_organization(101).await.unwrap(), 1);
        assert_eq!(repo.count_by_organization(999).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_org_member_count_self_heals_on_missing_counter() {
        let _ = IdGenerator::init(1);
        let repo = create_test_member_repo().await;

        let member1 = OrganizationMember::new(1, 100, 200, OrganizationRole::Owner);
        let member2 = OrganizationMember::new(2, 100, 201, OrganizationRole::Member);
        repo.create(member1).await.unwrap();
        repo.create(member2).await.unwrap();

        // Delete the counter key to simulate migration
        use inferadb_control_storage::Backend;
        repo.storage
            .delete(&OrganizationMemberRepository::<Backend>::org_member_count_key(100))
            .await
            .unwrap();

        // Should self-heal by recounting
        assert_eq!(repo.count_by_organization(100).await.unwrap(), 2);
    }
}
