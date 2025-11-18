use crate::entities::{
    OrganizationPermission, OrganizationTeam, OrganizationTeamMember, OrganizationTeamPermission,
};
use crate::error::{Error, Result};
use infera_management_storage::StorageBackend;

/// Repository for OrganizationTeam entity operations
///
/// Key schema:
/// - team:{id} -> OrganizationTeam data
/// - team:org:{org_id}:{idx} -> team_id (for org listing)
/// - team:name:{org_id}:{name_lowercase} -> team_id (for duplicate name checking)
pub struct OrganizationTeamRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> OrganizationTeamRepository<S> {
    /// Create a new team repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for team by ID
    fn team_key(id: i64) -> Vec<u8> {
        format!("team:{}", id).into_bytes()
    }

    /// Generate key for team by organization index
    fn team_org_index_key(org_id: i64, idx: i64) -> Vec<u8> {
        format!("team:org:{}:{}", org_id, idx).into_bytes()
    }

    /// Generate key for team by name (for duplicate checking)
    fn team_name_index_key(org_id: i64, name: &str) -> Vec<u8> {
        format!("team:name:{}:{}", org_id, name.to_lowercase()).into_bytes()
    }

    /// Create a new team
    pub async fn create(&self, team: OrganizationTeam) -> Result<()> {
        // Serialize team
        let team_data = serde_json::to_vec(&team)
            .map_err(|e| Error::Internal(format!("Failed to serialize team: {}", e)))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {}", e)))?;

        // Check for duplicate name within organization
        let name_key = Self::team_name_index_key(team.organization_id, &team.name);
        if self
            .storage
            .get(&name_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to check duplicate team name: {}", e)))?
            .is_some()
        {
            return Err(Error::AlreadyExists(format!(
                "A team named '{}' already exists in this organization",
                team.name
            )));
        }

        // Store team record
        txn.set(Self::team_key(team.id), team_data.clone());

        // Store organization index
        txn.set(
            Self::team_org_index_key(team.organization_id, team.id),
            team.id.to_le_bytes().to_vec(),
        );

        // Store name index
        txn.set(name_key, team.id.to_le_bytes().to_vec());

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit team creation: {}", e)))?;

        Ok(())
    }

    /// Get a team by ID
    pub async fn get(&self, id: i64) -> Result<Option<OrganizationTeam>> {
        let key = Self::team_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get team: {}", e)))?;

        match data {
            Some(bytes) => {
                let team: OrganizationTeam = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("Failed to deserialize team: {}", e)))?;
                Ok(Some(team))
            }
            None => Ok(None),
        }
    }

    /// List all teams for an organization (including soft-deleted)
    pub async fn list_by_organization(&self, org_id: i64) -> Result<Vec<OrganizationTeam>> {
        let prefix = format!("team:org:{}:", org_id);
        let start = prefix.clone().into_bytes();
        let end = format!("team:org:{}~", org_id).into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get organization teams: {}", e)))?;

        let mut teams = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(team) = self.get(id).await? {
                teams.push(team);
            }
        }

        Ok(teams)
    }

    /// List active (non-deleted) teams for an organization
    pub async fn list_active_by_organization(&self, org_id: i64) -> Result<Vec<OrganizationTeam>> {
        let all_teams = self.list_by_organization(org_id).await?;
        Ok(all_teams.into_iter().filter(|t| !t.is_deleted()).collect())
    }

    /// Update a team
    pub async fn update(&self, team: OrganizationTeam) -> Result<()> {
        // Get the existing team to clean up old indexes if name changed
        let existing = self
            .get(team.id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Team {} not found", team.id)))?;

        // Serialize updated team
        let team_data = serde_json::to_vec(&team)
            .map_err(|e| Error::Internal(format!("Failed to serialize team: {}", e)))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {}", e)))?;

        // If name changed, update name index
        if existing.name != team.name {
            // Delete old name index
            txn.delete(Self::team_name_index_key(
                existing.organization_id,
                &existing.name,
            ));

            // Check for duplicate new name
            let new_name_key = Self::team_name_index_key(team.organization_id, &team.name);
            if self
                .storage
                .get(&new_name_key)
                .await
                .map_err(|e| {
                    Error::Internal(format!("Failed to check duplicate team name: {}", e))
                })?
                .is_some()
            {
                return Err(Error::AlreadyExists(format!(
                    "A team named '{}' already exists in this organization",
                    team.name
                )));
            }

            // Store new name index
            txn.set(new_name_key, team.id.to_le_bytes().to_vec());
        }

        // Update team record
        txn.set(Self::team_key(team.id), team_data);

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit team update: {}", e)))?;

        Ok(())
    }

    /// Delete a team (removes all indexes)
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get the team first to clean up indexes
        let team = self
            .get(id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Team {} not found", id)))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {}", e)))?;

        // Delete team record
        txn.delete(Self::team_key(id));

        // Delete organization index
        txn.delete(Self::team_org_index_key(team.organization_id, team.id));

        // Delete name index
        txn.delete(Self::team_name_index_key(team.organization_id, &team.name));

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit team deletion: {}", e)))?;

        Ok(())
    }

    /// Count teams in an organization
    pub async fn count_by_organization(&self, org_id: i64) -> Result<usize> {
        let teams = self.list_by_organization(org_id).await?;
        Ok(teams.len())
    }

    /// Count active (non-deleted) teams in an organization
    pub async fn count_active_by_organization(&self, org_id: i64) -> Result<usize> {
        let teams = self.list_active_by_organization(org_id).await?;
        Ok(teams.len())
    }
}

/// Repository for OrganizationTeamMember entity operations
///
/// Key schema:
/// - team_member:{id} -> OrganizationTeamMember data
/// - team_member:team:{team_id}:{user_id} -> member_id (for unique constraint)
/// - team_member:user:{user_id}:{team_id} -> member_id (for user's teams lookup)
pub struct OrganizationTeamMemberRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> OrganizationTeamMemberRepository<S> {
    /// Create a new team member repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for member by ID
    fn member_key(id: i64) -> Vec<u8> {
        format!("team_member:{}", id).into_bytes()
    }

    /// Generate key for team-user unique constraint
    fn team_user_index_key(team_id: i64, user_id: i64) -> Vec<u8> {
        format!("team_member:team:{}:{}", team_id, user_id).into_bytes()
    }

    /// Generate key for user's team memberships
    fn user_team_index_key(user_id: i64, team_id: i64) -> Vec<u8> {
        format!("team_member:user:{}:{}", user_id, team_id).into_bytes()
    }

    /// Create a new team member
    pub async fn create(&self, member: OrganizationTeamMember) -> Result<()> {
        // Serialize member
        let member_data = serde_json::to_vec(&member)
            .map_err(|e| Error::Internal(format!("Failed to serialize team member: {}", e)))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {}", e)))?;

        // Check for duplicate member (team_id, user_id unique)
        let unique_key = Self::team_user_index_key(member.team_id, member.user_id);
        if self
            .storage
            .get(&unique_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to check duplicate member: {}", e)))?
            .is_some()
        {
            return Err(Error::AlreadyExists(
                "User is already a member of this team".to_string(),
            ));
        }

        // Store member record
        txn.set(Self::member_key(member.id), member_data.clone());

        // Store team-user index
        txn.set(unique_key, member.id.to_le_bytes().to_vec());

        // Store user-team index
        txn.set(
            Self::user_team_index_key(member.user_id, member.team_id),
            member.id.to_le_bytes().to_vec(),
        );

        // Commit transaction
        txn.commit().await.map_err(|e| {
            Error::Internal(format!("Failed to commit team member creation: {}", e))
        })?;

        Ok(())
    }

    /// Get a member by ID
    pub async fn get(&self, id: i64) -> Result<Option<OrganizationTeamMember>> {
        let key = Self::member_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get team member: {}", e)))?;

        match data {
            Some(bytes) => {
                let member: OrganizationTeamMember =
                    serde_json::from_slice(&bytes).map_err(|e| {
                        Error::Internal(format!("Failed to deserialize team member: {}", e))
                    })?;
                Ok(Some(member))
            }
            None => Ok(None),
        }
    }

    /// Get a member by team and user
    pub async fn get_by_team_and_user(
        &self,
        team_id: i64,
        user_id: i64,
    ) -> Result<Option<OrganizationTeamMember>> {
        let index_key = Self::team_user_index_key(team_id, user_id);
        let data =
            self.storage.get(&index_key).await.map_err(|e| {
                Error::Internal(format!("Failed to get member by team/user: {}", e))
            })?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::Internal("Invalid member index data".to_string()));
                }
                let id = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
                self.get(id).await
            }
            None => Ok(None),
        }
    }

    /// List all members for a team
    pub async fn list_by_team(&self, team_id: i64) -> Result<Vec<OrganizationTeamMember>> {
        let prefix = format!("team_member:team:{}:", team_id);
        let start = prefix.clone().into_bytes();
        let end = format!("team_member:team:{}~", team_id).into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get team members: {}", e)))?;

        let mut members = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(member) = self.get(id).await? {
                members.push(member);
            }
        }

        Ok(members)
    }

    /// List all teams for a user
    pub async fn list_by_user(&self, user_id: i64) -> Result<Vec<OrganizationTeamMember>> {
        let prefix = format!("team_member:user:{}:", user_id);
        let start = prefix.clone().into_bytes();
        let end = format!("team_member:user:{}~", user_id).into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get user teams: {}", e)))?;

        let mut members = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(member) = self.get(id).await? {
                members.push(member);
            }
        }

        Ok(members)
    }

    /// Update a team member (manager flag)
    pub async fn update(&self, member: OrganizationTeamMember) -> Result<()> {
        // Verify member exists
        self.get(member.id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Team member {} not found", member.id)))?;

        // Serialize updated member
        let member_data = serde_json::to_vec(&member)
            .map_err(|e| Error::Internal(format!("Failed to serialize team member: {}", e)))?;

        // Update member record
        self.storage
            .set(Self::member_key(member.id), member_data)
            .await
            .map_err(|e| Error::Internal(format!("Failed to update team member: {}", e)))?;

        Ok(())
    }

    /// Delete a team member (removes all indexes)
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get the member first to clean up indexes
        let member = self
            .get(id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Team member {} not found", id)))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {}", e)))?;

        // Delete member record
        txn.delete(Self::member_key(id));

        // Delete team-user index
        txn.delete(Self::team_user_index_key(member.team_id, member.user_id));

        // Delete user-team index
        txn.delete(Self::user_team_index_key(member.user_id, member.team_id));

        // Commit transaction
        txn.commit().await.map_err(|e| {
            Error::Internal(format!("Failed to commit team member deletion: {}", e))
        })?;

        Ok(())
    }

    /// Delete all members for a team (used when team is deleted)
    pub async fn delete_by_team(&self, team_id: i64) -> Result<()> {
        let members = self.list_by_team(team_id).await?;

        for member in members {
            self.delete(member.id).await?;
        }

        Ok(())
    }

    /// Count members in a team
    pub async fn count_by_team(&self, team_id: i64) -> Result<usize> {
        let members = self.list_by_team(team_id).await?;
        Ok(members.len())
    }
}

/// Repository for OrganizationTeamPermission entity operations
///
/// Key schema:
/// - team_permission:{id} -> OrganizationTeamPermission data
/// - team_permission:team:{team_id}:{permission} -> permission_id (for unique constraint)
/// - team_permission:team_list:{team_id}:{id} -> permission_id (for team's permissions listing)
pub struct OrganizationTeamPermissionRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> OrganizationTeamPermissionRepository<S> {
    /// Create a new team permission repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for permission by ID
    fn permission_key(id: i64) -> Vec<u8> {
        format!("team_permission:{}", id).into_bytes()
    }

    /// Generate key for team-permission unique constraint
    fn team_permission_index_key(team_id: i64, permission: OrganizationPermission) -> Vec<u8> {
        format!("team_permission:team:{}:{:?}", team_id, permission).into_bytes()
    }

    /// Generate key for team's permissions listing
    fn team_permission_list_key(team_id: i64, id: i64) -> Vec<u8> {
        format!("team_permission:team_list:{}:{}", team_id, id).into_bytes()
    }

    /// Create a new team permission
    pub async fn create(&self, permission: OrganizationTeamPermission) -> Result<()> {
        // Serialize permission
        let permission_data = serde_json::to_vec(&permission)
            .map_err(|e| Error::Internal(format!("Failed to serialize team permission: {}", e)))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {}", e)))?;

        // Check for duplicate permission (team_id, permission unique)
        let unique_key = Self::team_permission_index_key(permission.team_id, permission.permission);
        if self
            .storage
            .get(&unique_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to check duplicate permission: {}", e)))?
            .is_some()
        {
            return Err(Error::AlreadyExists(
                "Team already has this permission".to_string(),
            ));
        }

        // Store permission record
        txn.set(Self::permission_key(permission.id), permission_data.clone());

        // Store team-permission index
        txn.set(unique_key, permission.id.to_le_bytes().to_vec());

        // Store team permissions list index
        txn.set(
            Self::team_permission_list_key(permission.team_id, permission.id),
            permission.id.to_le_bytes().to_vec(),
        );

        // Commit transaction
        txn.commit().await.map_err(|e| {
            Error::Internal(format!("Failed to commit team permission creation: {}", e))
        })?;

        Ok(())
    }

    /// Get a permission by ID
    pub async fn get(&self, id: i64) -> Result<Option<OrganizationTeamPermission>> {
        let key = Self::permission_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get team permission: {}", e)))?;

        match data {
            Some(bytes) => {
                let permission: OrganizationTeamPermission = serde_json::from_slice(&bytes)
                    .map_err(|e| {
                        Error::Internal(format!("Failed to deserialize team permission: {}", e))
                    })?;
                Ok(Some(permission))
            }
            None => Ok(None),
        }
    }

    /// Get a permission by team and permission type
    pub async fn get_by_team_and_permission(
        &self,
        team_id: i64,
        permission: OrganizationPermission,
    ) -> Result<Option<OrganizationTeamPermission>> {
        let index_key = Self::team_permission_index_key(team_id, permission);
        let data = self.storage.get(&index_key).await.map_err(|e| {
            Error::Internal(format!(
                "Failed to get permission by team/permission: {}",
                e
            ))
        })?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::Internal("Invalid permission index data".to_string()));
                }
                let id = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
                self.get(id).await
            }
            None => Ok(None),
        }
    }

    /// List all permissions for a team
    pub async fn list_by_team(&self, team_id: i64) -> Result<Vec<OrganizationTeamPermission>> {
        let prefix = format!("team_permission:team_list:{}:", team_id);
        let start = prefix.clone().into_bytes();
        let end = format!("team_permission:team_list:{}~", team_id).into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get team permissions: {}", e)))?;

        let mut permissions = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(permission) = self.get(id).await? {
                permissions.push(permission);
            }
        }

        Ok(permissions)
    }

    /// Delete a team permission (removes all indexes)
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get the permission first to clean up indexes
        let permission = self
            .get(id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Team permission {} not found", id)))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {}", e)))?;

        // Delete permission record
        txn.delete(Self::permission_key(id));

        // Delete team-permission index
        txn.delete(Self::team_permission_index_key(
            permission.team_id,
            permission.permission,
        ));

        // Delete team permissions list index
        txn.delete(Self::team_permission_list_key(permission.team_id, id));

        // Commit transaction
        txn.commit().await.map_err(|e| {
            Error::Internal(format!("Failed to commit team permission deletion: {}", e))
        })?;

        Ok(())
    }

    /// Delete all permissions for a team (used when team is deleted)
    pub async fn delete_by_team(&self, team_id: i64) -> Result<()> {
        let permissions = self.list_by_team(team_id).await?;

        for permission in permissions {
            self.delete(permission.id).await?;
        }

        Ok(())
    }

    /// Count permissions for a team
    pub async fn count_by_team(&self, team_id: i64) -> Result<usize> {
        let permissions = self.list_by_team(team_id).await?;
        Ok(permissions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{
        OrganizationPermission, OrganizationTeam, OrganizationTeamMember,
        OrganizationTeamPermission,
    };
    use infera_management_storage::MemoryBackend;

    #[tokio::test]
    async fn test_create_and_get_team() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamRepository::new(storage);

        let team = OrganizationTeam::new(1, 100, "Engineering".to_string()).unwrap();
        repo.create(team.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert_eq!(retrieved.id, 1);
        assert_eq!(retrieved.name, "Engineering");
        assert_eq!(retrieved.organization_id, 100);
    }

    #[tokio::test]
    async fn test_team_duplicate_name() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamRepository::new(storage);

        let team1 = OrganizationTeam::new(1, 100, "Engineering".to_string()).unwrap();
        repo.create(team1).await.unwrap();

        let team2 = OrganizationTeam::new(2, 100, "Engineering".to_string()).unwrap();
        let result = repo.create(team2).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_teams_by_organization() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamRepository::new(storage);

        let team1 = OrganizationTeam::new(1, 100, "Engineering".to_string()).unwrap();
        let team2 = OrganizationTeam::new(2, 100, "Sales".to_string()).unwrap();
        let team3 = OrganizationTeam::new(3, 200, "Other".to_string()).unwrap();

        repo.create(team1).await.unwrap();
        repo.create(team2).await.unwrap();
        repo.create(team3).await.unwrap();

        let teams = repo.list_by_organization(100).await.unwrap();
        assert_eq!(teams.len(), 2);
    }

    #[tokio::test]
    async fn test_update_team_name() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamRepository::new(storage);

        let mut team = OrganizationTeam::new(1, 100, "Old Name".to_string()).unwrap();
        repo.create(team.clone()).await.unwrap();

        team.set_name("New Name".to_string()).unwrap();
        repo.update(team).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "New Name");
    }

    #[tokio::test]
    async fn test_delete_team() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamRepository::new(storage);

        let team = OrganizationTeam::new(1, 100, "Engineering".to_string()).unwrap();
        repo.create(team).await.unwrap();

        repo.delete(1).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_create_and_get_team_member() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamMemberRepository::new(storage);

        let member = OrganizationTeamMember::new(1, 100, 200, false);
        repo.create(member.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert_eq!(retrieved.id, 1);
        assert_eq!(retrieved.team_id, 100);
        assert_eq!(retrieved.user_id, 200);
        assert!(!retrieved.manager);
    }

    #[tokio::test]
    async fn test_team_member_duplicate() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamMemberRepository::new(storage);

        let member1 = OrganizationTeamMember::new(1, 100, 200, false);
        repo.create(member1).await.unwrap();

        let member2 = OrganizationTeamMember::new(2, 100, 200, true);
        let result = repo.create(member2).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_members_by_team() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamMemberRepository::new(storage);

        let member1 = OrganizationTeamMember::new(1, 100, 200, false);
        let member2 = OrganizationTeamMember::new(2, 100, 201, true);
        let member3 = OrganizationTeamMember::new(3, 200, 202, false);

        repo.create(member1).await.unwrap();
        repo.create(member2).await.unwrap();
        repo.create(member3).await.unwrap();

        let members = repo.list_by_team(100).await.unwrap();
        assert_eq!(members.len(), 2);
    }

    #[tokio::test]
    async fn test_list_teams_by_user() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamMemberRepository::new(storage);

        let member1 = OrganizationTeamMember::new(1, 100, 200, false);
        let member2 = OrganizationTeamMember::new(2, 101, 200, false);
        let member3 = OrganizationTeamMember::new(3, 102, 201, false);

        repo.create(member1).await.unwrap();
        repo.create(member2).await.unwrap();
        repo.create(member3).await.unwrap();

        let memberships = repo.list_by_user(200).await.unwrap();
        assert_eq!(memberships.len(), 2);
    }

    #[tokio::test]
    async fn test_update_team_member_manager_flag() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamMemberRepository::new(storage);

        let mut member = OrganizationTeamMember::new(1, 100, 200, false);
        repo.create(member.clone()).await.unwrap();

        member.set_manager(true);
        repo.update(member).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert!(retrieved.manager);
    }

    #[tokio::test]
    async fn test_delete_team_member() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamMemberRepository::new(storage);

        let member = OrganizationTeamMember::new(1, 100, 200, false);
        repo.create(member).await.unwrap();

        repo.delete(1).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_create_and_get_team_permission() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamPermissionRepository::new(storage);

        let permission = OrganizationTeamPermission::new(
            1,
            100,
            OrganizationPermission::OrgPermClientCreate,
            999,
        );
        repo.create(permission.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert_eq!(retrieved.id, 1);
        assert_eq!(retrieved.team_id, 100);
        assert_eq!(
            retrieved.permission,
            OrganizationPermission::OrgPermClientCreate
        );
        assert_eq!(retrieved.granted_by_user_id, 999);
    }

    #[tokio::test]
    async fn test_team_permission_duplicate() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamPermissionRepository::new(storage);

        let permission1 = OrganizationTeamPermission::new(
            1,
            100,
            OrganizationPermission::OrgPermClientCreate,
            999,
        );
        repo.create(permission1).await.unwrap();

        let permission2 = OrganizationTeamPermission::new(
            2,
            100,
            OrganizationPermission::OrgPermClientCreate,
            998,
        );
        let result = repo.create(permission2).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_permissions_by_team() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamPermissionRepository::new(storage);

        let perm1 = OrganizationTeamPermission::new(
            1,
            100,
            OrganizationPermission::OrgPermClientCreate,
            999,
        );
        let perm2 = OrganizationTeamPermission::new(
            2,
            100,
            OrganizationPermission::OrgPermVaultCreate,
            999,
        );
        let perm3 =
            OrganizationTeamPermission::new(3, 200, OrganizationPermission::OrgPermTeamCreate, 999);

        repo.create(perm1).await.unwrap();
        repo.create(perm2).await.unwrap();
        repo.create(perm3).await.unwrap();

        let permissions = repo.list_by_team(100).await.unwrap();
        assert_eq!(permissions.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_team_permission() {
        let storage = MemoryBackend::new();
        let repo = OrganizationTeamPermissionRepository::new(storage);

        let permission = OrganizationTeamPermission::new(
            1,
            100,
            OrganizationPermission::OrgPermClientCreate,
            999,
        );
        repo.create(permission).await.unwrap();

        repo.delete(1).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert!(retrieved.is_none());
    }
}
