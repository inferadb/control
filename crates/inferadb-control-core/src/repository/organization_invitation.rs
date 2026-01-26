use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::OrganizationInvitation,
    error::{Error, Result},
};

/// Repository for OrganizationInvitation entity operations
///
/// Key schema:
/// - invite:{id} -> OrganizationInvitation data
/// - invite:token:{token} -> invitation_id (for token lookup)
/// - invite:org:{org_id}:{idx} -> invitation_id (for org listing)
/// - invite:email:{email}:{org_id} -> invitation_id (for duplicate checking)
pub struct OrganizationInvitationRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> OrganizationInvitationRepository<S> {
    /// Create a new organization invitation repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for invitation by ID
    fn invitation_key(id: i64) -> Vec<u8> {
        format!("invite:{id}").into_bytes()
    }

    /// Generate key for invitation token index
    fn invitation_token_index_key(token: &str) -> Vec<u8> {
        format!("invite:token:{token}").into_bytes()
    }

    /// Generate key for invitation by organization index
    fn invitation_org_index_key(org_id: i64, idx: i64) -> Vec<u8> {
        format!("invite:org:{org_id}:{idx}").into_bytes()
    }

    /// Generate key for invitation by email and organization (for duplicate checking)
    fn invitation_email_org_index_key(email: &str, org_id: i64) -> Vec<u8> {
        format!("invite:email:{}:{}", email.to_lowercase(), org_id).into_bytes()
    }

    /// Create a new organization invitation
    pub async fn create(&self, invitation: OrganizationInvitation) -> Result<()> {
        // Serialize invitation
        let invitation_data = serde_json::to_vec(&invitation)
            .map_err(|e| Error::Internal(format!("Failed to serialize invitation: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Check for duplicate invitation (email + org)
        let email_org_key =
            Self::invitation_email_org_index_key(&invitation.email, invitation.organization_id);
        if self
            .storage
            .get(&email_org_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to check duplicate invitation: {e}")))?
            .is_some()
        {
            return Err(Error::AlreadyExists(format!(
                "An invitation for '{}' already exists in this organization",
                invitation.email
            )));
        }

        // Store invitation record
        txn.set(Self::invitation_key(invitation.id), invitation_data.clone());

        // Store token index
        txn.set(
            Self::invitation_token_index_key(&invitation.token),
            invitation.id.to_le_bytes().to_vec(),
        );

        // Store organization index (using invitation ID as index)
        txn.set(
            Self::invitation_org_index_key(invitation.organization_id, invitation.id),
            invitation.id.to_le_bytes().to_vec(),
        );

        // Store email+org index
        txn.set(email_org_key, invitation.id.to_le_bytes().to_vec());

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit invitation creation: {e}")))?;

        Ok(())
    }

    /// Get an invitation by ID
    pub async fn get(&self, id: i64) -> Result<Option<OrganizationInvitation>> {
        let key = Self::invitation_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get invitation: {e}")))?;

        match data {
            Some(bytes) => {
                let invitation: OrganizationInvitation =
                    serde_json::from_slice(&bytes).map_err(|e| {
                        Error::Internal(format!("Failed to deserialize invitation: {e}"))
                    })?;
                Ok(Some(invitation))
            },
            None => Ok(None),
        }
    }

    /// Get an invitation by token
    pub async fn get_by_token(&self, token: &str) -> Result<Option<OrganizationInvitation>> {
        let index_key = Self::invitation_token_index_key(token);
        let data = self
            .storage
            .get(&index_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get invitation by token: {e}")))?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::Internal("Invalid invitation token index data".to_string()));
                }
                let id = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// List all active invitations for an organization
    pub async fn list_by_organization(&self, org_id: i64) -> Result<Vec<OrganizationInvitation>> {
        let prefix = format!("invite:org:{org_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("invite:org:{org_id}~").into_bytes();

        let kvs =
            self.storage.get_range(start..end).await.map_err(|e| {
                Error::Internal(format!("Failed to get organization invitations: {e}"))
            })?;

        let mut invitations = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(invitation) = self.get(id).await? {
                invitations.push(invitation);
            }
        }

        Ok(invitations)
    }

    /// Check if an invitation exists for an email in an organization
    pub async fn exists_for_email_in_org(&self, email: &str, org_id: i64) -> Result<bool> {
        let key = Self::invitation_email_org_index_key(email, org_id);
        let data =
            self.storage.get(&key).await.map_err(|e| {
                Error::Internal(format!("Failed to check invitation existence: {e}"))
            })?;

        Ok(data.is_some())
    }

    /// Delete an invitation
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get the invitation first to clean up indexes
        let invitation = self
            .get(id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Invitation {id} not found")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Delete invitation record
        txn.delete(Self::invitation_key(id));

        // Delete token index
        txn.delete(Self::invitation_token_index_key(&invitation.token));

        // Delete organization index
        txn.delete(Self::invitation_org_index_key(invitation.organization_id, invitation.id));

        // Delete email+org index
        txn.delete(Self::invitation_email_org_index_key(
            &invitation.email,
            invitation.organization_id,
        ));

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit invitation deletion: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use inferadb_control_storage::Backend;
    use inferadb_control_types::entities::OrganizationRole;

    use super::*;

    fn create_test_repo() -> OrganizationInvitationRepository<Backend> {
        OrganizationInvitationRepository::new(Backend::memory())
    }

    fn create_test_invitation(id: i64, org_id: i64, email: &str) -> Result<OrganizationInvitation> {
        let token = OrganizationInvitation::generate_token()?;
        OrganizationInvitation::builder()
            .id(id)
            .organization_id(org_id)
            .invited_by_user_id(999)
            .email(email.to_string())
            .role(OrganizationRole::Member)
            .token(token)
            .create()
    }

    #[tokio::test]
    async fn test_create_and_get_invitation() {
        let repo = create_test_repo();
        let invitation = create_test_invitation(1, 100, "test@example.com").unwrap();
        let token = invitation.token.clone();

        repo.create(invitation.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert_eq!(retrieved, Some(invitation.clone()));

        let by_token = repo.get_by_token(&token).await.unwrap();
        assert_eq!(by_token, Some(invitation));
    }

    #[tokio::test]
    async fn test_duplicate_invitation_rejected() {
        let repo = create_test_repo();
        let invitation1 = create_test_invitation(1, 100, "test@example.com").unwrap();
        let invitation2 = create_test_invitation(2, 100, "test@example.com").unwrap();

        repo.create(invitation1).await.unwrap();

        let result = repo.create(invitation2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn test_list_by_organization() {
        let repo = create_test_repo();
        let inv1 = create_test_invitation(1, 100, "user1@example.com").unwrap();
        let inv2 = create_test_invitation(2, 100, "user2@example.com").unwrap();
        let inv3 = create_test_invitation(3, 200, "user3@example.com").unwrap();

        repo.create(inv1).await.unwrap();
        repo.create(inv2).await.unwrap();
        repo.create(inv3).await.unwrap();

        let org_100_invitations = repo.list_by_organization(100).await.unwrap();
        assert_eq!(org_100_invitations.len(), 2);

        let org_200_invitations = repo.list_by_organization(200).await.unwrap();
        assert_eq!(org_200_invitations.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_invitation() {
        let repo = create_test_repo();
        let invitation = create_test_invitation(1, 100, "test@example.com").unwrap();
        let token = invitation.token.clone();

        repo.create(invitation).await.unwrap();
        assert!(repo.get(1).await.unwrap().is_some());

        repo.delete(1).await.unwrap();
        assert!(repo.get(1).await.unwrap().is_none());
        assert!(repo.get_by_token(&token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_exists_for_email_in_org() {
        let repo = create_test_repo();
        let invitation = create_test_invitation(1, 100, "test@example.com").unwrap();

        assert!(!repo.exists_for_email_in_org("test@example.com", 100).await.unwrap());

        repo.create(invitation).await.unwrap();

        assert!(repo.exists_for_email_in_org("test@example.com", 100).await.unwrap());
        assert!(!repo.exists_for_email_in_org("test@example.com", 200).await.unwrap());
    }
}
