use inferadb_control_storage::{StorageBackend, to_storage_range};
use inferadb_control_types::{
    OrganizationSlug,
    entities::OrganizationInvitation,
    error::{Error, Result},
};

/// Repository for OrganizationInvitation entity operations
///
/// Key schema:
/// - invite:{id} -> OrganizationInvitation data
/// - invite:token:{token} -> invitation_id (for token lookup)
/// - invite:org:{organization}:{idx} -> invitation_id (for org listing)
/// - invite:email:{email}:{organization} -> invitation_id (for duplicate checking)
pub struct OrganizationInvitationRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> OrganizationInvitationRepository<S> {
    /// Create a new organization invitation repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for invitation by ID
    fn invitation_key(id: u64) -> Vec<u8> {
        format!("invite:{id}").into_bytes()
    }

    /// Generate key for invitation token index
    fn invitation_token_index_key(token: &str) -> Vec<u8> {
        format!("invite:token:{token}").into_bytes()
    }

    /// Generate key for invitation by organization index
    fn invitation_org_index_key(organization: OrganizationSlug, idx: u64) -> Vec<u8> {
        format!("invite:org:{organization}:{idx}").into_bytes()
    }

    /// Generate key for invitation by email and organization (for duplicate checking)
    fn invitation_email_org_index_key(email: &str, organization: OrganizationSlug) -> Vec<u8> {
        format!("invite:email:{}:{}", email.to_lowercase(), organization).into_bytes()
    }

    /// Create a new organization invitation
    pub async fn create(&self, invitation: OrganizationInvitation) -> Result<()> {
        // Serialize invitation
        let invitation_data = serde_json::to_vec(&invitation)
            .map_err(|e| Error::internal(format!("Failed to serialize invitation: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self.storage.transaction().await?;

        // Check for duplicate invitation (email + org)
        let email_org_key =
            Self::invitation_email_org_index_key(&invitation.email, invitation.organization);
        if self.storage.get(&email_org_key).await?.is_some() {
            return Err(Error::already_exists(format!(
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
            Self::invitation_org_index_key(invitation.organization, invitation.id),
            invitation.id.to_le_bytes().to_vec(),
        );

        // Store email+org index
        txn.set(email_org_key, invitation.id.to_le_bytes().to_vec());

        // Commit transaction
        txn.commit().await?;

        Ok(())
    }

    /// Get an invitation by ID
    pub async fn get(&self, id: u64) -> Result<Option<OrganizationInvitation>> {
        let key = Self::invitation_key(id);
        let data = self.storage.get(&key).await?;

        match data {
            Some(bytes) => {
                let invitation: OrganizationInvitation =
                    serde_json::from_slice(&bytes).map_err(|e| {
                        Error::internal(format!("Failed to deserialize invitation: {e}"))
                    })?;
                Ok(Some(invitation))
            },
            None => Ok(None),
        }
    }

    /// Get an invitation by token
    pub async fn get_by_token(&self, token: &str) -> Result<Option<OrganizationInvitation>> {
        let index_key = Self::invitation_token_index_key(token);
        let data = self.storage.get(&index_key).await?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::internal("Invalid invitation token index data".to_string()));
                }
                let id = super::parse_u64_id(&bytes)?;
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// List all active invitations for an organization
    pub async fn list_by_organization(
        &self,
        organization: OrganizationSlug,
    ) -> Result<Vec<OrganizationInvitation>> {
        let prefix = format!("invite:org:{organization}:");
        let start = prefix.clone().into_bytes();
        let end = format!("invite:org:{organization}~").into_bytes();

        let kvs = self.storage.get_range(to_storage_range(start..end)).await?;

        let mut invitations = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_u64_id(&kv.value) else { continue };
            if let Some(invitation) = self.get(id).await? {
                invitations.push(invitation);
            }
        }

        Ok(invitations)
    }

    /// Check if an invitation exists for an email in an organization
    pub async fn exists_for_email_in_org(
        &self,
        email: &str,
        organization: OrganizationSlug,
    ) -> Result<bool> {
        let key = Self::invitation_email_org_index_key(email, organization);
        let data = self.storage.get(&key).await?;

        Ok(data.is_some())
    }

    /// Delete an invitation
    pub async fn delete(&self, id: u64) -> Result<()> {
        // Get the invitation first to clean up indexes
        let invitation = self
            .get(id)
            .await?
            .ok_or_else(|| Error::not_found(format!("Invitation {id} not found")))?;

        // Use transaction for atomicity
        let mut txn = self.storage.transaction().await?;

        // Delete invitation record
        txn.delete(Self::invitation_key(id));

        // Delete token index
        txn.delete(Self::invitation_token_index_key(&invitation.token));

        // Delete organization index
        txn.delete(Self::invitation_org_index_key(invitation.organization, invitation.id));

        // Delete email+org index
        txn.delete(Self::invitation_email_org_index_key(
            &invitation.email,
            invitation.organization,
        ));

        // Commit transaction
        txn.commit().await?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_control_storage::MemoryBackend;
    use inferadb_control_types::{OrganizationSlug, entities::OrganizationRole};

    use super::*;

    fn create_test_repo() -> OrganizationInvitationRepository<MemoryBackend> {
        OrganizationInvitationRepository::new(MemoryBackend::new())
    }

    fn create_test_invitation(
        id: u64,
        organization: OrganizationSlug,
        email: &str,
    ) -> Result<OrganizationInvitation> {
        let token = OrganizationInvitation::generate_token()?;
        OrganizationInvitation::builder()
            .id(id)
            .organization(organization)
            .invited_by_user_id(999_u64)
            .email(email.to_string())
            .role(OrganizationRole::Member)
            .token(token)
            .create()
    }

    #[tokio::test]
    async fn test_create_and_get_invitation() {
        let repo = create_test_repo();
        let invitation =
            create_test_invitation(1, OrganizationSlug::from(100_u64), "test@example.com").unwrap();
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
        let invitation1 =
            create_test_invitation(1, OrganizationSlug::from(100_u64), "test@example.com").unwrap();
        let invitation2 =
            create_test_invitation(2, OrganizationSlug::from(100_u64), "test@example.com").unwrap();

        repo.create(invitation1).await.unwrap();

        let result = repo.create(invitation2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists { .. }));
    }

    #[tokio::test]
    async fn test_list_by_organization() {
        let repo = create_test_repo();
        let inv1 = create_test_invitation(1, OrganizationSlug::from(100_u64), "user1@example.com")
            .unwrap();
        let inv2 = create_test_invitation(2, OrganizationSlug::from(100_u64), "user2@example.com")
            .unwrap();
        let inv3 = create_test_invitation(3, OrganizationSlug::from(200_u64), "user3@example.com")
            .unwrap();

        repo.create(inv1).await.unwrap();
        repo.create(inv2).await.unwrap();
        repo.create(inv3).await.unwrap();

        let org_100_invitations =
            repo.list_by_organization(OrganizationSlug::from(100_u64)).await.unwrap();
        assert_eq!(org_100_invitations.len(), 2);

        let org_200_invitations =
            repo.list_by_organization(OrganizationSlug::from(200_u64)).await.unwrap();
        assert_eq!(org_200_invitations.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_invitation() {
        let repo = create_test_repo();
        let invitation =
            create_test_invitation(1, OrganizationSlug::from(100_u64), "test@example.com").unwrap();
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
        let invitation =
            create_test_invitation(1, OrganizationSlug::from(100_u64), "test@example.com").unwrap();

        assert!(
            !repo
                .exists_for_email_in_org("test@example.com", OrganizationSlug::from(100_u64))
                .await
                .unwrap()
        );

        repo.create(invitation).await.unwrap();

        assert!(
            repo.exists_for_email_in_org("test@example.com", OrganizationSlug::from(100_u64))
                .await
                .unwrap()
        );
        assert!(
            !repo
                .exists_for_email_in_org("test@example.com", OrganizationSlug::from(200_u64))
                .await
                .unwrap()
        );
    }
}
