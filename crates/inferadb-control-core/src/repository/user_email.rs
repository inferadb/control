use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::UserEmail,
    error::{Error, Result},
};

/// Repository for UserEmail entity operations
///
/// Key schema:
/// - user_email:{id} -> UserEmail data
/// - user_email:user:{user_id}:{email} -> email_id (for user's email lookups)
/// - user_email:email:{email} -> email_id (for unique email lookups)
/// - user_email:user:{user_id}:primary -> email_id (for primary email lookup)
pub struct UserEmailRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> UserEmailRepository<S> {
    /// Create a new user email repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for email by ID
    fn email_key(id: i64) -> Vec<u8> {
        format!("user_email:{id}").into_bytes()
    }

    /// Generate key for user's email index
    fn user_email_index_key(user_id: i64, email: &str) -> Vec<u8> {
        format!("user_email:user:{}:{}", user_id, email.to_lowercase()).into_bytes()
    }

    /// Generate key for global email index
    fn email_index_key(email: &str) -> Vec<u8> {
        format!("user_email:email:{}", email.to_lowercase()).into_bytes()
    }

    /// Generate key for primary email index
    fn primary_email_index_key(user_id: i64) -> Vec<u8> {
        format!("user_email:user:{user_id}:primary").into_bytes()
    }

    /// Create a new user email
    ///
    /// This operation is atomic - all indexes are created together
    pub async fn create(&self, email: UserEmail) -> Result<()> {
        // Check if email already exists globally
        let email_idx_key = Self::email_index_key(&email.email);
        if self
            .storage
            .get(&email_idx_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to check email uniqueness: {e}")))?
            .is_some()
        {
            return Err(Error::Validation(format!("Email '{}' is already in use", email.email)));
        }

        // If this is a primary email, check if user already has one
        if email.primary {
            let primary_key = Self::primary_email_index_key(email.user_id);
            if self
                .storage
                .get(&primary_key)
                .await
                .map_err(|e| Error::Internal(format!("Failed to check primary email: {e}")))?
                .is_some()
            {
                return Err(Error::Validation("User already has a primary email".to_string()));
            }
        }

        // Serialize email
        let email_data = serde_json::to_vec(&email)
            .map_err(|e| Error::Internal(format!("Failed to serialize email: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Store email record
        txn.set(Self::email_key(email.id), email_data);

        // Store user's email index
        txn.set(
            Self::user_email_index_key(email.user_id, &email.email),
            email.id.to_le_bytes().to_vec(),
        );

        // Store global email index
        txn.set(email_idx_key, email.id.to_le_bytes().to_vec());

        // Store primary email index if this is primary
        if email.primary {
            txn.set(Self::primary_email_index_key(email.user_id), email.id.to_le_bytes().to_vec());
        }

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit email creation: {e}")))?;

        Ok(())
    }

    /// Get an email by ID
    pub async fn get(&self, id: i64) -> Result<Option<UserEmail>> {
        let key = Self::email_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get email: {e}")))?;

        match data {
            Some(bytes) => {
                let email: UserEmail = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("Failed to deserialize email: {e}")))?;
                Ok(Some(email))
            },
            None => Ok(None),
        }
    }

    /// Get an email by email address (case-insensitive)
    pub async fn get_by_email(&self, email: &str) -> Result<Option<UserEmail>> {
        let email_key = Self::email_index_key(email);
        let id_data = self
            .storage
            .get(&email_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to lookup email: {e}")))?;

        match id_data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::Internal("Invalid email ID in email index".to_string()));
                }
                let id = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// Get user's primary email
    pub async fn get_primary_email(&self, user_id: i64) -> Result<Option<UserEmail>> {
        let primary_key = Self::primary_email_index_key(user_id);
        let id_data = self
            .storage
            .get(&primary_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to lookup primary email: {e}")))?;

        match id_data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::Internal("Invalid email ID in primary index".to_string()));
                }
                let id = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// Get all emails for a user
    pub async fn get_user_emails(&self, user_id: i64) -> Result<Vec<UserEmail>> {
        // Use range query to get all emails for this user
        let prefix = format!("user_email:user:{user_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("user_email:user:{user_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get user emails: {e}")))?;

        let mut emails = Vec::new();
        for kv in kvs {
            // Skip the primary index key
            let key_str = String::from_utf8_lossy(&kv.key);
            if key_str.ends_with(":primary") {
                continue;
            }

            if kv.value.len() != 8 {
                continue; // Skip invalid entries
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(email) = self.get(id).await? {
                emails.push(email);
            }
        }

        // Sort by ID to ensure consistent ordering
        emails.sort_by_key(|e| e.id);

        Ok(emails)
    }

    /// Update an email
    pub async fn update(&self, email: UserEmail) -> Result<()> {
        // Get existing email
        let existing = self
            .get(email.id)
            .await?
            .ok_or_else(|| Error::NotFound("Email not found".to_string()))?;

        // Check if email address changed (should not be allowed in typical flows)
        if existing.email != email.email {
            return Err(Error::Validation("Email address cannot be changed directly".to_string()));
        }

        // Check if primary status changed
        let primary_changed = existing.primary != email.primary;

        // If becoming primary, ensure no other primary exists
        if email.primary && !existing.primary {
            let current_primary = self.get_primary_email(email.user_id).await?;
            if current_primary.is_some() {
                return Err(Error::Validation(
                    "User already has a primary email. Unset the current primary first."
                        .to_string(),
                ));
            }
        }

        // Serialize email
        let email_data = serde_json::to_vec(&email)
            .map_err(|e| Error::Internal(format!("Failed to serialize email: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Update email record
        txn.set(Self::email_key(email.id), email_data);

        // Update primary index if status changed
        if primary_changed {
            if email.primary {
                // Add primary index
                txn.set(
                    Self::primary_email_index_key(email.user_id),
                    email.id.to_le_bytes().to_vec(),
                );
            } else {
                // Remove primary index
                txn.delete(Self::primary_email_index_key(email.user_id));
            }
        }

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit email update: {e}")))?;

        Ok(())
    }

    /// Delete an email and all associated indexes
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get email to remove indexes
        let email =
            self.get(id).await?.ok_or_else(|| Error::NotFound("Email not found".to_string()))?;

        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Delete email record
        txn.delete(Self::email_key(id));

        // Delete user's email index
        txn.delete(Self::user_email_index_key(email.user_id, &email.email));

        // Delete global email index
        txn.delete(Self::email_index_key(&email.email));

        // Delete primary index if this was primary
        if email.primary {
            txn.delete(Self::primary_email_index_key(email.user_id));
        }

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit email deletion: {e}")))?;

        Ok(())
    }

    /// Check if an email address is in use (case-insensitive)
    pub async fn is_email_in_use(&self, email: &str) -> Result<bool> {
        Ok(self.get_by_email(email).await?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use inferadb_control_storage::MemoryBackend;

    use super::*;

    async fn create_test_email(id: i64, user_id: i64, email: &str, primary: bool) -> UserEmail {
        UserEmail::builder()
            .id(id)
            .user_id(user_id)
            .email(email.to_string())
            .primary(primary)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_create_email() {
        let storage = MemoryBackend::new();
        let repo = UserEmailRepository::new(storage);
        let email = create_test_email(1, 100, "alice@example.com", true).await;

        repo.create(email.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert_eq!(retrieved.email, email.email);
        assert_eq!(retrieved.user_id, email.user_id);
        assert!(retrieved.primary);
    }

    #[tokio::test]
    async fn test_create_duplicate_email() {
        let storage = MemoryBackend::new();
        let repo = UserEmailRepository::new(storage);

        let email1 = create_test_email(1, 100, "alice@example.com", true).await;
        let email2 = create_test_email(2, 101, "alice@example.com", true).await;

        repo.create(email1).await.unwrap();
        let result = repo.create(email2).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Validation(_)));
    }

    #[tokio::test]
    async fn test_get_by_email() {
        let storage = MemoryBackend::new();
        let repo = UserEmailRepository::new(storage);
        let email = create_test_email(1, 100, "alice@example.com", true).await;

        repo.create(email.clone()).await.unwrap();

        // Test case-insensitive lookup
        let retrieved = repo.get_by_email("ALICE@EXAMPLE.COM").await.unwrap().unwrap();
        assert_eq!(retrieved.email, "alice@example.com");
    }

    #[tokio::test]
    async fn test_get_primary_email() {
        let storage = MemoryBackend::new();
        let repo = UserEmailRepository::new(storage);
        let email = create_test_email(1, 100, "alice@example.com", true).await;

        repo.create(email.clone()).await.unwrap();

        let primary = repo.get_primary_email(100).await.unwrap().unwrap();
        assert_eq!(primary.id, 1);
        assert!(primary.primary);
    }

    #[tokio::test]
    async fn test_get_user_emails() {
        let storage = MemoryBackend::new();
        let repo = UserEmailRepository::new(storage);

        let email1 = create_test_email(1, 100, "alice@example.com", true).await;
        let email2 = create_test_email(2, 100, "alice2@example.com", false).await;

        repo.create(email1).await.unwrap();
        repo.create(email2).await.unwrap();

        let emails = repo.get_user_emails(100).await.unwrap();
        assert_eq!(emails.len(), 2);
    }

    #[tokio::test]
    async fn test_update_verification() {
        let storage = MemoryBackend::new();
        let repo = UserEmailRepository::new(storage);
        let mut email = create_test_email(1, 100, "alice@example.com", true).await;

        repo.create(email.clone()).await.unwrap();

        // Verify email
        email.verify();
        repo.update(email.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert!(retrieved.verified_at.is_some());
    }

    #[tokio::test]
    async fn test_set_primary() {
        let storage = MemoryBackend::new();
        let repo = UserEmailRepository::new(storage);
        let mut email = create_test_email(1, 100, "alice@example.com", false).await;

        repo.create(email.clone()).await.unwrap();

        // Set as primary
        email.set_primary(true);
        repo.update(email.clone()).await.unwrap();

        let primary = repo.get_primary_email(100).await.unwrap().unwrap();
        assert_eq!(primary.id, 1);
    }

    #[tokio::test]
    async fn test_delete_email() {
        let storage = MemoryBackend::new();
        let repo = UserEmailRepository::new(storage);
        let email = create_test_email(1, 100, "alice@example.com", true).await;

        repo.create(email.clone()).await.unwrap();
        repo.delete(1).await.unwrap();

        // Email should not exist
        assert!(repo.get(1).await.unwrap().is_none());

        // Email should be available again
        assert!(!repo.is_email_in_use("alice@example.com").await.unwrap());
    }

    #[tokio::test]
    async fn test_multiple_primary_prevention() {
        let storage = MemoryBackend::new();
        let repo = UserEmailRepository::new(storage);

        let email1 = create_test_email(1, 100, "alice@example.com", true).await;
        let email2 = create_test_email(2, 100, "alice2@example.com", true).await;

        repo.create(email1).await.unwrap();
        let result = repo.create(email2).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Validation(_)));
    }
}
