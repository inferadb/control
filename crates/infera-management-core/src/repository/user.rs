use crate::entities::User;
use crate::error::{Error, Result};
use infera_management_storage::StorageBackend;

/// Repository for User entity operations
///
/// Key schema:
/// - user:{id} -> User data
/// - user:name:{name} -> user_id (for unique name lookups)
pub struct UserRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> UserRepository<S> {
    /// Create a new user repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for user by ID
    fn user_key(id: i64) -> Vec<u8> {
        format!("user:{}", id).into_bytes()
    }

    /// Generate key for name index
    fn name_index_key(name: &str) -> Vec<u8> {
        format!("user:name:{}", name.to_lowercase()).into_bytes()
    }

    /// Create a new user
    ///
    /// This operation is atomic - either both the user record and name index
    /// are created, or neither is.
    pub async fn create(&self, user: User) -> Result<()> {
        // Serialize user
        let user_data = serde_json::to_vec(&user)
            .map_err(|e| Error::Internal(format!("Failed to serialize user: {}", e)))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {}", e)))?;

        // Store user record
        txn.set(Self::user_key(user.id), user_data);

        // Store name index (not enforcing uniqueness, just for lookup)
        let name_key = Self::name_index_key(&user.name);
        txn.set(name_key, user.id.to_le_bytes().to_vec());

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit user creation: {}", e)))?;

        Ok(())
    }

    /// Get a user by ID
    pub async fn get(&self, id: i64) -> Result<Option<User>> {
        let key = Self::user_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get user: {}", e)))?;

        match data {
            Some(bytes) => {
                let user: User = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("Failed to deserialize user: {}", e)))?;

                // Filter out soft-deleted users
                if user.deleted_at.is_some() {
                    Ok(None)
                } else {
                    Ok(Some(user))
                }
            }
            None => Ok(None),
        }
    }

    /// Get a user by name (case-insensitive)
    pub async fn get_by_name(&self, name: &str) -> Result<Option<User>> {
        let name_key = Self::name_index_key(name);
        let id_data = self
            .storage
            .get(&name_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to lookup user by name: {}", e)))?;

        match id_data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::Internal("Invalid user ID in name index".to_string()));
                }
                let id = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
                self.get(id).await
            }
            None => Ok(None),
        }
    }

    /// Update a user
    ///
    /// Note: Name changes require updating the name index atomically
    pub async fn update(&self, user: User) -> Result<()> {
        // Get existing user to check if name changed
        let existing = self.get(user.id).await?;
        let existing = existing.ok_or_else(|| Error::NotFound("User not found".to_string()))?;

        let name_changed = existing.name != user.name;

        // Serialize user
        let user_data = serde_json::to_vec(&user)
            .map_err(|e| Error::Internal(format!("Failed to serialize user: {}", e)))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {}", e)))?;

        // Update user record
        txn.set(Self::user_key(user.id), user_data);

        // Update name index if name changed
        if name_changed {
            // Remove old name index
            txn.delete(Self::name_index_key(&existing.name));
            // Add new name index
            txn.set(
                Self::name_index_key(&user.name),
                user.id.to_le_bytes().to_vec(),
            );
        }

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit user update: {}", e)))?;

        Ok(())
    }

    /// Soft delete a user
    pub async fn soft_delete(&self, id: i64) -> Result<()> {
        let mut user = self
            .get(id)
            .await?
            .ok_or_else(|| Error::NotFound("User not found".to_string()))?;

        user.soft_delete();
        self.update(user).await
    }

    /// Hard delete a user and all associated indexes
    ///
    /// Warning: This permanently removes the user from storage
    pub async fn hard_delete(&self, id: i64) -> Result<()> {
        // Get user to remove name index
        let user = self.get(id).await?;

        if let Some(user) = user {
            let mut txn = self
                .storage
                .transaction()
                .await
                .map_err(|e| Error::Internal(format!("Failed to start transaction: {}", e)))?;

            // Delete user record
            txn.delete(Self::user_key(id));

            // Delete name index
            txn.delete(Self::name_index_key(&user.name));

            // Commit transaction
            txn.commit()
                .await
                .map_err(|e| Error::Internal(format!("Failed to commit user deletion: {}", e)))?;
        }

        Ok(())
    }

    /// Check if a user exists by ID (excluding soft-deleted)
    pub async fn exists(&self, id: i64) -> Result<bool> {
        Ok(self.get(id).await?.is_some())
    }

    /// Check if a name is available (case-insensitive)
    pub async fn is_name_available(&self, name: &str) -> Result<bool> {
        Ok(self.get_by_name(name).await?.is_none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use infera_management_storage::MemoryBackend;

    async fn create_test_user(id: i64, name: &str) -> User {
        User::new(id, name.to_string(), None).unwrap()
    }

    #[tokio::test]
    async fn test_create_user() {
        let storage = MemoryBackend::new();
        let repo = UserRepository::new(storage);
        let user = create_test_user(1, "alice").await;

        repo.create(user.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert_eq!(retrieved.id, user.id);
        assert_eq!(retrieved.name, user.name);
    }

    #[tokio::test]
    async fn test_get_by_name() {
        let storage = MemoryBackend::new();
        let repo = UserRepository::new(storage);
        let user = create_test_user(1, "alice").await;

        repo.create(user.clone()).await.unwrap();

        // Test case-insensitive lookup
        let retrieved = repo.get_by_name("ALICE").await.unwrap().unwrap();
        assert_eq!(retrieved.id, user.id);
        assert_eq!(retrieved.name, user.name);
    }

    #[tokio::test]
    async fn test_update_user() {
        let storage = MemoryBackend::new();
        let repo = UserRepository::new(storage);
        let mut user = create_test_user(1, "alice").await;

        repo.create(user.clone()).await.unwrap();

        // Update user
        user.accept_tos();
        repo.update(user.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert!(retrieved.tos_accepted_at.is_some());
    }

    #[tokio::test]
    async fn test_update_name() {
        let storage = MemoryBackend::new();
        let repo = UserRepository::new(storage);
        let mut user = create_test_user(1, "alice").await;

        repo.create(user.clone()).await.unwrap();

        // Change name
        user.name = "alice2".to_string();
        repo.update(user.clone()).await.unwrap();

        // Old name should not exist
        assert!(repo.get_by_name("alice").await.unwrap().is_none());

        // New name should work
        let retrieved = repo.get_by_name("alice2").await.unwrap().unwrap();
        assert_eq!(retrieved.id, 1);
    }

    #[tokio::test]
    async fn test_soft_delete() {
        let storage = MemoryBackend::new();
        let repo = UserRepository::new(storage);
        let user = create_test_user(1, "alice").await;

        repo.create(user.clone()).await.unwrap();
        repo.soft_delete(1).await.unwrap();

        // Soft-deleted user should not be retrieved
        assert!(repo.get(1).await.unwrap().is_none());
        assert!(!repo.exists(1).await.unwrap());
    }

    #[tokio::test]
    async fn test_hard_delete() {
        let storage = MemoryBackend::new();
        let repo = UserRepository::new(storage);
        let user = create_test_user(1, "alice").await;

        repo.create(user.clone()).await.unwrap();
        repo.hard_delete(1).await.unwrap();

        // User should not exist
        assert!(repo.get(1).await.unwrap().is_none());

        // Name should be available again
        assert!(repo.is_name_available("alice").await.unwrap());
    }

    #[tokio::test]
    async fn test_is_name_available() {
        let storage = MemoryBackend::new();
        let repo = UserRepository::new(storage);

        assert!(repo.is_name_available("alice").await.unwrap());

        let user = create_test_user(1, "alice").await;
        repo.create(user).await.unwrap();

        assert!(!repo.is_name_available("alice").await.unwrap());
        assert!(!repo.is_name_available("ALICE").await.unwrap()); // Case-insensitive
    }
}
