use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::UserEmailVerificationToken,
    error::{Error, Result},
};

/// Repository for UserEmailVerificationToken entity operations
///
/// Key schema:
/// - email_verify_token:{id} -> UserEmailVerificationToken data
/// - email_verify_token:token:{token} -> token_id (for token lookup)
/// - email_verify_token:email:{user_email_id}:{id} -> token_id (for email's token lookups)
pub struct UserEmailVerificationTokenRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> UserEmailVerificationTokenRepository<S> {
    /// Create a new email verification token repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for token by ID
    fn token_key(id: i64) -> Vec<u8> {
        format!("email_verify_token:{id}").into_bytes()
    }

    /// Generate key for token string index
    fn token_string_index_key(token: &str) -> Vec<u8> {
        format!("email_verify_token:token:{token}").into_bytes()
    }

    /// Generate key for email's token index
    fn email_token_index_key(user_email_id: i64, token_id: i64) -> Vec<u8> {
        format!("email_verify_token:email:{user_email_id}:{token_id}").into_bytes()
    }

    /// Create a new email verification token
    ///
    /// Tokens are automatically stored with TTL based on their expiry time (24 hours)
    pub async fn create(&self, token: UserEmailVerificationToken) -> Result<()> {
        // Serialize token
        let token_data = serde_json::to_vec(&token)
            .map_err(|e| Error::Internal(format!("Failed to serialize token: {e}")))?;

        // Expired tokens are filtered out in get() since transactions don't support TTL

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Store token record
        txn.set(Self::token_key(token.id), token_data);

        // Store token string index (for lookup by token)
        txn.set(Self::token_string_index_key(&token.token), token.id.to_le_bytes().to_vec());

        // Store email's token index
        txn.set(
            Self::email_token_index_key(token.user_email_id, token.id),
            token.id.to_le_bytes().to_vec(),
        );

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit token creation: {e}")))?;

        Ok(())
    }

    /// Get a token by ID
    ///
    /// Returns None if token doesn't exist or is expired
    pub async fn get(&self, id: i64) -> Result<Option<UserEmailVerificationToken>> {
        let key = Self::token_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get token: {e}")))?;

        match data {
            Some(bytes) => {
                let token: UserEmailVerificationToken = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("Failed to deserialize token: {e}")))?;

                Ok(Some(token))
            },
            None => Ok(None),
        }
    }

    /// Get a token by the token string
    ///
    /// Returns None if token doesn't exist or is expired
    pub async fn get_by_token(&self, token: &str) -> Result<Option<UserEmailVerificationToken>> {
        let index_key = Self::token_string_index_key(token);
        let data = self
            .storage
            .get(&index_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get token by string: {e}")))?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::Internal("Invalid token index data".to_string()));
                }
                let id = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// Get all tokens for a specific email
    ///
    /// Returns all tokens (used and unused) for the email
    pub async fn get_by_email(
        &self,
        user_email_id: i64,
    ) -> Result<Vec<UserEmailVerificationToken>> {
        // Use range query to get all tokens for this email
        let prefix = format!("email_verify_token:email:{user_email_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("email_verify_token:email:{user_email_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get email tokens: {e}")))?;

        let mut tokens = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue; // Skip invalid entries
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(token) = self.get(id).await? {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }

    /// Update an existing token (e.g., mark as used)
    pub async fn update(&self, token: UserEmailVerificationToken) -> Result<()> {
        // Serialize token
        let token_data = serde_json::to_vec(&token)
            .map_err(|e| Error::Internal(format!("Failed to serialize token: {e}")))?;

        // Update token record
        let token_key = Self::token_key(token.id);
        self.storage
            .set(token_key, token_data)
            .await
            .map_err(|e| Error::Internal(format!("Failed to update token: {e}")))?;

        Ok(())
    }

    /// Delete a token (revoke it)
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get the token first to get the token string and email ID for index cleanup
        let token =
            self.get(id).await?.ok_or_else(|| Error::NotFound(format!("Token {id} not found")))?;

        // Use transaction to delete all related keys atomically
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Delete main token record
        txn.delete(Self::token_key(id));

        // Delete token string index
        txn.delete(Self::token_string_index_key(&token.token));

        // Delete email token index
        txn.delete(Self::email_token_index_key(token.user_email_id, token.id));

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit token deletion: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use inferadb_control_storage::Backend;

    use super::*;
    use crate::IdGenerator;

    async fn create_test_repo() -> UserEmailVerificationTokenRepository<Backend> {
        let storage = Backend::memory();
        UserEmailVerificationTokenRepository::new(storage)
    }

    #[tokio::test]
    async fn test_create_and_get_token() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token_string = UserEmailVerificationToken::generate_token();
        let token = UserEmailVerificationToken::builder()
            .id(100)
            .user_email_id(1)
            .token(token_string)
            .create()
            .unwrap();

        repo.create(token.clone()).await.unwrap();

        let retrieved = repo.get(100).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), token);
    }

    #[tokio::test]
    async fn test_get_by_token_string() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token_string = UserEmailVerificationToken::generate_token();
        let token = UserEmailVerificationToken::builder()
            .id(100)
            .user_email_id(1)
            .token(token_string.clone())
            .create()
            .unwrap();

        repo.create(token.clone()).await.unwrap();

        let retrieved = repo.get_by_token(&token_string).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), token);
    }

    #[tokio::test]
    async fn test_get_by_email() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token1_string = UserEmailVerificationToken::generate_token();
        let token1 = UserEmailVerificationToken::builder()
            .id(100)
            .user_email_id(1)
            .token(token1_string)
            .create()
            .unwrap();

        let token2_string = UserEmailVerificationToken::generate_token();
        let token2 = UserEmailVerificationToken::builder()
            .id(101)
            .user_email_id(1)
            .token(token2_string)
            .create()
            .unwrap();

        let token3_string = UserEmailVerificationToken::generate_token();
        let token3 = UserEmailVerificationToken::builder()
            .id(102)
            .user_email_id(2)
            .token(token3_string)
            .create()
            .unwrap();

        repo.create(token1.clone()).await.unwrap();
        repo.create(token2.clone()).await.unwrap();
        repo.create(token3.clone()).await.unwrap();

        let email1_tokens = repo.get_by_email(1).await.unwrap();
        assert_eq!(email1_tokens.len(), 2);

        let email2_tokens = repo.get_by_email(2).await.unwrap();
        assert_eq!(email2_tokens.len(), 1);
    }

    #[tokio::test]
    async fn test_update_token() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token_string = UserEmailVerificationToken::generate_token();
        let mut token = UserEmailVerificationToken::builder()
            .id(100)
            .user_email_id(1)
            .token(token_string)
            .create()
            .unwrap();

        repo.create(token.clone()).await.unwrap();

        // Mark as used
        token.mark_used();
        repo.update(token.clone()).await.unwrap();

        let retrieved = repo.get(100).await.unwrap().unwrap();
        assert!(retrieved.is_used());
    }

    #[tokio::test]
    async fn test_delete_token() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token_string = UserEmailVerificationToken::generate_token();
        let token = UserEmailVerificationToken::builder()
            .id(100)
            .user_email_id(1)
            .token(token_string.clone())
            .create()
            .unwrap();

        repo.create(token).await.unwrap();

        // Verify it exists
        assert!(repo.get(100).await.unwrap().is_some());

        // Delete it
        repo.delete(100).await.unwrap();

        // Verify it's gone
        assert!(repo.get(100).await.unwrap().is_none());
        assert!(repo.get_by_token(&token_string).await.unwrap().is_none());
    }
}
