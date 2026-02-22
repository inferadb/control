use std::{marker::PhantomData, time::Duration};

use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::SecureTokenEntity,
    error::{Error, Result},
};

/// Generic repository for entities that implement [`SecureTokenEntity`]
///
/// Provides CRUD operations with consistent key schema:
/// - `{prefix}:{id}` → serialized entity
/// - `{prefix}:token:{token_value}` → token ID (for token string lookup)
/// - `{prefix}:{fk_prefix}:{foreign_key}:{id}` → token ID (for foreign key lookup)
pub struct SecureTokenRepository<S: StorageBackend, T: SecureTokenEntity> {
    storage: S,
    _phantom: PhantomData<T>,
}

impl<S: StorageBackend, T: SecureTokenEntity> SecureTokenRepository<S, T> {
    /// Create a new repository instance
    pub fn new(storage: S) -> Self {
        Self { storage, _phantom: PhantomData }
    }

    /// Generate primary key for token by ID
    fn token_key(id: i64) -> Vec<u8> {
        format!("{}:{id}", T::key_prefix()).into_bytes()
    }

    /// Generate key for token string index
    fn token_string_index_key(token: &str) -> Vec<u8> {
        format!("{}:token:{token}", T::key_prefix()).into_bytes()
    }

    /// Generate key for the foreign key index
    fn foreign_key_index_key(foreign_key_id: i64, token_id: i64) -> Vec<u8> {
        format!("{}:{}:{foreign_key_id}:{token_id}", T::key_prefix(), T::foreign_key_prefix())
            .into_bytes()
    }

    /// Apply TTL to all 3 storage keys for a token
    ///
    /// Uses `set_with_ttl` on each key individually. Called after transaction
    /// commit to work around `BufferedBackend` silently dropping TTL.
    /// See `AuthorizationCodeRepository::create` for the canonical two-phase pattern.
    async fn set_all_keys_with_ttl(&self, token: &T, ttl: Duration) -> Result<()> {
        let st = token.secure_token();
        let token_data = serde_json::to_vec(token)
            .map_err(|e| Error::internal(format!("Failed to serialize token: {e}")))?;

        self.storage
            .set_with_ttl(Self::token_key(st.id), token_data, ttl)
            .await
            .map_err(|e| Error::internal(format!("Failed to set TTL on token key: {e}")))?;

        self.storage
            .set_with_ttl(
                Self::token_string_index_key(&st.token),
                st.id.to_le_bytes().to_vec(),
                ttl,
            )
            .await
            .map_err(|e| Error::internal(format!("Failed to set TTL on token index: {e}")))?;

        self.storage
            .set_with_ttl(
                Self::foreign_key_index_key(token.foreign_key_id(), st.id),
                st.id.to_le_bytes().to_vec(),
                ttl,
            )
            .await
            .map_err(|e| Error::internal(format!("Failed to set TTL on foreign key index: {e}")))?;

        Ok(())
    }

    /// Store a new token entity
    ///
    /// Creates the primary record and both secondary indexes atomically,
    /// then applies TTL matching the token's time until expiry.
    pub async fn create(&self, token: T) -> Result<()> {
        let st = token.secure_token();
        let token_data = serde_json::to_vec(&token)
            .map_err(|e| Error::internal(format!("Failed to serialize token: {e}")))?;

        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

        txn.set(Self::token_key(st.id), token_data);
        txn.set(Self::token_string_index_key(&st.token), st.id.to_le_bytes().to_vec());
        txn.set(
            Self::foreign_key_index_key(token.foreign_key_id(), st.id),
            st.id.to_le_bytes().to_vec(),
        );

        txn.commit()
            .await
            .map_err(|e| Error::internal(format!("Failed to commit token creation: {e}")))?;

        // Two-phase write: apply TTL after transaction commit.
        // BufferedBackend silently drops TTL, so we set it on each key individually.
        let ttl_secs = st.time_until_expiry().num_seconds().max(1) as u64;
        self.set_all_keys_with_ttl(&token, Duration::from_secs(ttl_secs)).await?;

        Ok(())
    }

    /// Get a token by its primary ID
    pub async fn get(&self, id: i64) -> Result<Option<T>> {
        let key = Self::token_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::internal(format!("Failed to get token: {e}")))?;

        match data {
            Some(bytes) => {
                let token: T = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::internal(format!("Failed to deserialize token: {e}")))?;
                Ok(Some(token))
            },
            None => Ok(None),
        }
    }

    /// Get a token by its token string value
    pub async fn get_by_token(&self, token: &str) -> Result<Option<T>> {
        let index_key = Self::token_string_index_key(token);
        let data = self
            .storage
            .get(&index_key)
            .await
            .map_err(|e| Error::internal(format!("Failed to get token by string: {e}")))?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::internal("Invalid token index data".to_string()));
                }
                let id = super::parse_i64_id(&bytes)?;
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// Get all tokens for a given foreign key value
    ///
    /// Returns all tokens (used and unused) associated with the foreign key.
    pub async fn get_by_foreign_key(&self, foreign_key_id: i64) -> Result<Vec<T>> {
        let prefix = format!("{}:{}:{foreign_key_id}:", T::key_prefix(), T::foreign_key_prefix());
        let start = prefix.clone().into_bytes();
        let end = format!("{}:{}:{foreign_key_id}~", T::key_prefix(), T::foreign_key_prefix())
            .into_bytes();

        let kvs =
            self.storage.get_range(start..end).await.map_err(|e| {
                Error::internal(format!("Failed to get tokens by foreign key: {e}"))
            })?;

        let mut tokens = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let Ok(id) = super::parse_i64_id(&kv.value) else { continue };
            if let Some(token) = self.get(id).await? {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }

    /// Update an existing token (e.g., mark as used)
    pub async fn update(&self, token: T) -> Result<()> {
        let token_data = serde_json::to_vec(&token)
            .map_err(|e| Error::internal(format!("Failed to serialize token: {e}")))?;

        let token_key = Self::token_key(token.secure_token().id);
        self.storage
            .set(token_key, token_data)
            .await
            .map_err(|e| Error::internal(format!("Failed to update token: {e}")))?;

        Ok(())
    }

    /// Delete a token and its indexes
    pub async fn delete(&self, id: i64) -> Result<()> {
        let token =
            self.get(id).await?.ok_or_else(|| Error::not_found(format!("Token {id} not found")))?;
        let st = token.secure_token();

        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

        txn.delete(Self::token_key(id));
        txn.delete(Self::token_string_index_key(&st.token));
        txn.delete(Self::foreign_key_index_key(token.foreign_key_id(), st.id));

        txn.commit()
            .await
            .map_err(|e| Error::internal(format!("Failed to commit token deletion: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chrono::Utc;
    use inferadb_control_storage::{MemoryBackend, backend::StorageBackend};
    use inferadb_control_types::entities::UserEmailVerificationToken;

    use super::*;

    type TestRepo = SecureTokenRepository<MemoryBackend, UserEmailVerificationToken>;

    fn create_test_token(id: i64, user_email_id: i64) -> UserEmailVerificationToken {
        let token_string = UserEmailVerificationToken::generate_token();
        UserEmailVerificationToken::builder()
            .id(id)
            .user_email_id(user_email_id)
            .token(token_string)
            .create()
            .unwrap()
    }

    #[tokio::test]
    async fn test_create_sets_ttl_on_all_keys() {
        let storage = MemoryBackend::new();
        let repo = TestRepo::new(storage.clone());

        let token = create_test_token(100, 1);
        let token_string = token.secure_token.token.clone();

        repo.create(token).await.unwrap();

        // All 3 keys should exist after creation with TTL
        assert!(storage.get(b"email_verify_token:100").await.unwrap().is_some());
        assert!(
            storage
                .get(format!("email_verify_token:token:{token_string}").as_bytes())
                .await
                .unwrap()
                .is_some()
        );
        assert!(storage.get(b"email_verify_token:email:1:100").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_ttl_matches_time_until_expiry() {
        let storage = MemoryBackend::new();
        let repo = TestRepo::new(storage.clone());

        // Create a token with a short custom expiry (2 seconds)
        let mut token = create_test_token(200, 2);
        token.secure_token.expires_at = Utc::now() + chrono::Duration::seconds(2);
        let token_string = token.secure_token.token.clone();

        repo.create(token).await.unwrap();

        // Keys should exist immediately
        assert!(storage.get(b"email_verify_token:200").await.unwrap().is_some());
        assert!(
            storage
                .get(format!("email_verify_token:token:{token_string}").as_bytes())
                .await
                .unwrap()
                .is_some()
        );
        assert!(storage.get(b"email_verify_token:email:2:200").await.unwrap().is_some());

        // Wait for TTL expiry
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // All 3 keys should be absent after TTL expiry
        assert!(storage.get(b"email_verify_token:200").await.unwrap().is_none());
        assert!(
            storage
                .get(format!("email_verify_token:token:{token_string}").as_bytes())
                .await
                .unwrap()
                .is_none()
        );
        assert!(storage.get(b"email_verify_token:email:2:200").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_token_keys_expire_from_storage() {
        let storage = MemoryBackend::new();
        let repo = TestRepo::new(storage.clone());

        // Create a token with a 1 second TTL
        let mut token = create_test_token(300, 3);
        token.secure_token.expires_at = Utc::now() + chrono::Duration::seconds(1);

        repo.create(token).await.unwrap();

        // Keys should exist immediately
        assert!(storage.get(b"email_verify_token:300").await.unwrap().is_some());

        // Wait for TTL expiry
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // All 3 keys should be absent
        assert!(storage.get(b"email_verify_token:300").await.unwrap().is_none());
        assert!(storage.get(b"email_verify_token:email:3:300").await.unwrap().is_none());
    }
}
