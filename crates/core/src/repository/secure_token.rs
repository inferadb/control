use std::marker::PhantomData;

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

    /// Store a new token entity
    ///
    /// Creates the primary record and both secondary indexes atomically.
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
