use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use inferadb_control_const::limits::MAX_PASSKEYS_PER_USER;
use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::PasskeyCredential,
    error::{Error, Result},
};

/// Repository for PasskeyCredential entity operations
///
/// Key schema:
/// - passkey:{id} -> PasskeyCredential data
/// - passkey:user:{user_id}:{id} -> credential_id (for user's credential lookups)
/// - passkey:cred_id:{cred_id_base64} -> id (for lookup by WebAuthn credential ID)
pub struct PasskeyCredentialRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> PasskeyCredentialRepository<S> {
    /// Create a new passkey credential repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for passkey by ID
    fn passkey_key(id: i64) -> Vec<u8> {
        format!("passkey:{id}").into_bytes()
    }

    /// Generate key for user's passkey index
    fn user_passkey_index_key(user_id: i64, passkey_id: i64) -> Vec<u8> {
        format!("passkey:user:{user_id}:{passkey_id}").into_bytes()
    }

    /// Generate key for credential ID lookup
    fn credential_id_index_key(credential_id: &[u8]) -> Vec<u8> {
        let cred_id_base64 = URL_SAFE_NO_PAD.encode(credential_id);
        format!("passkey:cred_id:{cred_id_base64}").into_bytes()
    }

    /// Create a new passkey credential
    pub async fn create(&self, credential: PasskeyCredential) -> Result<()> {
        // Check current credential count
        let current_credentials = self.get_user_credentials(credential.user_id).await?;

        if current_credentials.len() >= MAX_PASSKEYS_PER_USER {
            return Err(Error::too_many_passkeys(MAX_PASSKEYS_PER_USER));
        }

        // Serialize credential
        let credential_data = serde_json::to_vec(&credential)
            .map_err(|e| Error::internal(format!("Failed to serialize passkey credential: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

        // Store credential record
        txn.set(Self::passkey_key(credential.id), credential_data);

        // Store user's credential index
        txn.set(
            Self::user_passkey_index_key(credential.user_id, credential.id),
            credential.id.to_le_bytes().to_vec(),
        );

        // Store credential ID index for lookup during authentication
        txn.set(
            Self::credential_id_index_key(&credential.credential_id),
            credential.id.to_le_bytes().to_vec(),
        );

        // Commit transaction
        txn.commit().await.map_err(|e| {
            Error::internal(format!("Failed to commit passkey credential creation: {e}"))
        })?;

        Ok(())
    }

    /// Get a passkey credential by ID
    pub async fn get(&self, id: i64) -> Result<Option<PasskeyCredential>> {
        let key = Self::passkey_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::internal(format!("Failed to get passkey credential: {e}")))?;

        match data {
            Some(bytes) => {
                let credential = serde_json::from_slice(&bytes).map_err(|e| {
                    Error::internal(format!("Failed to deserialize passkey credential: {e}"))
                })?;
                Ok(Some(credential))
            },
            None => Ok(None),
        }
    }

    /// Get a passkey credential by WebAuthn credential ID
    pub async fn get_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>> {
        // Look up the internal ID from the credential ID index
        let key = Self::credential_id_index_key(credential_id);
        let id_data = self.storage.get(&key).await.map_err(|e| {
            Error::internal(format!("Failed to lookup passkey by credential ID: {e}"))
        })?;

        match id_data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::internal("Invalid credential ID index data".to_string()));
                }
                let id = super::parse_i64_id(&bytes)?;
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// Get all passkey credentials for a user
    pub async fn get_user_credentials(&self, user_id: i64) -> Result<Vec<PasskeyCredential>> {
        let start = format!("passkey:user:{user_id}:").into_bytes();
        let mut end = start.clone();
        // Increment the last byte to create an exclusive end range
        if let Some(last) = end.last_mut() {
            *last = last.saturating_add(1);
        }

        let items = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::internal(format!("Failed to list user passkeys: {e}")))?;

        let mut credentials = Vec::new();
        for kv in items {
            let Ok(credential_id) = super::parse_i64_id(&kv.value) else { continue };
            if let Some(credential) = self.get(credential_id).await? {
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }

    /// Update a passkey credential
    pub async fn update(&self, credential: &PasskeyCredential) -> Result<()> {
        // Serialize credential
        let credential_data = serde_json::to_vec(credential)
            .map_err(|e| Error::internal(format!("Failed to serialize passkey credential: {e}")))?;

        // Update the record
        self.storage
            .set(Self::passkey_key(credential.id), credential_data)
            .await
            .map_err(|e| Error::internal(format!("Failed to update passkey credential: {e}")))?;

        Ok(())
    }

    /// Delete a passkey credential
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get the credential first to access indexes
        let credential = self
            .get(id)
            .await?
            .ok_or_else(|| Error::not_found("Passkey credential".to_string()))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

        // Delete credential record
        txn.delete(Self::passkey_key(id));

        // Delete user index
        txn.delete(Self::user_passkey_index_key(credential.user_id, id));

        // Delete credential ID index
        txn.delete(Self::credential_id_index_key(&credential.credential_id));

        // Commit transaction
        txn.commit().await.map_err(|e| {
            Error::internal(format!("Failed to commit passkey credential deletion: {e}"))
        })?;

        Ok(())
    }

    /// Delete all passkey credentials for a user (used during user deletion)
    pub async fn delete_user_credentials(&self, user_id: i64) -> Result<()> {
        let credentials = self.get_user_credentials(user_id).await?;

        for credential in credentials {
            self.delete(credential.id).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_control_storage::MemoryBackend;

    use super::*;

    async fn create_test_repo() -> PasskeyCredentialRepository<MemoryBackend> {
        let backend = MemoryBackend::new();
        PasskeyCredentialRepository::new(backend)
    }

    #[tokio::test]
    async fn test_max_passkeys_limit() {
        // Note: Creating real Passkey objects requires the full WebAuthn flow
        // This test just verifies the constant exists
        assert_eq!(MAX_PASSKEYS_PER_USER, 20);
    }

    #[tokio::test]
    async fn test_get_nonexistent_credential() {
        let repo = create_test_repo().await;
        let result = repo.get(123456).await.unwrap();
        assert!(result.is_none());
    }
}
