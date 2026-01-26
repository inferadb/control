use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::VaultRefreshToken,
    error::{Error, Result},
};

/// Repository for VaultRefreshToken entity operations
///
/// Key schema:
/// - vault_refresh_token:{id} -> VaultRefreshToken data
/// - vault_refresh_token:token:{token} -> token_id (for token lookup)
/// - vault_refresh_token:vault:{vault_id}:{id} -> token_id (for vault's token lookups)
/// - vault_refresh_token:session:{session_id}:{id} -> token_id (for session's token lookups)
/// - vault_refresh_token:client:{client_id}:{id} -> token_id (for client's token lookups)
pub struct VaultRefreshTokenRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> VaultRefreshTokenRepository<S> {
    /// Create a new vault refresh token repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for token by ID
    fn token_key(id: i64) -> Vec<u8> {
        format!("vault_refresh_token:{id}").into_bytes()
    }

    /// Generate key for token lookup index
    fn token_lookup_key(token: &str) -> Vec<u8> {
        format!("vault_refresh_token:token:{token}").into_bytes()
    }

    /// Generate key for vault's token index
    fn vault_token_index_key(vault_id: i64, token_id: i64) -> Vec<u8> {
        format!("vault_refresh_token:vault:{vault_id}:{token_id}").into_bytes()
    }

    /// Generate key for session's token index
    fn session_token_index_key(session_id: i64, token_id: i64) -> Vec<u8> {
        format!("vault_refresh_token:session:{session_id}:{token_id}").into_bytes()
    }

    /// Generate key for client's token index
    fn client_token_index_key(client_id: i64, token_id: i64) -> Vec<u8> {
        format!("vault_refresh_token:client:{client_id}:{token_id}").into_bytes()
    }

    /// Create a new vault refresh token
    pub async fn create(&self, token: VaultRefreshToken) -> Result<()> {
        // Serialize token
        let token_data = serde_json::to_vec(&token)
            .map_err(|e| Error::internal(format!("Failed to serialize token: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

        // Store token record
        txn.set(Self::token_key(token.id), token_data);

        // Store token lookup index (for finding token by token string)
        txn.set(Self::token_lookup_key(&token.token), token.id.to_le_bytes().to_vec());

        // Store vault's token index
        txn.set(
            Self::vault_token_index_key(token.vault_id, token.id),
            token.id.to_le_bytes().to_vec(),
        );

        // Store session or client index
        if let Some(session_id) = token.user_session_id {
            txn.set(
                Self::session_token_index_key(session_id, token.id),
                token.id.to_le_bytes().to_vec(),
            );
        } else if let Some(client_id) = token.org_api_key_id {
            txn.set(
                Self::client_token_index_key(client_id, token.id),
                token.id.to_le_bytes().to_vec(),
            );
        }

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::internal(format!("Failed to commit token creation: {e}")))?;

        Ok(())
    }

    /// Get a token by ID
    pub async fn get(&self, id: i64) -> Result<Option<VaultRefreshToken>> {
        let key = Self::token_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::internal(format!("Failed to get token: {e}")))?;

        match data {
            Some(bytes) => {
                let token: VaultRefreshToken = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::internal(format!("Failed to deserialize token: {e}")))?;
                Ok(Some(token))
            },
            None => Ok(None),
        }
    }

    /// Get a token by token string
    pub async fn get_by_token(&self, token: &str) -> Result<Option<VaultRefreshToken>> {
        let lookup_key = Self::token_lookup_key(token);
        let id_data = self
            .storage
            .get(&lookup_key)
            .await
            .map_err(|e| Error::internal(format!("Failed to lookup token: {e}")))?;

        match id_data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::internal("Invalid token lookup data".to_string()));
                }
                let id = super::parse_i64_id(&bytes)?;
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// Update a token (for marking as used or revoked)
    pub async fn update(&self, token: &VaultRefreshToken) -> Result<()> {
        let token_data = serde_json::to_vec(token)
            .map_err(|e| Error::internal(format!("Failed to serialize token: {e}")))?;

        self.storage
            .set(Self::token_key(token.id), token_data)
            .await
            .map_err(|e| Error::internal(format!("Failed to update token: {e}")))?;

        Ok(())
    }

    /// List all tokens for a vault
    pub async fn list_by_vault(&self, vault_id: i64) -> Result<Vec<VaultRefreshToken>> {
        let prefix = format!("vault_refresh_token:vault:{vault_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_refresh_token:vault:{vault_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::internal(format!("Failed to get vault tokens: {e}")))?;

        let mut tokens = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_i64_id(&kv.value) else { continue };
            if let Some(token) = self.get(id).await? {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }

    /// List all tokens for a session
    pub async fn list_by_session(&self, session_id: i64) -> Result<Vec<VaultRefreshToken>> {
        let prefix = format!("vault_refresh_token:session:{session_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_refresh_token:session:{session_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::internal(format!("Failed to get session tokens: {e}")))?;

        let mut tokens = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_i64_id(&kv.value) else { continue };
            if let Some(token) = self.get(id).await? {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }

    /// List all tokens for a client
    pub async fn list_by_client(&self, client_id: i64) -> Result<Vec<VaultRefreshToken>> {
        let prefix = format!("vault_refresh_token:client:{client_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_refresh_token:client:{client_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::internal(format!("Failed to get client tokens: {e}")))?;

        let mut tokens = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_i64_id(&kv.value) else { continue };
            if let Some(token) = self.get(id).await? {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }

    /// Revoke all tokens for a session (called when session is deleted)
    pub async fn revoke_by_session(&self, session_id: i64) -> Result<usize> {
        let tokens = self.list_by_session(session_id).await?;
        let mut revoked_count = 0;

        for mut token in tokens {
            if !token.is_revoked() {
                token.mark_revoked();
                self.update(&token).await?;
                revoked_count += 1;
            }
        }

        Ok(revoked_count)
    }

    /// Revoke all tokens for a client (called when client is deleted/revoked)
    pub async fn revoke_by_client(&self, client_id: i64) -> Result<usize> {
        let tokens = self.list_by_client(client_id).await?;
        let mut revoked_count = 0;

        for mut token in tokens {
            if !token.is_revoked() {
                token.mark_revoked();
                self.update(&token).await?;
                revoked_count += 1;
            }
        }

        Ok(revoked_count)
    }

    /// Revoke all tokens for a vault (called when vault is deleted)
    pub async fn revoke_by_vault(&self, vault_id: i64) -> Result<usize> {
        let tokens = self.list_by_vault(vault_id).await?;
        let mut revoked_count = 0;

        for mut token in tokens {
            if !token.is_revoked() {
                token.mark_revoked();
                self.update(&token).await?;
                revoked_count += 1;
            }
        }

        Ok(revoked_count)
    }

    /// Delete expired tokens (for cleanup jobs)
    ///
    /// Returns the number of tokens deleted
    pub async fn delete_expired(&self) -> Result<usize> {
        // This would require a full scan in production
        // For now, we implement a stub that returns 0
        // In production, you'd want to use a separate index for expired tokens
        // or implement a background job that periodically scans and deletes them
        Ok(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_control_storage::MemoryBackend;
    use inferadb_control_types::entities::VaultRole;

    use super::*;

    fn create_test_repo() -> VaultRefreshTokenRepository<MemoryBackend> {
        VaultRefreshTokenRepository::new(MemoryBackend::new())
    }

    #[tokio::test]
    async fn test_create_and_get_session_token() {
        let repo = create_test_repo();
        let token = VaultRefreshToken::new_for_session()
            .id(1)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();

        repo.create(token.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert_eq!(retrieved, Some(token));
    }

    #[tokio::test]
    async fn test_create_and_get_client_token() {
        let repo = create_test_repo();
        let token = VaultRefreshToken::new_for_client()
            .id(1)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .create()
            .unwrap();

        repo.create(token.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert_eq!(retrieved, Some(token));
    }

    #[tokio::test]
    async fn test_get_by_token_string() {
        let repo = create_test_repo();
        let token = VaultRefreshToken::new_for_session()
            .id(1)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();

        let token_str = token.token.clone();
        repo.create(token.clone()).await.unwrap();

        let retrieved = repo.get_by_token(&token_str).await.unwrap();
        assert_eq!(retrieved, Some(token));
    }

    #[tokio::test]
    async fn test_get_by_token_not_found() {
        let repo = create_test_repo();
        let retrieved = repo.get_by_token("nonexistent").await.unwrap();
        assert_eq!(retrieved, None);
    }

    #[tokio::test]
    async fn test_update_token() {
        let repo = create_test_repo();
        let mut token = VaultRefreshToken::new_for_session()
            .id(1)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();

        repo.create(token.clone()).await.unwrap();

        // Mark as used
        token.mark_used();
        repo.update(&token).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert!(retrieved.is_used());
    }

    #[tokio::test]
    async fn test_list_by_vault() {
        let repo = create_test_repo();

        let token1 = VaultRefreshToken::new_for_session()
            .id(1)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();
        let token2 = VaultRefreshToken::new_for_client()
            .id(2)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .create()
            .unwrap();
        let token3 = VaultRefreshToken::new_for_session()
            .id(3)
            .vault_id(999)
            .organization_id(200)
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();

        repo.create(token1).await.unwrap();
        repo.create(token2).await.unwrap();
        repo.create(token3).await.unwrap();

        let vault_100_tokens = repo.list_by_vault(100).await.unwrap();
        assert_eq!(vault_100_tokens.len(), 2);

        let vault_999_tokens = repo.list_by_vault(999).await.unwrap();
        assert_eq!(vault_999_tokens.len(), 1);
    }

    #[tokio::test]
    async fn test_list_by_session() {
        let repo = create_test_repo();

        let token1 = VaultRefreshToken::new_for_session()
            .id(1)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();
        let token2 = VaultRefreshToken::new_for_session()
            .id(2)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();
        let token3 = VaultRefreshToken::new_for_session()
            .id(3)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Reader)
            .user_session_id(999)
            .create()
            .unwrap();

        repo.create(token1).await.unwrap();
        repo.create(token2).await.unwrap();
        repo.create(token3).await.unwrap();

        let session_300_tokens = repo.list_by_session(300).await.unwrap();
        assert_eq!(session_300_tokens.len(), 2);

        let session_999_tokens = repo.list_by_session(999).await.unwrap();
        assert_eq!(session_999_tokens.len(), 1);
    }

    #[tokio::test]
    async fn test_list_by_client() {
        let repo = create_test_repo();

        let token1 = VaultRefreshToken::new_for_client()
            .id(1)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .create()
            .unwrap();
        let token2 = VaultRefreshToken::new_for_client()
            .id(2)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .create()
            .unwrap();
        let token3 = VaultRefreshToken::new_for_client()
            .id(3)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Writer)
            .org_api_key_id(999)
            .create()
            .unwrap();

        repo.create(token1).await.unwrap();
        repo.create(token2).await.unwrap();
        repo.create(token3).await.unwrap();

        let client_400_tokens = repo.list_by_client(400).await.unwrap();
        assert_eq!(client_400_tokens.len(), 2);

        let client_999_tokens = repo.list_by_client(999).await.unwrap();
        assert_eq!(client_999_tokens.len(), 1);
    }

    #[tokio::test]
    async fn test_revoke_by_session() {
        let repo = create_test_repo();

        let token1 = VaultRefreshToken::new_for_session()
            .id(1)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();
        let token2 = VaultRefreshToken::new_for_session()
            .id(2)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();

        repo.create(token1).await.unwrap();
        repo.create(token2).await.unwrap();

        let revoked_count = repo.revoke_by_session(300).await.unwrap();
        assert_eq!(revoked_count, 2);

        let token1_after = repo.get(1).await.unwrap().unwrap();
        let token2_after = repo.get(2).await.unwrap().unwrap();
        assert!(token1_after.is_revoked());
        assert!(token2_after.is_revoked());
    }

    #[tokio::test]
    async fn test_revoke_by_client() {
        let repo = create_test_repo();

        let token1 = VaultRefreshToken::new_for_client()
            .id(1)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .create()
            .unwrap();
        let token2 = VaultRefreshToken::new_for_client()
            .id(2)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .create()
            .unwrap();

        repo.create(token1).await.unwrap();
        repo.create(token2).await.unwrap();

        let revoked_count = repo.revoke_by_client(400).await.unwrap();
        assert_eq!(revoked_count, 2);

        let token1_after = repo.get(1).await.unwrap().unwrap();
        let token2_after = repo.get(2).await.unwrap().unwrap();
        assert!(token1_after.is_revoked());
        assert!(token2_after.is_revoked());
    }

    #[tokio::test]
    async fn test_revoke_by_vault() {
        let repo = create_test_repo();

        let token1 = VaultRefreshToken::new_for_session()
            .id(1)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();
        let token2 = VaultRefreshToken::new_for_client()
            .id(2)
            .vault_id(100)
            .organization_id(200)
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .create()
            .unwrap();

        repo.create(token1).await.unwrap();
        repo.create(token2).await.unwrap();

        let revoked_count = repo.revoke_by_vault(100).await.unwrap();
        assert_eq!(revoked_count, 2);

        let token1_after = repo.get(1).await.unwrap().unwrap();
        let token2_after = repo.get(2).await.unwrap().unwrap();
        assert!(token1_after.is_revoked());
        assert!(token2_after.is_revoked());
    }
}
