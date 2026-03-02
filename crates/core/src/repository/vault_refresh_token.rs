use std::time::Duration;

use inferadb_control_storage::{StorageBackend, to_storage_range};
use inferadb_control_types::{
    VaultSlug,
    entities::VaultRefreshToken,
    error::{Error, Result},
};

/// TTL for used tokens during the rotation grace window.
/// Concurrent requests may still reference the old token during rotation.
const USED_TOKEN_RESIDUAL_TTL: Duration = Duration::from_secs(5 * 60);

/// TTL for revoked tokens before Ledger GC removes them.
const REVOKED_TOKEN_RESIDUAL_TTL: Duration = Duration::from_secs(60);

/// Repository for VaultRefreshToken entity operations
///
/// Key schema:
/// - vault_refresh_token:{id} -> VaultRefreshToken data
/// - vault_refresh_token:token:{token} -> token_id (for token lookup)
/// - vault_refresh_token:vault:{vault}:{id} -> token_id (for vault's token lookups)
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
    fn token_key(id: u64) -> Vec<u8> {
        format!("vault_refresh_token:{id}").into_bytes()
    }

    /// Generate key for token lookup index
    fn token_lookup_key(token: &str) -> Vec<u8> {
        format!("vault_refresh_token:token:{token}").into_bytes()
    }

    /// Generate key for vault's token index
    fn vault_token_index_key(vault: VaultSlug, token_id: u64) -> Vec<u8> {
        format!("vault_refresh_token:vault:{vault}:{token_id}").into_bytes()
    }

    /// Generate key for session's token index
    fn session_token_index_key(session_id: u64, token_id: u64) -> Vec<u8> {
        format!("vault_refresh_token:session:{session_id}:{token_id}").into_bytes()
    }

    /// Generate key for client's token index
    fn client_token_index_key(client_id: u64, token_id: u64) -> Vec<u8> {
        format!("vault_refresh_token:client:{client_id}:{token_id}").into_bytes()
    }

    /// Compute the appropriate TTL for a token based on its current state.
    fn compute_ttl(token: &VaultRefreshToken) -> Duration {
        if token.is_used() {
            USED_TOKEN_RESIDUAL_TTL
        } else if token.is_revoked() {
            REVOKED_TOKEN_RESIDUAL_TTL
        } else {
            let now = chrono::Utc::now();
            let secs = if token.expires_at > now {
                (token.expires_at - now).num_seconds().max(1) as u64
            } else {
                1
            };
            Duration::from_secs(secs)
        }
    }

    /// Write all token keys with the given TTL.
    ///
    /// Used for non-transactional updates that need to set or reset TTL
    /// on every key (e.g. mark-used, revocation).
    async fn set_all_keys_with_ttl(&self, token: &VaultRefreshToken, ttl: Duration) -> Result<()> {
        let token_data = serde_json::to_vec(token)
            .map_err(|e| Error::internal(format!("Failed to serialize token: {e}")))?;

        self.storage.set_with_ttl(Self::token_key(token.id), token_data, ttl).await?;

        self.storage
            .set_with_ttl(
                Self::token_lookup_key(&token.token),
                token.id.to_le_bytes().to_vec(),
                ttl,
            )
            .await?;

        self.storage
            .set_with_ttl(
                Self::vault_token_index_key(token.vault, token.id),
                token.id.to_le_bytes().to_vec(),
                ttl,
            )
            .await?;

        if let Some(session_id) = token.user_session_id {
            self.storage
                .set_with_ttl(
                    Self::session_token_index_key(session_id, token.id),
                    token.id.to_le_bytes().to_vec(),
                    ttl,
                )
                .await?;
        } else if let Some(client_id) = token.org_api_key_id {
            self.storage
                .set_with_ttl(
                    Self::client_token_index_key(client_id, token.id),
                    token.id.to_le_bytes().to_vec(),
                    ttl,
                )
                .await?;
        }

        Ok(())
    }

    /// Create a new vault refresh token
    pub async fn create(&self, token: VaultRefreshToken) -> Result<()> {
        let token_data = serde_json::to_vec(&token)
            .map_err(|e| Error::internal(format!("Failed to serialize token: {e}")))?;

        let ttl = Self::compute_ttl(&token);

        let mut txn = self.storage.transaction().await?;

        txn.set_with_ttl(Self::token_key(token.id), token_data, ttl);
        txn.set_with_ttl(
            Self::token_lookup_key(&token.token),
            token.id.to_le_bytes().to_vec(),
            ttl,
        );
        txn.set_with_ttl(
            Self::vault_token_index_key(token.vault, token.id),
            token.id.to_le_bytes().to_vec(),
            ttl,
        );

        if let Some(session_id) = token.user_session_id {
            txn.set_with_ttl(
                Self::session_token_index_key(session_id, token.id),
                token.id.to_le_bytes().to_vec(),
                ttl,
            );
        } else if let Some(client_id) = token.org_api_key_id {
            txn.set_with_ttl(
                Self::client_token_index_key(client_id, token.id),
                token.id.to_le_bytes().to_vec(),
                ttl,
            );
        }

        txn.commit().await?;

        Ok(())
    }

    /// Get a token by ID
    pub async fn get(&self, id: u64) -> Result<Option<VaultRefreshToken>> {
        let key = Self::token_key(id);
        let data = self.storage.get(&key).await?;

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
        let id_data = self.storage.get(&lookup_key).await?;

        match id_data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::internal("Invalid token lookup data".to_string()));
                }
                let id = super::parse_u64_id(&bytes)?;
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// Update a token (for marking as used or revoked)
    ///
    /// Applies state-aware TTL to all keys: used tokens get a 5-minute
    /// rotation grace window, revoked tokens get a 60-second residual,
    /// and active tokens retain their remaining TTL.
    pub async fn update(&self, token: &VaultRefreshToken) -> Result<()> {
        let ttl = Self::compute_ttl(token);
        self.set_all_keys_with_ttl(token, ttl).await
    }

    /// List all tokens for a vault
    pub async fn list_by_vault(&self, vault: VaultSlug) -> Result<Vec<VaultRefreshToken>> {
        let prefix = format!("vault_refresh_token:vault:{vault}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_refresh_token:vault:{vault}~").into_bytes();

        let kvs = self.storage.get_range(to_storage_range(start..end)).await?;

        let mut tokens = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_u64_id(&kv.value) else { continue };
            if let Some(token) = self.get(id).await? {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }

    /// List all tokens for a session
    pub async fn list_by_session(&self, session_id: u64) -> Result<Vec<VaultRefreshToken>> {
        let prefix = format!("vault_refresh_token:session:{session_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_refresh_token:session:{session_id}~").into_bytes();

        let kvs = self.storage.get_range(to_storage_range(start..end)).await?;

        let mut tokens = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_u64_id(&kv.value) else { continue };
            if let Some(token) = self.get(id).await? {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }

    /// List all tokens for a client
    pub async fn list_by_client(&self, client_id: u64) -> Result<Vec<VaultRefreshToken>> {
        let prefix = format!("vault_refresh_token:client:{client_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("vault_refresh_token:client:{client_id}~").into_bytes();

        let kvs = self.storage.get_range(to_storage_range(start..end)).await?;

        let mut tokens = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_u64_id(&kv.value) else { continue };
            if let Some(token) = self.get(id).await? {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }

    /// Revoke all tokens for a session (called when session is deleted)
    pub async fn revoke_by_session(&self, session_id: u64) -> Result<usize> {
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
    pub async fn revoke_by_client(&self, client_id: u64) -> Result<usize> {
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
    pub async fn revoke_by_vault(&self, vault: VaultSlug) -> Result<usize> {
        let tokens = self.list_by_vault(vault).await?;
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_control_storage::MemoryBackend;
    use inferadb_control_types::{OrganizationSlug, entities::VaultRole};

    use super::*;

    fn create_test_repo() -> VaultRefreshTokenRepository<MemoryBackend> {
        VaultRefreshTokenRepository::new(MemoryBackend::new())
    }

    fn create_test_repo_with_storage() -> (VaultRefreshTokenRepository<MemoryBackend>, MemoryBackend)
    {
        let storage = MemoryBackend::new();
        let repo = VaultRefreshTokenRepository::new(storage.clone());
        (repo, storage)
    }

    #[tokio::test]
    async fn test_create_and_get_session_token() {
        let repo = create_test_repo();
        let token = VaultRefreshToken::new_for_session()
            .id(1)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
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
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
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
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
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
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
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
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();
        let token2 = VaultRefreshToken::new_for_client()
            .id(2)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .create()
            .unwrap();
        let token3 = VaultRefreshToken::new_for_session()
            .id(3)
            .vault(VaultSlug::from(999_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();

        repo.create(token1).await.unwrap();
        repo.create(token2).await.unwrap();
        repo.create(token3).await.unwrap();

        let vault_100_tokens = repo.list_by_vault(VaultSlug::from(100_u64)).await.unwrap();
        assert_eq!(vault_100_tokens.len(), 2);

        let vault_999_tokens = repo.list_by_vault(VaultSlug::from(999_u64)).await.unwrap();
        assert_eq!(vault_999_tokens.len(), 1);
    }

    #[tokio::test]
    async fn test_list_by_session() {
        let repo = create_test_repo();

        let token1 = VaultRefreshToken::new_for_session()
            .id(1)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();
        let token2 = VaultRefreshToken::new_for_session()
            .id(2)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();
        let token3 = VaultRefreshToken::new_for_session()
            .id(3)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
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
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .create()
            .unwrap();
        let token2 = VaultRefreshToken::new_for_client()
            .id(2)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .create()
            .unwrap();
        let token3 = VaultRefreshToken::new_for_client()
            .id(3)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
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
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();
        let token2 = VaultRefreshToken::new_for_session()
            .id(2)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
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
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .create()
            .unwrap();
        let token2 = VaultRefreshToken::new_for_client()
            .id(2)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
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
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .create()
            .unwrap();
        let token2 = VaultRefreshToken::new_for_client()
            .id(2)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .create()
            .unwrap();

        repo.create(token1).await.unwrap();
        repo.create(token2).await.unwrap();

        let revoked_count = repo.revoke_by_vault(VaultSlug::from(100_u64)).await.unwrap();
        assert_eq!(revoked_count, 2);

        let token1_after = repo.get(1).await.unwrap().unwrap();
        let token2_after = repo.get(2).await.unwrap().unwrap();
        assert!(token1_after.is_revoked());
        assert!(token2_after.is_revoked());
    }

    // ========================================================================
    // TTL Tests
    // ========================================================================

    #[tokio::test]
    async fn test_create_token_sets_ttl_on_all_keys() {
        let (repo, storage) = create_test_repo_with_storage();
        let token = VaultRefreshToken::new_for_session()
            .id(1)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .ttl_seconds(2)
            .create()
            .unwrap();
        let token_str = token.token.clone();

        repo.create(token).await.unwrap();

        // All 4 keys should exist immediately
        assert!(storage.get(b"vault_refresh_token:1").await.unwrap().is_some());
        assert!(
            storage
                .get(format!("vault_refresh_token:token:{token_str}").as_bytes())
                .await
                .unwrap()
                .is_some()
        );
        assert!(storage.get(b"vault_refresh_token:vault:100:1").await.unwrap().is_some());
        assert!(storage.get(b"vault_refresh_token:session:300:1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_token_keys_expire_from_storage() {
        let (repo, storage) = create_test_repo_with_storage();
        let token = VaultRefreshToken::new_for_session()
            .id(1)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .ttl_seconds(2)
            .create()
            .unwrap();
        let token_str = token.token.clone();

        repo.create(token).await.unwrap();

        // Wait for TTL to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // All 4 keys should be absent from raw storage
        assert!(
            storage.get(b"vault_refresh_token:1").await.unwrap().is_none(),
            "main record should be expired"
        );
        assert!(
            storage
                .get(format!("vault_refresh_token:token:{token_str}").as_bytes())
                .await
                .unwrap()
                .is_none(),
            "token lookup should be expired"
        );
        assert!(
            storage.get(b"vault_refresh_token:vault:100:1").await.unwrap().is_none(),
            "vault index should be expired"
        );
        assert!(
            storage.get(b"vault_refresh_token:session:300:1").await.unwrap().is_none(),
            "session index should be expired"
        );
    }

    #[tokio::test]
    async fn test_mark_used_sets_residual_ttl() {
        let (repo, storage) = create_test_repo_with_storage();
        let mut token = VaultRefreshToken::new_for_session()
            .id(1)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Reader)
            .user_session_id(300)
            .ttl_seconds(2)
            .create()
            .unwrap();

        repo.create(token.clone()).await.unwrap();

        // Mark as used (sets USED_TOKEN_RESIDUAL_TTL = 5 min)
        token.mark_used();
        repo.update(&token).await.unwrap();

        // Wait past the original 2-second creation TTL
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Keys should still exist because mark_used set a 5-minute residual TTL
        assert!(
            storage.get(b"vault_refresh_token:1").await.unwrap().is_some(),
            "used token should persist with 5-minute residual TTL"
        );
        assert!(
            storage.get(b"vault_refresh_token:vault:100:1").await.unwrap().is_some(),
            "vault index should persist with residual TTL"
        );
    }

    #[tokio::test]
    async fn test_revoke_sets_residual_ttl() {
        let (repo, storage) = create_test_repo_with_storage();
        let mut token = VaultRefreshToken::new_for_client()
            .id(1)
            .vault(VaultSlug::from(100_u64))
            .organization(OrganizationSlug::from(200_u64))
            .vault_role(VaultRole::Writer)
            .org_api_key_id(400)
            .ttl_seconds(2)
            .create()
            .unwrap();

        repo.create(token.clone()).await.unwrap();

        // Revoke (sets REVOKED_TOKEN_RESIDUAL_TTL = 60s)
        token.mark_revoked();
        repo.update(&token).await.unwrap();

        // Wait past the original 2-second creation TTL
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Keys should still exist because revoke set a 60-second residual TTL
        assert!(
            storage.get(b"vault_refresh_token:1").await.unwrap().is_some(),
            "revoked token should persist with 60s residual TTL"
        );
        assert!(
            storage.get(b"vault_refresh_token:client:400:1").await.unwrap().is_some(),
            "client index should persist with residual TTL"
        );
    }
}
