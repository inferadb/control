use std::time::Duration;

use inferadb_control_const::limits::MAX_CONCURRENT_SESSIONS;
use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::UserSession,
    error::{Error, Result},
};

/// TTL applied to revoked sessions, allowing a brief window for in-flight
/// requests to observe the revocation before Ledger GC removes the record.
const REVOKED_SESSION_TTL: Duration = Duration::from_secs(60);

/// Repository for UserSession entity operations
///
/// Key schema:
/// - session:{id} -> UserSession data
/// - session:user:{user_id}:{id} -> session_id (for user's session lookups)
/// - session:active:{id} -> session_id (for active session tracking)
pub struct UserSessionRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> UserSessionRepository<S> {
    /// Create a new user session repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for session by ID
    fn session_key(id: u64) -> Vec<u8> {
        format!("session:{id}").into_bytes()
    }

    /// Generate key for user's session index
    fn user_session_index_key(user_id: u64, session_id: u64) -> Vec<u8> {
        format!("session:user:{user_id}:{session_id}").into_bytes()
    }

    /// Generate key for active session index
    fn active_session_index_key(id: u64) -> Vec<u8> {
        format!("session:active:{id}").into_bytes()
    }

    /// Write all 3 session keys with the given TTL.
    ///
    /// This is used after transaction commit (two-phase pattern) and for
    /// non-transactional updates that need to set or reset TTL on every key.
    async fn set_all_keys_with_ttl(&self, session: &UserSession, ttl: Duration) -> Result<()> {
        let session_data = serde_json::to_vec(session)
            .map_err(|e| Error::internal(format!("Failed to serialize session: {e}")))?;

        self.storage
            .set_with_ttl(Self::session_key(session.id), session_data, ttl)
            .await
            .map_err(|e| Error::internal(format!("Failed to set session TTL: {e}")))?;

        self.storage
            .set_with_ttl(
                Self::user_session_index_key(session.user_id, session.id),
                session.id.to_le_bytes().to_vec(),
                ttl,
            )
            .await
            .map_err(|e| Error::internal(format!("Failed to set user session index TTL: {e}")))?;

        self.storage
            .set_with_ttl(
                Self::active_session_index_key(session.id),
                session.id.to_le_bytes().to_vec(),
                ttl,
            )
            .await
            .map_err(|e| Error::internal(format!("Failed to set active session index TTL: {e}")))?;

        Ok(())
    }

    /// Create a new session
    ///
    /// Sessions are automatically stored with TTL based on their expiry time
    /// Enforces maximum concurrent session limit (10 per user)
    pub async fn create(&self, session: UserSession) -> Result<()> {
        // Check current session count and enforce limit
        let mut current_sessions = self.get_user_sessions(session.user_id).await?;

        if current_sessions.len() >= MAX_CONCURRENT_SESSIONS {
            // Evict oldest session (by last_activity_at)
            current_sessions.sort_by(|a, b| a.last_activity_at.cmp(&b.last_activity_at));
            let oldest_session = &current_sessions[0];
            tracing::info!(
                "Evicting oldest session {} for user {} (reached max concurrent sessions)",
                oldest_session.id,
                session.user_id
            );
            self.revoke(oldest_session.id).await?;
        }

        // Serialize session
        let session_data = serde_json::to_vec(&session)
            .map_err(|e| Error::internal(format!("Failed to serialize session: {e}")))?;

        let ttl_seconds =
            session.time_until_expiry().map(|d| d.num_seconds().max(1) as u64).unwrap_or(1);

        // Use transaction for atomicity (TTL is applied after commit via two-phase pattern)
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

        // Store session record
        txn.set(Self::session_key(session.id), session_data);

        // Store user's session index
        txn.set(
            Self::user_session_index_key(session.user_id, session.id),
            session.id.to_le_bytes().to_vec(),
        );

        // Store active session index
        txn.set(Self::active_session_index_key(session.id), session.id.to_le_bytes().to_vec());

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::internal(format!("Failed to commit session creation: {e}")))?;

        // Apply TTL to all keys (two-phase pattern: transaction for atomicity, then TTL)
        self.set_all_keys_with_ttl(&session, Duration::from_secs(ttl_seconds)).await?;

        Ok(())
    }

    /// Get a session by ID
    ///
    /// Returns None if session doesn't exist, is expired, or is revoked
    pub async fn get(&self, id: u64) -> Result<Option<UserSession>> {
        let key = Self::session_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::internal(format!("Failed to get session: {e}")))?;

        match data {
            Some(bytes) => {
                let session: UserSession = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::internal(format!("Failed to deserialize session: {e}")))?;

                // Only return active sessions
                if session.is_active() { Ok(Some(session)) } else { Ok(None) }
            },
            None => Ok(None),
        }
    }

    /// Get all active sessions for a user
    pub async fn get_user_sessions(&self, user_id: u64) -> Result<Vec<UserSession>> {
        // Use range query to get all sessions for this user
        let prefix = format!("session:user:{user_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("session:user:{user_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::internal(format!("Failed to get user sessions: {e}")))?;

        let mut sessions = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue; // Skip invalid entries
            }
            let Ok(id) = super::parse_u64_id(&kv.value) else { continue };
            if let Some(session) = self.get(id).await? {
                // Only include active sessions
                if session.is_active() {
                    sessions.push(session);
                }
            }
        }

        // Sort by last activity (most recent first)
        sessions.sort_by(|a, b| b.last_activity_at.cmp(&a.last_activity_at));

        Ok(sessions)
    }

    /// Update a session
    ///
    /// This is typically used to update last activity time (sliding window)
    pub async fn update(&self, session: UserSession) -> Result<()> {
        // Verify session exists
        let existing = self.get(session.id).await?;
        if existing.is_none() {
            return Err(Error::not_found("Session not found".to_string()));
        }

        // Serialize session
        let session_data = serde_json::to_vec(&session)
            .map_err(|e| Error::internal(format!("Failed to serialize session: {e}")))?;

        // Update session record
        self.storage
            .set(Self::session_key(session.id), session_data)
            .await
            .map_err(|e| Error::internal(format!("Failed to update session: {e}")))?;

        Ok(())
    }

    /// Update session activity (sliding window expiry)
    ///
    /// This extends the session expiry time, updates last activity, and resets
    /// TTL on all 3 storage keys to the full session type duration.
    pub async fn update_activity(&self, id: u64) -> Result<()> {
        let mut session = self
            .get(id)
            .await?
            .ok_or_else(|| Error::not_found("Session not found or expired".to_string()))?;

        session.update_activity();

        let ttl = Duration::from_secs(session.session_type.ttl_seconds() as u64);
        self.set_all_keys_with_ttl(&session, ttl).await
    }

    /// Revoke a session (soft delete)
    ///
    /// Sets a short residual TTL so the revoked record remains briefly
    /// visible for in-flight requests, then Ledger GC removes it.
    pub async fn revoke(&self, id: u64) -> Result<()> {
        let mut session = self
            .get(id)
            .await?
            .ok_or_else(|| Error::not_found("Session not found or expired".to_string()))?;

        session.revoke();
        self.set_all_keys_with_ttl(&session, REVOKED_SESSION_TTL).await
    }

    /// Revoke all sessions for a user
    pub async fn revoke_user_sessions(&self, user_id: u64) -> Result<()> {
        let sessions = self.get_user_sessions(user_id).await?;

        for session in sessions {
            self.revoke(session.id).await?;
        }

        Ok(())
    }

    /// Delete a session and all associated indexes
    ///
    /// This is a hard delete that removes all traces of the session
    pub async fn delete(&self, id: u64) -> Result<()> {
        // Get session to remove indexes
        let session = self.get(id).await?;

        if let Some(session) = session {
            let mut txn = self
                .storage
                .transaction()
                .await
                .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

            // Delete session record
            txn.delete(Self::session_key(id));

            // Delete user's session index
            txn.delete(Self::user_session_index_key(session.user_id, id));

            // Delete active session index
            txn.delete(Self::active_session_index_key(id));

            // Commit transaction
            txn.commit()
                .await
                .map_err(|e| Error::internal(format!("Failed to commit session deletion: {e}")))?;
        }

        Ok(())
    }

    /// Check if a session exists and is active
    pub async fn is_active(&self, id: u64) -> Result<bool> {
        Ok(self.get(id).await?.is_some())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chrono::Utc;
    use inferadb_control_storage::MemoryBackend;
    use inferadb_control_types::entities::SessionType;

    use super::*;

    async fn create_test_session(id: u64, user_id: u64, session_type: SessionType) -> UserSession {
        UserSession::builder().id(id).user_id(user_id).session_type(session_type).create()
    }

    #[tokio::test]
    async fn test_create_session() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage);
        let session = create_test_session(1, 100, SessionType::Web).await;

        repo.create(session.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert_eq!(retrieved.id, session.id);
        assert_eq!(retrieved.user_id, session.user_id);
    }

    #[tokio::test]
    async fn test_get_user_sessions() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage);

        let session1 = create_test_session(1, 100, SessionType::Web).await;
        let session2 = create_test_session(2, 100, SessionType::Cli).await;
        let session3 = create_test_session(3, 101, SessionType::Web).await;

        repo.create(session1).await.unwrap();
        repo.create(session2).await.unwrap();
        repo.create(session3).await.unwrap();

        let sessions = repo.get_user_sessions(100).await.unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn test_update_activity() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage);
        let session = create_test_session(1, 100, SessionType::Web).await;

        repo.create(session.clone()).await.unwrap();

        // Wait a bit
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Update activity
        repo.update_activity(1).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert!(retrieved.last_activity_at > session.last_activity_at);
    }

    #[tokio::test]
    async fn test_revoke_session() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage);
        let session = create_test_session(1, 100, SessionType::Web).await;

        repo.create(session.clone()).await.unwrap();
        repo.revoke(1).await.unwrap();

        // Revoked session should not be retrieved
        assert!(repo.get(1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_revoke_user_sessions() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage);

        let session1 = create_test_session(1, 100, SessionType::Web).await;
        let session2 = create_test_session(2, 100, SessionType::Cli).await;

        repo.create(session1).await.unwrap();
        repo.create(session2).await.unwrap();

        // Revoke all sessions for user 100
        repo.revoke_user_sessions(100).await.unwrap();

        let sessions = repo.get_user_sessions(100).await.unwrap();
        assert_eq!(sessions.len(), 0);
    }

    #[tokio::test]
    async fn test_delete_session() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage);
        let session = create_test_session(1, 100, SessionType::Web).await;

        repo.create(session.clone()).await.unwrap();
        repo.delete(1).await.unwrap();

        // Deleted session should not exist
        assert!(repo.get(1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_is_active() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage);
        let session = create_test_session(1, 100, SessionType::Web).await;

        assert!(!repo.is_active(1).await.unwrap());

        repo.create(session).await.unwrap();
        assert!(repo.is_active(1).await.unwrap());

        repo.revoke(1).await.unwrap();
        assert!(!repo.is_active(1).await.unwrap());
    }

    #[tokio::test]
    async fn test_session_types() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage);

        let web_session = create_test_session(1, 100, SessionType::Web).await;
        let cli_session = create_test_session(2, 100, SessionType::Cli).await;
        let sdk_session = create_test_session(3, 100, SessionType::Sdk).await;

        repo.create(web_session.clone()).await.unwrap();
        repo.create(cli_session.clone()).await.unwrap();
        repo.create(sdk_session.clone()).await.unwrap();

        // Verify different session types have different expiry times
        assert!(web_session.expires_at < cli_session.expires_at);
        assert!(cli_session.expires_at < sdk_session.expires_at);
    }

    #[tokio::test]
    async fn test_max_concurrent_sessions() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage);

        // Create 10 sessions (at the limit)
        for i in 1..=10 {
            let session = create_test_session(i, 100, SessionType::Web).await;
            repo.create(session).await.unwrap();
        }

        // Verify we have exactly 10 sessions
        let sessions = repo.get_user_sessions(100).await.unwrap();
        assert_eq!(sessions.len(), 10);

        // Create an 11th session, which should evict the oldest
        let session_11 = create_test_session(11, 100, SessionType::Web).await;
        repo.create(session_11).await.unwrap();

        // Still should have 10 sessions
        let sessions = repo.get_user_sessions(100).await.unwrap();
        assert_eq!(sessions.len(), 10);

        // Session 1 should be revoked (oldest by activity)
        assert!(!repo.is_active(1).await.unwrap());

        // Session 11 should be active
        assert!(repo.is_active(11).await.unwrap());
    }

    // ========================================================================
    // TTL Tests
    // ========================================================================

    #[tokio::test]
    async fn test_create_session_sets_ttl_on_all_keys() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage.clone());

        let mut session = create_test_session(1, 100, SessionType::Web).await;
        session.expires_at = Utc::now() + chrono::Duration::seconds(2);

        repo.create(session).await.unwrap();

        // All 3 keys should exist in raw storage immediately after creation
        assert!(storage.get(b"session:1").await.unwrap().is_some());
        assert!(storage.get(b"session:user:100:1").await.unwrap().is_some());
        assert!(storage.get(b"session:active:1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_update_activity_resets_ttl_on_all_keys() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage.clone());

        let mut session = create_test_session(1, 100, SessionType::Web).await;
        session.expires_at = Utc::now() + chrono::Duration::seconds(2);

        repo.create(session).await.unwrap();

        // update_activity resets TTL to the full session type duration (24h for Web)
        repo.update_activity(1).await.unwrap();

        // Wait past the original 2-second TTL
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // All 3 keys should still exist because update_activity reset TTL to 24h
        assert!(
            storage.get(b"session:1").await.unwrap().is_some(),
            "session key should persist after TTL reset"
        );
        assert!(
            storage.get(b"session:user:100:1").await.unwrap().is_some(),
            "user index key should persist after TTL reset"
        );
        assert!(
            storage.get(b"session:active:1").await.unwrap().is_some(),
            "active index key should persist after TTL reset"
        );
    }

    #[tokio::test]
    async fn test_revoke_session_sets_residual_ttl() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage.clone());

        let mut session = create_test_session(1, 100, SessionType::Web).await;
        session.expires_at = Utc::now() + chrono::Duration::seconds(2);

        repo.create(session).await.unwrap();

        // Revoke immediately — sets REVOKED_SESSION_TTL (60s), overwriting the 2s creation TTL
        repo.revoke(1).await.unwrap();

        // Wait past the original 2-second TTL
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // All 3 keys should still exist because revoke set a 60-second residual TTL
        assert!(
            storage.get(b"session:1").await.unwrap().is_some(),
            "session key should persist with 60s residual TTL"
        );
        assert!(
            storage.get(b"session:user:100:1").await.unwrap().is_some(),
            "user index key should persist with 60s residual TTL"
        );
        assert!(
            storage.get(b"session:active:1").await.unwrap().is_some(),
            "active index key should persist with 60s residual TTL"
        );
    }

    #[tokio::test]
    async fn test_session_keys_expire_from_storage() {
        let storage = MemoryBackend::new();
        let repo = UserSessionRepository::new(storage.clone());

        let mut session = create_test_session(1, 100, SessionType::Web).await;
        session.expires_at = Utc::now() + chrono::Duration::seconds(2);

        repo.create(session).await.unwrap();

        // Wait for TTL to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // All 3 keys should be absent from raw storage
        assert!(
            storage.get(b"session:1").await.unwrap().is_none(),
            "session key should be expired from storage"
        );
        assert!(
            storage.get(b"session:user:100:1").await.unwrap().is_none(),
            "user index key should be expired from storage"
        );
        assert!(
            storage.get(b"session:active:1").await.unwrap().is_none(),
            "active index key should be expired from storage"
        );
    }
}
