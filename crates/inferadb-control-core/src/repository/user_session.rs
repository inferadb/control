use inferadb_control_const::limits::MAX_CONCURRENT_SESSIONS;
use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::UserSession,
    error::{Error, Result},
};

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
    fn session_key(id: i64) -> Vec<u8> {
        format!("session:{id}").into_bytes()
    }

    /// Generate key for user's session index
    fn user_session_index_key(user_id: i64, session_id: i64) -> Vec<u8> {
        format!("session:user:{user_id}:{session_id}").into_bytes()
    }

    /// Generate key for active session index
    fn active_session_index_key(id: i64) -> Vec<u8> {
        format!("session:active:{id}").into_bytes()
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
            .map_err(|e| Error::Internal(format!("Failed to serialize session: {e}")))?;

        // Calculate TTL in seconds from now until expiry
        let _ttl_seconds =
            session.time_until_expiry().map(|d| d.num_seconds().max(0) as u64).unwrap_or(0);

        // Expired sessions are filtered out in get() since transactions don't support TTL

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Store session record
        txn.set(Self::session_key(session.id), session_data);

        // Store user's session index with TTL
        txn.set(
            Self::user_session_index_key(session.user_id, session.id),
            session.id.to_le_bytes().to_vec(),
        );

        // Store active session index with TTL
        txn.set(Self::active_session_index_key(session.id), session.id.to_le_bytes().to_vec());

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit session creation: {e}")))?;

        Ok(())
    }

    /// Get a session by ID
    ///
    /// Returns None if session doesn't exist, is expired, or is revoked
    pub async fn get(&self, id: i64) -> Result<Option<UserSession>> {
        let key = Self::session_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get session: {e}")))?;

        match data {
            Some(bytes) => {
                let session: UserSession = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("Failed to deserialize session: {e}")))?;

                // Only return active sessions
                if session.is_active() { Ok(Some(session)) } else { Ok(None) }
            },
            None => Ok(None),
        }
    }

    /// Get all active sessions for a user
    pub async fn get_user_sessions(&self, user_id: i64) -> Result<Vec<UserSession>> {
        // Use range query to get all sessions for this user
        let prefix = format!("session:user:{user_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("session:user:{user_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get user sessions: {e}")))?;

        let mut sessions = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue; // Skip invalid entries
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
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
            return Err(Error::NotFound("Session not found".to_string()));
        }

        // Serialize session
        let session_data = serde_json::to_vec(&session)
            .map_err(|e| Error::Internal(format!("Failed to serialize session: {e}")))?;

        // Update session record
        self.storage
            .set(Self::session_key(session.id), session_data)
            .await
            .map_err(|e| Error::Internal(format!("Failed to update session: {e}")))?;

        Ok(())
    }

    /// Update session activity (sliding window expiry)
    ///
    /// This extends the session expiry time and updates last activity
    pub async fn update_activity(&self, id: i64) -> Result<()> {
        let mut session = self
            .get(id)
            .await?
            .ok_or_else(|| Error::NotFound("Session not found or expired".to_string()))?;

        session.update_activity();
        self.update(session).await
    }

    /// Revoke a session (soft delete)
    pub async fn revoke(&self, id: i64) -> Result<()> {
        let mut session = self
            .get(id)
            .await?
            .ok_or_else(|| Error::NotFound("Session not found or expired".to_string()))?;

        session.revoke();
        self.update(session).await
    }

    /// Revoke all sessions for a user
    pub async fn revoke_user_sessions(&self, user_id: i64) -> Result<()> {
        let sessions = self.get_user_sessions(user_id).await?;

        for session in sessions {
            self.revoke(session.id).await?;
        }

        Ok(())
    }

    /// Delete a session and all associated indexes
    ///
    /// This is a hard delete that removes all traces of the session
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get session to remove indexes
        let session = self.get(id).await?;

        if let Some(session) = session {
            let mut txn = self
                .storage
                .transaction()
                .await
                .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

            // Delete session record
            txn.delete(Self::session_key(id));

            // Delete user's session index
            txn.delete(Self::user_session_index_key(session.user_id, id));

            // Delete active session index
            txn.delete(Self::active_session_index_key(id));

            // Commit transaction
            txn.commit()
                .await
                .map_err(|e| Error::Internal(format!("Failed to commit session deletion: {e}")))?;
        }

        Ok(())
    }

    /// Clean up expired sessions
    ///
    /// This should be called periodically to remove expired sessions
    /// Note: With TTL-aware storage backends, this may not be necessary
    pub async fn cleanup_expired(&self) -> Result<usize> {
        // Get all active session indexes
        let start = b"session:active:".to_vec();
        let end = b"session:active:~".to_vec();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get active sessions: {e}")))?;

        let mut cleaned = 0;

        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());

            // Try to get session - if expired, it will return None
            if self.get(id).await?.is_none() {
                // Session is expired or revoked, delete it
                self.delete(id).await?;
                cleaned += 1;
            }
        }

        Ok(cleaned)
    }

    /// Check if a session exists and is active
    pub async fn is_active(&self, id: i64) -> Result<bool> {
        Ok(self.get(id).await?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use inferadb_control_storage::MemoryBackend;
    use inferadb_control_types::entities::SessionType;

    use super::*;

    async fn create_test_session(id: i64, user_id: i64, session_type: SessionType) -> UserSession {
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
}
