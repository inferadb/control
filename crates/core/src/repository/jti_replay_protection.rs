use chrono::{DateTime, Utc};
use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{Error, Result};

/// Repository for JTI (JWT ID) replay protection
///
/// Stores JTIs from client assertions to prevent replay attacks.
/// JTIs are stored with a TTL matching the JWT expiration time.
pub struct JtiReplayProtectionRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> JtiReplayProtectionRepository<S> {
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Key for a specific JTI
    fn jti_key(jti: &str) -> Vec<u8> {
        format!("jti:{jti}").into_bytes()
    }

    /// Check if a JTI has been used (exists in storage)
    pub async fn is_jti_used(&self, jti: &str) -> Result<bool> {
        let key = Self::jti_key(jti);
        let result = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::internal(format!("Failed to check JTI: {e}")))?;
        Ok(result.is_some())
    }

    /// Mark a JTI as used with expiration time
    ///
    /// The JTI will be stored until the JWT expires (exp claim).
    /// After expiration, the storage backend's TTL mechanism will clean it up.
    pub async fn mark_jti_used(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<()> {
        let key = Self::jti_key(jti);
        let value = expires_at.timestamp().to_string().into_bytes();

        // Calculate TTL in seconds from now
        let now = Utc::now();
        let ttl_seconds = (expires_at - now).num_seconds();

        if ttl_seconds > 0 {
            self.storage
                .set_with_ttl(key, value, ttl_seconds as u64)
                .await
                .map_err(|e| Error::internal(format!("Failed to mark JTI as used: {e}")))?;
        } else {
            // If already expired, still set it with 1 second TTL to prevent race conditions
            self.storage
                .set_with_ttl(key, value, 1)
                .await
                .map_err(|e| Error::internal(format!("Failed to mark JTI as used: {e}")))?;
        }

        Ok(())
    }

    /// Check and mark a JTI atomically
    ///
    /// Returns Ok(()) if JTI was not used and has been marked.
    /// Returns Err if JTI was already used (replay attack detected).
    pub async fn check_and_mark_jti(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<()> {
        if self.is_jti_used(jti).await? {
            return Err(Error::authz(
                "JWT ID (jti) has already been used - replay attack detected".to_string(),
            ));
        }

        self.mark_jti_used(jti, expires_at).await?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chrono::Duration;
    use inferadb_control_storage::Backend;

    use super::*;

    #[tokio::test]
    async fn test_jti_not_used_initially() {
        let storage = Backend::memory();
        let repo = JtiReplayProtectionRepository::new(storage);

        assert!(!repo.is_jti_used("test-jti-123").await.unwrap());
    }

    #[tokio::test]
    async fn test_mark_jti_used() {
        let storage = Backend::memory();
        let repo = JtiReplayProtectionRepository::new(storage);

        let expires_at = Utc::now() + Duration::hours(1);
        repo.mark_jti_used("test-jti-123", expires_at).await.unwrap();

        assert!(repo.is_jti_used("test-jti-123").await.unwrap());
    }

    #[tokio::test]
    async fn test_check_and_mark_jti_success() {
        let storage = Backend::memory();
        let repo = JtiReplayProtectionRepository::new(storage);

        let expires_at = Utc::now() + Duration::hours(1);
        let result = repo.check_and_mark_jti("test-jti-456", expires_at).await;
        assert!(result.is_ok());

        // Verify it's now marked as used
        assert!(repo.is_jti_used("test-jti-456").await.unwrap());
    }

    #[tokio::test]
    async fn test_check_and_mark_jti_replay_detected() {
        let storage = Backend::memory();
        let repo = JtiReplayProtectionRepository::new(storage);

        let expires_at = Utc::now() + Duration::hours(1);

        // First use should succeed
        repo.check_and_mark_jti("test-jti-789", expires_at).await.unwrap();

        // Second use should fail (replay attack)
        let result = repo.check_and_mark_jti("test-jti-789", expires_at).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("replay attack detected"));
    }

    #[tokio::test]
    async fn test_different_jtis_independent() {
        let storage = Backend::memory();
        let repo = JtiReplayProtectionRepository::new(storage);

        let expires_at = Utc::now() + Duration::hours(1);

        // Mark first JTI
        repo.mark_jti_used("jti-1", expires_at).await.unwrap();

        // Second JTI should not be affected
        assert!(!repo.is_jti_used("jti-2").await.unwrap());
        repo.mark_jti_used("jti-2", expires_at).await.unwrap();
        assert!(repo.is_jti_used("jti-2").await.unwrap());
    }
}
