use inferadb_management_storage::StorageBackend;
use inferadb_management_types::{
    entities::AuthorizationCode,
    error::{Error, Result},
};

/// Repository for AuthorizationCode entity operations
///
/// Key schema:
/// - authz_code:{code} -> AuthorizationCode data (TTL: 10 minutes)
/// - authz_code:session:{session_id}:{code} -> code (for session's code lookups)
pub struct AuthorizationCodeRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> AuthorizationCodeRepository<S> {
    /// Create a new authorization code repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for code by code string
    fn code_key(code: &str) -> Vec<u8> {
        format!("authz_code:{}", code).into_bytes()
    }

    /// Generate key for session's code index
    fn session_code_index_key(session_id: i64, code: &str) -> Vec<u8> {
        format!("authz_code:session:{}:{}", session_id, code).into_bytes()
    }

    /// Create a new authorization code
    ///
    /// Authorization codes are automatically stored with TTL (10 minutes)
    pub async fn create(&self, code: AuthorizationCode) -> Result<()> {
        // Serialize code
        let code_data = serde_json::to_vec(&code)
            .map_err(|e| Error::Internal(format!("Failed to serialize code: {}", e)))?;

        // Calculate TTL in seconds from now until expiry
        let ttl_seconds = code
            .time_until_expiry()
            .map(|d| d.num_seconds().max(0) as u64)
            .unwrap_or(AuthorizationCode::TTL_SECONDS as u64);

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {}", e)))?;

        // Store code record with TTL
        txn.set(Self::code_key(&code.code), code_data.clone());

        // Store session's code index with TTL
        txn.set(
            Self::session_code_index_key(code.session_id, &code.code),
            code.code.as_bytes().to_vec(),
        );

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit code creation: {}", e)))?;

        // Set TTL for the code record (after commit since TTL is not transactional)
        self.storage
            .set_with_ttl(Self::code_key(&code.code), code_data, ttl_seconds)
            .await
            .map_err(|e| Error::Internal(format!("Failed to set code TTL: {}", e)))?;

        // Set TTL for the session index
        self.storage
            .set_with_ttl(
                Self::session_code_index_key(code.session_id, &code.code),
                code.code.as_bytes().to_vec(),
                ttl_seconds,
            )
            .await
            .map_err(|e| Error::Internal(format!("Failed to set session index TTL: {}", e)))?;

        Ok(())
    }

    /// Get an authorization code by code string
    ///
    /// Returns None if code doesn't exist, is expired, or has been used
    pub async fn get_by_code(&self, code: &str) -> Result<Option<AuthorizationCode>> {
        let key = Self::code_key(code);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get code: {}", e)))?;

        match data {
            Some(bytes) => {
                let auth_code: AuthorizationCode = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("Failed to deserialize code: {}", e)))?;

                // Only return valid codes
                if auth_code.is_valid() { Ok(Some(auth_code)) } else { Ok(None) }
            },
            None => Ok(None),
        }
    }

    /// Update an authorization code (e.g., to mark as used)
    pub async fn update(&self, code: AuthorizationCode) -> Result<()> {
        // Verify code exists
        let existing = self.get_by_code(&code.code).await?;
        if existing.is_none() {
            return Err(Error::NotFound("Authorization code not found".to_string()));
        }

        // Serialize code
        let code_data = serde_json::to_vec(&code)
            .map_err(|e| Error::Internal(format!("Failed to serialize code: {}", e)))?;

        // Calculate TTL in seconds from now until expiry
        let ttl_seconds =
            code.time_until_expiry().map(|d| d.num_seconds().max(0) as u64).unwrap_or(1); // Minimum 1 second to ensure it gets written

        // Update code record with TTL
        self.storage
            .set_with_ttl(Self::code_key(&code.code), code_data, ttl_seconds)
            .await
            .map_err(|e| Error::Internal(format!("Failed to update code: {}", e)))?;

        Ok(())
    }

    /// Mark a code as used
    pub async fn mark_used(&self, code: &str) -> Result<()> {
        let mut auth_code = self.get_by_code(code).await?.ok_or_else(|| {
            Error::NotFound("Authorization code not found or expired".to_string())
        })?;

        auth_code.mark_used();
        self.update(auth_code).await
    }

    /// Delete an authorization code and all associated indexes
    pub async fn delete(&self, code: &str) -> Result<()> {
        // Get code to remove indexes
        let auth_code = self.get_by_code(code).await?;

        if let Some(auth_code) = auth_code {
            let mut txn = self
                .storage
                .transaction()
                .await
                .map_err(|e| Error::Internal(format!("Failed to start transaction: {}", e)))?;

            // Delete code record
            txn.delete(Self::code_key(code));

            // Delete session's code index
            txn.delete(Self::session_code_index_key(auth_code.session_id, code));

            // Commit transaction
            txn.commit()
                .await
                .map_err(|e| Error::Internal(format!("Failed to commit code deletion: {}", e)))?;
        }

        Ok(())
    }

    /// Check if a code exists and is valid
    pub async fn is_valid(&self, code: &str) -> Result<bool> {
        Ok(self.get_by_code(code).await?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use inferadb_management_storage::MemoryBackend;

    use super::*;

    fn create_test_code(id: i64, code: &str, session_id: i64) -> AuthorizationCode {
        AuthorizationCode::new(
            id,
            code.to_string(),
            session_id,
            "test-challenge".to_string(),
            "S256".to_string(),
        )
    }

    #[tokio::test]
    async fn test_create_code() {
        let storage = MemoryBackend::new();
        let repo = AuthorizationCodeRepository::new(storage);
        let code = create_test_code(1, "test-code-123", 100);

        repo.create(code.clone()).await.unwrap();

        let retrieved = repo.get_by_code("test-code-123").await.unwrap().unwrap();
        assert_eq!(retrieved.id, code.id);
        assert_eq!(retrieved.session_id, code.session_id);
        assert_eq!(retrieved.code, code.code);
    }

    #[tokio::test]
    async fn test_get_nonexistent_code() {
        let storage = MemoryBackend::new();
        let repo = AuthorizationCodeRepository::new(storage);

        let result = repo.get_by_code("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_mark_used() {
        let storage = MemoryBackend::new();
        let repo = AuthorizationCodeRepository::new(storage);
        let code = create_test_code(1, "test-code-123", 100);

        repo.create(code.clone()).await.unwrap();

        // Verify code is valid
        assert!(repo.is_valid("test-code-123").await.unwrap());

        // Mark as used
        repo.mark_used("test-code-123").await.unwrap();

        // Code should no longer be valid
        assert!(!repo.is_valid("test-code-123").await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_code() {
        let storage = MemoryBackend::new();
        let repo = AuthorizationCodeRepository::new(storage);
        let code = create_test_code(1, "test-code-123", 100);

        repo.create(code.clone()).await.unwrap();
        repo.delete("test-code-123").await.unwrap();

        // Deleted code should not exist
        assert!(repo.get_by_code("test-code-123").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_is_valid() {
        let storage = MemoryBackend::new();
        let repo = AuthorizationCodeRepository::new(storage);
        let code = create_test_code(1, "test-code-123", 100);

        assert!(!repo.is_valid("test-code-123").await.unwrap());

        repo.create(code).await.unwrap();
        assert!(repo.is_valid("test-code-123").await.unwrap());

        repo.mark_used("test-code-123").await.unwrap();
        assert!(!repo.is_valid("test-code-123").await.unwrap());
    }
}
