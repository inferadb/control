use crate::entities::VaultRole;
use crate::error::{Error, Result};
use chrono::{DateTime, Duration, Utc};
use hex::encode as hex_encode;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Vault refresh token for obtaining new access tokens
///
/// Refresh tokens are long-lived credentials that can be exchanged for
/// new short-lived JWT access tokens. They are bound to either a user
/// session (for user authentication) or a client (for client authentication).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRefreshToken {
    pub id: i64,
    /// Hex-encoded token value (32 bytes = 64 hex characters)
    pub token: String,
    /// Vault this token grants access to
    pub vault_id: i64,
    /// Organization that owns the vault
    pub organization_id: i64,
    /// Role granted by this token
    pub vault_role: VaultRole,
    /// User session this token is bound to (for user authentication)
    /// Mutually exclusive with org_api_key_id
    pub user_session_id: Option<i64>,
    /// Client this token is bound to (for client authentication)
    /// Mutually exclusive with user_session_id
    pub org_api_key_id: Option<i64>,
    /// When the token was created
    pub created_at: DateTime<Utc>,
    /// When the token expires
    pub expires_at: DateTime<Utc>,
    /// When the token was used (for one-time use detection)
    pub used_at: Option<DateTime<Utc>>,
    /// When the token was revoked
    pub revoked_at: Option<DateTime<Utc>>,
}

impl VaultRefreshToken {
    /// Default TTL for user session refresh tokens (1 hour per spec)
    pub const USER_SESSION_TTL_SECONDS: i64 = 3600;

    /// Default TTL for client refresh tokens (7 days per spec)
    pub const CLIENT_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

    /// Create a new refresh token for a user session
    pub fn new_for_session(
        id: i64,
        vault_id: i64,
        organization_id: i64,
        vault_role: VaultRole,
        user_session_id: i64,
        ttl_seconds: Option<i64>,
    ) -> Result<Self> {
        let token = Self::generate_token();
        let now = Utc::now();
        let ttl = ttl_seconds.unwrap_or(Self::USER_SESSION_TTL_SECONDS);
        let expires_at = now + Duration::seconds(ttl);

        Ok(Self {
            id,
            token,
            vault_id,
            organization_id,
            vault_role,
            user_session_id: Some(user_session_id),
            org_api_key_id: None,
            created_at: now,
            expires_at,
            used_at: None,
            revoked_at: None,
        })
    }

    /// Create a new refresh token for a client
    pub fn new_for_client(
        id: i64,
        vault_id: i64,
        organization_id: i64,
        vault_role: VaultRole,
        org_api_key_id: i64,
        ttl_seconds: Option<i64>,
    ) -> Result<Self> {
        let token = Self::generate_token();
        let now = Utc::now();
        let ttl = ttl_seconds.unwrap_or(Self::CLIENT_TTL_SECONDS);
        let expires_at = now + Duration::seconds(ttl);

        Ok(Self {
            id,
            token,
            vault_id,
            organization_id,
            vault_role,
            user_session_id: None,
            org_api_key_id: Some(org_api_key_id),
            created_at: now,
            expires_at,
            used_at: None,
            revoked_at: None,
        })
    }

    /// Generate a cryptographically random token (32 bytes, hex-encoded)
    fn generate_token() -> String {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        hex_encode(bytes)
    }

    /// Check if the token has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check if the token has been used
    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    /// Check if the token has been revoked
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Check if the token is valid (not expired, used, or revoked)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_used() && !self.is_revoked()
    }

    /// Mark the token as used (for replay attack detection)
    pub fn mark_used(&mut self) {
        self.used_at = Some(Utc::now());
    }

    /// Revoke the token
    pub fn mark_revoked(&mut self) {
        self.revoked_at = Some(Utc::now());
    }

    /// Validate token for refresh operation
    ///
    /// Returns an error if:
    /// - Token is expired
    /// - Token has already been used
    /// - Token has been revoked
    pub fn validate_for_refresh(&self) -> Result<()> {
        if self.is_revoked() {
            return Err(Error::Authz("Refresh token has been revoked".to_string()));
        }

        if self.is_used() {
            return Err(Error::Authz(
                "Refresh token has already been used (replay attack detected)".to_string(),
            ));
        }

        if self.is_expired() {
            return Err(Error::Authz("Refresh token has expired".to_string()));
        }

        Ok(())
    }

    /// Validate that the token is bound to the expected auth context
    ///
    /// For session-based tokens: validates user_session_id matches
    /// For client-based tokens: validates org_api_key_id matches
    pub fn validate_auth_context(
        &self,
        user_session_id: Option<i64>,
        org_api_key_id: Option<i64>,
    ) -> Result<()> {
        match (self.user_session_id, self.org_api_key_id) {
            (Some(token_session_id), None) => {
                // Token is session-bound
                if user_session_id != Some(token_session_id) {
                    return Err(Error::Authz(
                        "Refresh token is bound to a different session".to_string(),
                    ));
                }
            }
            (None, Some(token_client_id)) => {
                // Token is client-bound
                if org_api_key_id != Some(token_client_id) {
                    return Err(Error::Authz(
                        "Refresh token is bound to a different client".to_string(),
                    ));
                }
            }
            _ => {
                return Err(Error::Internal(
                    "Invalid refresh token: must be bound to session or client".to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        let token1 = VaultRefreshToken::generate_token();
        let token2 = VaultRefreshToken::generate_token();

        // Tokens should be 64 hex characters (32 bytes)
        assert_eq!(token1.len(), 64);
        assert_eq!(token2.len(), 64);

        // Tokens should be different (random)
        assert_ne!(token1, token2);

        // Tokens should be valid hex
        assert!(hex::decode(&token1).is_ok());
        assert!(hex::decode(&token2).is_ok());
    }

    #[test]
    fn test_new_for_session() {
        let token =
            VaultRefreshToken::new_for_session(1, 100, 200, VaultRole::Reader, 300, None).unwrap();

        assert_eq!(token.id, 1);
        assert_eq!(token.vault_id, 100);
        assert_eq!(token.organization_id, 200);
        assert_eq!(token.vault_role, VaultRole::Reader);
        assert_eq!(token.user_session_id, Some(300));
        assert_eq!(token.org_api_key_id, None);
        assert!(!token.is_expired());
        assert!(!token.is_used());
        assert!(!token.is_revoked());
        assert!(token.is_valid());
    }

    #[test]
    fn test_new_for_client() {
        let token =
            VaultRefreshToken::new_for_client(1, 100, 200, VaultRole::Writer, 400, None).unwrap();

        assert_eq!(token.id, 1);
        assert_eq!(token.vault_id, 100);
        assert_eq!(token.organization_id, 200);
        assert_eq!(token.vault_role, VaultRole::Writer);
        assert_eq!(token.user_session_id, None);
        assert_eq!(token.org_api_key_id, Some(400));
        assert!(!token.is_expired());
        assert!(!token.is_used());
        assert!(!token.is_revoked());
        assert!(token.is_valid());
    }

    #[test]
    fn test_token_expiration() {
        // Create a token with negative TTL (already expired)
        let token =
            VaultRefreshToken::new_for_session(1, 100, 200, VaultRole::Reader, 300, Some(-1))
                .unwrap();

        assert!(token.is_expired());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_mark_used() {
        let mut token =
            VaultRefreshToken::new_for_session(1, 100, 200, VaultRole::Reader, 300, None).unwrap();

        assert!(!token.is_used());
        assert!(token.is_valid());

        token.mark_used();
        assert!(token.is_used());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_mark_revoked() {
        let mut token =
            VaultRefreshToken::new_for_session(1, 100, 200, VaultRole::Reader, 300, None).unwrap();

        assert!(!token.is_revoked());
        assert!(token.is_valid());

        token.mark_revoked();
        assert!(token.is_revoked());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_validate_for_refresh_success() {
        let token =
            VaultRefreshToken::new_for_session(1, 100, 200, VaultRole::Reader, 300, None).unwrap();

        assert!(token.validate_for_refresh().is_ok());
    }

    #[test]
    fn test_validate_for_refresh_expired() {
        let token =
            VaultRefreshToken::new_for_session(1, 100, 200, VaultRole::Reader, 300, Some(-1))
                .unwrap();

        let result = token.validate_for_refresh();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_validate_for_refresh_used() {
        let mut token =
            VaultRefreshToken::new_for_session(1, 100, 200, VaultRole::Reader, 300, None).unwrap();

        token.mark_used();
        let result = token.validate_for_refresh();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("already been used"));
    }

    #[test]
    fn test_validate_for_refresh_revoked() {
        let mut token =
            VaultRefreshToken::new_for_session(1, 100, 200, VaultRole::Reader, 300, None).unwrap();

        token.mark_revoked();
        let result = token.validate_for_refresh();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("revoked"));
    }

    #[test]
    fn test_validate_auth_context_session() {
        let token =
            VaultRefreshToken::new_for_session(1, 100, 200, VaultRole::Reader, 300, None).unwrap();

        // Correct session
        assert!(token.validate_auth_context(Some(300), None).is_ok());

        // Wrong session
        assert!(token.validate_auth_context(Some(999), None).is_err());

        // Client instead of session
        assert!(token.validate_auth_context(None, Some(400)).is_err());
    }

    #[test]
    fn test_validate_auth_context_client() {
        let token =
            VaultRefreshToken::new_for_client(1, 100, 200, VaultRole::Writer, 400, None).unwrap();

        // Correct client
        assert!(token.validate_auth_context(None, Some(400)).is_ok());

        // Wrong client
        assert!(token.validate_auth_context(None, Some(999)).is_err());

        // Session instead of client
        assert!(token.validate_auth_context(Some(300), None).is_err());
    }

    #[test]
    fn test_default_ttl() {
        // User session default TTL is 1 hour
        assert_eq!(VaultRefreshToken::USER_SESSION_TTL_SECONDS, 3600);

        // Client default TTL is 7 days
        assert_eq!(VaultRefreshToken::CLIENT_TTL_SECONDS, 7 * 24 * 60 * 60);
    }
}
