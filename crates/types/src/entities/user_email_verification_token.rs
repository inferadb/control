use bon::bon;
use chrono::Duration;
use serde::{Deserialize, Serialize};

use super::secure_token::{SecureToken, SecureTokenEntity};
use crate::error::Result;

/// Email verification token expiry duration (24 hours)
const TOKEN_EXPIRY_HOURS: i64 = 24;

/// Email verification token entity
///
/// Links a [`SecureToken`] to a specific user email address for
/// confirming email ownership. Expires after 24 hours.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserEmailVerificationToken {
    /// UserEmail ID this token is for
    pub user_email_id: i64,

    /// Shared secure token fields (id, token, created_at, expires_at, used_at)
    #[serde(flatten)]
    pub secure_token: SecureToken,
}

#[bon]
impl UserEmailVerificationToken {
    /// Create a new email verification token
    ///
    /// # Arguments
    ///
    /// * `id` - Snowflake ID for the token
    /// * `user_email_id` - ID of the UserEmail to verify
    /// * `token` - The verification token (must be 64 hex characters)
    #[builder(on(String, into), finish_fn = create)]
    pub fn new(id: i64, user_email_id: i64, token: String) -> Result<Self> {
        let secure_token = SecureToken::new(id, token, Duration::hours(TOKEN_EXPIRY_HOURS))?;
        Ok(Self { user_email_id, secure_token })
    }

    /// Generate a random verification token
    ///
    /// Returns a 32-byte random token as a 64-character hex string.
    pub fn generate_token() -> String {
        SecureToken::generate_token()
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        self.secure_token.is_expired()
    }

    /// Check if token has been used
    pub fn is_used(&self) -> bool {
        self.secure_token.is_used()
    }

    /// Check if token is valid (not expired and not used)
    pub fn is_valid(&self) -> bool {
        self.secure_token.is_valid()
    }

    /// Mark token as used
    pub fn mark_used(&mut self) {
        self.secure_token.mark_used();
    }

    /// Get time until expiry
    pub fn time_until_expiry(&self) -> Duration {
        self.secure_token.time_until_expiry()
    }
}

impl SecureTokenEntity for UserEmailVerificationToken {
    fn key_prefix() -> &'static str {
        "email_verify_token"
    }

    fn foreign_key_prefix() -> &'static str {
        "email"
    }

    fn secure_token(&self) -> &SecureToken {
        &self.secure_token
    }

    fn secure_token_mut(&mut self) -> &mut SecureToken {
        &mut self.secure_token
    }

    fn foreign_key_id(&self) -> i64 {
        self.user_email_id
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_create_token() {
        let token = UserEmailVerificationToken::generate_token();
        let result =
            UserEmailVerificationToken::builder().id(1).user_email_id(100).token(token).create();
        assert!(result.is_ok());

        let token_entity = result.unwrap();
        assert_eq!(token_entity.secure_token.id, 1);
        assert_eq!(token_entity.user_email_id, 100);
        assert!(!token_entity.is_expired());
        assert!(!token_entity.is_used());
        assert!(token_entity.is_valid());
    }

    #[test]
    fn test_token_validation_length() {
        let result =
            UserEmailVerificationToken::builder().id(1).user_email_id(100).token("short").create();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), crate::error::Error::Validation { .. }));
    }

    #[test]
    fn test_token_validation_hex() {
        let invalid_token = "z".repeat(64);
        let result = UserEmailVerificationToken::builder()
            .id(1)
            .user_email_id(100)
            .token(invalid_token)
            .create();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), crate::error::Error::Validation { .. }));
    }

    #[test]
    fn test_generate_token() {
        let token1 = UserEmailVerificationToken::generate_token();
        let token2 = UserEmailVerificationToken::generate_token();

        assert_eq!(token1.len(), 64);
        assert_eq!(token2.len(), 64);
        assert_ne!(token1, token2);
        assert!(token1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_mark_used() {
        let token = UserEmailVerificationToken::generate_token();
        let mut token_entity = UserEmailVerificationToken::builder()
            .id(1)
            .user_email_id(100)
            .token(token)
            .create()
            .unwrap();

        assert!(!token_entity.is_used());
        assert!(token_entity.is_valid());

        token_entity.mark_used();

        assert!(token_entity.is_used());
        assert!(!token_entity.is_valid());
    }

    #[test]
    fn test_time_until_expiry() {
        let token = UserEmailVerificationToken::generate_token();
        let token_entity = UserEmailVerificationToken::builder()
            .id(1)
            .user_email_id(100)
            .token(token)
            .create()
            .unwrap();

        let time_left = token_entity.time_until_expiry();
        assert!(time_left > Duration::hours(23));
        assert!(time_left <= Duration::hours(24));
    }

    #[test]
    fn test_serde_roundtrip() {
        let token = UserEmailVerificationToken::generate_token();
        let entity = UserEmailVerificationToken::builder()
            .id(42)
            .user_email_id(100)
            .token(token)
            .create()
            .unwrap();

        let json = serde_json::to_string(&entity).unwrap();
        let deserialized: UserEmailVerificationToken = serde_json::from_str(&json).unwrap();
        assert_eq!(entity, deserialized);
    }
}
