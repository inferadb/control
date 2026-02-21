use bon::bon;
use chrono::Duration;
use serde::{Deserialize, Serialize};

use super::secure_token::{SecureToken, SecureTokenEntity};
use crate::error::Result;

/// Password reset token expiry duration (1 hour)
const TOKEN_EXPIRY_HOURS: i64 = 1;

/// Password reset token entity
///
/// Links a [`SecureToken`] to a specific user for securely resetting
/// their password. Expires after 1 hour and can only be used once.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserPasswordResetToken {
    /// ID of the user this token is for
    pub user_id: i64,

    /// Shared secure token fields (id, token, created_at, expires_at, used_at)
    #[serde(flatten)]
    pub secure_token: SecureToken,
}

#[bon]
impl UserPasswordResetToken {
    /// Create a new password reset token
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for the token
    /// * `user_id` - ID of the user this token is for
    /// * `token` - The token string (must be 64 hex characters)
    #[builder(on(String, into), finish_fn = create)]
    pub fn new(id: i64, user_id: i64, token: String) -> Result<Self> {
        let secure_token = SecureToken::new(id, token, Duration::hours(TOKEN_EXPIRY_HOURS))?;
        Ok(Self { user_id, secure_token })
    }

    /// Generate a new cryptographically secure random token string
    ///
    /// Returns a 64-character hex-encoded string (32 bytes of entropy).
    pub fn generate_token() -> String {
        SecureToken::generate_token()
    }

    /// Check if the token has expired
    pub fn is_expired(&self) -> bool {
        self.secure_token.is_expired()
    }

    /// Check if the token has been used
    pub fn is_used(&self) -> bool {
        self.secure_token.is_used()
    }

    /// Check if the token is valid (not expired and not used)
    pub fn is_valid(&self) -> bool {
        self.secure_token.is_valid()
    }

    /// Mark the token as used
    pub fn mark_used(&mut self) {
        self.secure_token.mark_used();
    }
}

impl SecureTokenEntity for UserPasswordResetToken {
    fn key_prefix() -> &'static str {
        "password_reset_token"
    }

    fn foreign_key_prefix() -> &'static str {
        "user"
    }

    fn secure_token(&self) -> &SecureToken {
        &self.secure_token
    }

    fn secure_token_mut(&mut self) -> &mut SecureToken {
        &mut self.secure_token
    }

    fn foreign_key_id(&self) -> i64 {
        self.user_id
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        let token = UserPasswordResetToken::generate_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

        // Ensure tokens are unique
        let token2 = UserPasswordResetToken::generate_token();
        assert_ne!(token, token2);
    }

    #[test]
    fn test_new_token() {
        let token_string = UserPasswordResetToken::generate_token();
        let token = UserPasswordResetToken::builder()
            .id(1)
            .user_id(100)
            .token(token_string.clone())
            .create();

        assert!(token.is_ok());
        let token = token.unwrap();
        assert_eq!(token.secure_token.id, 1);
        assert_eq!(token.user_id, 100);
        assert_eq!(token.secure_token.token, token_string);
        assert!(token.secure_token.used_at.is_none());
    }

    #[test]
    fn test_invalid_token_format() {
        // Too short
        let result = UserPasswordResetToken::builder().id(1).user_id(100).token("short").create();
        assert!(result.is_err());

        // Not hex
        let result = UserPasswordResetToken::builder()
            .id(1)
            .user_id(100)
            .token("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")
            .create();
        assert!(result.is_err());

        // Correct length but not all hex
        let result = UserPasswordResetToken::builder()
            .id(1)
            .user_id(100)
            .token("abcdef123456789012345678901234567890123456789012345678901234567g")
            .create();
        assert!(result.is_err());
    }

    #[test]
    fn test_token_expiry() {
        let token_string = UserPasswordResetToken::generate_token();
        let mut token = UserPasswordResetToken::builder()
            .id(1)
            .user_id(100)
            .token(token_string)
            .create()
            .unwrap();

        // Should not be expired initially
        assert!(!token.is_expired());
        assert!(token.is_valid());

        // Manually set expiry to the past
        token.secure_token.expires_at = chrono::Utc::now() - Duration::seconds(1);
        assert!(token.is_expired());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_token_usage() {
        let token_string = UserPasswordResetToken::generate_token();
        let mut token = UserPasswordResetToken::builder()
            .id(1)
            .user_id(100)
            .token(token_string)
            .create()
            .unwrap();

        // Should not be used initially
        assert!(!token.is_used());
        assert!(token.is_valid());

        // Mark as used
        token.mark_used();
        assert!(token.is_used());
        assert!(!token.is_valid());
        assert!(token.secure_token.used_at.is_some());
    }

    #[test]
    fn test_expiry_duration() {
        let token_string = UserPasswordResetToken::generate_token();
        let token = UserPasswordResetToken::builder()
            .id(1)
            .user_id(100)
            .token(token_string)
            .create()
            .unwrap();

        let duration = token.secure_token.expires_at - token.secure_token.created_at;
        // Allow for small timing differences
        assert!(duration.num_minutes() >= 59 && duration.num_minutes() <= 60);
    }

    #[test]
    fn test_serde_roundtrip() {
        let token_string = UserPasswordResetToken::generate_token();
        let entity = UserPasswordResetToken::builder()
            .id(42)
            .user_id(100)
            .token(token_string)
            .create()
            .unwrap();

        let json = serde_json::to_string(&entity).unwrap();
        let deserialized: UserPasswordResetToken = serde_json::from_str(&json).unwrap();
        assert_eq!(entity, deserialized);
    }
}
