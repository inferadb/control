use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Password reset token expiry duration (1 hour)
const TOKEN_EXPIRY_HOURS: i64 = 1;

/// Represents a password reset token for a user
///
/// Password reset tokens are used to securely reset a user's password.
/// They expire after 1 hour and can only be used once.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserPasswordResetToken {
    /// Unique identifier for the token
    pub id: i64,
    /// ID of the user this token is for
    pub user_id: i64,
    /// The token string (64-char hex-encoded, 32 bytes of entropy)
    pub token: String,
    /// When the token was created
    pub created_at: DateTime<Utc>,
    /// When the token expires
    pub expires_at: DateTime<Utc>,
    /// When the token was used (if used)
    pub used_at: Option<DateTime<Utc>>,
}

impl UserPasswordResetToken {
    /// Create a new password reset token
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for the token
    /// * `user_id` - ID of the user this token is for
    /// * `token` - The token string (must be 64 hex characters)
    ///
    /// # Errors
    ///
    /// Returns an error if the token format is invalid
    pub fn new(id: i64, user_id: i64, token: String) -> Result<Self> {
        // Validate token format (64 hex characters = 32 bytes)
        if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Validation("Token must be 64 hexadecimal characters".to_string()));
        }

        let now = Utc::now();
        let expires_at = now + Duration::hours(TOKEN_EXPIRY_HOURS);

        Ok(Self { id, user_id, token, created_at: now, expires_at, used_at: None })
    }

    /// Generate a new cryptographically secure random token string
    ///
    /// Returns a 64-character hex-encoded string (32 bytes of entropy)
    pub fn generate_token() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        let bytes: [u8; 32] = rng.random();
        hex::encode(bytes)
    }

    /// Check if the token has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the token has been used
    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    /// Check if the token is valid (not expired and not used)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_used()
    }

    /// Mark the token as used
    pub fn mark_used(&mut self) {
        self.used_at = Some(Utc::now());
    }
}

#[cfg(test)]
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
        let token = UserPasswordResetToken::new(1, 100, token_string.clone());

        assert!(token.is_ok());
        let token = token.unwrap();
        assert_eq!(token.id, 1);
        assert_eq!(token.user_id, 100);
        assert_eq!(token.token, token_string);
        assert!(token.used_at.is_none());
    }

    #[test]
    fn test_invalid_token_format() {
        // Too short
        let result = UserPasswordResetToken::new(1, 100, "short".to_string());
        assert!(result.is_err());

        // Not hex
        let result = UserPasswordResetToken::new(
            1,
            100,
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg".to_string(),
        );
        assert!(result.is_err());

        // Correct length but not all hex
        let result = UserPasswordResetToken::new(
            1,
            100,
            "abcdef123456789012345678901234567890123456789012345678901234567g".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_token_expiry() {
        let token_string = UserPasswordResetToken::generate_token();
        let mut token = UserPasswordResetToken::new(1, 100, token_string).unwrap();

        // Should not be expired initially
        assert!(!token.is_expired());
        assert!(token.is_valid());

        // Manually set expiry to the past
        token.expires_at = Utc::now() - Duration::seconds(1);
        assert!(token.is_expired());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_token_usage() {
        let token_string = UserPasswordResetToken::generate_token();
        let mut token = UserPasswordResetToken::new(1, 100, token_string).unwrap();

        // Should not be used initially
        assert!(!token.is_used());
        assert!(token.is_valid());

        // Mark as used
        token.mark_used();
        assert!(token.is_used());
        assert!(!token.is_valid());
        assert!(token.used_at.is_some());
    }

    #[test]
    fn test_expiry_duration() {
        let token_string = UserPasswordResetToken::generate_token();
        let token = UserPasswordResetToken::new(1, 100, token_string).unwrap();

        let duration = token.expires_at - token.created_at;
        // Allow for small timing differences
        assert!(
            duration.num_hours() == TOKEN_EXPIRY_HOURS
                || duration.num_hours() == TOKEN_EXPIRY_HOURS - 1
        );
    }
}
