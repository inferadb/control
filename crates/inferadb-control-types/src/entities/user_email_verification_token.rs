use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Email verification token expiry duration (24 hours)
const TOKEN_EXPIRY_HOURS: i64 = 24;

/// UserEmailVerificationToken entity for email verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserEmailVerificationToken {
    /// Unique token ID (Snowflake ID)
    pub id: i64,

    /// UserEmail ID this token is for
    pub user_email_id: i64,

    /// Verification token (32 bytes, hex-encoded = 64 chars)
    pub token: String,

    /// When the token was created
    pub created_at: DateTime<Utc>,

    /// When the token expires
    pub expires_at: DateTime<Utc>,

    /// When the token was used (if verified)
    pub used_at: Option<DateTime<Utc>>,
}

impl UserEmailVerificationToken {
    /// Create a new email verification token
    ///
    /// # Arguments
    ///
    /// * `id` - Snowflake ID for the token
    /// * `user_email_id` - ID of the UserEmail to verify
    /// * `token` - The verification token (should be 64 hex chars)
    ///
    /// # Returns
    ///
    /// A new UserEmailVerificationToken instance or an error if token is invalid
    pub fn new(id: i64, user_email_id: i64, token: String) -> Result<Self> {
        // Validate token format (must be 64 hex characters)
        if token.len() != 64 {
            return Err(Error::Validation(
                "Token must be exactly 64 characters (32 bytes hex-encoded)".to_string(),
            ));
        }

        if !token.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Validation(
                "Token must contain only hexadecimal characters".to_string(),
            ));
        }

        let now = Utc::now();
        let expires_at = now + Duration::hours(TOKEN_EXPIRY_HOURS);

        Ok(Self { id, user_email_id, token, created_at: now, expires_at, used_at: None })
    }

    /// Generate a random verification token
    ///
    /// Returns a 32-byte random token as a 64-character hex string
    pub fn generate_token() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        let bytes: [u8; 32] = rng.random();
        hex::encode(bytes)
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if token has been used
    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    /// Check if token is valid (not expired and not used)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_used()
    }

    /// Mark token as used
    pub fn mark_used(&mut self) {
        self.used_at = Some(Utc::now());
    }

    /// Get time until expiry
    pub fn time_until_expiry(&self) -> Duration {
        self.expires_at - Utc::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_token() {
        let token = UserEmailVerificationToken::generate_token();
        let result = UserEmailVerificationToken::new(1, 100, token);
        assert!(result.is_ok());

        let token_entity = result.unwrap();
        assert_eq!(token_entity.id, 1);
        assert_eq!(token_entity.user_email_id, 100);
        assert!(!token_entity.is_expired());
        assert!(!token_entity.is_used());
        assert!(token_entity.is_valid());
    }

    #[test]
    fn test_token_validation_length() {
        let result = UserEmailVerificationToken::new(1, 100, "short".to_string());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Validation(_)));
    }

    #[test]
    fn test_token_validation_hex() {
        let invalid_token = "z".repeat(64);
        let result = UserEmailVerificationToken::new(1, 100, invalid_token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Validation(_)));
    }

    #[test]
    fn test_generate_token() {
        let token1 = UserEmailVerificationToken::generate_token();
        let token2 = UserEmailVerificationToken::generate_token();

        assert_eq!(token1.len(), 64);
        assert_eq!(token2.len(), 64);
        assert_ne!(token1, token2); // Should be unique
        assert!(token1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_mark_used() {
        let token = UserEmailVerificationToken::generate_token();
        let mut token_entity = UserEmailVerificationToken::new(1, 100, token).unwrap();

        assert!(!token_entity.is_used());
        assert!(token_entity.is_valid());

        token_entity.mark_used();

        assert!(token_entity.is_used());
        assert!(!token_entity.is_valid());
    }

    #[test]
    fn test_time_until_expiry() {
        let token = UserEmailVerificationToken::generate_token();
        let token_entity = UserEmailVerificationToken::new(1, 100, token).unwrap();

        let time_left = token_entity.time_until_expiry();
        assert!(time_left > Duration::hours(23));
        assert!(time_left <= Duration::hours(24));
    }
}
