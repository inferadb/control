use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Token hex length: 64 characters (32 bytes hex-encoded)
const TOKEN_HEX_LENGTH: usize = 64;

/// Shared fields and behavior for secure, time-limited, single-use tokens
///
/// `SecureToken` encapsulates the common lifecycle of cryptographic tokens
/// used for email verification, password reset, and similar flows:
/// generation, format validation, expiry tracking, and single-use enforcement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecureToken {
    /// Unique token ID (Snowflake ID)
    pub id: i64,

    /// Token value (32 bytes, hex-encoded = 64 chars)
    pub token: String,

    /// When the token was created
    pub created_at: DateTime<Utc>,

    /// When the token expires
    pub expires_at: DateTime<Utc>,

    /// When the token was used (if consumed)
    pub used_at: Option<DateTime<Utc>>,
}

impl SecureToken {
    /// Create a new secure token with the given TTL
    ///
    /// Validates the token format (must be exactly 64 hex characters) and
    /// sets expiry based on the provided time-to-live duration.
    pub fn new(id: i64, token: String, ttl: Duration) -> Result<Self> {
        validate_token_format(&token)?;
        let now = Utc::now();
        Ok(Self { id, token, created_at: now, expires_at: now + ttl, used_at: None })
    }

    /// Generate a cryptographically secure random token
    ///
    /// Returns a 32-byte random value as a 64-character hex string.
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

    /// Mark the token as used at the current time
    pub fn mark_used(&mut self) {
        self.used_at = Some(Utc::now());
    }

    /// Get time remaining until expiry
    pub fn time_until_expiry(&self) -> Duration {
        self.expires_at - Utc::now()
    }
}

/// Validates that a token string is exactly 64 hex characters
fn validate_token_format(token: &str) -> Result<()> {
    if token.len() != TOKEN_HEX_LENGTH {
        return Err(Error::validation(
            "Token must be exactly 64 characters (32 bytes hex-encoded)".to_string(),
        ));
    }

    if !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::validation(
            "Token must contain only hexadecimal characters".to_string(),
        ));
    }

    Ok(())
}

/// Trait for entity types that embed a [`SecureToken`]
///
/// Implement this trait on token entities to enable generic repository
/// operations via the shared `SecureTokenRepository`.
pub trait SecureTokenEntity:
    Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static
{
    /// Storage key prefix for this token type (e.g., `"email_verify_token"`)
    fn key_prefix() -> &'static str;

    /// Storage key prefix for the foreign key index (e.g., `"email"`, `"user"`)
    fn foreign_key_prefix() -> &'static str;

    /// Access the embedded secure token
    fn secure_token(&self) -> &SecureToken;

    /// Access the embedded secure token mutably
    fn secure_token_mut(&mut self) -> &mut SecureToken;

    /// Get the foreign key value for the secondary index
    fn foreign_key_id(&self) -> i64;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        let token1 = SecureToken::generate_token();
        let token2 = SecureToken::generate_token();

        assert_eq!(token1.len(), 64);
        assert_eq!(token2.len(), 64);
        assert_ne!(token1, token2);
        assert!(token1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_new_valid_token() {
        let token_string = SecureToken::generate_token();
        let token = SecureToken::new(1, token_string.clone(), Duration::hours(1));
        assert!(token.is_ok());

        let token = token.unwrap();
        assert_eq!(token.id, 1);
        assert_eq!(token.token, token_string);
        assert!(!token.is_expired());
        assert!(!token.is_used());
        assert!(token.is_valid());
    }

    #[test]
    fn test_invalid_token_length() {
        let result = SecureToken::new(1, "short".to_string(), Duration::hours(1));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Validation { .. }));
    }

    #[test]
    fn test_invalid_token_hex() {
        let result = SecureToken::new(1, "z".repeat(64), Duration::hours(1));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Validation { .. }));
    }

    #[test]
    fn test_mark_used() {
        let token_string = SecureToken::generate_token();
        let mut token = SecureToken::new(1, token_string, Duration::hours(1)).unwrap();
        assert!(token.is_valid());

        token.mark_used();
        assert!(token.is_used());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_expired_token() {
        let token_string = SecureToken::generate_token();
        let mut token = SecureToken::new(1, token_string, Duration::hours(1)).unwrap();
        token.expires_at = Utc::now() - Duration::seconds(1);

        assert!(token.is_expired());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_time_until_expiry() {
        let token_string = SecureToken::generate_token();
        let token = SecureToken::new(1, token_string, Duration::hours(24)).unwrap();
        let time_left = token.time_until_expiry();

        assert!(time_left > Duration::hours(23));
        assert!(time_left <= Duration::hours(24));
    }

    #[test]
    fn test_ttl_determines_expiry() {
        let token_string = SecureToken::generate_token();
        let token = SecureToken::new(1, token_string, Duration::hours(1)).unwrap();
        let duration = token.expires_at - token.created_at;

        // Allow minor timing variance
        assert!(duration.num_minutes() >= 59 && duration.num_minutes() <= 60);
    }
}
