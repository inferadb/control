use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Authorization code for CLI OAuth flow with PKCE
///
/// Used in the authorization code grant flow with PKCE (RFC 7636).
/// These codes are short-lived (10 minutes) and can only be used once.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationCode {
    /// Unique code ID (Snowflake ID)
    pub id: i64,

    /// The authorization code itself (cryptographically random)
    pub code: String,

    /// User session ID this code is bound to
    pub session_id: i64,

    /// PKCE code challenge (base64url encoded SHA256 of code_verifier)
    pub code_challenge: String,

    /// PKCE code challenge method (only "S256" is supported)
    pub code_challenge_method: String,

    /// When the code was created
    pub created_at: DateTime<Utc>,

    /// When the code expires (10 minutes from creation)
    pub expires_at: DateTime<Utc>,

    /// When the code was used (None if not yet used)
    pub used_at: Option<DateTime<Utc>>,
}

impl AuthorizationCode {
    /// TTL for authorization codes in seconds (10 minutes)
    pub const TTL_SECONDS: i64 = 10 * 60;

    /// Create a new authorization code
    ///
    /// # Arguments
    ///
    /// * `id` - Snowflake ID for the code
    /// * `code` - The authorization code string (cryptographically random)
    /// * `session_id` - User session ID this code is bound to
    /// * `code_challenge` - PKCE code challenge
    /// * `code_challenge_method` - PKCE code challenge method (must be "S256")
    ///
    /// # Returns
    ///
    /// A new AuthorizationCode instance
    pub fn new(
        id: i64,
        code: String,
        session_id: i64,
        code_challenge: String,
        code_challenge_method: String,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(Self::TTL_SECONDS);

        Self {
            id,
            code,
            session_id,
            code_challenge,
            code_challenge_method,
            created_at: now,
            expires_at,
            used_at: None,
        }
    }

    /// Check if the code is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the code has been used
    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    /// Check if the code is valid (not expired and not used)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_used()
    }

    /// Mark the code as used
    pub fn mark_used(&mut self) {
        if self.used_at.is_none() {
            self.used_at = Some(Utc::now());
        }
    }

    /// Get time until expiration
    pub fn time_until_expiry(&self) -> Option<Duration> {
        let now = Utc::now();
        if now < self.expires_at { Some(self.expires_at - now) } else { None }
    }

    /// Verify a PKCE code_verifier against the stored challenge
    ///
    /// # Arguments
    ///
    /// * `code_verifier` - The code verifier to check
    ///
    /// # Returns
    ///
    /// True if the verifier matches the challenge, false otherwise
    pub fn verify_code_verifier(&self, code_verifier: &str) -> bool {
        // Only S256 method is supported
        if self.code_challenge_method != "S256" {
            return false;
        }

        // Compute SHA256 of the code_verifier
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let hash = hasher.finalize();

        // Base64url encode the hash (without padding)
        let computed_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

        // Compare with stored challenge
        computed_challenge == self.code_challenge
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_authorization_code() {
        let code = AuthorizationCode::new(
            1,
            "test-code-123".to_string(),
            100,
            "test-challenge".to_string(),
            "S256".to_string(),
        );

        assert_eq!(code.id, 1);
        assert_eq!(code.code, "test-code-123");
        assert_eq!(code.session_id, 100);
        assert_eq!(code.code_challenge, "test-challenge");
        assert_eq!(code.code_challenge_method, "S256");
        assert!(!code.is_expired());
        assert!(!code.is_used());
        assert!(code.is_valid());
    }

    #[test]
    fn test_code_expiry() {
        let mut code = AuthorizationCode::new(
            1,
            "test-code".to_string(),
            100,
            "challenge".to_string(),
            "S256".to_string(),
        );

        // Manually set expiry to the past
        code.expires_at = Utc::now() - Duration::seconds(1);

        assert!(code.is_expired());
        assert!(!code.is_valid());
    }

    #[test]
    fn test_mark_used() {
        let mut code = AuthorizationCode::new(
            1,
            "test-code".to_string(),
            100,
            "challenge".to_string(),
            "S256".to_string(),
        );

        assert!(!code.is_used());
        assert!(code.is_valid());

        code.mark_used();
        assert!(code.is_used());
        assert!(!code.is_valid());
    }

    #[test]
    fn test_time_until_expiry() {
        let code = AuthorizationCode::new(
            1,
            "test-code".to_string(),
            100,
            "challenge".to_string(),
            "S256".to_string(),
        );

        let time_left = code.time_until_expiry();
        assert!(time_left.is_some());

        let mut expired_code = AuthorizationCode::new(
            1,
            "test-code".to_string(),
            100,
            "challenge".to_string(),
            "S256".to_string(),
        );
        expired_code.expires_at = Utc::now() - Duration::seconds(1);
        assert!(expired_code.time_until_expiry().is_none());
    }

    #[test]
    fn test_verify_code_verifier() {
        // Test with a known verifier/challenge pair
        // code_verifier = "test-verifier-123456789012345678901234567890123456789012345678"
        // SHA256(code_verifier) = base64url(hash)
        use sha2::{Digest, Sha256};

        let verifier = "test-verifier-123456789012345678901234567890123456789012345678";
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

        let code = AuthorizationCode::new(
            1,
            "test-code".to_string(),
            100,
            challenge.clone(),
            "S256".to_string(),
        );

        // Correct verifier should match
        assert!(code.verify_code_verifier(verifier));

        // Wrong verifier should not match
        assert!(!code.verify_code_verifier("wrong-verifier"));
    }

    #[test]
    fn test_verify_code_verifier_wrong_method() {
        let code = AuthorizationCode::new(
            1,
            "test-code".to_string(),
            100,
            "challenge".to_string(),
            "plain".to_string(), // Unsupported method
        );

        // Should always return false for unsupported methods
        assert!(!code.verify_code_verifier("any-verifier"));
    }
}
