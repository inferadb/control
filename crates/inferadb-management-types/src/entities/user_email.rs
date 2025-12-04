use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// UserEmail entity representing a user's email address
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserEmail {
    /// Unique email ID (Snowflake ID)
    pub id: i64,

    /// User ID this email belongs to
    pub user_id: i64,

    /// Email address (normalized to lowercase)
    pub email: String,

    /// Whether this is the primary email
    pub primary: bool,

    /// When the email was verified
    pub verified_at: Option<DateTime<Utc>>,

    /// When the email was created
    pub created_at: DateTime<Utc>,
}

impl UserEmail {
    /// Create a new unverified email
    ///
    /// # Arguments
    ///
    /// * `id` - Snowflake ID for the email
    /// * `user_id` - ID of the user
    /// * `email` - Email address (will be normalized)
    /// * `primary` - Whether this is the primary email
    ///
    /// # Returns
    ///
    /// A new UserEmail instance
    ///
    /// # Errors
    ///
    /// Returns an error if email validation fails
    pub fn new(id: i64, user_id: i64, email: String, primary: bool) -> Result<Self> {
        let normalized_email = Self::normalize_email(&email)?;

        Ok(Self {
            id,
            user_id,
            email: normalized_email,
            primary,
            verified_at: None,
            created_at: Utc::now(),
        })
    }

    /// Normalize and validate email address
    ///
    /// Rules:
    /// - Must contain @ symbol
    /// - Must not be empty
    /// - Converted to lowercase
    /// - Basic format validation
    pub fn normalize_email(email: &str) -> Result<String> {
        let trimmed = email.trim();

        if trimmed.is_empty() {
            return Err(Error::Validation("Email cannot be empty".to_string()));
        }

        // Basic email validation
        if !trimmed.contains('@') {
            return Err(Error::Validation("Email must contain @ symbol".to_string()));
        }

        let parts: Vec<&str> = trimmed.split('@').collect();
        if parts.len() != 2 {
            return Err(Error::Validation("Invalid email format".to_string()));
        }

        if parts[0].is_empty() || parts[1].is_empty() {
            return Err(Error::Validation("Invalid email format".to_string()));
        }

        // Normalize to lowercase
        Ok(trimmed.to_lowercase())
    }

    /// Check if email is verified
    pub fn is_verified(&self) -> bool {
        self.verified_at.is_some()
    }

    /// Mark email as verified
    pub fn verify(&mut self) {
        if self.verified_at.is_none() {
            self.verified_at = Some(Utc::now());
        }
    }

    /// Set as primary email
    pub fn set_primary(&mut self, is_primary: bool) {
        self.primary = is_primary;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_email() {
        let email = UserEmail::new(1, 100, "Test@Example.COM".to_string(), true).unwrap();
        assert_eq!(email.id, 1);
        assert_eq!(email.user_id, 100);
        assert_eq!(email.email, "test@example.com"); // Normalized to lowercase
        assert!(email.primary);
        assert!(!email.is_verified());
    }

    #[test]
    fn test_normalize_email() {
        assert_eq!(UserEmail::normalize_email("Test@Example.COM").unwrap(), "test@example.com");
        assert_eq!(UserEmail::normalize_email("  user@domain.com  ").unwrap(), "user@domain.com");
    }

    #[test]
    fn test_validate_email_empty() {
        assert!(UserEmail::normalize_email("").is_err());
        assert!(UserEmail::normalize_email("   ").is_err());
    }

    #[test]
    fn test_validate_email_no_at() {
        assert!(UserEmail::normalize_email("notanemail").is_err());
    }

    #[test]
    fn test_validate_email_invalid_format() {
        assert!(UserEmail::normalize_email("@domain.com").is_err());
        assert!(UserEmail::normalize_email("user@").is_err());
        assert!(UserEmail::normalize_email("user@@domain.com").is_err());
    }

    #[test]
    fn test_verify() {
        let mut email = UserEmail::new(1, 100, "test@example.com".to_string(), true).unwrap();
        assert!(!email.is_verified());

        email.verify();
        assert!(email.is_verified());

        // Should not change if called again
        let first_verification = email.verified_at;
        email.verify();
        assert_eq!(email.verified_at, first_verification);
    }

    #[test]
    fn test_set_primary() {
        let mut email = UserEmail::new(1, 100, "test@example.com".to_string(), false).unwrap();
        assert!(!email.primary);

        email.set_primary(true);
        assert!(email.primary);

        email.set_primary(false);
        assert!(!email.primary);
    }
}
