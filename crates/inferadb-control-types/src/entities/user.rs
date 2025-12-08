use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// User entity representing a registered user
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    /// Unique user ID (Snowflake ID)
    pub id: i64,

    /// User's display name
    pub name: String,

    /// When the user was created
    pub created_at: DateTime<Utc>,

    /// When the user accepted the Terms of Service
    pub tos_accepted_at: Option<DateTime<Utc>>,

    /// Argon2id password hash (PHC string format)
    /// None if user only uses passkeys
    pub password_hash: Option<String>,

    /// When the user was soft-deleted
    pub deleted_at: Option<DateTime<Utc>>,
}

impl User {
    /// Create a new user
    ///
    /// # Arguments
    ///
    /// * `id` - Snowflake ID for the user
    /// * `name` - Display name
    /// * `password_hash` - Optional password hash
    ///
    /// # Returns
    ///
    /// A new User instance
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails
    pub fn new(id: i64, name: String, password_hash: Option<String>) -> Result<Self> {
        Self::validate_name(&name)?;

        Ok(Self {
            id,
            name,
            created_at: Utc::now(),
            tos_accepted_at: None,
            password_hash,
            deleted_at: None,
        })
    }

    /// Validate user name
    ///
    /// Rules:
    /// - Must be 1-100 characters
    /// - Must not be empty or only whitespace
    pub fn validate_name(name: &str) -> Result<()> {
        let trimmed = name.trim();

        if trimmed.is_empty() {
            return Err(Error::Validation("Name cannot be empty or only whitespace".to_string()));
        }

        if trimmed.len() > 100 {
            return Err(Error::Validation(format!(
                "Name must be 100 characters or less, got {}",
                trimmed.len()
            )));
        }

        Ok(())
    }

    /// Check if user has accepted ToS
    pub fn has_accepted_tos(&self) -> bool {
        self.tos_accepted_at.is_some()
    }

    /// Mark ToS as accepted
    pub fn accept_tos(&mut self) {
        if self.tos_accepted_at.is_none() {
            self.tos_accepted_at = Some(Utc::now());
        }
    }

    /// Check if user is deleted
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Soft delete the user
    pub fn soft_delete(&mut self) {
        if self.deleted_at.is_none() {
            self.deleted_at = Some(Utc::now());
        }
    }

    /// Check if user has a password
    pub fn has_password(&self) -> bool {
        self.password_hash.is_some()
    }

    /// Update password hash
    pub fn set_password_hash(&mut self, hash: String) {
        self.password_hash = Some(hash);
    }

    /// Update user name
    pub fn set_name(&mut self, name: String) -> Result<()> {
        Self::validate_name(&name)?;
        self.name = name;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_user() {
        let user = User::new(1, "Test User".to_string(), Some("hash".to_string())).unwrap();
        assert_eq!(user.id, 1);
        assert_eq!(user.name, "Test User");
        assert!(user.has_password());
        assert!(!user.has_accepted_tos());
        assert!(!user.is_deleted());
    }

    #[test]
    fn test_validate_name_empty() {
        assert!(User::validate_name("").is_err());
        assert!(User::validate_name("   ").is_err());
    }

    #[test]
    fn test_validate_name_too_long() {
        let long_name = "a".repeat(101);
        assert!(User::validate_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_name_valid() {
        assert!(User::validate_name("Valid Name").is_ok());
        assert!(User::validate_name("A").is_ok());
        assert!(User::validate_name(&"a".repeat(100)).is_ok());
    }

    #[test]
    fn test_accept_tos() {
        let mut user = User::new(1, "Test".to_string(), None).unwrap();
        assert!(!user.has_accepted_tos());

        user.accept_tos();
        assert!(user.has_accepted_tos());

        // Should not change if called again
        let first_acceptance = user.tos_accepted_at;
        user.accept_tos();
        assert_eq!(user.tos_accepted_at, first_acceptance);
    }

    #[test]
    fn test_soft_delete() {
        let mut user = User::new(1, "Test".to_string(), None).unwrap();
        assert!(!user.is_deleted());

        user.soft_delete();
        assert!(user.is_deleted());
    }

    #[test]
    fn test_set_name() {
        let mut user = User::new(1, "Original".to_string(), None).unwrap();
        user.set_name("Updated".to_string()).unwrap();
        assert_eq!(user.name, "Updated");

        assert!(user.set_name("".to_string()).is_err());
    }
}
