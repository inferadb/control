use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    entities::OrganizationRole,
    error::{Error, Result},
};

/// Represents an invitation to join an organization
///
/// Invitations are sent by organization admins/owners to invite users to join
/// their organization with a specific role. Invitations expire after 7 days.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrganizationInvitation {
    /// Unique identifier for the invitation
    pub id: i64,
    /// Organization ID the invitation is for
    pub organization_id: i64,
    /// User ID who created the invitation
    pub invited_by_user_id: i64,
    /// Email address of the person being invited
    pub email: String,
    /// Role the invitee will have in the organization
    pub role: OrganizationRole,
    /// Secure token used to accept the invitation
    pub token: String,
    /// When the invitation was created
    pub created_at: DateTime<Utc>,
    /// When the invitation expires
    pub expires_at: DateTime<Utc>,
}

impl OrganizationInvitation {
    /// Default invitation expiry duration (7 days)
    const EXPIRY_DURATION_DAYS: i64 = 7;

    /// Create a new organization invitation
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for the invitation
    /// * `organization_id` - Organization ID the invitation is for
    /// * `invited_by_user_id` - User ID who created the invitation
    /// * `email` - Email address of the person being invited
    /// * `role` - Role the invitee will have
    /// * `token` - Secure token (should be 32 bytes, hex-encoded)
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails
    pub fn new(
        id: i64,
        organization_id: i64,
        invited_by_user_id: i64,
        email: String,
        role: OrganizationRole,
        token: String,
    ) -> Result<Self> {
        Self::validate_email(&email)?;
        Self::validate_token(&token)?;

        let created_at = Utc::now();
        let expires_at = created_at + Duration::days(Self::EXPIRY_DURATION_DAYS);

        Ok(Self {
            id,
            organization_id,
            invited_by_user_id,
            email: email.trim().to_lowercase(),
            role,
            token,
            created_at,
            expires_at,
        })
    }

    /// Validate email address format
    ///
    /// # Errors
    ///
    /// Returns an error if the email is invalid
    pub fn validate_email(email: &str) -> Result<()> {
        let trimmed = email.trim();

        if trimmed.is_empty() {
            return Err(Error::Validation("Email cannot be empty".to_string()));
        }

        // Basic email validation
        if !trimmed.contains('@') || !trimmed.contains('.') {
            return Err(Error::Validation("Invalid email format".to_string()));
        }

        if trimmed.len() > 255 {
            return Err(Error::Validation("Email must be 255 characters or less".to_string()));
        }

        Ok(())
    }

    /// Validate invitation token
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid
    pub fn validate_token(token: &str) -> Result<()> {
        if token.is_empty() {
            return Err(Error::Validation("Token cannot be empty".to_string()));
        }

        // Expecting 32 bytes hex-encoded = 64 characters
        if token.len() != 64 {
            return Err(Error::Validation(
                "Token must be 64 characters (32 bytes hex-encoded)".to_string(),
            ));
        }

        // Verify it's valid hex
        if !token.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Validation("Token must be hex-encoded".to_string()));
        }

        Ok(())
    }

    /// Check if the invitation has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Generate a secure random token (32 bytes, hex-encoded)
    ///
    /// # Errors
    ///
    /// Returns an error if token generation fails
    pub fn generate_token() -> Result<String> {
        use rand::Rng;

        let mut token_bytes = [0u8; 32];
        rand::rng().fill(&mut token_bytes);

        Ok(hex::encode(token_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_invitation() {
        let token = OrganizationInvitation::generate_token().unwrap();
        let invitation = OrganizationInvitation::new(
            1,
            100,
            200,
            "test@example.com".to_string(),
            OrganizationRole::Member,
            token,
        )
        .unwrap();

        assert_eq!(invitation.id, 1);
        assert_eq!(invitation.organization_id, 100);
        assert_eq!(invitation.invited_by_user_id, 200);
        assert_eq!(invitation.email, "test@example.com");
        assert_eq!(invitation.role, OrganizationRole::Member);
        assert!(!invitation.is_expired());
    }

    #[test]
    fn test_email_validation() {
        assert!(OrganizationInvitation::validate_email("test@example.com").is_ok());
        assert!(OrganizationInvitation::validate_email("  user@domain.co.uk  ").is_ok());
        assert!(OrganizationInvitation::validate_email("").is_err());
        assert!(OrganizationInvitation::validate_email("notanemail").is_err());
        assert!(OrganizationInvitation::validate_email("missing@domain").is_err());
    }

    #[test]
    fn test_token_validation() {
        let valid_token = "a".repeat(64);
        assert!(OrganizationInvitation::validate_token(&valid_token).is_ok());

        assert!(OrganizationInvitation::validate_token("").is_err());
        assert!(OrganizationInvitation::validate_token("short").is_err());
        assert!(OrganizationInvitation::validate_token(&"z".repeat(64)).is_err());
        // 'z' not hex
    }

    #[test]
    fn test_generate_token() {
        let token1 = OrganizationInvitation::generate_token().unwrap();
        let token2 = OrganizationInvitation::generate_token().unwrap();

        assert_eq!(token1.len(), 64);
        assert_eq!(token2.len(), 64);
        assert_ne!(token1, token2); // Should be random
        assert!(OrganizationInvitation::validate_token(&token1).is_ok());
        assert!(OrganizationInvitation::validate_token(&token2).is_ok());
    }

    #[test]
    fn test_email_normalized() {
        let token = OrganizationInvitation::generate_token().unwrap();
        let invitation = OrganizationInvitation::new(
            1,
            100,
            200,
            "  Test@Example.COM  ".to_string(),
            OrganizationRole::Member,
            token,
        )
        .unwrap();

        assert_eq!(invitation.email, "test@example.com");
    }
}
