use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A client represents a backend service or application that can authenticate
/// with the InferaDB system using certificates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    /// Unique identifier for the client
    pub id: i64,
    /// Organization this client belongs to
    pub organization_id: i64,
    /// Human-readable name for the client
    pub name: String,
    /// When the client was created
    pub created_at: DateTime<Utc>,
    /// User who created this client
    pub created_by_user_id: i64,
    /// When the client was soft-deleted (if applicable)
    pub deleted_at: Option<DateTime<Utc>>,
}

impl Client {
    /// Create a new client
    pub fn new(
        id: i64,
        organization_id: i64,
        name: String,
        created_by_user_id: i64,
    ) -> Result<Self> {
        Self::validate_name(&name)?;

        Ok(Self {
            id,
            organization_id,
            name,
            created_at: Utc::now(),
            created_by_user_id,
            deleted_at: None,
        })
    }

    /// Validate client name
    pub fn validate_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(Error::Validation("Client name cannot be empty".to_string()));
        }
        if name.len() > 100 {
            return Err(Error::Validation(
                "Client name cannot exceed 100 characters".to_string(),
            ));
        }
        Ok(())
    }

    /// Check if client is deleted
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Soft delete this client
    pub fn mark_deleted(&mut self) {
        self.deleted_at = Some(Utc::now());
    }
}

/// A certificate for a client, containing Ed25519 public/private key pair
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientCertificate {
    /// Unique identifier for the certificate
    pub id: i64,
    /// Client this certificate belongs to
    pub client_id: i64,
    /// Ed25519 public key (32 bytes, base64 encoded)
    pub public_key: String,
    /// Encrypted Ed25519 private key (AES-256-GCM encrypted, base64 encoded)
    pub private_key_encrypted: String,
    /// Key ID in format: org-<org_id>-client-<client_id>-cert-<cert_id>
    pub kid: String,
    /// Human-readable name for this certificate
    pub name: String,
    /// When the certificate was created
    pub created_at: DateTime<Utc>,
    /// User who created this certificate
    pub created_by_user_id: i64,
    /// When the certificate was last used for authentication
    pub last_used_at: Option<DateTime<Utc>>,
    /// When the certificate was revoked (if applicable)
    pub revoked_at: Option<DateTime<Utc>>,
    /// User who revoked this certificate (if applicable)
    pub revoked_by_user_id: Option<i64>,
    /// When the certificate was soft-deleted (if applicable)
    pub deleted_at: Option<DateTime<Utc>>,
}

impl ClientCertificate {
    /// Create a new client certificate
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: i64,
        client_id: i64,
        organization_id: i64,
        public_key: String,
        private_key_encrypted: String,
        name: String,
        created_by_user_id: i64,
    ) -> Result<Self> {
        Self::validate_name(&name)?;
        let kid = Self::generate_kid(organization_id, client_id, id);

        Ok(Self {
            id,
            client_id,
            public_key,
            private_key_encrypted,
            kid,
            name,
            created_at: Utc::now(),
            created_by_user_id,
            last_used_at: None,
            revoked_at: None,
            revoked_by_user_id: None,
            deleted_at: None,
        })
    }

    /// Generate a kid (key ID) in the format: org-<org_id>-client-<client_id>-cert-<cert_id>
    pub fn generate_kid(organization_id: i64, client_id: i64, cert_id: i64) -> String {
        format!(
            "org-{}-client-{}-cert-{}",
            organization_id, client_id, cert_id
        )
    }

    /// Validate certificate name
    pub fn validate_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(Error::Validation(
                "Certificate name cannot be empty".to_string(),
            ));
        }
        if name.len() > 100 {
            return Err(Error::Validation(
                "Certificate name cannot exceed 100 characters".to_string(),
            ));
        }
        Ok(())
    }

    /// Check if certificate is active (not revoked or deleted)
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none() && self.deleted_at.is_none()
    }

    /// Check if certificate is revoked
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Check if certificate is deleted
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Revoke this certificate
    pub fn mark_revoked(&mut self, revoked_by_user_id: i64) {
        self.revoked_at = Some(Utc::now());
        self.revoked_by_user_id = Some(revoked_by_user_id);
    }

    /// Soft delete this certificate
    pub fn mark_deleted(&mut self) {
        self.deleted_at = Some(Utc::now());
    }

    /// Update last used timestamp
    pub fn mark_used(&mut self) {
        self.last_used_at = Some(Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = Client::new(1, 100, "Test Client".to_string(), 999).unwrap();
        assert_eq!(client.id, 1);
        assert_eq!(client.organization_id, 100);
        assert_eq!(client.name, "Test Client");
        assert_eq!(client.created_by_user_id, 999);
        assert!(!client.is_deleted());
    }

    #[test]
    fn test_client_name_validation() {
        assert!(Client::validate_name("Valid Name").is_ok());
        assert!(Client::validate_name("").is_err());
        assert!(Client::validate_name(&"a".repeat(101)).is_err());
    }

    #[test]
    fn test_client_soft_delete() {
        let mut client = Client::new(1, 100, "Test Client".to_string(), 999).unwrap();
        assert!(!client.is_deleted());

        client.mark_deleted();
        assert!(client.is_deleted());
        assert!(client.deleted_at.is_some());
    }

    #[test]
    fn test_certificate_creation() {
        let cert = ClientCertificate::new(
            1,
            100,
            200,
            "public_key_base64".to_string(),
            "encrypted_private_key_base64".to_string(),
            "Test Certificate".to_string(),
            999,
        )
        .unwrap();

        assert_eq!(cert.id, 1);
        assert_eq!(cert.client_id, 100);
        assert_eq!(cert.kid, "org-200-client-100-cert-1");
        assert_eq!(cert.name, "Test Certificate");
        assert!(cert.is_active());
        assert!(!cert.is_revoked());
        assert!(!cert.is_deleted());
    }

    #[test]
    fn test_certificate_kid_format() {
        let kid = ClientCertificate::generate_kid(123, 456, 789);
        assert_eq!(kid, "org-123-client-456-cert-789");
    }

    #[test]
    fn test_certificate_name_validation() {
        assert!(ClientCertificate::validate_name("Valid Name").is_ok());
        assert!(ClientCertificate::validate_name("").is_err());
        assert!(ClientCertificate::validate_name(&"a".repeat(101)).is_err());
    }

    #[test]
    fn test_certificate_revocation() {
        let mut cert = ClientCertificate::new(
            1,
            100,
            200,
            "public_key".to_string(),
            "private_key".to_string(),
            "Test Cert".to_string(),
            999,
        )
        .unwrap();

        assert!(cert.is_active());
        assert!(!cert.is_revoked());

        cert.mark_revoked(888);
        assert!(!cert.is_active());
        assert!(cert.is_revoked());
        assert_eq!(cert.revoked_by_user_id, Some(888));
    }

    #[test]
    fn test_certificate_deletion() {
        let mut cert = ClientCertificate::new(
            1,
            100,
            200,
            "public_key".to_string(),
            "private_key".to_string(),
            "Test Cert".to_string(),
            999,
        )
        .unwrap();

        assert!(cert.is_active());
        assert!(!cert.is_deleted());

        cert.mark_deleted();
        assert!(!cert.is_active());
        assert!(cert.is_deleted());
    }

    #[test]
    fn test_certificate_mark_used() {
        let mut cert = ClientCertificate::new(
            1,
            100,
            200,
            "public_key".to_string(),
            "private_key".to_string(),
            "Test Cert".to_string(),
            999,
        )
        .unwrap();

        assert!(cert.last_used_at.is_none());

        cert.mark_used();
        assert!(cert.last_used_at.is_some());
    }
}
