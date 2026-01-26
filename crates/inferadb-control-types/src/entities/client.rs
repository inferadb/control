use bon::bon;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A client represents a backend service or application that can authenticate
/// with the InferaDB system using certificates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    /// Unique identifier for the client
    pub id: i64,
    /// Organization this client belongs to
    pub organization_id: i64,
    /// Default vault for this client (for token generation)
    #[serde(default)]
    pub vault_id: Option<i64>,
    /// Human-readable name for the client
    pub name: String,
    /// Optional description of the client
    #[serde(default)]
    pub description: String,
    /// When the client was created
    pub created_at: DateTime<Utc>,
    /// User who created this client
    pub created_by_user_id: i64,
    /// When the client was soft-deleted (if applicable)
    pub deleted_at: Option<DateTime<Utc>>,
}

#[bon]
impl Client {
    /// Create a new client
    #[builder(on(String, into), finish_fn = create)]
    pub fn new(
        id: i64,
        organization_id: i64,
        vault_id: Option<i64>,
        name: String,
        description: Option<String>,
        created_by_user_id: i64,
    ) -> Result<Self> {
        Self::validate_name(&name)?;

        Ok(Self {
            id,
            organization_id,
            vault_id,
            name,
            description: description.unwrap_or_default(),
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
            return Err(Error::Validation("Client name cannot exceed 100 characters".to_string()));
        }
        Ok(())
    }

    /// Update the client name
    pub fn set_name(&mut self, name: String) -> Result<()> {
        Self::validate_name(&name)?;
        self.name = name;
        Ok(())
    }

    /// Update the client description
    pub fn set_description(&mut self, description: String) {
        self.description = description;
    }

    /// Update the default vault ID
    pub fn set_vault_id(&mut self, vault_id: Option<i64>) {
        self.vault_id = vault_id;
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

#[bon]
impl ClientCertificate {
    /// Create a new client certificate
    #[builder(on(String, into), finish_fn = create)]
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
        format!("org-{organization_id}-client-{client_id}-cert-{cert_id}")
    }

    /// Validate certificate name
    pub fn validate_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(Error::Validation("Certificate name cannot be empty".to_string()));
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
        let client = Client::builder()
            .id(1)
            .organization_id(100)
            .name("Test Client")
            .created_by_user_id(999)
            .create()
            .unwrap();
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
        let mut client = Client::builder()
            .id(1)
            .organization_id(100)
            .name("Test Client")
            .created_by_user_id(999)
            .create()
            .unwrap();
        assert!(!client.is_deleted());

        client.mark_deleted();
        assert!(client.is_deleted());
        assert!(client.deleted_at.is_some());
    }

    #[test]
    fn test_certificate_creation() {
        let cert = ClientCertificate::builder()
            .id(1)
            .client_id(100)
            .organization_id(200)
            .public_key("public_key_base64".to_string())
            .private_key_encrypted("encrypted_private_key_base64".to_string())
            .name("Test Certificate")
            .created_by_user_id(999)
            .create()
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
        let mut cert = ClientCertificate::builder()
            .id(1)
            .client_id(100)
            .organization_id(200)
            .public_key("public_key".to_string())
            .private_key_encrypted("private_key".to_string())
            .name("Test Cert")
            .created_by_user_id(999)
            .create()
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
        let mut cert = ClientCertificate::builder()
            .id(1)
            .client_id(100)
            .organization_id(200)
            .public_key("public_key".to_string())
            .private_key_encrypted("private_key".to_string())
            .name("Test Cert")
            .created_by_user_id(999)
            .create()
            .unwrap();

        assert!(cert.is_active());
        assert!(!cert.is_deleted());

        cert.mark_deleted();
        assert!(!cert.is_active());
        assert!(cert.is_deleted());
    }

    #[test]
    fn test_certificate_mark_used() {
        let mut cert = ClientCertificate::builder()
            .id(1)
            .client_id(100)
            .organization_id(200)
            .public_key("public_key".to_string())
            .private_key_encrypted("private_key".to_string())
            .name("Test Cert")
            .created_by_user_id(999)
            .create()
            .unwrap();

        assert!(cert.last_used_at.is_none());

        cert.mark_used();
        assert!(cert.last_used_at.is_some());
    }
}
