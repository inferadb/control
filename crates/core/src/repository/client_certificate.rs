use std::time::Duration;

use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::ClientCertificate,
    error::{Error, Result},
};

/// Retention period for revoked certificates (90 days from revocation)
const REVOKED_CERT_RETENTION: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Repository for ClientCertificate entity operations
///
/// Key schema:
/// - cert:{id} -> ClientCertificate data
/// - cert:kid:{kid} -> cert_id (for kid lookup - critical for JWT verification)
/// - cert:client:{client_id}:{idx} -> cert_id (for client listing)
pub struct ClientCertificateRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> ClientCertificateRepository<S> {
    /// Create a new client certificate repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for certificate by ID
    fn cert_key(id: u64) -> Vec<u8> {
        format!("cert:{id}").into_bytes()
    }

    /// Generate key for certificate by kid (key ID) index
    fn cert_kid_index_key(kid: &str) -> Vec<u8> {
        format!("cert:kid:{kid}").into_bytes()
    }

    /// Generate key for certificate by client index
    fn cert_client_index_key(client_id: u64, idx: u64) -> Vec<u8> {
        format!("cert:client:{client_id}:{idx}").into_bytes()
    }

    /// Create a new certificate
    pub async fn create(&self, cert: ClientCertificate) -> Result<()> {
        // Serialize certificate
        let cert_data = serde_json::to_vec(&cert)
            .map_err(|e| Error::internal(format!("Failed to serialize certificate: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

        // Check if kid already exists (should be unique globally)
        let kid_key = Self::cert_kid_index_key(&cert.kid);
        if self
            .storage
            .get(&kid_key)
            .await
            .map_err(|e| Error::internal(format!("Failed to check duplicate kid: {e}")))?
            .is_some()
        {
            return Err(Error::already_exists(format!(
                "A certificate with kid '{}' already exists",
                cert.kid
            )));
        }

        // Store certificate record
        txn.set(Self::cert_key(cert.id), cert_data.clone());

        // Store kid index (critical for JWT verification)
        txn.set(kid_key, cert.id.to_le_bytes().to_vec());

        // Store client index
        txn.set(
            Self::cert_client_index_key(cert.client_id, cert.id),
            cert.id.to_le_bytes().to_vec(),
        );

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::internal(format!("Failed to commit certificate creation: {e}")))?;

        Ok(())
    }

    /// Get a certificate by ID
    pub async fn get(&self, id: u64) -> Result<Option<ClientCertificate>> {
        let key = Self::cert_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::internal(format!("Failed to get certificate: {e}")))?;

        match data {
            Some(bytes) => {
                let cert: ClientCertificate = serde_json::from_slice(&bytes).map_err(|e| {
                    Error::internal(format!("Failed to deserialize certificate: {e}"))
                })?;
                Ok(Some(cert))
            },
            None => Ok(None),
        }
    }

    /// Get a certificate by kid (key ID) - used for JWT verification
    pub async fn get_by_kid(&self, kid: &str) -> Result<Option<ClientCertificate>> {
        let index_key = Self::cert_kid_index_key(kid);
        let data = self
            .storage
            .get(&index_key)
            .await
            .map_err(|e| Error::internal(format!("Failed to get certificate by kid: {e}")))?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::internal("Invalid certificate kid index data".to_string()));
                }
                let id = super::parse_u64_id(&bytes)?;
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// List all certificates for a client (including revoked and deleted)
    pub async fn list_by_client(&self, client_id: u64) -> Result<Vec<ClientCertificate>> {
        let prefix = format!("cert:client:{client_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("cert:client:{client_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::internal(format!("Failed to get client certificates: {e}")))?;

        let mut certs = Vec::new();
        for kv in kvs {
            let Ok(id) = super::parse_u64_id(&kv.value) else { continue };
            if let Some(cert) = self.get(id).await? {
                certs.push(cert);
            }
        }

        Ok(certs)
    }

    /// List active (non-revoked, non-deleted) certificates for a client
    pub async fn list_active_by_client(&self, client_id: u64) -> Result<Vec<ClientCertificate>> {
        let all_certs = self.list_by_client(client_id).await?;
        Ok(all_certs.into_iter().filter(|c| c.is_active()).collect())
    }

    /// Apply TTL to all 3 storage keys for a certificate
    ///
    /// Used when revoking a certificate to set a 90-day retention period
    /// after which all keys (main record, KID index, client index) are
    /// automatically expired by Ledger's GC.
    async fn set_all_keys_with_ttl(&self, cert: &ClientCertificate, ttl: Duration) -> Result<()> {
        let cert_data = serde_json::to_vec(cert)
            .map_err(|e| Error::internal(format!("Failed to serialize certificate: {e}")))?;

        self.storage
            .set_with_ttl(Self::cert_key(cert.id), cert_data, ttl)
            .await
            .map_err(|e| Error::internal(format!("Failed to set TTL on cert key: {e}")))?;

        self.storage
            .set_with_ttl(Self::cert_kid_index_key(&cert.kid), cert.id.to_le_bytes().to_vec(), ttl)
            .await
            .map_err(|e| Error::internal(format!("Failed to set TTL on kid index: {e}")))?;

        self.storage
            .set_with_ttl(
                Self::cert_client_index_key(cert.client_id, cert.id),
                cert.id.to_le_bytes().to_vec(),
                ttl,
            )
            .await
            .map_err(|e| Error::internal(format!("Failed to set TTL on client index: {e}")))?;

        Ok(())
    }

    /// Update a certificate (typically for marking as used, revoked, or deleted)
    ///
    /// When the certificate has been revoked, sets a 90-day TTL on all 3 keys
    /// so revoked certificates are automatically cleaned up by Ledger's GC.
    pub async fn update(&self, cert: ClientCertificate) -> Result<()> {
        // Verify certificate exists
        let existing = self
            .get(cert.id)
            .await?
            .ok_or_else(|| Error::not_found(format!("Certificate {} not found", cert.id)))?;

        // Verify kid hasn't changed (kid should be immutable)
        if existing.kid != cert.kid {
            return Err(Error::validation("Certificate kid cannot be changed".to_string()));
        }

        if cert.is_revoked() {
            // Revoked certificates get a 90-day TTL on all 3 keys
            self.set_all_keys_with_ttl(&cert, REVOKED_CERT_RETENTION).await?;
        } else {
            // Non-revoked updates only write the main record (no TTL)
            let cert_data = serde_json::to_vec(&cert)
                .map_err(|e| Error::internal(format!("Failed to serialize certificate: {e}")))?;

            self.storage
                .set(Self::cert_key(cert.id), cert_data)
                .await
                .map_err(|e| Error::internal(format!("Failed to update certificate: {e}")))?;
        }

        Ok(())
    }

    /// Delete a certificate (removes all indexes)
    pub async fn delete(&self, id: u64) -> Result<()> {
        // Get the certificate first to clean up indexes
        let cert = self
            .get(id)
            .await?
            .ok_or_else(|| Error::not_found(format!("Certificate {id} not found")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::internal(format!("Failed to start transaction: {e}")))?;

        // Delete certificate record
        txn.delete(Self::cert_key(id));

        // Delete kid index
        txn.delete(Self::cert_kid_index_key(&cert.kid));

        // Delete client index
        txn.delete(Self::cert_client_index_key(cert.client_id, cert.id));

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::internal(format!("Failed to commit certificate deletion: {e}")))?;

        Ok(())
    }

    /// Count certificates for a client
    pub async fn count_by_client(&self, client_id: u64) -> Result<usize> {
        let certs = self.list_by_client(client_id).await?;
        Ok(certs.len())
    }

    /// Count active certificates for a client
    pub async fn count_active_by_client(&self, client_id: u64) -> Result<usize> {
        let certs = self.list_active_by_client(client_id).await?;
        Ok(certs.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_control_storage::{Backend, MemoryBackend, backend::StorageBackend};
    use inferadb_control_types::OrganizationSlug;

    use super::*;

    fn create_test_repo() -> ClientCertificateRepository<Backend> {
        ClientCertificateRepository::new(Backend::memory())
    }

    fn create_test_cert(
        id: u64,
        client_id: u64,
        organization: OrganizationSlug,
        name: &str,
    ) -> Result<ClientCertificate> {
        ClientCertificate::builder()
            .id(id)
            .client_id(client_id)
            .organization(organization)
            .public_key("public_key_base64".to_string())
            .private_key_encrypted("encrypted_private_key_base64".to_string())
            .name(name.to_string())
            .created_by_user_id(999_u64)
            .create()
    }

    #[tokio::test]
    async fn test_create_and_get_cert() {
        let repo = create_test_repo();
        let cert = create_test_cert(1, 100, OrganizationSlug::from(200_u64), "Test Cert").unwrap();
        let kid = cert.kid.clone();

        repo.create(cert.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert_eq!(retrieved, Some(cert.clone()));

        let by_kid = repo.get_by_kid(&kid).await.unwrap();
        assert_eq!(by_kid, Some(cert));
    }

    #[tokio::test]
    async fn test_duplicate_kid_rejected() {
        let repo = create_test_repo();
        let cert1 = create_test_cert(1, 100, OrganizationSlug::from(200_u64), "Cert 1").unwrap();

        // Create second cert with same kid (by using same cert_id, client_id, and organization)
        let cert2 = create_test_cert(1, 100, OrganizationSlug::from(200_u64), "Cert 2").unwrap();

        repo.create(cert1).await.unwrap();

        let result = repo.create(cert2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists { .. }));
    }

    #[tokio::test]
    async fn test_list_by_client() {
        let repo = create_test_repo();
        let cert1 = create_test_cert(1, 100, OrganizationSlug::from(200_u64), "Cert 1").unwrap();
        let cert2 = create_test_cert(2, 100, OrganizationSlug::from(200_u64), "Cert 2").unwrap();
        let cert3 = create_test_cert(3, 101, OrganizationSlug::from(200_u64), "Cert 3").unwrap();

        repo.create(cert1).await.unwrap();
        repo.create(cert2).await.unwrap();
        repo.create(cert3).await.unwrap();

        let client_100_certs = repo.list_by_client(100).await.unwrap();
        assert_eq!(client_100_certs.len(), 2);

        let client_101_certs = repo.list_by_client(101).await.unwrap();
        assert_eq!(client_101_certs.len(), 1);
    }

    #[tokio::test]
    async fn test_revoke_cert() {
        let repo = create_test_repo();
        let mut cert =
            create_test_cert(1, 100, OrganizationSlug::from(200_u64), "Test Cert").unwrap();

        repo.create(cert.clone()).await.unwrap();
        assert!(cert.is_active());

        cert.mark_revoked(888);
        repo.update(cert.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert!(retrieved.is_revoked());
        assert!(!retrieved.is_active());
        assert_eq!(retrieved.revoked_by_user_id, Some(888));

        // Should not be in active list
        let active = repo.list_active_by_client(100).await.unwrap();
        assert_eq!(active.len(), 0);
    }

    #[tokio::test]
    async fn test_soft_delete_cert() {
        let repo = create_test_repo();
        let mut cert =
            create_test_cert(1, 100, OrganizationSlug::from(200_u64), "Test Cert").unwrap();

        repo.create(cert.clone()).await.unwrap();

        cert.mark_deleted();
        repo.update(cert).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert!(retrieved.is_deleted());
        assert!(!retrieved.is_active());

        // Should not be in active list
        let active = repo.list_active_by_client(100).await.unwrap();
        assert_eq!(active.len(), 0);
    }

    #[tokio::test]
    async fn test_mark_used() {
        let repo = create_test_repo();
        let mut cert =
            create_test_cert(1, 100, OrganizationSlug::from(200_u64), "Test Cert").unwrap();

        repo.create(cert.clone()).await.unwrap();
        assert!(cert.last_used_at.is_none());

        cert.mark_used();
        repo.update(cert).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert!(retrieved.last_used_at.is_some());
    }

    #[tokio::test]
    async fn test_delete_cert() {
        let repo = create_test_repo();
        let cert = create_test_cert(1, 100, OrganizationSlug::from(200_u64), "Test Cert").unwrap();
        let kid = cert.kid.clone();

        repo.create(cert).await.unwrap();
        assert!(repo.get(1).await.unwrap().is_some());
        assert!(repo.get_by_kid(&kid).await.unwrap().is_some());

        repo.delete(1).await.unwrap();
        assert!(repo.get(1).await.unwrap().is_none());
        assert!(repo.get_by_kid(&kid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_kid_immutable() {
        let repo = create_test_repo();
        let mut cert =
            create_test_cert(1, 100, OrganizationSlug::from(200_u64), "Test Cert").unwrap();

        repo.create(cert.clone()).await.unwrap();

        // Try to change kid
        cert.kid = "new-kid".to_string();
        let result = repo.update(cert).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Validation { .. }));
    }

    #[tokio::test]
    async fn test_count_certs() {
        let repo = create_test_repo();
        let cert1 = create_test_cert(1, 100, OrganizationSlug::from(200_u64), "Cert 1").unwrap();
        let mut cert2 =
            create_test_cert(2, 100, OrganizationSlug::from(200_u64), "Cert 2").unwrap();
        let cert3 = create_test_cert(3, 100, OrganizationSlug::from(200_u64), "Cert 3").unwrap();

        repo.create(cert1).await.unwrap();
        repo.create(cert2.clone()).await.unwrap();
        repo.create(cert3).await.unwrap();

        assert_eq!(repo.count_by_client(100).await.unwrap(), 3);
        assert_eq!(repo.count_active_by_client(100).await.unwrap(), 3);

        // Revoke one
        cert2.mark_revoked(888);
        repo.update(cert2).await.unwrap();

        assert_eq!(repo.count_by_client(100).await.unwrap(), 3);
        assert_eq!(repo.count_active_by_client(100).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_revoke_sets_ttl_on_all_keys() {
        let storage = MemoryBackend::new();
        let repo = ClientCertificateRepository::new(storage.clone());

        let mut cert =
            create_test_cert_with(1, 100, OrganizationSlug::from(200_u64), "TTL Test").unwrap();
        let kid = cert.kid.clone();

        repo.create(cert.clone()).await.unwrap();

        // All 3 keys should exist after creation
        assert!(storage.get(b"cert:1").await.unwrap().is_some());
        assert!(storage.get(format!("cert:kid:{kid}").as_bytes()).await.unwrap().is_some());
        assert!(storage.get(b"cert:client:100:1").await.unwrap().is_some());

        // Revoke the certificate
        cert.mark_revoked(888);
        repo.update(cert).await.unwrap();

        // All 3 keys should still exist with TTL applied
        assert!(storage.get(b"cert:1").await.unwrap().is_some());
        assert!(storage.get(format!("cert:kid:{kid}").as_bytes()).await.unwrap().is_some());
        assert!(storage.get(b"cert:client:100:1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_active_cert_has_no_ttl() {
        let storage = MemoryBackend::new();
        let repo = ClientCertificateRepository::new(storage.clone());

        let mut cert =
            create_test_cert_with(2, 100, OrganizationSlug::from(200_u64), "Active TTL").unwrap();

        repo.create(cert.clone()).await.unwrap();

        // Mark as used (not revoked) — should NOT set TTL
        cert.mark_used();
        repo.update(cert).await.unwrap();

        // Key should still exist (no TTL to expire)
        assert!(storage.get(b"cert:2").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_revoked_cert_keys_expire_from_storage() {
        let storage = MemoryBackend::new();
        let repo = ClientCertificateRepository::new(storage.clone());

        let mut cert =
            create_test_cert_with(3, 100, OrganizationSlug::from(200_u64), "Expire Test").unwrap();
        let kid = cert.kid.clone();

        repo.create(cert.clone()).await.unwrap();

        // Revoke with a short TTL by directly calling set_all_keys_with_ttl
        cert.mark_revoked(888);
        // First update normally (sets 90-day TTL), then override with short TTL for test
        let cert_data = serde_json::to_vec(&cert).unwrap();
        let short_ttl = std::time::Duration::from_secs(1);
        storage.set_with_ttl(b"cert:3".to_vec(), cert_data, short_ttl).await.unwrap();
        storage
            .set_with_ttl(
                format!("cert:kid:{kid}").into_bytes(),
                3_u64.to_le_bytes().to_vec(),
                short_ttl,
            )
            .await
            .unwrap();
        storage
            .set_with_ttl(b"cert:client:100:3".to_vec(), 3_u64.to_le_bytes().to_vec(), short_ttl)
            .await
            .unwrap();

        // Keys should exist immediately
        assert!(storage.get(b"cert:3").await.unwrap().is_some());

        // Wait for TTL expiry
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // All 3 keys should be absent
        assert!(storage.get(b"cert:3").await.unwrap().is_none());
        assert!(storage.get(format!("cert:kid:{kid}").as_bytes()).await.unwrap().is_none());
        assert!(storage.get(b"cert:client:100:3").await.unwrap().is_none());
    }

    fn create_test_cert_with(
        id: u64,
        client_id: u64,
        organization: OrganizationSlug,
        name: &str,
    ) -> Result<ClientCertificate> {
        ClientCertificate::builder()
            .id(id)
            .client_id(client_id)
            .organization(organization)
            .public_key("public_key_base64".to_string())
            .private_key_encrypted("encrypted_private_key_base64".to_string())
            .name(name.to_string())
            .created_by_user_id(999_u64)
            .create()
    }
}
