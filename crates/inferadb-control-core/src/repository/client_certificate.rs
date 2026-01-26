use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::ClientCertificate,
    error::{Error, Result},
};

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
    fn cert_key(id: i64) -> Vec<u8> {
        format!("cert:{id}").into_bytes()
    }

    /// Generate key for certificate by kid (key ID) index
    fn cert_kid_index_key(kid: &str) -> Vec<u8> {
        format!("cert:kid:{kid}").into_bytes()
    }

    /// Generate key for certificate by client index
    fn cert_client_index_key(client_id: i64, idx: i64) -> Vec<u8> {
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
    pub async fn get(&self, id: i64) -> Result<Option<ClientCertificate>> {
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
                let id = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// List all certificates for a client (including revoked and deleted)
    pub async fn list_by_client(&self, client_id: i64) -> Result<Vec<ClientCertificate>> {
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
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(cert) = self.get(id).await? {
                certs.push(cert);
            }
        }

        Ok(certs)
    }

    /// List active (non-revoked, non-deleted) certificates for a client
    pub async fn list_active_by_client(&self, client_id: i64) -> Result<Vec<ClientCertificate>> {
        let all_certs = self.list_by_client(client_id).await?;
        Ok(all_certs.into_iter().filter(|c| c.is_active()).collect())
    }

    /// List all active certificates across all clients (for JWKS endpoints)
    pub async fn list_all_active(&self) -> Result<Vec<ClientCertificate>> {
        let prefix = "cert:".to_string();
        let start = prefix.clone().into_bytes();
        let end = "cert~".to_string().into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::internal(format!("Failed to get all certificates: {e}")))?;

        tracing::debug!(kv_count = kvs.len(), "list_all_active: Retrieved KV pairs from storage");

        let mut certs = Vec::new();
        let mut skipped_indexes = 0;
        let mut invalid_json = 0;
        let mut inactive_certs = 0;

        for kv in kvs {
            // Only process actual certificate records, not indexes
            let key_str = String::from_utf8_lossy(&kv.key);
            if !key_str.starts_with("cert:kid:") && !key_str.starts_with("cert:client:") {
                match serde_json::from_slice::<ClientCertificate>(&kv.value) {
                    Ok(cert) => {
                        if cert.is_active() {
                            tracing::debug!(
                                cert_id = cert.id,
                                kid = %cert.kid,
                                "Found active certificate"
                            );
                            certs.push(cert);
                        } else {
                            inactive_certs += 1;
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            key = %key_str,
                            error = %e,
                            "Failed to deserialize certificate"
                        );
                        invalid_json += 1;
                    },
                }
            } else {
                skipped_indexes += 1;
            }
        }

        tracing::debug!(
            active_certs = certs.len(),
            inactive_certs,
            skipped_indexes,
            invalid_json,
            "list_all_active: Summary"
        );

        Ok(certs)
    }

    /// Update a certificate (typically for marking as used, revoked, or deleted)
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

        // Serialize updated certificate
        let cert_data = serde_json::to_vec(&cert)
            .map_err(|e| Error::internal(format!("Failed to serialize certificate: {e}")))?;

        // Update certificate record
        self.storage
            .set(Self::cert_key(cert.id), cert_data)
            .await
            .map_err(|e| Error::internal(format!("Failed to update certificate: {e}")))?;

        Ok(())
    }

    /// Delete a certificate (removes all indexes)
    pub async fn delete(&self, id: i64) -> Result<()> {
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
    pub async fn count_by_client(&self, client_id: i64) -> Result<usize> {
        let certs = self.list_by_client(client_id).await?;
        Ok(certs.len())
    }

    /// Count active certificates for a client
    pub async fn count_active_by_client(&self, client_id: i64) -> Result<usize> {
        let certs = self.list_active_by_client(client_id).await?;
        Ok(certs.len())
    }

    /// Delete revoked certificates that were revoked before the given cutoff date.
    ///
    /// This is used by the background cleanup job to remove old revoked certificates
    /// after the retention period (e.g., 90 days).
    ///
    /// Returns the number of certificates deleted.
    pub async fn delete_revoked_older_than(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize> {
        // Get all certificates by scanning the cert: prefix
        let prefix = "cert:".to_string();
        let start = prefix.clone().into_bytes();
        let end = "cert~".to_string().into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::internal(format!("Failed to scan certificates: {e}")))?;

        let mut deleted_count = 0;

        for kv in kvs {
            // Only process actual certificate records, not indexes
            let key_str = String::from_utf8_lossy(&kv.key);
            if key_str.starts_with("cert:kid:") || key_str.starts_with("cert:client:") {
                continue;
            }

            // Try to deserialize the certificate
            let cert: ClientCertificate = match serde_json::from_slice(&kv.value) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Check if certificate is revoked and older than cutoff
            if let Some(revoked_at) = cert.revoked_at
                && revoked_at < cutoff
            {
                // Delete the certificate and its indexes
                if let Err(e) = self.delete(cert.id).await {
                    tracing::warn!(
                        cert_id = cert.id,
                        error = %e,
                        "Failed to delete old revoked certificate"
                    );
                    continue;
                }
                deleted_count += 1;
            }
        }

        Ok(deleted_count)
    }
}

#[cfg(test)]
mod tests {
    use inferadb_control_storage::Backend;

    use super::*;

    fn create_test_repo() -> ClientCertificateRepository<Backend> {
        ClientCertificateRepository::new(Backend::memory())
    }

    fn create_test_cert(
        id: i64,
        client_id: i64,
        org_id: i64,
        name: &str,
    ) -> Result<ClientCertificate> {
        ClientCertificate::builder()
            .id(id)
            .client_id(client_id)
            .organization_id(org_id)
            .public_key("public_key_base64".to_string())
            .private_key_encrypted("encrypted_private_key_base64".to_string())
            .name(name.to_string())
            .created_by_user_id(999)
            .create()
    }

    #[tokio::test]
    async fn test_create_and_get_cert() {
        let repo = create_test_repo();
        let cert = create_test_cert(1, 100, 200, "Test Cert").unwrap();
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
        let cert1 = create_test_cert(1, 100, 200, "Cert 1").unwrap();

        // Create second cert with same kid (by using same cert_id, client_id, and org_id)
        let cert2 = create_test_cert(1, 100, 200, "Cert 2").unwrap();

        repo.create(cert1).await.unwrap();

        let result = repo.create(cert2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists { .. }));
    }

    #[tokio::test]
    async fn test_list_by_client() {
        let repo = create_test_repo();
        let cert1 = create_test_cert(1, 100, 200, "Cert 1").unwrap();
        let cert2 = create_test_cert(2, 100, 200, "Cert 2").unwrap();
        let cert3 = create_test_cert(3, 101, 200, "Cert 3").unwrap();

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
        let mut cert = create_test_cert(1, 100, 200, "Test Cert").unwrap();

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
        let mut cert = create_test_cert(1, 100, 200, "Test Cert").unwrap();

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
        let mut cert = create_test_cert(1, 100, 200, "Test Cert").unwrap();

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
        let cert = create_test_cert(1, 100, 200, "Test Cert").unwrap();
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
        let mut cert = create_test_cert(1, 100, 200, "Test Cert").unwrap();

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
        let cert1 = create_test_cert(1, 100, 200, "Cert 1").unwrap();
        let mut cert2 = create_test_cert(2, 100, 200, "Cert 2").unwrap();
        let cert3 = create_test_cert(3, 100, 200, "Cert 3").unwrap();

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
    async fn test_delete_revoked_older_than() {
        let repo = create_test_repo();
        let cert1 = create_test_cert(1, 100, 200, "Cert 1").unwrap();
        let mut cert2 = create_test_cert(2, 100, 200, "Cert 2").unwrap();
        let cert3 = create_test_cert(3, 100, 200, "Cert 3").unwrap();

        repo.create(cert1).await.unwrap();
        repo.create(cert2.clone()).await.unwrap();
        repo.create(cert3).await.unwrap();

        // Revoke cert2
        cert2.mark_revoked(888);
        repo.update(cert2).await.unwrap();

        // Delete revoked certs older than now (should delete cert2)
        let cutoff = chrono::Utc::now() + chrono::Duration::seconds(1);
        let deleted = repo.delete_revoked_older_than(cutoff).await.unwrap();
        assert_eq!(deleted, 1);

        // cert2 should be gone
        assert!(repo.get(2).await.unwrap().is_none());

        // cert1 and cert3 should still exist
        assert!(repo.get(1).await.unwrap().is_some());
        assert!(repo.get(3).await.unwrap().is_some());

        // Running again should delete nothing
        let deleted = repo.delete_revoked_older_than(cutoff).await.unwrap();
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn test_delete_revoked_older_than_respects_cutoff() {
        let repo = create_test_repo();
        let mut cert = create_test_cert(1, 100, 200, "Cert 1").unwrap();

        repo.create(cert.clone()).await.unwrap();

        // Revoke the cert
        cert.mark_revoked(888);
        repo.update(cert).await.unwrap();

        // Use a cutoff in the past (should not delete the cert since it was just revoked)
        let cutoff = chrono::Utc::now() - chrono::Duration::days(1);
        let deleted = repo.delete_revoked_older_than(cutoff).await.unwrap();
        assert_eq!(deleted, 0);

        // Cert should still exist
        assert!(repo.get(1).await.unwrap().is_some());
    }
}
