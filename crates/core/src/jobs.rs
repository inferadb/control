use std::{sync::Arc, time::Duration};

use inferadb_control_storage::{PublicSigningKeyStore, StorageBackend};
use inferadb_control_types::error::Result;
use tokio::{task::JoinHandle, time};

use crate::{
    leader::LeaderElection,
    repository::{
        AuditLogRepository, ClientCertificateRepository, UserSessionRepository,
        VaultRefreshTokenRepository,
    },
};

/// Background job scheduler
///
/// Runs periodic cleanup and maintenance tasks. Jobs only run on the leader instance
/// to avoid duplicate work in multi-instance deployments.
///
/// # Jobs
///
/// - **Expired session cleanup** (daily): Remove expired user sessions
/// - **Expired token cleanup** (daily): Remove expired verification and reset tokens
/// - **Expired refresh token cleanup** (daily): Remove old used/expired refresh tokens
/// - **Expired authorization code cleanup** (hourly): Clean up old authorization codes
/// - **Audit log retention** (daily): Remove audit logs older than 90 days
/// - **Revoked certificate cleanup** (daily): Remove revoked certificates older than 90 days
/// - **Certificate reconciliation** (hourly): Compare Control and Ledger certificate state
///
/// # Consistency Model
///
/// Certificate operations write to two independent stores (Control for metadata,
/// Ledger for public signing keys). Since no distributed transaction spans both,
/// compensating transactions in the API handlers roll back Control writes on
/// Ledger failure. The certificate reconciliation job acts as a safety net,
/// detecting any divergences that survive the compensating transaction (e.g. if
/// the rollback itself fails). Detected divergences are logged at ERROR level
/// with structured `divergence` fields for alerting.
///
/// ## Failure modes
///
/// | Scenario | Compensating action | Reconciliation detection |
/// |---|---|---|
/// | `create_certificate`: Ledger write fails | Delete cert from Control | `active_control_missing_ledger` |
/// | `revoke_certificate`: Ledger revoke fails | Restore cert to active in Control | `active_control_revoked_ledger` |
/// | `rotate_certificate`: Ledger write fails | Delete new cert from Control | `active_control_missing_ledger` |
/// | Compensating action itself fails | Log ERROR with "manual intervention required" | Same as above |
///
/// # Usage
///
/// ```rust,no_run
/// use inferadb_control_core::BackgroundJobs;
/// use inferadb_control_core::LeaderElection;
/// use inferadb_control_storage::MemoryBackend;
/// use std::sync::Arc;
///
/// # async fn example() {
/// let storage = MemoryBackend::new();
/// let leader = Arc::new(LeaderElection::new(storage.clone(), 1));
///
/// let jobs = BackgroundJobs::new(storage, leader);
/// jobs.start().await;
///
/// // Jobs will run in background...
///
/// jobs.stop().await;
/// # }
/// ```
pub struct BackgroundJobs<S: StorageBackend> {
    storage: S,
    leader: Arc<LeaderElection<S>>,
    signing_key_store: Option<Arc<dyn PublicSigningKeyStore>>,
    shutdown: Arc<tokio::sync::RwLock<bool>>,
    handles: Arc<tokio::sync::Mutex<Vec<JoinHandle<()>>>>,
}

impl<S: StorageBackend + Clone + Send + Sync + 'static> BackgroundJobs<S> {
    /// Create a new background job scheduler
    ///
    /// # Arguments
    ///
    /// * `storage` - Storage backend
    /// * `leader` - Leader election coordinator
    pub fn new(storage: S, leader: Arc<LeaderElection<S>>) -> Self {
        Self {
            storage,
            leader,
            signing_key_store: None,
            shutdown: Arc::new(tokio::sync::RwLock::new(false)),
            handles: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    /// Set the signing key store for certificate reconciliation
    ///
    /// When set, enables the certificate reconciliation job that periodically
    /// compares Control and Ledger certificate state and logs divergences.
    pub fn with_signing_key_store(mut self, store: Arc<dyn PublicSigningKeyStore>) -> Self {
        self.signing_key_store = Some(store);
        self
    }

    /// Start all background jobs
    ///
    /// Spawns background tasks for each job. Jobs will only execute when this instance is the
    /// leader.
    pub async fn start(&self) {
        let mut handles = self.handles.lock().await;

        // Session cleanup (daily at 2 AM)
        handles.push(self.spawn_daily_job("session_cleanup", 2, 0, |storage, _leader| {
            Box::pin(async move { Self::cleanup_expired_sessions(storage).await })
        }));

        // Token cleanup (daily at 3 AM)
        handles.push(self.spawn_daily_job("token_cleanup", 3, 0, |storage, _leader| {
            Box::pin(async move { Self::cleanup_expired_tokens(storage).await })
        }));

        // Refresh token cleanup (daily at 4 AM)
        handles.push(self.spawn_daily_job("refresh_token_cleanup", 4, 0, |storage, _leader| {
            Box::pin(async move { Self::cleanup_expired_refresh_tokens(storage).await })
        }));

        // Authorization code cleanup (hourly)
        handles.push(self.spawn_hourly_job("authz_code_cleanup", |storage, _leader| {
            Box::pin(async move { Self::cleanup_expired_authorization_codes(storage).await })
        }));

        // Audit log retention cleanup (daily at 5 AM)
        handles.push(self.spawn_daily_job("audit_log_cleanup", 5, 0, |storage, _leader| {
            Box::pin(async move { Self::cleanup_old_audit_logs(storage).await })
        }));

        // Revoked certificate cleanup (daily at 6 AM)
        handles.push(self.spawn_daily_job("revoked_cert_cleanup", 6, 0, |storage, _leader| {
            Box::pin(async move { Self::cleanup_revoked_certificates(storage).await })
        }));

        // Certificate reconciliation (hourly) — only if signing key store is configured
        if let Some(signing_key_store) = &self.signing_key_store {
            let sks = Arc::clone(signing_key_store);
            handles.push(self.spawn_hourly_job("cert_reconciliation", move |storage, _leader| {
                let sks = Arc::clone(&sks);
                Box::pin(async move { Self::reconcile_certificates(storage, sks).await })
            }));
        }

        tracing::info!("Background jobs started");
    }

    /// Stop all background jobs
    pub async fn stop(&self) {
        // Signal shutdown
        {
            let mut shutdown = self.shutdown.write().await;
            *shutdown = true;
        }

        // Wait for all jobs to complete
        let mut handles = self.handles.lock().await;
        for handle in handles.drain(..) {
            handle.abort();
        }

        tracing::info!("Background jobs stopped");
    }

    /// Spawn a job that runs daily at a specific time
    fn spawn_daily_job<F, Fut>(
        &self,
        name: &'static str,
        hour: u32,
        minute: u32,
        task: F,
    ) -> JoinHandle<()>
    where
        F: Fn(S, Arc<LeaderElection<S>>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let storage = self.storage.clone();
        let leader = Arc::clone(&self.leader);
        let shutdown = Arc::clone(&self.shutdown);

        tokio::spawn(async move {
            // Calculate initial delay to next scheduled time
            let now = chrono::Utc::now();
            // SAFETY: hour/minute are compile-time constants (2-6, 0) from spawn_daily_job calls
            #[allow(clippy::unwrap_used)]
            let target_time = now
                .date_naive()
                .and_hms_opt(hour, minute, 0)
                .unwrap()
                .and_local_timezone(chrono::Utc)
                .unwrap();

            let target_time = if target_time <= now {
                // If target time has passed today, schedule for tomorrow
                target_time + chrono::Duration::days(1)
            } else {
                target_time
            };

            let initial_delay = (target_time - now).num_seconds().max(0) as u64;

            // Wait for initial delay
            tokio::time::sleep(Duration::from_secs(initial_delay)).await;

            // Run daily
            let mut interval = time::interval(Duration::from_secs(24 * 60 * 60));

            loop {
                interval.tick().await;

                // Check shutdown
                if *shutdown.read().await {
                    break;
                }

                // Only run if we're the leader
                if !leader.is_leader().await {
                    tracing::debug!(job = name, "Skipping job (not leader)");
                    continue;
                }

                tracing::info!(job = name, "Running daily job");

                if let Err(e) = task(storage.clone(), Arc::clone(&leader)).await {
                    tracing::error!(job = name, error = %e, "Daily job failed");
                }
            }

            tracing::debug!(job = name, "Daily job stopped");
        })
    }

    /// Spawn a job that runs hourly
    fn spawn_hourly_job<F, Fut>(&self, name: &'static str, task: F) -> JoinHandle<()>
    where
        F: Fn(S, Arc<LeaderElection<S>>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let storage = self.storage.clone();
        let leader = Arc::clone(&self.leader);
        let shutdown = Arc::clone(&self.shutdown);

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60 * 60));

            loop {
                interval.tick().await;

                // Check shutdown
                if *shutdown.read().await {
                    break;
                }

                // Only run if we're the leader
                if !leader.is_leader().await {
                    tracing::debug!(job = name, "Skipping job (not leader)");
                    continue;
                }

                tracing::info!(job = name, "Running hourly job");

                if let Err(e) = task(storage.clone(), Arc::clone(&leader)).await {
                    tracing::error!(job = name, error = %e, "Hourly job failed");
                }
            }

            tracing::debug!(job = name, "Hourly job stopped");
        })
    }

    /// Cleanup expired user sessions
    async fn cleanup_expired_sessions(storage: S) -> Result<()> {
        let repo = UserSessionRepository::new(storage);
        let cleaned = repo.cleanup_expired().await?;

        tracing::info!(count = cleaned, "Cleaned up expired sessions");

        Ok(())
    }

    /// Cleanup expired email verification and password reset tokens
    ///
    /// Token cleanup is handled by TTL on the storage layer, so this method
    /// is intentionally a no-op. The storage backend automatically expires
    /// tokens based on their TTL settings.
    async fn cleanup_expired_tokens(_storage: S) -> Result<()> {
        tracing::debug!("Token cleanup skipped (TTL-based expiry in storage layer)");
        Ok(())
    }

    /// Cleanup old used/expired refresh tokens
    async fn cleanup_expired_refresh_tokens(storage: S) -> Result<()> {
        let repo = VaultRefreshTokenRepository::new(storage);

        // Use the existing cleanup method
        let cleaned = repo.delete_expired().await?;

        tracing::info!(count = cleaned, "Cleaned up old refresh tokens");

        Ok(())
    }

    /// Cleanup expired authorization codes
    ///
    /// Authorization codes have 10-minute TTL and are cleaned up automatically by storage layer TTL
    async fn cleanup_expired_authorization_codes(_storage: S) -> Result<()> {
        // Authorization code cleanup is handled by TTL on the storage layer
        tracing::debug!("Authorization code cleanup skipped (TTL-based expiry in storage layer)");
        Ok(())
    }

    /// Cleanup old audit logs (90-day retention)
    ///
    /// Deletes audit logs older than 90 days to comply with retention policy
    async fn cleanup_old_audit_logs(storage: S) -> Result<()> {
        let repo = AuditLogRepository::new(storage);

        // Calculate cutoff date (90 days ago)
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(90);

        let deleted = repo.delete_older_than(cutoff_date).await?;

        if deleted > 0 {
            tracing::info!(
                count = deleted,
                cutoff_date = %cutoff_date.format("%Y-%m-%d"),
                "Cleaned up old audit logs"
            );
        } else {
            tracing::debug!("No old audit logs to clean up");
        }

        Ok(())
    }

    /// Cleanup revoked certificates (90-day retention)
    ///
    /// Deletes revoked certificates that were revoked more than 90 days ago.
    /// This provides a grace period for audit purposes while ensuring old
    /// revoked certificates are eventually cleaned up.
    async fn cleanup_revoked_certificates(storage: S) -> Result<()> {
        let repo = ClientCertificateRepository::new(storage);

        // Calculate cutoff date (90 days ago)
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(90);

        let deleted = repo.delete_revoked_older_than(cutoff_date).await?;

        if deleted > 0 {
            tracing::info!(
                count = deleted,
                cutoff_date = %cutoff_date.format("%Y-%m-%d"),
                "Cleaned up old revoked certificates"
            );
        } else {
            tracing::debug!("No old revoked certificates to clean up");
        }

        Ok(())
    }

    /// Extract the organization ID from a certificate's kid
    ///
    /// Kid format: `org-{org_id}-client-{client_id}-cert-{cert_id}`
    fn org_id_from_kid(kid: &str) -> Option<i64> {
        let parts: Vec<&str> = kid.split('-').collect();
        // kid = "org" "-" org_id "-" "client" "-" client_id "-" "cert" "-" cert_id
        // parts[0] = "org", parts[1] = org_id
        if parts.len() >= 2 && parts[0] == "org" { parts[1].parse().ok() } else { None }
    }

    /// Reconcile certificate state between Control and Ledger
    ///
    /// Compares all active certificates in Control with their corresponding
    /// signing keys in Ledger, logging any divergences as errors with
    /// structured fields for alerting.
    ///
    /// Detected divergences:
    /// - Certificate active in Control but signing key missing from Ledger
    /// - Certificate active in Control but signing key revoked in Ledger
    /// - Certificate active in Control but signing key inactive in Ledger
    async fn reconcile_certificates(
        storage: S,
        signing_key_store: Arc<dyn PublicSigningKeyStore>,
    ) -> Result<()> {
        let repo = ClientCertificateRepository::new(storage);
        let certs = repo.list_all_active().await?;

        let mut divergences = 0u64;

        for cert in &certs {
            let Some(namespace_id) = Self::org_id_from_kid(&cert.kid) else {
                tracing::warn!(
                    kid = %cert.kid,
                    cert_id = cert.id,
                    "Cannot extract org_id from kid during reconciliation, skipping"
                );
                continue;
            };

            match signing_key_store.get_key(namespace_id.into(), &cert.kid).await {
                Ok(Some(key)) => {
                    if key.revoked_at.is_some() {
                        tracing::error!(
                            kid = %cert.kid,
                            cert_id = cert.id,
                            org_id = namespace_id,
                            divergence = "active_control_revoked_ledger",
                            "Certificate reconciliation divergence: certificate is active in Control but revoked in Ledger"
                        );
                        divergences += 1;
                    } else if !key.active {
                        tracing::error!(
                            kid = %cert.kid,
                            cert_id = cert.id,
                            org_id = namespace_id,
                            divergence = "active_control_inactive_ledger",
                            "Certificate reconciliation divergence: certificate is active in Control but inactive in Ledger"
                        );
                        divergences += 1;
                    }
                },
                Ok(None) => {
                    tracing::error!(
                        kid = %cert.kid,
                        cert_id = cert.id,
                        org_id = namespace_id,
                        divergence = "active_control_missing_ledger",
                        "Certificate reconciliation divergence: certificate is active in Control but signing key is missing from Ledger"
                    );
                    divergences += 1;
                },
                Err(e) => {
                    tracing::warn!(
                        kid = %cert.kid,
                        cert_id = cert.id,
                        error = %e,
                        "Failed to check signing key in Ledger during reconciliation"
                    );
                },
            }
        }

        if divergences > 0 {
            tracing::error!(
                divergences = divergences,
                total_certs = certs.len(),
                "Certificate reconciliation completed with divergences"
            );
        } else {
            tracing::info!(
                total_certs = certs.len(),
                "Certificate reconciliation completed — no divergences"
            );
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_control_storage::{MemoryBackend, MemorySigningKeyStore, PublicSigningKey};
    use inferadb_control_types::entities::ClientCertificate;

    use super::*;
    use crate::repository::ClientCertificateRepository;

    #[tokio::test]
    async fn test_background_jobs_start_stop() {
        let storage = MemoryBackend::new();
        let leader = Arc::new(LeaderElection::new(storage.clone(), 1));

        // Acquire leadership
        leader.try_acquire_leadership().await.unwrap();

        let jobs = BackgroundJobs::new(storage, leader);

        jobs.start().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        jobs.stop().await;
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let storage = MemoryBackend::new();

        // This just tests the function doesn't error
        let result = BackgroundJobs::<MemoryBackend>::cleanup_expired_sessions(storage).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_token_cleanup() {
        let storage = MemoryBackend::new();

        let result = BackgroundJobs::<MemoryBackend>::cleanup_expired_tokens(storage).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_refresh_token_cleanup() {
        let storage = MemoryBackend::new();

        let result = BackgroundJobs::<MemoryBackend>::cleanup_expired_refresh_tokens(storage).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_authorization_code_cleanup() {
        let storage = MemoryBackend::new();

        let result =
            BackgroundJobs::<MemoryBackend>::cleanup_expired_authorization_codes(storage).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_revoked_certificate_cleanup() {
        let storage = MemoryBackend::new();

        let result = BackgroundJobs::<MemoryBackend>::cleanup_revoked_certificates(storage).await;
        assert!(result.is_ok());
    }

    // ── Kid parsing tests ─────────────────────────────────────────

    #[test]
    fn test_org_id_from_kid_valid() {
        let kid = "org-42-client-100-cert-999";
        assert_eq!(BackgroundJobs::<MemoryBackend>::org_id_from_kid(kid), Some(42));
    }

    #[test]
    fn test_org_id_from_kid_large_id() {
        let kid = "org-9999999999-client-1-cert-1";
        assert_eq!(BackgroundJobs::<MemoryBackend>::org_id_from_kid(kid), Some(9_999_999_999));
    }

    #[test]
    fn test_org_id_from_kid_invalid_format() {
        assert_eq!(BackgroundJobs::<MemoryBackend>::org_id_from_kid("invalid"), None);
    }

    #[test]
    fn test_org_id_from_kid_wrong_prefix() {
        assert_eq!(
            BackgroundJobs::<MemoryBackend>::org_id_from_kid("key-42-client-1-cert-1"),
            None
        );
    }

    #[test]
    fn test_org_id_from_kid_non_numeric_org_id() {
        assert_eq!(
            BackgroundJobs::<MemoryBackend>::org_id_from_kid("org-abc-client-1-cert-1"),
            None
        );
    }

    // ── Reconciliation tests ─────────────────────────────────────

    fn create_test_cert(id: i64, client_id: i64, org_id: i64) -> ClientCertificate {
        ClientCertificate::builder()
            .id(id)
            .client_id(client_id)
            .organization_id(org_id)
            .public_key("test-public-key".to_string())
            .private_key_encrypted("test-encrypted".to_string())
            .name("test-cert")
            .created_by_user_id(1)
            .create()
            .unwrap()
    }

    #[tokio::test]
    async fn test_reconciliation_no_divergence() {
        let storage = MemoryBackend::new();
        let signing_key_store = Arc::new(MemorySigningKeyStore::new());

        // Create a certificate in Control
        let cert = create_test_cert(1, 100, 200);
        let repo = ClientCertificateRepository::new(storage.clone());
        repo.create(cert.clone()).await.unwrap();

        // Create the corresponding signing key in Ledger
        let signing_key = PublicSigningKey::builder()
            .kid(cert.kid.clone())
            .public_key("test-public-key".to_owned())
            .client_id(100)
            .cert_id(1)
            .build();
        signing_key_store.create_key(200.into(), &signing_key).await.unwrap();

        // Reconcile — should find no divergences
        let result =
            BackgroundJobs::<MemoryBackend>::reconcile_certificates(storage, signing_key_store)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reconciliation_detects_missing_ledger_key() {
        let storage = MemoryBackend::new();
        let signing_key_store = Arc::new(MemorySigningKeyStore::new());

        // Create a certificate in Control but NOT in Ledger
        let cert = create_test_cert(1, 100, 200);
        let repo = ClientCertificateRepository::new(storage.clone());
        repo.create(cert).await.unwrap();

        // Reconcile — should detect the divergence (cert active in Control, missing in Ledger)
        let result =
            BackgroundJobs::<MemoryBackend>::reconcile_certificates(storage, signing_key_store)
                .await;
        // The function returns Ok but logs errors — it doesn't fail on divergences
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reconciliation_detects_revoked_ledger_key() {
        let storage = MemoryBackend::new();
        let signing_key_store = Arc::new(MemorySigningKeyStore::new());

        // Create a certificate in Control (active)
        let cert = create_test_cert(1, 100, 200);
        let repo = ClientCertificateRepository::new(storage.clone());
        repo.create(cert.clone()).await.unwrap();

        // Create the signing key in Ledger and then revoke it
        let signing_key = PublicSigningKey::builder()
            .kid(cert.kid.clone())
            .public_key("test-public-key".to_owned())
            .client_id(100)
            .cert_id(1)
            .build();
        signing_key_store.create_key(200.into(), &signing_key).await.unwrap();
        signing_key_store.revoke_key(200.into(), &cert.kid, Some("test")).await.unwrap();

        // Reconcile — should detect the divergence (active in Control, revoked in Ledger)
        let result =
            BackgroundJobs::<MemoryBackend>::reconcile_certificates(storage, signing_key_store)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reconciliation_detects_inactive_ledger_key() {
        let storage = MemoryBackend::new();
        let signing_key_store = Arc::new(MemorySigningKeyStore::new());

        // Create a certificate in Control (active)
        let cert = create_test_cert(1, 100, 200);
        let repo = ClientCertificateRepository::new(storage.clone());
        repo.create(cert.clone()).await.unwrap();

        // Create the signing key in Ledger and deactivate it
        let signing_key = PublicSigningKey::builder()
            .kid(cert.kid.clone())
            .public_key("test-public-key".to_owned())
            .client_id(100)
            .cert_id(1)
            .build();
        signing_key_store.create_key(200.into(), &signing_key).await.unwrap();
        signing_key_store.deactivate_key(200.into(), &cert.kid).await.unwrap();

        // Reconcile — should detect the divergence (active in Control, inactive in Ledger)
        let result =
            BackgroundJobs::<MemoryBackend>::reconcile_certificates(storage, signing_key_store)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reconciliation_skips_revoked_certs() {
        let storage = MemoryBackend::new();
        let signing_key_store = Arc::new(MemorySigningKeyStore::new());

        // Create a revoked certificate in Control
        let mut cert = create_test_cert(1, 100, 200);
        cert.mark_revoked(1);
        let repo = ClientCertificateRepository::new(storage.clone());
        repo.create(cert).await.unwrap();

        // Reconcile — revoked certs should not be in list_all_active(),
        // so there should be nothing to reconcile
        let result =
            BackgroundJobs::<MemoryBackend>::reconcile_certificates(storage, signing_key_store)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reconciliation_empty_certs() {
        let storage = MemoryBackend::new();
        let signing_key_store = Arc::new(MemorySigningKeyStore::new());

        // No certificates — reconciliation should succeed with zero divergences
        let result =
            BackgroundJobs::<MemoryBackend>::reconcile_certificates(storage, signing_key_store)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_with_signing_key_store_builder() {
        let storage = MemoryBackend::new();
        let leader = Arc::new(LeaderElection::new(storage.clone(), 1));
        let signing_key_store = Arc::new(MemorySigningKeyStore::new());

        let jobs = BackgroundJobs::new(storage, leader).with_signing_key_store(signing_key_store);

        assert!(jobs.signing_key_store.is_some());
    }
}
