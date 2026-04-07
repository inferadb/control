//! `StorageBackend` implementation backed by Ledger's entity store.
//!
//! Delegates key-value operations to a [`LedgerClient`], enabling distributed
//! rate limiting across multiple Control instances. All keys are stored as
//! entities in a system organization namespace with no vault.

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use inferadb_common_storage::{
    StorageRange,
    error::{StorageError, StorageResult},
    health::{HealthMetadata, HealthProbe, HealthStatus},
    transaction::Transaction,
    types::KeyValue,
};
use inferadb_ledger_sdk::{LedgerClient, SdkError, SetCondition};
use inferadb_ledger_types::{OrganizationSlug, UserSlug};
use tonic::Code;

/// Storage backend that delegates to Ledger's entity store.
///
/// Used for distributed rate limiting across Control instances. All operations
/// target a single system organization with no vault, using entity keys derived
/// from the raw byte keys via UTF-8 lossy conversion.
///
/// # Limitations
///
/// - **Range queries**: Not supported. `get_range` returns an empty vec and `clear_range` is a
///   no-op. The rate limiter does not use range queries.
/// - **Transactions**: Not supported. `transaction` returns [`StorageError::Internal`]. The rate
///   limiter does not use transactions.
/// - **Compare-and-set**: Uses a read-then-write pattern rather than true atomic CAS. Ledger's CAS
///   is version-based, not value-based. For ephemeral rate limit counters, this approximation is
///   acceptable.
pub struct LedgerStorageBackend {
    /// Shared Ledger client instance.
    client: Arc<LedgerClient>,
    /// Caller identity for Ledger RPCs.
    caller: UserSlug,
    /// Organization namespace for all rate limit keys.
    organization: OrganizationSlug,
}

impl LedgerStorageBackend {
    /// Creates a new Ledger-backed storage backend.
    pub fn new(
        client: Arc<LedgerClient>,
        caller: UserSlug,
        organization: OrganizationSlug,
    ) -> Self {
        Self { client, caller, organization }
    }

    /// Converts a byte key to a UTF-8 string for use as a Ledger entity key.
    fn key_to_string(key: &[u8]) -> String {
        String::from_utf8_lossy(key).into_owned()
    }

    /// Computes the Unix epoch seconds expiration timestamp from a TTL duration.
    fn ttl_to_expires_at(ttl: Duration) -> Option<u64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Some(now.as_secs().saturating_add(ttl.as_secs()))
    }

    /// Maps an [`SdkError`] to a [`StorageError`].
    ///
    /// `NotFound` RPC errors are not mapped here; callers that expect
    /// `Ok(None)` for missing keys should handle `NotFound` before calling.
    fn map_sdk_error(err: SdkError) -> StorageError {
        match &err {
            SdkError::Connection { message } => {
                StorageError::connection_with_source(message.clone(), err)
            },
            SdkError::Transport { .. } => {
                StorageError::connection_with_source("Ledger transport error", err)
            },
            SdkError::Timeout { .. } => StorageError::Timeout { context: None, span_id: None },
            SdkError::Unavailable { message } => {
                StorageError::connection_with_source(message.clone(), err)
            },
            SdkError::Rpc { code: Code::NotFound, .. } => {
                StorageError::internal("unexpected NotFound in error mapping")
            },
            SdkError::Rpc { code, message, .. } if *code == Code::FailedPrecondition => {
                tracing::debug!(
                    message,
                    "Ledger CAS precondition failed, mapping to StorageError::Conflict"
                );
                StorageError::conflict()
            },
            _ => StorageError::internal_with_source(format!("Ledger SDK error: {err}"), err),
        }
    }
}

#[async_trait]
impl inferadb_common_storage::StorageBackend for LedgerStorageBackend {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        let key_str = Self::key_to_string(key);
        match self.client.read(self.caller, self.organization, None, key_str, None, None).await {
            Ok(Some(value)) => Ok(Some(Bytes::from(value))),
            Ok(None) => Ok(None),
            Err(SdkError::Rpc { code: Code::NotFound, .. }) => Ok(None),
            Err(err) => Err(Self::map_sdk_error(err)),
        }
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        let key_str = Self::key_to_string(&key);
        self.client
            .set_entity(self.caller, self.organization, None, key_str, value, None, None, None)
            .await
            .map(|_| ())
            .map_err(Self::map_sdk_error)
    }

    async fn compare_and_set(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        let key_str = Self::key_to_string(key);
        let condition = match expected {
            None => Some(SetCondition::NotExists),
            Some(expected_bytes) => Some(SetCondition::ValueEquals(expected_bytes.to_vec())),
        };
        self.client
            .set_entity(
                self.caller,
                self.organization,
                None,
                key_str,
                new_value,
                None,
                condition,
                None,
            )
            .await
            .map(|_| ())
            .map_err(Self::map_sdk_error)
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        let key_str = Self::key_to_string(key);
        match self.client.delete_entity(self.caller, self.organization, None, key_str, None).await {
            Ok(_) => Ok(()),
            // Deleting a non-existent key is a no-op.
            Err(SdkError::Rpc { code: Code::NotFound, .. }) => Ok(()),
            Err(err) => Err(Self::map_sdk_error(err)),
        }
    }

    async fn get_range(&self, _range: StorageRange) -> StorageResult<Vec<KeyValue>> {
        // Range queries are not used by the rate limiter.
        Ok(Vec::new())
    }

    async fn clear_range(&self, _range: StorageRange) -> StorageResult<()> {
        // Range deletes are not used by the rate limiter.
        Ok(())
    }

    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()> {
        let key_str = Self::key_to_string(&key);
        let expires_at = Self::ttl_to_expires_at(ttl);
        self.client
            .set_entity(
                self.caller,
                self.organization,
                None,
                key_str,
                value,
                expires_at,
                None,
                None,
            )
            .await
            .map(|_| ())
            .map_err(Self::map_sdk_error)
    }

    async fn compare_and_set_with_ttl(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
        ttl: Duration,
    ) -> StorageResult<()> {
        let key_str = Self::key_to_string(key);
        let expires_at = Self::ttl_to_expires_at(ttl);
        let condition = match expected {
            None => Some(SetCondition::NotExists),
            Some(expected_bytes) => Some(SetCondition::ValueEquals(expected_bytes.to_vec())),
        };
        self.client
            .set_entity(
                self.caller,
                self.organization,
                None,
                key_str,
                new_value,
                expires_at,
                condition,
                None,
            )
            .await
            .map(|_| ())
            .map_err(Self::map_sdk_error)
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        Err(StorageError::internal("LedgerStorageBackend does not support transactions"))
    }

    async fn health_check(&self, _probe: HealthProbe) -> StorageResult<HealthStatus> {
        let start = std::time::Instant::now();
        // Probe Ledger connectivity by reading a key that almost certainly does not exist.
        match self.client.read(self.caller, self.organization, None, "__health__", None, None).await
        {
            Ok(_) | Err(SdkError::Rpc { code: Code::NotFound, .. }) => {
                let metadata = HealthMetadata::new(start.elapsed(), "ledger");
                Ok(HealthStatus::healthy(metadata))
            },
            Err(err) => {
                let mut details = HashMap::new();
                details.insert("error".to_owned(), err.to_string());
                let metadata = HealthMetadata {
                    check_duration: start.elapsed(),
                    backend: "ledger".to_owned(),
                    details,
                };
                Ok(HealthStatus::Unhealthy(metadata, err.to_string()))
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── key_to_string ───────────────────────────────────────────

    #[test]
    fn test_key_to_string_valid_utf8_preserved() {
        assert_eq!(LedgerStorageBackend::key_to_string(b"hello"), "hello");
    }

    #[test]
    fn test_key_to_string_invalid_utf8_uses_replacement_char() {
        let key = b"rate:\xff\xfe";
        let result = LedgerStorageBackend::key_to_string(key);

        assert!(result.starts_with("rate:"));
        assert!(result.contains('\u{FFFD}'));
    }

    #[test]
    fn test_key_to_string_empty_returns_empty() {
        assert_eq!(LedgerStorageBackend::key_to_string(b""), "");
    }

    // ── ttl_to_expires_at ───────────────────────────────────────

    #[test]
    fn test_ttl_to_expires_at_adds_ttl_to_current_time() {
        let ttl = Duration::from_secs(3600);

        let expires = LedgerStorageBackend::ttl_to_expires_at(ttl).unwrap();

        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!(expires >= now + 3599);
        assert!(expires <= now + 3601);
    }

    #[test]
    fn test_ttl_to_expires_at_zero_returns_approximately_now() {
        let expires = LedgerStorageBackend::ttl_to_expires_at(Duration::ZERO).unwrap();

        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!(expires >= now.saturating_sub(1));
        assert!(expires <= now + 1);
    }

    // ── map_sdk_error ───────────────────────────────────────────

    #[test]
    fn test_map_sdk_error_connection_maps_to_connection() {
        let err = SdkError::Connection { message: "refused".to_owned() };

        let mapped = LedgerStorageBackend::map_sdk_error(err);

        assert!(matches!(mapped, StorageError::Connection { .. }));
    }

    #[test]
    fn test_map_sdk_error_transport_maps_to_connection() {
        let transport_err: Box<dyn std::error::Error + Send + Sync> = "transport failed".into();
        let err = SdkError::Transport { source: std::sync::Arc::new(transport_err) };

        let mapped = LedgerStorageBackend::map_sdk_error(err);

        assert!(matches!(mapped, StorageError::Connection { .. }));
    }

    #[test]
    fn test_map_sdk_error_timeout_maps_to_timeout() {
        let err = SdkError::Timeout { duration_ms: 5000 };

        let mapped = LedgerStorageBackend::map_sdk_error(err);

        assert!(matches!(mapped, StorageError::Timeout { .. }));
    }

    #[test]
    fn test_map_sdk_error_unavailable_maps_to_connection() {
        let err = SdkError::Unavailable { message: "server down".to_owned() };

        let mapped = LedgerStorageBackend::map_sdk_error(err);

        assert!(matches!(mapped, StorageError::Connection { .. }));
    }

    #[test]
    fn test_map_sdk_error_failed_precondition_maps_to_conflict() {
        let err = SdkError::Rpc {
            code: Code::FailedPrecondition,
            message: "version mismatch".to_owned(),
            request_id: None,
            trace_id: None,
            error_details: None,
        };

        let mapped = LedgerStorageBackend::map_sdk_error(err);

        assert!(matches!(mapped, StorageError::Conflict { .. }));
    }

    #[test]
    fn test_map_sdk_error_not_found_maps_to_internal() {
        let err = SdkError::Rpc {
            code: Code::NotFound,
            message: "not found".to_owned(),
            request_id: None,
            trace_id: None,
            error_details: None,
        };

        let mapped = LedgerStorageBackend::map_sdk_error(err);

        assert!(matches!(mapped, StorageError::Internal { .. }));
    }

    #[test]
    fn test_map_sdk_error_other_rpc_maps_to_internal() {
        let err = SdkError::Rpc {
            code: Code::PermissionDenied,
            message: "denied".to_owned(),
            request_id: None,
            trace_id: None,
            error_details: None,
        };

        let mapped = LedgerStorageBackend::map_sdk_error(err);

        assert!(matches!(mapped, StorageError::Internal { .. }));
    }

    #[test]
    fn test_map_sdk_error_config_maps_to_internal() {
        let err = SdkError::Config { message: "bad config".to_owned() };

        let mapped = LedgerStorageBackend::map_sdk_error(err);

        assert!(matches!(mapped, StorageError::Internal { .. }));
    }
}
