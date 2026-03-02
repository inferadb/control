use std::time::Duration;

use chrono::{DateTime, Utc};
use inferadb_control_storage::{StorageBackend, to_storage_range};
use inferadb_control_types::{
    OrganizationSlug,
    entities::{AuditEventType, AuditLog, AuditResourceType},
    error::{Error, Result},
};

const PREFIX_AUDIT_LOG: &str = "audit_log:";

/// Audit log retention period (90 days)
const AUDIT_LOG_RETENTION: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Query filters for audit logs
#[derive(Debug, Clone, Default)]
pub struct AuditLogFilters {
    /// Filter by actor (user_id)
    pub actor: Option<u64>,
    /// Filter by event type
    pub action: Option<AuditEventType>,
    /// Filter by resource type
    pub resource_type: Option<AuditResourceType>,
    /// Filter by start date
    pub start_date: Option<DateTime<Utc>>,
    /// Filter by end date
    pub end_date: Option<DateTime<Utc>>,
}

/// Repository for audit log operations
pub struct AuditLogRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> AuditLogRepository<S> {
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    pub async fn create(&self, log: AuditLog) -> Result<()> {
        log.validate()?;
        let key = Self::key(log.id);
        let value = serde_json::to_vec(&log)
            .map_err(|e| Error::internal(format!("Failed to serialize audit log: {e}")))?;
        self.storage.set_with_ttl(key, value, AUDIT_LOG_RETENTION).await?;
        Ok(())
    }

    pub async fn get(&self, id: u64) -> Result<Option<AuditLog>> {
        let key = Self::key(id);
        match self.storage.get(&key).await {
            Ok(Some(value)) => {
                let log = serde_json::from_slice(&value).map_err(|e| {
                    Error::internal(format!("Failed to deserialize audit log: {e}"))
                })?;
                Ok(Some(log))
            },
            Ok(None) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List audit logs for an organization with optional filters and pagination
    pub async fn list_by_organization(
        &self,
        organization: OrganizationSlug,
        filters: AuditLogFilters,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<AuditLog>, usize)> {
        // For in-memory backend, we need to scan all logs
        // In production with Ledger, we would use indexes

        // This is a simplified implementation that scans all logs
        // In a real implementation, we would use a secondary index on organization + created_at

        let start_key = PREFIX_AUDIT_LOG.as_bytes().to_vec();
        let end_key = {
            let mut key = start_key.clone();
            key.push(0xFF);
            key
        };

        let kvs = self.storage.get_range(to_storage_range(start_key..end_key)).await?;

        let mut all_logs: Vec<AuditLog> =
            kvs.into_iter().filter_map(|kv| serde_json::from_slice(&kv.value).ok()).collect();

        // Filter by organization
        all_logs.retain(|log| log.organization == Some(organization));

        // Apply filters
        if let Some(actor) = filters.actor {
            all_logs.retain(|log| log.user_id == Some(actor));
        }

        if let Some(action) = filters.action {
            all_logs.retain(|log| log.event_type == action);
        }

        if let Some(resource_type) = filters.resource_type {
            all_logs.retain(|log| log.resource_type == Some(resource_type));
        }

        if let Some(start_date) = filters.start_date {
            all_logs.retain(|log| log.created_at >= start_date);
        }

        if let Some(end_date) = filters.end_date {
            all_logs.retain(|log| log.created_at <= end_date);
        }

        // Sort by created_at descending (newest first)
        all_logs.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        let total = all_logs.len();

        // Apply pagination
        let start = offset as usize;
        let paginated_logs = all_logs.into_iter().skip(start).take(limit as usize).collect();

        Ok((paginated_logs, total))
    }

    fn key(id: u64) -> Vec<u8> {
        format!("{PREFIX_AUDIT_LOG}{id}").into_bytes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_control_storage::{MemoryBackend, backend::StorageBackend};
    use inferadb_control_types::entities::AuditEventType;

    use super::*;

    #[tokio::test]
    async fn test_create_and_get_audit_log() {
        let storage = MemoryBackend::new();
        let repo = AuditLogRepository::new(storage);
        let log = AuditLog::builder()
            .event_type(AuditEventType::UserLogin)
            .organization(OrganizationSlug::from(1_u64))
            .user_id(100)
            .ip_address("192.168.1.1")
            .build();
        repo.create(log.clone()).await.unwrap();
        let retrieved = repo.get(log.id).await.unwrap();
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_create_sets_ttl() {
        let storage = MemoryBackend::new();
        let repo = AuditLogRepository::new(storage.clone());

        let log = AuditLog::builder()
            .event_type(AuditEventType::UserLogin)
            .organization(OrganizationSlug::from(1_u64))
            .user_id(100)
            .ip_address("192.168.1.1")
            .build();
        let log_id = log.id;

        repo.create(log).await.unwrap();

        // Key should exist immediately after creation
        let key = format!("audit_log:{log_id}");
        assert!(storage.get(key.as_bytes()).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_audit_log_expires_from_storage() {
        let storage = MemoryBackend::new();

        // Write directly with a short TTL to verify MemoryBackend TTL behavior
        let log = AuditLog::builder()
            .event_type(AuditEventType::UserLogin)
            .organization(OrganizationSlug::from(1_u64))
            .user_id(100)
            .ip_address("192.168.1.1")
            .build();
        let log_id = log.id;
        let key = format!("audit_log:{log_id}");
        let value = serde_json::to_vec(&log).unwrap();

        storage.set_with_ttl(key.as_bytes().to_vec(), value, Duration::from_secs(1)).await.unwrap();

        // Key should exist immediately
        assert!(storage.get(key.as_bytes()).await.unwrap().is_some());

        // Wait for TTL expiry
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Key should be absent after TTL expiry
        assert!(storage.get(key.as_bytes()).await.unwrap().is_none());
    }
}
