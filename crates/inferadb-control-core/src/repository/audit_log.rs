use chrono::{DateTime, Utc};
use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::{AuditEventType, AuditLog, AuditResourceType},
    error::{Error, Result},
};

const PREFIX_AUDIT_LOG: &[u8] = b"audit_log:";
// For future index implementation
#[allow(dead_code)]
const PREFIX_AUDIT_LOG_BY_ORG: &[u8] = b"audit_log_by_org:";

/// Query filters for audit logs
#[derive(Debug, Clone, Default)]
pub struct AuditLogFilters {
    /// Filter by actor (user_id)
    pub actor: Option<i64>,
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
            .map_err(|e| Error::Internal(format!("Failed to serialize audit log: {e}")))?;
        self.storage
            .set(key, value)
            .await
            .map_err(|e| Error::Internal(format!("Failed to write audit log: {e}")))?;
        Ok(())
    }

    pub async fn get(&self, id: i64) -> Result<Option<AuditLog>> {
        let key = Self::key(id);
        match self.storage.get(&key).await {
            Ok(Some(value)) => {
                let log = serde_json::from_slice(&value).map_err(|e| {
                    Error::Internal(format!("Failed to deserialize audit log: {e}"))
                })?;
                Ok(Some(log))
            },
            Ok(None) => Ok(None),
            Err(e) => Err(Error::Internal(format!("Failed to get audit log: {e}"))),
        }
    }

    /// List audit logs for an organization with optional filters and pagination
    pub async fn list_by_organization(
        &self,
        organization_id: i64,
        filters: AuditLogFilters,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<AuditLog>, usize)> {
        // For in-memory backend, we need to scan all logs
        // In production with Ledger, we would use indexes

        // This is a simplified implementation that scans all logs
        // In a real implementation, we would use a secondary index on organization_id + created_at

        let prefix = format!("{}{}", String::from_utf8_lossy(PREFIX_AUDIT_LOG), "");
        let start_key = prefix.as_bytes().to_vec();
        let end_key = {
            let mut key = start_key.clone();
            key.push(0xFF);
            key
        };

        let kvs = self
            .storage
            .get_range(start_key..end_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to scan audit logs: {e}")))?;

        let mut all_logs: Vec<AuditLog> =
            kvs.into_iter().filter_map(|kv| serde_json::from_slice(&kv.value).ok()).collect();

        // Filter by organization
        all_logs.retain(|log| log.organization_id == Some(organization_id));

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

    /// Delete audit logs older than the specified date
    ///
    /// Returns the number of logs deleted
    pub async fn delete_older_than(&self, cutoff_date: DateTime<Utc>) -> Result<usize> {
        let prefix = format!("{}{}", String::from_utf8_lossy(PREFIX_AUDIT_LOG), "");
        let start_key = prefix.as_bytes().to_vec();
        let end_key = {
            let mut key = start_key.clone();
            key.push(0xFF);
            key
        };

        let kvs = self
            .storage
            .get_range(start_key..end_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to scan audit logs: {e}")))?;

        let mut deleted_count = 0;

        for kv in kvs {
            if let Ok(log) = serde_json::from_slice::<AuditLog>(&kv.value)
                && log.created_at < cutoff_date
            {
                self.storage
                    .delete(&kv.key)
                    .await
                    .map_err(|e| Error::Internal(format!("Failed to delete audit log: {e}")))?;
                deleted_count += 1;
            }
        }

        Ok(deleted_count)
    }

    fn key(id: i64) -> Vec<u8> {
        format!("{}{}", String::from_utf8_lossy(PREFIX_AUDIT_LOG), id).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use inferadb_control_storage::MemoryBackend;
    use inferadb_control_types::entities::AuditEventType;

    use super::*;

    #[tokio::test]
    async fn test_create_and_get_audit_log() {
        let storage = MemoryBackend::new();
        let repo = AuditLogRepository::new(storage);
        let log = AuditLog::new(AuditEventType::UserLogin, Some(1), Some(100))
            .with_ip_address("192.168.1.1");
        repo.create(log.clone()).await.unwrap();
        let retrieved = repo.get(log.id).await.unwrap();
        assert!(retrieved.is_some());
    }
}
