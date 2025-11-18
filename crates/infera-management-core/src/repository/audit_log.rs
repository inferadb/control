use crate::entities::AuditLog;
use crate::error::{Error, Result};
use infera_management_storage::StorageBackend;

const PREFIX_AUDIT_LOG: &[u8] = b"audit_log:";

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
            .map_err(|e| Error::Internal(format!("Failed to serialize audit log: {}", e)))?;
        self.storage
            .set(key, value)
            .await
            .map_err(|e| Error::Internal(format!("Failed to write audit log: {}", e)))?;
        Ok(())
    }

    pub async fn get(&self, id: i64) -> Result<Option<AuditLog>> {
        let key = Self::key(id);
        match self.storage.get(&key).await {
            Ok(Some(value)) => {
                let log = serde_json::from_slice(&value).map_err(|e| {
                    Error::Internal(format!("Failed to deserialize audit log: {}", e))
                })?;
                Ok(Some(log))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::Internal(format!("Failed to get audit log: {}", e))),
        }
    }

    fn key(id: i64) -> Vec<u8> {
        format!("{}{}", String::from_utf8_lossy(PREFIX_AUDIT_LOG), id).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::AuditEventType;
    use infera_management_storage::MemoryBackend;

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
