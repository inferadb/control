//! FDB-based cache invalidation writer for Control-to-Engine communication
//!
//! This module writes cache invalidation events to FDB, which Engine instances
//! watch using FDB's watch API. This replaces HTTP-based webhook notifications.

use std::sync::Arc;

use chrono::Utc;
use foundationdb::{Database, options::MutationType};
use inferadb_control_fdb_shared::{
    INVALIDATION_LOG_PREFIX, INVALIDATION_VERSION_KEY, InvalidationEvent, InvalidationLogEntry,
    invalidation_log_key,
};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// TTL for invalidation log entries (1 hour)
const INVALIDATION_LOG_TTL_MS: i64 = 60 * 60 * 1000;

/// FDB-based cache invalidation writer
///
/// Writes invalidation events to FDB that Engine instances watch.
/// Uses atomic increment on a version key to trigger Engine watches.
#[derive(Clone)]
pub struct FdbInvalidationWriter {
    db: Arc<Database>,
    control_id: String,
}

impl FdbInvalidationWriter {
    /// Create a new FDB invalidation writer
    pub fn new(db: Arc<Database>, control_id: String) -> Self {
        Self { db, control_id }
    }

    /// Write an invalidation event to FDB
    ///
    /// This atomically:
    /// 1. Increments the version key (triggers Engine watches)
    /// 2. Writes the event to the invalidation log
    async fn write_event(&self, event: InvalidationEvent) -> Result<(), String> {
        let timestamp_ms = Utc::now().timestamp_millis();
        let event_id = Uuid::new_v4().to_string();

        let log_entry = InvalidationLogEntry {
            event_id: event_id.clone(),
            timestamp_ms,
            event: event.clone(),
            source_control_id: self.control_id.clone(),
        };

        let log_key = invalidation_log_key(timestamp_ms, &event_id);
        let log_value = serde_json::to_vec(&log_entry)
            .map_err(|e| format!("Failed to serialize invalidation event: {e}"))?;

        let db = Arc::clone(&self.db);
        db.run({
            let log_key = log_key.clone();
            let log_value = log_value.clone();
            move |trx, _maybe_committed| {
                let log_key = log_key.clone();
                let log_value = log_value.clone();
                async move {
                    // Atomically increment the version key to trigger Engine watches
                    // Using little-endian 8-byte integer for atomic add
                    trx.atomic_op(INVALIDATION_VERSION_KEY, &1i64.to_le_bytes(), MutationType::Add);

                    // Write the event to the log
                    trx.set(&log_key, &log_value);

                    Ok(())
                }
            }
        })
        .await
        .map_err(|e| format!("Failed to write invalidation event to FDB: {e}"))?;

        debug!(
            event_id = %event_id,
            event = ?event,
            "Wrote invalidation event to FDB"
        );

        Ok(())
    }

    /// Invalidate all caches for a specific vault
    pub async fn invalidate_vault(&self, vault_id: i64) -> Result<(), String> {
        info!(vault_id = %vault_id, "Sending FDB vault invalidation");
        self.write_event(InvalidationEvent::Vault { vault_id }).await
    }

    /// Invalidate all caches for an organization
    pub async fn invalidate_organization(&self, org_id: i64) -> Result<(), String> {
        info!(org_id = %org_id, "Sending FDB organization invalidation");
        self.write_event(InvalidationEvent::Organization { org_id }).await
    }

    /// Invalidate a specific certificate
    pub async fn invalidate_certificate(
        &self,
        org_id: i64,
        client_id: i64,
        cert_id: i64,
    ) -> Result<(), String> {
        info!(
            org_id = %org_id,
            client_id = %client_id,
            cert_id = %cert_id,
            "Sending FDB certificate invalidation"
        );
        self.write_event(InvalidationEvent::Certificate { org_id, client_id, cert_id }).await
    }

    /// Invalidate all caches (nuclear option)
    pub async fn invalidate_all(&self) -> Result<(), String> {
        warn!("Sending FDB invalidate-all event");
        self.write_event(InvalidationEvent::All).await
    }

    /// Clean up old invalidation log entries
    ///
    /// This should be called periodically to remove old events.
    /// Events older than INVALIDATION_LOG_TTL_MS are deleted.
    pub async fn cleanup_old_events(&self) -> Result<usize, String> {
        let cutoff_ms = Utc::now().timestamp_millis() - INVALIDATION_LOG_TTL_MS;

        // Range from start of log to cutoff timestamp
        let start_key = INVALIDATION_LOG_PREFIX.to_vec();
        let end_key = invalidation_log_key(cutoff_ms, "");

        let db = Arc::clone(&self.db);
        let deleted_count = db
            .run({
                let start_key = start_key.clone();
                let end_key = end_key.clone();
                move |trx, _maybe_committed| {
                    let start_key = start_key.clone();
                    let end_key = end_key.clone();
                    async move {
                        // Clear the range of old entries
                        trx.clear_range(&start_key, &end_key);
                        // We can't easily count deleted entries in FDB, so return 0
                        // The actual cleanup still happens
                        Ok(0usize)
                    }
                }
            })
            .await
            .map_err(|e| format!("Failed to cleanup old invalidation events: {e}"))?;

        debug!(cutoff_ms = cutoff_ms, "Cleaned up old invalidation events");

        Ok(deleted_count)
    }

    /// Start the background cleanup task
    ///
    /// Runs cleanup every 10 minutes to remove old invalidation events.
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                interval.tick().await;
                if let Err(e) = self.cleanup_old_events().await {
                    warn!(error = %e, "Failed to cleanup old invalidation events");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalidation_log_entry_serialization() {
        let entry = InvalidationLogEntry {
            event_id: "test-uuid".to_string(),
            timestamp_ms: 1234567890000,
            event: InvalidationEvent::Vault { vault_id: 42 },
            source_control_id: "ctrl-test".to_string(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: InvalidationLogEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.event_id, "test-uuid");
        assert_eq!(parsed.timestamp_ms, 1234567890000);
        assert_eq!(parsed.source_control_id, "ctrl-test");
    }

    #[test]
    fn test_invalidation_event_variants() {
        // Test all event variants serialize correctly
        let events = vec![
            InvalidationEvent::Vault { vault_id: 1 },
            InvalidationEvent::Organization { org_id: 2 },
            InvalidationEvent::Certificate { org_id: 3, client_id: 4, cert_id: 5 },
            InvalidationEvent::All,
        ];

        for event in events {
            let json = serde_json::to_string(&event).unwrap();
            let parsed: InvalidationEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, event);
        }
    }
}
