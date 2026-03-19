//! Audit event service wrapping Ledger SDK event operations.

use inferadb_control_types::error::Result;
use inferadb_ledger_sdk::{
    EventFilter, EventPage, EventSource, IngestResult, LedgerClient, SdkIngestEventEntry,
};
use inferadb_ledger_types::OrganizationSlug;

use super::error::SdkResultExt;

/// Lists audit events for an organization with optional filtering.
pub async fn list_events(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    filter: EventFilter,
    limit: u32,
) -> Result<EventPage> {
    ledger.list_events(organization, filter, limit).await.map_sdk_err()
}

/// Continues paginating audit events from a previous response.
pub async fn list_events_next(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    page_token: &str,
) -> Result<EventPage> {
    ledger.list_events_next(organization, page_token).await.map_sdk_err()
}

/// Ingests external audit events from the Control service.
pub async fn ingest_events(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    events: Vec<SdkIngestEventEntry>,
) -> Result<IngestResult> {
    ledger.ingest_events(organization, EventSource::Control, events).await.map_sdk_err()
}
