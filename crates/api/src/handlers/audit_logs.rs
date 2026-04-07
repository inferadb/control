//! Audit log handlers.
//!
//! Serves paginated audit events for an organization. Event ingestion
//! is handled by Ledger's event system.

use std::{collections::HashMap, time::Instant};

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use inferadb_control_core::SdkResultExt;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{EventFilter, EventOutcome, OrganizationSlug};
use serde::{Deserialize, Serialize};

use super::common::{CursorPaginationQuery, require_ledger, verify_org_membership_from_claims};
use crate::{
    handlers::state::{AppState, Result},
    middleware::UserClaims,
};

// ── Request / Response Types ────────────────────────────────────────

/// Query parameters for listing audit logs.
///
/// Embeds standard cursor pagination and adds audit-specific filters.
#[derive(Debug, Deserialize)]
pub struct ListAuditLogsQuery {
    /// Standard cursor-based pagination fields.
    #[serde(flatten)]
    pub pagination: CursorPaginationQuery,
    /// Filter by event type prefix (e.g., `"ledger.vault"`).
    pub event_type: Option<String>,
    /// Filter by principal (who performed the action).
    pub principal: Option<String>,
    /// Filter by outcome: `"success"`, `"failed"`, or `"denied"`.
    pub outcome: Option<String>,
}

/// A single audit log entry.
#[derive(Debug, Serialize)]
pub struct AuditLogEntry {
    /// UUID identifying this event.
    pub event_id: String,
    /// Hierarchical event type (e.g., `"ledger.vault.created"`).
    pub event_type: String,
    /// Who performed the action (e.g., `"user:42"`).
    pub principal: String,
    /// Result of the action (e.g., `"success"`, `"failed:NOT_FOUND"`).
    pub outcome: String,
    /// RFC 3339 timestamp of the event.
    pub timestamp: String,
    /// Service that emitted the event (e.g., `"control"`).
    pub source: String,
    /// Machine-readable action name (e.g., `"vault_created"`).
    pub action: String,
    /// Additional key-value context for the event.
    pub details: HashMap<String, String>,
}

/// Paginated audit log response.
#[derive(Debug, Serialize)]
pub struct ListAuditLogsResponse {
    /// Audit log entries for the current page.
    pub entries: Vec<AuditLogEntry>,
    /// Opaque token for fetching the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    /// Approximate total number of matching entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Formats an [`EventOutcome`](inferadb_ledger_sdk::EventOutcome) as a string.
fn format_outcome(outcome: &inferadb_ledger_sdk::EventOutcome) -> String {
    match outcome {
        EventOutcome::Success => "success".to_string(),
        EventOutcome::Failed { code, .. } => format!("failed:{code}"),
        EventOutcome::Denied { reason } => format!("denied:{reason}"),
    }
}

/// Converts a Ledger [`SdkEventEntry`](inferadb_ledger_sdk::SdkEventEntry) to an API response.
fn sdk_entry_to_response(entry: inferadb_ledger_sdk::SdkEventEntry) -> AuditLogEntry {
    AuditLogEntry {
        event_id: entry.event_id_string(),
        event_type: entry.event_type,
        principal: entry.principal,
        outcome: format_outcome(&entry.outcome),
        timestamp: entry.timestamp.to_rfc3339(),
        source: entry.source_service,
        action: entry.action,
        details: entry.details,
    }
}

/// Parses an outcome string into an [`EventFilter`].
fn parse_outcome_filter(outcome: &str) -> std::result::Result<EventFilter, CoreError> {
    let filter = EventFilter::new();
    match outcome {
        "success" => Ok(filter.outcome_success()),
        "failed" => Ok(filter.outcome_failed()),
        "denied" => Ok(filter.outcome_denied()),
        _ => Err(CoreError::validation(
            "invalid outcome filter: expected 'success', 'failed', or 'denied'",
        )),
    }
}

/// Builds an [`EventFilter`] from audit log query parameters.
fn build_event_filter(query: &ListAuditLogsQuery) -> std::result::Result<EventFilter, CoreError> {
    let mut filter = if let Some(ref outcome) = query.outcome {
        parse_outcome_filter(outcome)?
    } else {
        EventFilter::new()
    };

    if let Some(ref event_type) = query.event_type {
        filter = filter.event_type_prefix(event_type.as_str());
    }

    if let Some(ref principal) = query.principal {
        filter = filter.principal(principal.as_str());
    }

    Ok(filter)
}

// ── Handlers ────────────────────────────────────────────────────────

/// GET /control/v1/organizations/{org}/audit-logs
///
/// Lists audit logs for an organization.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Query(query): Query<ListAuditLogsQuery>,
) -> Result<Json<ListAuditLogsResponse>> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);

    verify_org_membership_from_claims(&state, ledger, org, &claims).await?;

    let page = if let Some(ref page_token) = query.pagination.page_token {
        let start = Instant::now();
        ledger
            .list_events_next(claims.user_slug, organization, page_token)
            .await
            .map_sdk_err_instrumented("list_events_next", start)?
    } else {
        let filter = build_event_filter(&query)?;
        let limit = query.pagination.validated_page_size();
        let start = Instant::now();
        ledger
            .list_events(claims.user_slug, organization, filter, limit)
            .await
            .map_sdk_err_instrumented("list_events", start)?
    };

    let entries = page.entries.into_iter().map(sdk_entry_to_response).collect();

    Ok(Json(ListAuditLogsResponse {
        entries,
        next_page_token: page.next_page_token,
        total_estimate: page.total_estimate,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use chrono::Utc;
    use inferadb_ledger_sdk::{EventOutcome, OrganizationSlug, SdkEventEntry};

    use super::*;

    // ── format_outcome ────────────────────────────────────────────

    #[test]
    fn format_outcome_success() {
        assert_eq!(format_outcome(&EventOutcome::Success), "success");
    }

    #[test]
    fn format_outcome_failed_includes_code() {
        let outcome = EventOutcome::Failed {
            code: "NOT_FOUND".to_string(),
            detail: "entity missing".to_string(),
        };
        assert_eq!(format_outcome(&outcome), "failed:NOT_FOUND");
    }

    #[test]
    fn format_outcome_denied_includes_reason() {
        let outcome = EventOutcome::Denied { reason: "rate_limited".to_string() };
        assert_eq!(format_outcome(&outcome), "denied:rate_limited");
    }

    // ── sdk_entry_to_response ─────────────────────────────────────

    fn make_test_entry() -> SdkEventEntry {
        SdkEventEntry {
            event_id: vec![0u8; 16],
            source_service: "control".to_string(),
            event_type: "ledger.vault.created".to_string(),
            timestamp: Utc::now(),
            scope: inferadb_ledger_sdk::EventScope::Organization,
            action: "vault_created".to_string(),
            emission_path: inferadb_ledger_sdk::EventEmissionPath::ApplyPhase,
            principal: "user:42".to_string(),
            organization: OrganizationSlug::new(1),
            vault: None,
            outcome: EventOutcome::Success,
            details: HashMap::from([("vault".to_string(), "my-vault".to_string())]),
            block_height: Some(100),
            node_id: None,
            trace_id: None,
            correlation_id: None,
            operations_count: Some(1),
        }
    }

    #[test]
    fn sdk_entry_to_response_maps_fields() {
        let entry = make_test_entry();
        let resp = sdk_entry_to_response(entry);
        assert_eq!(resp.event_type, "ledger.vault.created");
        assert_eq!(resp.principal, "user:42");
        assert_eq!(resp.outcome, "success");
        assert_eq!(resp.source, "control");
        assert_eq!(resp.action, "vault_created");
        assert_eq!(resp.details.get("vault").unwrap(), "my-vault");
    }

    #[test]
    fn sdk_entry_to_response_formats_event_id_as_uuid() {
        let entry = make_test_entry();
        let resp = sdk_entry_to_response(entry);
        assert_eq!(resp.event_id, "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn sdk_entry_to_response_with_failed_outcome() {
        let mut entry = make_test_entry();
        entry.outcome =
            EventOutcome::Failed { code: "PERM".to_string(), detail: "forbidden".to_string() };
        let resp = sdk_entry_to_response(entry);
        assert_eq!(resp.outcome, "failed:PERM");
    }

    // ── parse_outcome_filter ──────────────────────────────────────

    #[test]
    fn parse_outcome_filter_success() {
        assert!(parse_outcome_filter("success").is_ok());
    }

    #[test]
    fn parse_outcome_filter_failed() {
        assert!(parse_outcome_filter("failed").is_ok());
    }

    #[test]
    fn parse_outcome_filter_denied() {
        assert!(parse_outcome_filter("denied").is_ok());
    }

    #[test]
    fn parse_outcome_filter_invalid_returns_error() {
        let err = parse_outcome_filter("unknown").unwrap_err();
        assert!(matches!(err, CoreError::Validation { .. }));
    }

    // ── build_event_filter ────────────────────────────────────────

    #[test]
    fn build_event_filter_no_filters() {
        let query = ListAuditLogsQuery {
            pagination: CursorPaginationQuery { page_size: 50, page_token: None },
            event_type: None,
            principal: None,
            outcome: None,
        };
        assert!(build_event_filter(&query).is_ok());
    }

    #[test]
    fn build_event_filter_with_outcome() {
        let query = ListAuditLogsQuery {
            pagination: CursorPaginationQuery { page_size: 50, page_token: None },
            event_type: None,
            principal: None,
            outcome: Some("success".to_string()),
        };
        assert!(build_event_filter(&query).is_ok());
    }

    #[test]
    fn build_event_filter_with_event_type_and_principal() {
        let query = ListAuditLogsQuery {
            pagination: CursorPaginationQuery { page_size: 50, page_token: None },
            event_type: Some("ledger.vault".to_string()),
            principal: Some("user:42".to_string()),
            outcome: None,
        };
        assert!(build_event_filter(&query).is_ok());
    }

    #[test]
    fn build_event_filter_with_invalid_outcome() {
        let query = ListAuditLogsQuery {
            pagination: CursorPaginationQuery { page_size: 50, page_token: None },
            event_type: None,
            principal: None,
            outcome: Some("bogus".to_string()),
        };
        assert!(build_event_filter(&query).is_err());
    }

    #[test]
    fn build_event_filter_with_all_fields() {
        let query = ListAuditLogsQuery {
            pagination: CursorPaginationQuery { page_size: 50, page_token: None },
            event_type: Some("ledger.vault".to_string()),
            principal: Some("user:7".to_string()),
            outcome: Some("denied".to_string()),
        };
        assert!(build_event_filter(&query).is_ok());
    }

    // ── ListAuditLogsQuery deserialization ─────────────────────────

    #[test]
    fn list_audit_logs_query_deserializes_with_defaults() {
        let json = r#"{"page_size": 25}"#;
        let query: ListAuditLogsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.pagination.page_size, 25);
        assert!(query.event_type.is_none());
        assert!(query.principal.is_none());
        assert!(query.outcome.is_none());
    }

    // ── Response serialization ────────────────────────────────────

    #[test]
    fn audit_log_entry_serializes() {
        let entry = AuditLogEntry {
            event_id: "abc".to_string(),
            event_type: "test".to_string(),
            principal: "user:1".to_string(),
            outcome: "success".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            source: "control".to_string(),
            action: "test_action".to_string(),
            details: HashMap::new(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["event_id"], "abc");
        assert_eq!(json["outcome"], "success");
    }

    #[test]
    fn list_response_omits_none_fields() {
        let resp =
            ListAuditLogsResponse { entries: vec![], next_page_token: None, total_estimate: None };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("next_page_token").is_none());
        assert!(json.get("total_estimate").is_none());
    }

    #[test]
    fn list_response_includes_present_fields() {
        let resp = ListAuditLogsResponse {
            entries: vec![],
            next_page_token: Some("token".to_string()),
            total_estimate: Some(42),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["next_page_token"], "token");
        assert_eq!(json["total_estimate"], 42);
    }
}
