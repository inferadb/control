//! Audit log handlers.
//!
//! Audit logs are managed by Ledger's event system. The `list_audit_logs`
//! handler serves paginated events for an organization. Event ingestion
//! is handled directly by Ledger.

use std::{collections::HashMap, time::Instant};

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use inferadb_control_core::SdkResultExt;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{EventFilter, EventOutcome, OrganizationSlug};
use serde::{Deserialize, Serialize};

use super::common::require_ledger;
use crate::{
    handlers::auth::{AppState, Result},
    middleware::UserClaims,
};

// ── Request / Response Types ────────────────────────────────────────

/// Query parameters for listing audit logs.
#[derive(Debug, Deserialize)]
pub struct ListAuditLogsQuery {
    /// Number of items per page (default 50, max 100).
    pub page_size: Option<u32>,
    /// Opaque cursor for the next page.
    pub page_token: Option<String>,
    /// Filter by event type prefix (e.g., `"ledger.vault"`).
    pub event_type: Option<String>,
    /// Filter by principal (who performed the action).
    pub principal: Option<String>,
    /// Filter by outcome: `"success"`, `"failed"`, or `"denied"`.
    pub outcome: Option<String>,
}

/// A single audit log entry in the API response.
#[derive(Debug, Serialize)]
pub struct AuditLogEntry {
    pub event_id: String,
    pub event_type: String,
    pub principal: String,
    pub outcome: String,
    pub timestamp: String,
    pub source: String,
    pub action: String,
    pub details: HashMap<String, String>,
}

/// Paginated audit log listing response.
#[derive(Debug, Serialize)]
pub struct ListAuditLogsResponse {
    pub entries: Vec<AuditLogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
}

// ── Helpers ─────────────────────────────────────────────────────────

fn format_outcome(outcome: &inferadb_ledger_sdk::EventOutcome) -> String {
    match outcome {
        EventOutcome::Success => "success".to_string(),
        EventOutcome::Failed { code, .. } => format!("failed:{code}"),
        EventOutcome::Denied { reason } => format!("denied:{reason}"),
    }
}

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

fn parse_outcome_filter(outcome: &str) -> std::result::Result<EventFilter, CoreError> {
    let filter = EventFilter::new();
    match outcome {
        "success" => Ok(filter.outcome_success()),
        "failed" => Ok(filter.outcome_failed()),
        "denied" => Ok(filter.outcome_denied()),
        _ => Err(CoreError::validation(format!(
            "invalid outcome filter '{outcome}': expected 'success', 'failed', or 'denied'"
        ))),
    }
}

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

/// List audit logs for an organization.
///
/// GET /control/v1/organizations/{org}/audit-logs
pub async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Query(query): Query<ListAuditLogsQuery>,
) -> Result<Json<ListAuditLogsResponse>> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);

    // Verify the caller is a member of this organization.
    let start = Instant::now();
    ledger
        .get_organization(organization, claims.user_slug)
        .await
        .map_sdk_err_instrumented("get_organization", start)?;

    let page = if let Some(ref page_token) = query.page_token {
        let start = Instant::now();
        ledger
            .list_events_next(organization, page_token)
            .await
            .map_sdk_err_instrumented("list_events_next", start)?
    } else {
        let filter = build_event_filter(&query)?;
        let limit = query.page_size.unwrap_or(50).clamp(1, 100);
        let start = Instant::now();
        ledger
            .list_events(organization, filter, limit)
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
