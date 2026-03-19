//! Audit log handlers.
//!
//! Audit logs are managed by Ledger's event system. The `list_audit_logs`
//! handler serves paginated events for an organization, while `create_audit_log`
//! is an internal endpoint for ingesting Control-originated events.

use std::collections::HashMap;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use inferadb_control_core::service;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{EventFilter, EventOutcome, OrganizationSlug, SdkIngestEventEntry};
use serde::{Deserialize, Serialize};

use crate::{
    handlers::auth::{AppState, Result},
    middleware::UserClaims,
};

// ── Request / Response Types ────────────────────────────────────────

/// Query parameters for listing audit logs.
#[derive(Debug, Deserialize)]
pub struct ListAuditLogsQuery {
    /// Maximum entries per page (1..=1000, default 100).
    pub limit: Option<u32>,
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

/// Request body for creating an audit log entry (internal endpoint).
#[derive(Debug, Deserialize)]
pub struct CreateAuditLogRequest {
    /// Organization slug (external identifier).
    pub organization: u64,
    /// Hierarchical dot-separated event type (e.g., `"control.user.created"`).
    pub event_type: String,
    /// Who performed the action.
    pub principal: String,
    /// Outcome: `"success"`, `"failed"`, or `"denied"`.
    #[serde(default = "default_outcome")]
    pub outcome: String,
    /// Action-specific key-value context.
    #[serde(default)]
    pub details: HashMap<String, String>,
}

fn default_outcome() -> String {
    "success".to_string()
}

/// Response from creating an audit log entry.
#[derive(Debug, Serialize)]
pub struct CreateAuditLogResponse {
    pub accepted_count: u32,
    pub rejected_count: u32,
}

// ── Helpers ─────────────────────────────────────────────────────────

fn require_ledger(
    state: &AppState,
) -> std::result::Result<&inferadb_ledger_sdk::LedgerClient, CoreError> {
    state.ledger.as_deref().ok_or_else(|| CoreError::internal("Ledger client not configured"))
}

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

fn parse_request_outcome(
    outcome: &str,
    details: &HashMap<String, String>,
) -> std::result::Result<EventOutcome, CoreError> {
    match outcome {
        "success" => Ok(EventOutcome::Success),
        "failed" => Ok(EventOutcome::Failed {
            code: details.get("error_code").cloned().unwrap_or_default(),
            detail: details.get("error_detail").cloned().unwrap_or_default(),
        }),
        "denied" => Ok(EventOutcome::Denied {
            reason: details.get("denial_reason").cloned().unwrap_or_default(),
        }),
        _ => Err(CoreError::validation(format!(
            "invalid outcome '{outcome}': expected 'success', 'failed', or 'denied'"
        ))),
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// List audit logs for an organization.
///
/// GET /control/v1/organizations/{org}/audit-logs
pub async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Query(query): Query<ListAuditLogsQuery>,
) -> Result<Json<ListAuditLogsResponse>> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(org);

    let page = if let Some(ref page_token) = query.page_token {
        service::audit::list_events_next(ledger, organization, page_token).await?
    } else {
        let filter = build_event_filter(&query)?;
        let limit = query.limit.unwrap_or(100).clamp(1, 1000);
        service::audit::list_events(ledger, organization, filter, limit).await?
    };

    let entries = page.entries.into_iter().map(sdk_entry_to_response).collect();

    Ok(Json(ListAuditLogsResponse {
        entries,
        next_page_token: page.next_page_token,
        total_estimate: page.total_estimate,
    }))
}

/// Record an audit log event (internal endpoint).
///
/// POST /internal/audit
pub async fn create_audit_log(
    State(state): State<AppState>,
    Json(req): Json<CreateAuditLogRequest>,
) -> Result<(StatusCode, Json<CreateAuditLogResponse>)> {
    let ledger = require_ledger(&state)?;
    let organization = OrganizationSlug::new(req.organization);
    let outcome = parse_request_outcome(&req.outcome, &req.details)?;

    let event =
        SdkIngestEventEntry::new(&req.event_type, &req.principal, outcome).details(req.details);

    let result = service::audit::ingest_events(ledger, organization, vec![event]).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateAuditLogResponse {
            accepted_count: result.accepted_count,
            rejected_count: result.rejected_count,
        }),
    ))
}
