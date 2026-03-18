//! Audit log handlers (stub).
//!
//! Audit logs are managed by Ledger's event system (`list_events`).
//! These handlers return 500 until the event API integration is finalized.

use axum::{
    Extension, Json,
    extract::{Path, State},
};
use inferadb_control_types::Error as CoreError;
use serde::Serialize;

use crate::{
    handlers::auth::{AppState, Result},
    middleware::UserClaims,
};

/// Stub message response for unimplemented endpoints.
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

/// List audit logs for an organization.
///
/// GET /control/v1/organizations/{org}/audit-logs
pub async fn list_audit_logs(
    State(_state): State<AppState>,
    Extension(_claims): Extension<UserClaims>,
    Path(_org): Path<u64>,
) -> Result<Json<MessageResponse>> {
    Err(CoreError::internal(
        "audit log listing is not yet implemented; pending Ledger event API integration",
    )
    .into())
}

/// Record an audit log event (internal endpoint).
///
/// POST /internal/audit
pub async fn create_audit_log(State(_state): State<AppState>) -> Result<Json<MessageResponse>> {
    Err(CoreError::internal(
        "audit log creation is not yet implemented; pending Ledger event API integration",
    )
    .into())
}
