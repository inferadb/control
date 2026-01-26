use inferadb_control_core::{
    entities::{AuditEventType, AuditLog, AuditResourceType},
    repository::AuditLogRepository,
};
use serde_json::Value as JsonValue;

use crate::handlers::AppState;

/// Parameters for creating an audit log entry
#[derive(Debug, Default)]
pub struct AuditEventParams {
    pub organization_id: Option<i64>,
    pub user_id: Option<i64>,
    pub client_id: Option<i64>,
    pub resource_type: Option<AuditResourceType>,
    pub resource_id: Option<i64>,
    pub event_data: Option<JsonValue>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Helper to create and log an audit event
///
/// This is a fire-and-forget operation - errors are logged but don't fail the request
pub async fn log_audit_event(
    state: &AppState,
    event_type: AuditEventType,
    params: AuditEventParams,
) {
    let audit_log = AuditLog::builder()
        .event_type(event_type)
        .maybe_organization_id(params.organization_id)
        .maybe_user_id(params.user_id)
        .maybe_client_id(params.client_id)
        .maybe_resource_type(params.resource_type)
        .maybe_resource_id(params.resource_id)
        .maybe_event_data(params.event_data)
        .maybe_ip_address(params.ip_address)
        .maybe_user_agent(params.user_agent)
        .build();

    let repo = AuditLogRepository::new((*state.storage).clone());

    if let Err(e) = repo.create(audit_log).await {
        // Log the error but don't fail the request
        tracing::error!(
            error = %e,
            event_type = ?event_type,
            "Failed to create audit log"
        );
    }
}

/// Extract IP address from request headers
pub fn extract_ip_address(headers: &axum::http::HeaderMap) -> Option<String> {
    // Check X-Forwarded-For first (common in proxied environments)
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            // Fallback to X-Real-IP
            headers.get("x-real-ip").and_then(|v| v.to_str().ok()).map(|s| s.to_string())
        })
}

/// Extract user agent from request headers
pub fn extract_user_agent(headers: &axum::http::HeaderMap) -> Option<String> {
    headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}
