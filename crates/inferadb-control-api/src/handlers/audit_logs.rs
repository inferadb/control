use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use inferadb_control_core::{AuditLogFilters, RepositoryContext};
use inferadb_control_types::{
    dto::{
        AuditLogInfo, CreateAuditLogRequest, CreateAuditLogResponse, ListAuditLogsQuery,
        ListAuditLogsResponse,
    },
    entities::AuditLog,
};

use super::AppState;
use crate::middleware::{OrganizationContext, require_owner};

/// Internal endpoint for recording audit log events
///
/// POST /internal/audit
///
/// This is an internal endpoint used by other handlers to record audit events.
/// It's not exposed in the public API routes.
pub async fn create_audit_log(
    State(state): State<AppState>,
    Json(payload): Json<CreateAuditLogRequest>,
) -> Response {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Build audit log entry
    let log = AuditLog::builder()
        .event_type(payload.event_type)
        .maybe_organization_id(payload.organization_id)
        .maybe_user_id(payload.user_id)
        .maybe_client_id(payload.client_id)
        .maybe_resource_type(payload.resource_type)
        .maybe_resource_id(payload.resource_id)
        .maybe_event_data(payload.event_data)
        .maybe_ip_address(payload.ip_address)
        .maybe_user_agent(payload.user_agent)
        .build();

    match repos.audit_log.create(log).await {
        Ok(_) => {
            (StatusCode::CREATED, Json(CreateAuditLogResponse { success: true })).into_response()
        },
        Err(e) => {
            tracing::error!("Failed to create audit log: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to create audit log"
                })),
            )
                .into_response()
        },
    }
}

/// List audit logs for an organization
///
/// GET /v1/organizations/:org/audit-logs
///
/// Only OWNER role members can access audit logs.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Query(params): Query<ListAuditLogsQuery>,
) -> Response {
    // Require owner role
    if require_owner(&org_ctx).is_err() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Only organization owners can access audit logs"
            })),
        )
            .into_response();
    }

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    // Build filters
    let filters = AuditLogFilters {
        actor: params.actor,
        action: params.action,
        resource_type: params.resource_type,
        start_date: params.start_date,
        end_date: params.end_date,
    };

    // Query audit logs
    let repos = RepositoryContext::new((*state.storage).clone());
    match repos
        .audit_log
        .list_by_organization(org_ctx.organization_id, filters, limit, offset)
        .await
    {
        Ok((logs, total)) => {
            let audit_logs: Vec<AuditLogInfo> = logs
                .into_iter()
                .map(|log| AuditLogInfo {
                    id: log.id,
                    organization_id: log.organization_id,
                    user_id: log.user_id,
                    client_id: log.client_id,
                    event_type: log.event_type,
                    resource_type: log.resource_type,
                    resource_id: log.resource_id,
                    event_data: log.event_data,
                    ip_address: log.ip_address,
                    user_agent: log.user_agent,
                    created_at: log.created_at.to_rfc3339(),
                })
                .collect();

            (StatusCode::OK, Json(ListAuditLogsResponse { audit_logs, total, limit, offset }))
                .into_response()
        },
        Err(e) => {
            tracing::error!("Failed to list audit logs: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to list audit logs"
                })),
            )
                .into_response()
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use inferadb_control_core::AuditEventType;
    use inferadb_control_storage::Backend;

    use super::*;

    #[tokio::test]
    async fn test_create_audit_log() {
        let storage = Arc::new(Backend::memory());
        let state = AppState::new_test(storage);

        let payload = CreateAuditLogRequest {
            event_type: AuditEventType::UserLogin,
            organization_id: Some(1),
            user_id: Some(100),
            client_id: None,
            resource_type: None,
            resource_id: None,
            event_data: None,
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
        };

        let response = create_audit_log(State(state), Json(payload)).await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }
}
