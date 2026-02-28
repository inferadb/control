use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    OrganizationSlug,
    entities::{AuditEventType, AuditResourceType},
};

/// Internal endpoint for recording audit log events
#[derive(Debug, Deserialize)]
pub struct CreateAuditLogRequest {
    pub event_type: AuditEventType,
    pub organization: Option<OrganizationSlug>,
    pub user_id: Option<u64>,
    pub client_id: Option<u64>,
    pub resource_type: Option<AuditResourceType>,
    pub resource_id: Option<u64>,
    pub event_data: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateAuditLogResponse {
    pub success: bool,
}

/// Query parameters for listing audit logs
#[derive(Debug, Deserialize)]
pub struct ListAuditLogsQuery {
    /// Filter by actor (user_id)
    pub actor: Option<u64>,
    /// Filter by event type
    pub action: Option<AuditEventType>,
    /// Filter by resource type
    pub resource_type: Option<AuditResourceType>,
    /// Filter by start date (ISO 8601)
    pub start_date: Option<DateTime<Utc>>,
    /// Filter by end date (ISO 8601)
    pub end_date: Option<DateTime<Utc>>,
    /// Pagination limit (default: 50, max: 100)
    pub limit: Option<u64>,
    /// Pagination offset (default: 0)
    pub offset: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogInfo {
    pub id: u64,
    pub organization: Option<OrganizationSlug>,
    pub user_id: Option<u64>,
    pub client_id: Option<u64>,
    pub event_type: AuditEventType,
    pub resource_type: Option<AuditResourceType>,
    pub resource_id: Option<u64>,
    pub event_data: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ListAuditLogsResponse {
    pub audit_logs: Vec<AuditLogInfo>,
    pub total: usize,
    pub limit: u64,
    pub offset: u64,
}
