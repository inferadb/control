use bon::Builder;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{
    error::{Error, Result},
    id::IdGenerator,
};

/// Audit event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Authentication events
    UserLogin,
    UserLogout,
    UserSessionRevoked,
    UserSessionExpired,

    // Passkey events
    PasskeyAdded,
    PasskeyRemoved,

    // Password events
    PasswordChanged,
    PasswordResetRequested,
    PasswordResetCompleted,

    // User management
    UserRegistered,
    UserDeleted,
    UserEmailAdded,
    UserEmailVerified,
    UserEmailRemoved,

    // Organization management
    OrganizationCreated,
    OrganizationUpdated,
    OrganizationDeleted,
    OrganizationMemberAdded,
    OrganizationMemberRoleChanged,
    OrganizationMemberRemoved,
    OrganizationOwnershipTransferred,

    // Team management
    TeamCreated,
    TeamUpdated,
    TeamDeleted,
    TeamMemberAdded,
    TeamMemberRoleChanged,
    TeamMemberRemoved,
    TeamPermissionGranted,
    TeamPermissionRevoked,

    // Vault management
    VaultCreated,
    VaultUpdated,
    VaultDeleted,
    VaultAccessGranted,
    VaultAccessRevoked,
    VaultAccessUpdated,
    VaultTeamAccessGranted,
    VaultTeamAccessRevoked,
    VaultTeamAccessUpdated,

    // Client management
    ClientCreated,
    ClientUpdated,
    ClientDeleted,
    ClientCertificateCreated,
    ClientCertificateRotated,
    ClientCertificateRevoked,
    ClientCertificateDeleted,

    // Token events
    VaultTokenGenerated,
    VaultTokenRefreshed,
    RefreshTokenRevoked,

    // Security events
    RefreshTokenReused,
    InvalidJwt,
    RateLimitExceeded,
    ClockSkewDetected,
    WorkerIdCollision,
}

/// Resource type for audit log events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResourceType {
    User,
    Organization,
    OrganizationMember,
    Team,
    TeamMember,
    Vault,
    VaultGrant,
    Client,
    ClientCertificate,
    Session,
    RefreshToken,
    Passkey,
    Email,
}

/// Audit log entry
///
/// Records security-relevant events for compliance and debugging.
/// Audit logs are write-only and cannot be modified or deleted by users.
///
/// # Storage
///
/// Audit logs are stored with the following indexes:
/// - `organization_id` + `created_at` (for organization-scoped queries)
/// - `user_id` + `created_at` (for user activity tracking)
/// - `event_type` + `created_at` (for event type filtering)
///
/// # Retention
///
/// - Free tier: 90 days
/// - Paid tier: 1 year
#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
#[builder(on(String, into))]
pub struct AuditLog {
    /// Unique identifier
    #[builder(default = IdGenerator::next_id())]
    pub id: i64,

    /// Organization ID (if applicable)
    pub organization_id: Option<i64>,

    /// User ID who performed the action (if applicable)
    pub user_id: Option<i64>,

    /// Client ID that performed the action (if applicable)
    pub client_id: Option<i64>,

    /// Type of event
    pub event_type: AuditEventType,

    /// Type of resource affected
    pub resource_type: Option<AuditResourceType>,

    /// ID of the resource affected
    pub resource_id: Option<i64>,

    /// Additional event data (JSON)
    pub event_data: Option<JsonValue>,

    /// IP address of the request
    pub ip_address: Option<String>,

    /// User agent string
    pub user_agent: Option<String>,

    /// Timestamp when the event occurred
    #[builder(default = Utc::now())]
    pub created_at: DateTime<Utc>,
}

impl AuditLog {
    /// Validate the audit log entry
    pub fn validate(&self) -> Result<()> {
        // At least one of organization_id, user_id, or client_id must be set
        if self.organization_id.is_none() && self.user_id.is_none() && self.client_id.is_none() {
            return Err(Error::Validation(
                "At least one of organization_id, user_id, or client_id must be set".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_create_audit_log() {
        let log = AuditLog::builder()
            .event_type(AuditEventType::UserLogin)
            .organization_id(1)
            .user_id(100)
            .build();

        assert_eq!(log.event_type, AuditEventType::UserLogin);
        assert_eq!(log.organization_id, Some(1));
        assert_eq!(log.user_id, Some(100));
        assert!(log.validate().is_ok());
    }

    #[test]
    fn test_audit_log_with_resource() {
        let log = AuditLog::builder()
            .event_type(AuditEventType::VaultCreated)
            .organization_id(1)
            .user_id(100)
            .resource_type(AuditResourceType::Vault)
            .resource_id(500)
            .build();

        assert_eq!(log.resource_type, Some(AuditResourceType::Vault));
        assert_eq!(log.resource_id, Some(500));
    }

    #[test]
    fn test_audit_log_with_data() {
        let log = AuditLog::builder()
            .event_type(AuditEventType::OrganizationMemberRoleChanged)
            .organization_id(1)
            .user_id(100)
            .event_data(json!({
                "old_role": "member",
                "new_role": "admin"
            }))
            .build();

        assert!(log.event_data.is_some());
    }

    #[test]
    fn test_audit_log_with_ip_and_user_agent() {
        let log = AuditLog::builder()
            .event_type(AuditEventType::UserLogin)
            .organization_id(1)
            .user_id(100)
            .ip_address("192.168.1.1")
            .user_agent("Mozilla/5.0")
            .build();

        assert_eq!(log.ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(log.user_agent, Some("Mozilla/5.0".to_string()));
    }

    #[test]
    fn test_audit_log_validation() {
        let log = AuditLog::builder().event_type(AuditEventType::UserLogin).build();

        assert!(log.validate().is_err());
    }
}
