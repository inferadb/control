use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Vault entity for managing authorization policies
///
/// Vaults are synchronized with the @server API and contain authorization policies.
/// Each vault belongs to an organization and can have user/team access grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub id: i64,
    pub organization_id: i64,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub sync_status: VaultSyncStatus,
    pub sync_error: Option<String>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Vault synchronization status with @server
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VaultSyncStatus {
    /// Vault creation pending on @server
    Pending,
    /// Vault successfully synchronized with @server
    Synced,
    /// Vault synchronization failed
    Failed,
}

/// Role for vault access grants
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VaultRole {
    /// Can read vault data
    Reader,
    /// Can read and write vault data
    Writer,
    /// Can read, write, and manage grants
    Manager,
    /// Can do everything including vault deletion
    Admin,
}

impl VaultRole {
    /// Check if this role has at least the required role level
    pub fn has_permission(&self, required: VaultRole) -> bool {
        self >= &required
    }
}

/// User access grant for a vault
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultUserGrant {
    pub id: i64,
    pub vault_id: i64,
    pub user_id: i64,
    pub role: VaultRole,
    pub granted_at: DateTime<Utc>,
    pub granted_by_user_id: i64,
}

/// Team access grant for a vault
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultTeamGrant {
    pub id: i64,
    pub vault_id: i64,
    pub team_id: i64,
    pub role: VaultRole,
    pub granted_at: DateTime<Utc>,
    pub granted_by_user_id: i64,
}

impl Vault {
    /// Create a new vault
    pub fn new(
        id: i64,
        organization_id: i64,
        name: String,
        _created_by_user_id: i64,
    ) -> Result<Self> {
        Self::validate_name(&name)?;

        Ok(Self {
            id,
            organization_id,
            name,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            sync_status: VaultSyncStatus::Pending,
            sync_error: None,
            deleted_at: None,
        })
    }

    /// Validate vault name
    pub fn validate_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(Error::Validation("Vault name cannot be empty".to_string()));
        }

        if name.len() > 100 {
            return Err(Error::Validation("Vault name cannot exceed 100 characters".to_string()));
        }

        // Must be alphanumeric, hyphens, underscores, spaces
        if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ') {
            return Err(Error::Validation(
                "Vault name must contain only alphanumeric characters, hyphens, underscores, and spaces".to_string(),
            ));
        }

        Ok(())
    }

    /// Mark vault as synced with @server
    pub fn mark_synced(&mut self) {
        self.sync_status = VaultSyncStatus::Synced;
        self.sync_error = None;
        self.updated_at = Utc::now();
    }

    /// Mark vault sync as failed
    pub fn mark_sync_failed(&mut self, error: String) {
        self.sync_status = VaultSyncStatus::Failed;
        self.sync_error = Some(error);
        self.updated_at = Utc::now();
    }

    /// Mark vault as deleted (soft delete)
    pub fn mark_deleted(&mut self) {
        self.deleted_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Check if vault is deleted
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Check if vault is active (synced and not deleted)
    pub fn is_active(&self) -> bool {
        self.sync_status == VaultSyncStatus::Synced && !self.is_deleted()
    }
}

impl VaultUserGrant {
    /// Create a new user grant
    pub fn new(
        id: i64,
        vault_id: i64,
        user_id: i64,
        role: VaultRole,
        granted_by_user_id: i64,
    ) -> Self {
        Self { id, vault_id, user_id, role, granted_at: Utc::now(), granted_by_user_id }
    }
}

impl VaultTeamGrant {
    /// Create a new team grant
    pub fn new(
        id: i64,
        vault_id: i64,
        team_id: i64,
        role: VaultRole,
        granted_by_user_id: i64,
    ) -> Self {
        Self { id, vault_id, team_id, role, granted_at: Utc::now(), granted_by_user_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_vault() {
        let vault = Vault::new(1, 100, "Test Vault".to_string(), 999).unwrap();
        assert_eq!(vault.id, 1);
        assert_eq!(vault.organization_id, 100);
        assert_eq!(vault.name, "Test Vault");
        assert_eq!(vault.sync_status, VaultSyncStatus::Pending);
        assert!(vault.sync_error.is_none());
        assert!(vault.deleted_at.is_none());
    }

    #[test]
    fn test_validate_name() {
        assert!(Vault::validate_name("Valid Name").is_ok());
        assert!(Vault::validate_name("valid-name_123").is_ok());
        assert!(Vault::validate_name("").is_err());
        assert!(Vault::validate_name(&"a".repeat(101)).is_err());
        assert!(Vault::validate_name("invalid@name").is_err());
    }

    #[test]
    fn test_mark_synced() {
        let mut vault = Vault::new(1, 100, "Test".to_string(), 999).unwrap();
        vault.mark_synced();
        assert_eq!(vault.sync_status, VaultSyncStatus::Synced);
        assert!(vault.sync_error.is_none());
    }

    #[test]
    fn test_mark_sync_failed() {
        let mut vault = Vault::new(1, 100, "Test".to_string(), 999).unwrap();
        vault.mark_sync_failed("Connection error".to_string());
        assert_eq!(vault.sync_status, VaultSyncStatus::Failed);
        assert_eq!(vault.sync_error, Some("Connection error".to_string()));
    }

    #[test]
    fn test_mark_deleted() {
        let mut vault = Vault::new(1, 100, "Test".to_string(), 999).unwrap();
        assert!(!vault.is_deleted());
        vault.mark_deleted();
        assert!(vault.is_deleted());
    }

    #[test]
    fn test_vault_role_ordering() {
        assert!(VaultRole::Admin > VaultRole::Manager);
        assert!(VaultRole::Manager > VaultRole::Writer);
        assert!(VaultRole::Writer > VaultRole::Reader);
    }

    #[test]
    fn test_vault_role_has_permission() {
        assert!(VaultRole::Admin.has_permission(VaultRole::Reader));
        assert!(VaultRole::Manager.has_permission(VaultRole::Writer));
        assert!(!VaultRole::Reader.has_permission(VaultRole::Admin));
    }

    #[test]
    fn test_create_user_grant() {
        let grant = VaultUserGrant::new(1, 100, 200, VaultRole::Reader, 999);
        assert_eq!(grant.id, 1);
        assert_eq!(grant.vault_id, 100);
        assert_eq!(grant.user_id, 200);
        assert_eq!(grant.role, VaultRole::Reader);
        assert_eq!(grant.granted_by_user_id, 999);
    }

    #[test]
    fn test_create_team_grant() {
        let grant = VaultTeamGrant::new(1, 100, 300, VaultRole::Writer, 999);
        assert_eq!(grant.id, 1);
        assert_eq!(grant.vault_id, 100);
        assert_eq!(grant.team_id, 300);
        assert_eq!(grant.role, VaultRole::Writer);
        assert_eq!(grant.granted_by_user_id, 999);
    }
}
