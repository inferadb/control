use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Organization team entity for grouping users
///
/// Teams allow delegated permission management within an organization.
/// Team members can be granted specific permissions, and teams can be granted vault access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationTeam {
    pub id: i64,
    pub organization_id: i64,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Organization team member entity
///
/// Represents a user's membership in a team. Team managers have permission
/// to manage the team (add/remove members, update team settings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationTeamMember {
    pub id: i64,
    pub team_id: i64,
    pub user_id: i64,
    /// Whether this member is a manager of the team
    pub manager: bool,
    pub created_at: DateTime<Utc>,
}

/// Organization permissions that can be delegated to teams
///
/// Permissions allow teams to perform actions within an organization without
/// requiring OWNER or ADMIN roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrganizationPermission {
    // Client management permissions
    /// Create new clients
    OrgPermClientCreate,
    /// Read client information
    OrgPermClientRead,
    /// Revoke client certificates
    OrgPermClientRevoke,
    /// Delete clients
    OrgPermClientDelete,
    /// All client permissions (composite)
    OrgPermClientManage,

    // Vault management permissions
    /// Create new vaults
    OrgPermVaultCreate,
    /// Delete vaults (requires VAULT_ROLE_ADMIN on the vault)
    OrgPermVaultDelete,

    // Team management permissions
    /// Create new teams
    OrgPermTeamCreate,
    /// Delete teams
    OrgPermTeamDelete,
    /// Manage team members (add/remove)
    OrgPermTeamManageMembers,

    // Invitation permissions
    /// Send organization invitations
    OrgPermInviteUsers,
    /// Revoke organization invitations
    OrgPermRevokeInvitations,

    // High-privilege permissions
    /// Owner-level actions (transfer ownership, delete org)
    OrgPermOwnerActions,
}

impl OrganizationPermission {
    /// Check if a permission grants another permission
    ///
    /// Used for composite permissions like ORG_PERM_CLIENT_MANAGE
    pub fn grants(&self, permission: OrganizationPermission) -> bool {
        if self == &permission {
            return true;
        }

        match self {
            OrganizationPermission::OrgPermClientManage => matches!(
                permission,
                OrganizationPermission::OrgPermClientCreate
                    | OrganizationPermission::OrgPermClientRead
                    | OrganizationPermission::OrgPermClientRevoke
                    | OrganizationPermission::OrgPermClientDelete
            ),
            _ => false,
        }
    }

    /// Get all permissions granted by this permission (including itself)
    pub fn expanded(&self) -> Vec<OrganizationPermission> {
        let mut perms = vec![*self];

        if self == &OrganizationPermission::OrgPermClientManage {
            perms.extend_from_slice(&[
                OrganizationPermission::OrgPermClientCreate,
                OrganizationPermission::OrgPermClientRead,
                OrganizationPermission::OrgPermClientRevoke,
                OrganizationPermission::OrgPermClientDelete,
            ]);
        }

        perms
    }
}

/// Team permission grant
///
/// Grants a specific organization permission to all members of a team.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationTeamPermission {
    pub id: i64,
    pub team_id: i64,
    pub permission: OrganizationPermission,
    pub granted_by_user_id: i64,
    pub granted_at: DateTime<Utc>,
}

impl OrganizationTeam {
    /// Create a new organization team
    pub fn new(id: i64, organization_id: i64, name: String) -> Result<Self> {
        Self::validate_name(&name)?;

        Ok(Self {
            id,
            organization_id,
            name: name.trim().to_string(),
            created_at: Utc::now(),
            deleted_at: None,
        })
    }

    /// Validate team name
    pub fn validate_name(name: &str) -> Result<()> {
        let trimmed = name.trim();

        if trimmed.is_empty() {
            return Err(Error::Validation("Team name cannot be empty".to_string()));
        }

        if trimmed.len() > 100 {
            return Err(Error::Validation(
                "Team name must be 100 characters or less".to_string(),
            ));
        }

        // Must be alphanumeric, hyphens, underscores, spaces
        if !trimmed
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ')
        {
            return Err(Error::Validation(
                "Team name must contain only alphanumeric characters, hyphens, underscores, and spaces".to_string(),
            ));
        }

        Ok(())
    }

    /// Update the team name
    pub fn set_name(&mut self, name: String) -> Result<()> {
        Self::validate_name(&name)?;
        self.name = name.trim().to_string();
        Ok(())
    }

    /// Check if the team is deleted
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Soft-delete the team
    pub fn mark_deleted(&mut self) {
        self.deleted_at = Some(Utc::now());
    }
}

impl OrganizationTeamMember {
    /// Create a new team member
    pub fn new(id: i64, team_id: i64, user_id: i64, manager: bool) -> Self {
        Self {
            id,
            team_id,
            user_id,
            manager,
            created_at: Utc::now(),
        }
    }

    /// Set the manager flag
    pub fn set_manager(&mut self, manager: bool) {
        self.manager = manager;
    }
}

impl OrganizationTeamPermission {
    /// Create a new team permission grant
    pub fn new(
        id: i64,
        team_id: i64,
        permission: OrganizationPermission,
        granted_by_user_id: i64,
    ) -> Self {
        Self {
            id,
            team_id,
            permission,
            granted_by_user_id,
            granted_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_team() {
        let team = OrganizationTeam::new(1, 100, "Engineering Team".to_string()).unwrap();
        assert_eq!(team.id, 1);
        assert_eq!(team.organization_id, 100);
        assert_eq!(team.name, "Engineering Team");
        assert!(!team.is_deleted());
    }

    #[test]
    fn test_validate_team_name() {
        assert!(OrganizationTeam::validate_name("Valid Team").is_ok());
        assert!(OrganizationTeam::validate_name("team-name_123").is_ok());
        assert!(OrganizationTeam::validate_name("").is_err());
        assert!(OrganizationTeam::validate_name("   ").is_err());
        assert!(OrganizationTeam::validate_name(&"a".repeat(101)).is_err());
        assert!(OrganizationTeam::validate_name("invalid@team").is_err());
    }

    #[test]
    fn test_set_team_name() {
        let mut team = OrganizationTeam::new(1, 100, "Old Name".to_string()).unwrap();

        team.set_name("New Name".to_string()).unwrap();
        assert_eq!(team.name, "New Name");

        assert!(team.set_name("".to_string()).is_err());
        assert!(team.set_name("a".repeat(101)).is_err());
    }

    #[test]
    fn test_team_soft_delete() {
        let mut team = OrganizationTeam::new(1, 100, "Test Team".to_string()).unwrap();

        assert!(!team.is_deleted());
        team.mark_deleted();
        assert!(team.is_deleted());
    }

    #[test]
    fn test_create_team_member() {
        let member = OrganizationTeamMember::new(1, 100, 200, false);
        assert_eq!(member.id, 1);
        assert_eq!(member.team_id, 100);
        assert_eq!(member.user_id, 200);
        assert!(!member.manager);
    }

    #[test]
    fn test_create_team_manager() {
        let member = OrganizationTeamMember::new(1, 100, 200, true);
        assert_eq!(member.id, 1);
        assert_eq!(member.team_id, 100);
        assert_eq!(member.user_id, 200);
        assert!(member.manager);
    }

    #[test]
    fn test_set_manager_flag() {
        let mut member = OrganizationTeamMember::new(1, 100, 200, false);
        assert!(!member.manager);

        member.set_manager(true);
        assert!(member.manager);

        member.set_manager(false);
        assert!(!member.manager);
    }

    #[test]
    fn test_create_team_permission() {
        let permission = OrganizationTeamPermission::new(
            1,
            100,
            OrganizationPermission::OrgPermClientCreate,
            999,
        );
        assert_eq!(permission.id, 1);
        assert_eq!(permission.team_id, 100);
        assert_eq!(
            permission.permission,
            OrganizationPermission::OrgPermClientCreate
        );
        assert_eq!(permission.granted_by_user_id, 999);
    }

    #[test]
    fn test_permission_grants() {
        // Self-granting
        assert!(OrganizationPermission::OrgPermClientCreate
            .grants(OrganizationPermission::OrgPermClientCreate));

        // Composite permission granting
        assert!(OrganizationPermission::OrgPermClientManage
            .grants(OrganizationPermission::OrgPermClientCreate));
        assert!(OrganizationPermission::OrgPermClientManage
            .grants(OrganizationPermission::OrgPermClientRead));
        assert!(OrganizationPermission::OrgPermClientManage
            .grants(OrganizationPermission::OrgPermClientRevoke));
        assert!(OrganizationPermission::OrgPermClientManage
            .grants(OrganizationPermission::OrgPermClientDelete));

        // Non-granting
        assert!(!OrganizationPermission::OrgPermClientCreate
            .grants(OrganizationPermission::OrgPermClientDelete));
        assert!(!OrganizationPermission::OrgPermClientManage
            .grants(OrganizationPermission::OrgPermVaultCreate));
    }

    #[test]
    fn test_permission_expanded() {
        let client_create = OrganizationPermission::OrgPermClientCreate.expanded();
        assert_eq!(client_create.len(), 1);
        assert!(client_create.contains(&OrganizationPermission::OrgPermClientCreate));

        let client_manage = OrganizationPermission::OrgPermClientManage.expanded();
        assert_eq!(client_manage.len(), 5);
        assert!(client_manage.contains(&OrganizationPermission::OrgPermClientManage));
        assert!(client_manage.contains(&OrganizationPermission::OrgPermClientCreate));
        assert!(client_manage.contains(&OrganizationPermission::OrgPermClientRead));
        assert!(client_manage.contains(&OrganizationPermission::OrgPermClientRevoke));
        assert!(client_manage.contains(&OrganizationPermission::OrgPermClientDelete));
    }
}
