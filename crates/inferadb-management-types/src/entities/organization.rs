use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Organization tier enum defining resource limits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationTier {
    /// Development tier - limited resources for testing
    #[serde(rename = "TIER_DEV_V1")]
    TierDevV1,
    /// Professional tier - standard resource limits
    #[serde(rename = "TIER_PRO_V1")]
    TierProV1,
    /// Maximum tier - highest resource limits
    #[serde(rename = "TIER_MAX_V1")]
    TierMaxV1,
}

impl OrganizationTier {
    /// Get the maximum number of members allowed for this tier
    pub fn max_members(&self) -> usize {
        match self {
            OrganizationTier::TierDevV1 => 5,
            OrganizationTier::TierProV1 => 50,
            OrganizationTier::TierMaxV1 => 500,
        }
    }

    /// Get the maximum number of teams allowed for this tier
    pub fn max_teams(&self) -> usize {
        match self {
            OrganizationTier::TierDevV1 => 3,
            OrganizationTier::TierProV1 => 25,
            OrganizationTier::TierMaxV1 => 100,
        }
    }

    /// Get the maximum number of vaults allowed for this tier
    pub fn max_vaults(&self) -> usize {
        match self {
            OrganizationTier::TierDevV1 => 5,
            OrganizationTier::TierProV1 => 50,
            OrganizationTier::TierMaxV1 => 500,
        }
    }
}

/// Represents an organization (tenant) in the system
///
/// Organizations are the primary grouping mechanism for users, vaults, and other resources.
/// Each organization has a tier that determines resource limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Organization {
    /// Unique identifier for the organization
    pub id: i64,
    /// Organization name (must be unique globally)
    pub name: String,
    /// Organization tier determining resource limits
    pub tier: OrganizationTier,
    /// When the organization was created
    pub created_at: DateTime<Utc>,
    /// When the organization was soft-deleted (if applicable)
    pub deleted_at: Option<DateTime<Utc>>,
    /// When the organization was suspended (if applicable)
    pub suspended_at: Option<DateTime<Utc>>,
}

impl Organization {
    /// Create a new organization
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for the organization
    /// * `name` - Organization name (will be validated and trimmed)
    /// * `tier` - Organization tier
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails
    pub fn new(id: i64, name: String, tier: OrganizationTier) -> Result<Self> {
        Self::validate_name(&name)?;

        Ok(Self {
            id,
            name: name.trim().to_string(),
            tier,
            created_at: Utc::now(),
            deleted_at: None,
            suspended_at: None,
        })
    }

    /// Validate organization name
    ///
    /// # Errors
    ///
    /// Returns an error if the name is invalid
    pub fn validate_name(name: &str) -> Result<()> {
        let trimmed = name.trim();

        if trimmed.is_empty() {
            return Err(Error::Validation("Organization name cannot be empty".to_string()));
        }

        if trimmed.len() > 100 {
            return Err(Error::Validation(
                "Organization name must be 100 characters or less".to_string(),
            ));
        }

        Ok(())
    }

    /// Update the organization name
    ///
    /// # Errors
    ///
    /// Returns an error if the new name is invalid
    pub fn set_name(&mut self, name: String) -> Result<()> {
        Self::validate_name(&name)?;
        self.name = name.trim().to_string();
        Ok(())
    }

    /// Update the organization tier
    pub fn set_tier(&mut self, tier: OrganizationTier) {
        self.tier = tier;
    }

    /// Check if the organization is deleted
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Soft-delete the organization
    pub fn soft_delete(&mut self) {
        self.deleted_at = Some(Utc::now());
    }

    /// Check if the organization is suspended
    pub fn is_suspended(&self) -> bool {
        self.suspended_at.is_some() && self.deleted_at.is_none()
    }

    /// Suspend the organization
    pub fn suspend(&mut self) {
        self.suspended_at = Some(Utc::now());
    }

    /// Resume the organization (unsuspend)
    pub fn resume(&mut self) {
        self.suspended_at = None;
    }
}

/// Organization role enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationRole {
    /// Regular member with no special permissions
    #[serde(rename = "MEMBER")]
    Member,
    /// Administrator with elevated permissions
    #[serde(rename = "ADMIN")]
    Admin,
    /// Owner with full control over the organization
    #[serde(rename = "OWNER")]
    Owner,
}

impl OrganizationRole {
    /// Check if this role has at least the specified level
    pub fn has_permission(&self, required: OrganizationRole) -> bool {
        match required {
            OrganizationRole::Member => true,
            OrganizationRole::Admin => {
                matches!(self, OrganizationRole::Admin | OrganizationRole::Owner)
            },
            OrganizationRole::Owner => matches!(self, OrganizationRole::Owner),
        }
    }
}

/// Represents a user's membership in an organization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrganizationMember {
    /// Unique identifier for this membership
    pub id: i64,
    /// Organization ID
    pub organization_id: i64,
    /// User ID
    pub user_id: i64,
    /// Member's role in the organization
    pub role: OrganizationRole,
    /// When the membership was created
    pub created_at: DateTime<Utc>,
}

impl OrganizationMember {
    /// Create a new organization member
    pub fn new(id: i64, organization_id: i64, user_id: i64, role: OrganizationRole) -> Self {
        Self { id, organization_id, user_id, role, created_at: Utc::now() }
    }

    /// Update the member's role
    pub fn set_role(&mut self, role: OrganizationRole) {
        self.role = role;
    }

    /// Check if this member has at least the specified role
    pub fn has_permission(&self, required: OrganizationRole) -> bool {
        self.role.has_permission(required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_organization() {
        let org = Organization::new(1, "Test Org".to_string(), OrganizationTier::TierDevV1);
        assert!(org.is_ok());

        let org = org.unwrap();
        assert_eq!(org.id, 1);
        assert_eq!(org.name, "Test Org");
        assert_eq!(org.tier, OrganizationTier::TierDevV1);
        assert!(!org.is_deleted());
    }

    #[test]
    fn test_validate_name_empty() {
        let result = Organization::new(1, "".to_string(), OrganizationTier::TierDevV1);
        assert!(result.is_err());

        let result = Organization::new(1, "   ".to_string(), OrganizationTier::TierDevV1);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_name_too_long() {
        let long_name = "a".repeat(101);
        let result = Organization::new(1, long_name, OrganizationTier::TierDevV1);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_name() {
        let mut org =
            Organization::new(1, "Old Name".to_string(), OrganizationTier::TierDevV1).unwrap();

        org.set_name("New Name".to_string()).unwrap();
        assert_eq!(org.name, "New Name");

        assert!(org.set_name("".to_string()).is_err());
        assert!(org.set_name("a".repeat(101)).is_err());
    }

    #[test]
    fn test_soft_delete() {
        let mut org =
            Organization::new(1, "Test Org".to_string(), OrganizationTier::TierDevV1).unwrap();

        assert!(!org.is_deleted());
        org.soft_delete();
        assert!(org.is_deleted());
    }

    #[test]
    fn test_tier_limits() {
        assert_eq!(OrganizationTier::TierDevV1.max_members(), 5);
        assert_eq!(OrganizationTier::TierDevV1.max_teams(), 3);
        assert_eq!(OrganizationTier::TierDevV1.max_vaults(), 5);

        assert_eq!(OrganizationTier::TierProV1.max_members(), 50);
        assert_eq!(OrganizationTier::TierProV1.max_teams(), 25);
        assert_eq!(OrganizationTier::TierProV1.max_vaults(), 50);

        assert_eq!(OrganizationTier::TierMaxV1.max_members(), 500);
        assert_eq!(OrganizationTier::TierMaxV1.max_teams(), 100);
        assert_eq!(OrganizationTier::TierMaxV1.max_vaults(), 500);
    }

    #[test]
    fn test_create_organization_member() {
        let member = OrganizationMember::new(1, 100, 200, OrganizationRole::Member);
        assert_eq!(member.id, 1);
        assert_eq!(member.organization_id, 100);
        assert_eq!(member.user_id, 200);
        assert_eq!(member.role, OrganizationRole::Member);
    }

    #[test]
    fn test_role_permissions() {
        assert!(OrganizationRole::Owner.has_permission(OrganizationRole::Member));
        assert!(OrganizationRole::Owner.has_permission(OrganizationRole::Admin));
        assert!(OrganizationRole::Owner.has_permission(OrganizationRole::Owner));

        assert!(OrganizationRole::Admin.has_permission(OrganizationRole::Member));
        assert!(OrganizationRole::Admin.has_permission(OrganizationRole::Admin));
        assert!(!OrganizationRole::Admin.has_permission(OrganizationRole::Owner));

        assert!(OrganizationRole::Member.has_permission(OrganizationRole::Member));
        assert!(!OrganizationRole::Member.has_permission(OrganizationRole::Admin));
        assert!(!OrganizationRole::Member.has_permission(OrganizationRole::Owner));
    }

    #[test]
    fn test_member_set_role() {
        let mut member = OrganizationMember::new(1, 100, 200, OrganizationRole::Member);
        assert_eq!(member.role, OrganizationRole::Member);

        member.set_role(OrganizationRole::Admin);
        assert_eq!(member.role, OrganizationRole::Admin);

        member.set_role(OrganizationRole::Owner);
        assert_eq!(member.role, OrganizationRole::Owner);
    }

    #[test]
    fn test_member_has_permission() {
        let owner = OrganizationMember::new(1, 100, 200, OrganizationRole::Owner);
        assert!(owner.has_permission(OrganizationRole::Member));
        assert!(owner.has_permission(OrganizationRole::Admin));
        assert!(owner.has_permission(OrganizationRole::Owner));

        let admin = OrganizationMember::new(2, 100, 201, OrganizationRole::Admin);
        assert!(admin.has_permission(OrganizationRole::Member));
        assert!(admin.has_permission(OrganizationRole::Admin));
        assert!(!admin.has_permission(OrganizationRole::Owner));

        let member = OrganizationMember::new(3, 100, 202, OrganizationRole::Member);
        assert!(member.has_permission(OrganizationRole::Member));
        assert!(!member.has_permission(OrganizationRole::Admin));
        assert!(!member.has_permission(OrganizationRole::Owner));
    }

    #[test]
    fn test_suspend_organization() {
        let mut org =
            Organization::new(1, "Test Org".to_string(), OrganizationTier::TierDevV1).unwrap();

        assert!(!org.is_suspended());
        org.suspend();
        assert!(org.is_suspended());
        org.resume();
        assert!(!org.is_suspended());
    }

    #[test]
    fn test_suspended_not_deleted() {
        let mut org =
            Organization::new(1, "Test Org".to_string(), OrganizationTier::TierDevV1).unwrap();

        org.suspend();
        assert!(org.is_suspended());

        // Suspending shouldn't affect deleted state
        assert!(!org.is_deleted());

        // Deleting a suspended org should work
        org.soft_delete();
        assert!(org.is_deleted());
        // Deleted orgs are not considered suspended
        assert!(!org.is_suspended());
    }
}
