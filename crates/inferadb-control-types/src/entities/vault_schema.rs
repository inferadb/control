use std::{cmp::Ordering, fmt, str::FromStr};

use bon::bon;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Schema version using semantic versioning
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SchemaVersion {
    /// Create a new schema version
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// Create the initial version (1.0.0)
    pub fn initial() -> Self {
        Self::new(1, 0, 0)
    }

    /// Bump major version (resets minor and patch)
    pub fn bump_major(&self) -> Self {
        Self::new(self.major + 1, 0, 0)
    }

    /// Bump minor version (resets patch)
    pub fn bump_minor(&self) -> Self {
        Self::new(self.major, self.minor + 1, 0)
    }

    /// Bump patch version
    pub fn bump_patch(&self) -> Self {
        Self::new(self.major, self.minor, self.patch + 1)
    }
}

impl Default for SchemaVersion {
    fn default() -> Self {
        Self::initial()
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for SchemaVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::validation(
                "Schema version must be in format major.minor.patch (e.g., 1.0.0)".to_string(),
            ));
        }

        let major = parts[0]
            .parse::<u32>()
            .map_err(|_| Error::validation("Invalid major version number".to_string()))?;
        let minor = parts[1]
            .parse::<u32>()
            .map_err(|_| Error::validation("Invalid minor version number".to_string()))?;
        let patch = parts[2]
            .parse::<u32>()
            .map_err(|_| Error::validation("Invalid patch version number".to_string()))?;

        Ok(Self::new(major, minor, patch))
    }
}

impl PartialOrd for SchemaVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SchemaVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                other => other,
            },
            other => other,
        }
    }
}

/// Status of a schema version deployment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SchemaDeploymentStatus {
    /// Schema is being validated
    Validating,
    /// Schema is deployed but not active
    Deployed,
    /// Schema is the active version
    Active,
    /// Schema deployment failed
    Failed,
    /// Schema has been superseded by a newer version
    Superseded,
    /// Schema was rolled back
    RolledBack,
}

/// A deployed schema version for a vault
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSchema {
    /// Unique identifier for this schema version
    pub id: i64,
    /// Vault this schema belongs to
    pub vault_id: i64,
    /// Semantic version of this schema
    pub version: SchemaVersion,
    /// The IPL schema definition
    pub definition: String,
    /// User who deployed this schema
    pub author_user_id: i64,
    /// Description of changes in this version
    pub description: String,
    /// Parent version this was based on (None for initial version)
    pub parent_version_id: Option<i64>,
    /// Deployment status
    pub status: SchemaDeploymentStatus,
    /// Error message if deployment failed
    pub error_message: Option<String>,
    /// When this schema was created
    pub created_at: DateTime<Utc>,
    /// When this schema was activated (if active)
    pub activated_at: Option<DateTime<Utc>>,
    /// When this schema was superseded or rolled back
    pub deactivated_at: Option<DateTime<Utc>>,
}

#[bon]
impl VaultSchema {
    /// Create a new schema version
    #[builder(on(String, into), finish_fn = create)]
    pub fn new(
        id: i64,
        vault_id: i64,
        version: SchemaVersion,
        definition: String,
        author_user_id: i64,
        description: String,
        parent_version_id: Option<i64>,
    ) -> Result<Self> {
        Self::validate_definition(&definition)?;
        Self::validate_description(&description)?;

        Ok(Self {
            id,
            vault_id,
            version,
            definition,
            author_user_id,
            description,
            parent_version_id,
            status: SchemaDeploymentStatus::Validating,
            error_message: None,
            created_at: Utc::now(),
            activated_at: None,
            deactivated_at: None,
        })
    }

    /// Validate schema definition
    pub fn validate_definition(definition: &str) -> Result<()> {
        if definition.trim().is_empty() {
            return Err(Error::validation("Schema definition cannot be empty".to_string()));
        }

        // Basic size limit (1MB)
        if definition.len() > 1_048_576 {
            return Err(Error::validation("Schema definition cannot exceed 1MB".to_string()));
        }

        Ok(())
    }

    /// Validate description
    pub fn validate_description(description: &str) -> Result<()> {
        if description.len() > 2000 {
            return Err(Error::validation(
                "Schema description cannot exceed 2000 characters".to_string(),
            ));
        }
        Ok(())
    }

    /// Mark schema as deployed (validated but not active)
    pub fn mark_deployed(&mut self) {
        self.status = SchemaDeploymentStatus::Deployed;
        self.error_message = None;
    }

    /// Activate this schema version
    pub fn activate(&mut self) {
        self.status = SchemaDeploymentStatus::Active;
        self.activated_at = Some(Utc::now());
        self.error_message = None;
    }

    /// Mark deployment as failed
    pub fn mark_failed(&mut self, error: String) {
        self.status = SchemaDeploymentStatus::Failed;
        self.error_message = Some(error);
    }

    /// Mark as superseded by a newer version
    pub fn mark_superseded(&mut self) {
        self.status = SchemaDeploymentStatus::Superseded;
        self.deactivated_at = Some(Utc::now());
    }

    /// Mark as rolled back
    pub fn mark_rolled_back(&mut self) {
        self.status = SchemaDeploymentStatus::RolledBack;
        self.deactivated_at = Some(Utc::now());
    }

    /// Check if this schema is the active version
    pub fn is_active(&self) -> bool {
        self.status == SchemaDeploymentStatus::Active
    }

    /// Check if this schema can be activated
    pub fn can_activate(&self) -> bool {
        matches!(
            self.status,
            SchemaDeploymentStatus::Deployed
                | SchemaDeploymentStatus::Superseded
                | SchemaDeploymentStatus::RolledBack
        )
    }

    /// Check if this schema is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self.status, SchemaDeploymentStatus::Failed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_version_new() {
        let v = SchemaVersion::new(1, 2, 3);
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_schema_version_initial() {
        let v = SchemaVersion::initial();
        assert_eq!(v.to_string(), "1.0.0");
    }

    #[test]
    fn test_schema_version_display() {
        let v = SchemaVersion::new(2, 5, 10);
        assert_eq!(v.to_string(), "2.5.10");
    }

    #[test]
    fn test_schema_version_from_str() {
        let v: SchemaVersion = "1.2.3".parse().unwrap();
        assert_eq!(v, SchemaVersion::new(1, 2, 3));

        let v: SchemaVersion = "10.20.30".parse().unwrap();
        assert_eq!(v, SchemaVersion::new(10, 20, 30));
    }

    #[test]
    fn test_schema_version_from_str_invalid() {
        assert!("1.2".parse::<SchemaVersion>().is_err());
        assert!("1.2.3.4".parse::<SchemaVersion>().is_err());
        assert!("a.b.c".parse::<SchemaVersion>().is_err());
        assert!("1.2.c".parse::<SchemaVersion>().is_err());
    }

    #[test]
    fn test_schema_version_bump() {
        let v = SchemaVersion::new(1, 2, 3);

        let major = v.bump_major();
        assert_eq!(major, SchemaVersion::new(2, 0, 0));

        let minor = v.bump_minor();
        assert_eq!(minor, SchemaVersion::new(1, 3, 0));

        let patch = v.bump_patch();
        assert_eq!(patch, SchemaVersion::new(1, 2, 4));
    }

    #[test]
    fn test_schema_version_ordering() {
        let v1 = SchemaVersion::new(1, 0, 0);
        let v2 = SchemaVersion::new(1, 0, 1);
        let v3 = SchemaVersion::new(1, 1, 0);
        let v4 = SchemaVersion::new(2, 0, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
        assert!(v1 < v4);
    }

    #[test]
    fn test_create_vault_schema() {
        let schema = VaultSchema::builder()
            .id(1)
            .vault_id(100)
            .version(SchemaVersion::initial())
            .definition("entity User {}".to_string())
            .author_user_id(999)
            .description("Initial schema")
            .create()
            .unwrap();

        assert_eq!(schema.id, 1);
        assert_eq!(schema.vault_id, 100);
        assert_eq!(schema.version, SchemaVersion::initial());
        assert_eq!(schema.definition, "entity User {}");
        assert_eq!(schema.author_user_id, 999);
        assert_eq!(schema.description, "Initial schema");
        assert!(schema.parent_version_id.is_none());
        assert_eq!(schema.status, SchemaDeploymentStatus::Validating);
        assert!(schema.error_message.is_none());
        assert!(schema.activated_at.is_none());
        assert!(schema.deactivated_at.is_none());
    }

    #[test]
    fn test_validate_definition_empty() {
        assert!(VaultSchema::validate_definition("").is_err());
        assert!(VaultSchema::validate_definition("   ").is_err());
    }

    #[test]
    fn test_validate_definition_too_large() {
        let large = "a".repeat(2_000_000);
        assert!(VaultSchema::validate_definition(&large).is_err());
    }

    #[test]
    fn test_validate_description_too_long() {
        let long = "a".repeat(2001);
        assert!(VaultSchema::validate_description(&long).is_err());
    }

    #[test]
    fn test_schema_lifecycle() {
        let mut schema = VaultSchema::builder()
            .id(1)
            .vault_id(100)
            .version(SchemaVersion::initial())
            .definition("entity User {}".to_string())
            .author_user_id(999)
            .description("Initial schema")
            .create()
            .unwrap();

        assert_eq!(schema.status, SchemaDeploymentStatus::Validating);
        assert!(!schema.is_active());
        assert!(!schema.can_activate());

        schema.mark_deployed();
        assert_eq!(schema.status, SchemaDeploymentStatus::Deployed);
        assert!(!schema.is_active());
        assert!(schema.can_activate());

        schema.activate();
        assert_eq!(schema.status, SchemaDeploymentStatus::Active);
        assert!(schema.is_active());
        assert!(schema.activated_at.is_some());

        schema.mark_superseded();
        assert_eq!(schema.status, SchemaDeploymentStatus::Superseded);
        assert!(!schema.is_active());
        assert!(schema.deactivated_at.is_some());
        assert!(schema.can_activate()); // Can be reactivated
    }

    #[test]
    fn test_schema_failure() {
        let mut schema = VaultSchema::builder()
            .id(1)
            .vault_id(100)
            .version(SchemaVersion::initial())
            .definition("entity User {}".to_string())
            .author_user_id(999)
            .description("Initial schema")
            .create()
            .unwrap();

        schema.mark_failed("Syntax error on line 5".to_string());
        assert_eq!(schema.status, SchemaDeploymentStatus::Failed);
        assert_eq!(schema.error_message, Some("Syntax error on line 5".to_string()));
        assert!(schema.is_terminal());
    }

    #[test]
    fn test_schema_rollback() {
        let mut schema = VaultSchema::builder()
            .id(1)
            .vault_id(100)
            .version(SchemaVersion::initial())
            .definition("entity User {}".to_string())
            .author_user_id(999)
            .description("Initial schema")
            .create()
            .unwrap();

        schema.mark_deployed();
        schema.activate();
        schema.mark_rolled_back();

        assert_eq!(schema.status, SchemaDeploymentStatus::RolledBack);
        assert!(schema.deactivated_at.is_some());
        assert!(schema.can_activate()); // Can be reactivated
    }
}
