use serde::{Deserialize, Serialize};

use crate::entities::{SchemaDeploymentStatus, SchemaVersion};

// ============================================================================
// Request/Response Types - Schema Management
// ============================================================================

/// Request to deploy a new schema version
#[derive(Debug, Deserialize)]
pub struct DeploySchemaRequest {
    /// The IPL schema definition
    pub definition: String,
    /// Description of changes in this version
    #[serde(default)]
    pub description: String,
    /// Optional explicit version (if not provided, will auto-increment)
    pub version: Option<String>,
}

/// Response after deploying a new schema
#[derive(Debug, Serialize)]
pub struct DeploySchemaResponse {
    pub schema: SchemaInfo,
}

/// Schema information for API responses
#[derive(Debug, Serialize)]
pub struct SchemaInfo {
    pub id: i64,
    pub vault_id: i64,
    pub version: String,
    pub description: String,
    pub status: SchemaDeploymentStatus,
    pub author_user_id: i64,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activated_at: Option<String>,
}

/// Detailed schema response including definition
#[derive(Debug, Serialize)]
pub struct SchemaDetail {
    pub id: i64,
    pub vault_id: i64,
    pub version: String,
    pub definition: String,
    pub description: String,
    pub status: SchemaDeploymentStatus,
    pub error_message: Option<String>,
    pub author_user_id: i64,
    pub parent_version_id: Option<i64>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated_at: Option<String>,
}

/// Response for get schema endpoint
#[derive(Debug, Serialize)]
pub struct GetSchemaResponse {
    pub schema: SchemaDetail,
}

/// Response for list schemas endpoint
#[derive(Debug, Serialize)]
pub struct ListSchemasResponse {
    pub schemas: Vec<SchemaInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<crate::PaginationMeta>,
}

/// Query parameters for list schemas endpoint
#[derive(Debug, Deserialize, Default)]
pub struct ListSchemasQuery {
    /// Filter by deployment status
    pub status: Option<String>,
    /// Pagination limit
    pub limit: Option<usize>,
    /// Pagination offset
    pub offset: Option<usize>,
}

/// Request to activate a specific schema version
#[derive(Debug, Deserialize)]
pub struct ActivateSchemaRequest {
    // Empty for now, version comes from URL path
}

/// Response after activating a schema
#[derive(Debug, Serialize)]
pub struct ActivateSchemaResponse {
    pub schema: SchemaInfo,
    pub message: String,
}

/// Request to rollback to a previous schema version
#[derive(Debug, Deserialize)]
pub struct RollbackSchemaRequest {
    /// Version to rollback to (e.g., "1.0.0")
    pub target_version: String,
}

/// Response after rolling back a schema
#[derive(Debug, Serialize)]
pub struct RollbackSchemaResponse {
    /// The newly active schema (the one we rolled back to)
    pub active_schema: SchemaInfo,
    /// The schema that was rolled back from
    pub rolled_back_schema: SchemaInfo,
    pub message: String,
}

// ============================================================================
// Schema Diff Types
// ============================================================================

/// Request to compare two schema versions
#[derive(Debug, Deserialize)]
pub struct SchemaDiffQuery {
    /// Source version to compare from
    pub from: String,
    /// Target version to compare to
    pub to: String,
}

/// Type of change in a schema diff
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiffChangeType {
    Added,
    Removed,
    Modified,
}

/// A single change in the schema diff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDiffChange {
    /// Type of change (added, removed, modified)
    pub change_type: DiffChangeType,
    /// Type of element (entity, relation, permission, attribute)
    pub element_type: String,
    /// Name of the element
    pub element_name: String,
    /// For modified elements, the old value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,
    /// For modified elements, the new value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
    /// Whether this is a breaking change
    pub is_breaking: bool,
    /// Human-readable description of the change
    pub description: String,
}

/// Schema diff result
#[derive(Debug, Serialize)]
pub struct SchemaDiffResponse {
    /// Source version
    pub from_version: String,
    /// Target version
    pub to_version: String,
    /// List of changes
    pub changes: Vec<SchemaDiffChange>,
    /// Whether any changes are breaking
    pub has_breaking_changes: bool,
    /// Summary statistics
    pub summary: SchemaDiffSummary,
}

/// Summary of schema diff changes
#[derive(Debug, Default, Serialize)]
pub struct SchemaDiffSummary {
    pub entities_added: usize,
    pub entities_removed: usize,
    pub entities_modified: usize,
    pub relations_added: usize,
    pub relations_removed: usize,
    pub relations_modified: usize,
    pub permissions_added: usize,
    pub permissions_removed: usize,
    pub permissions_modified: usize,
}

// ============================================================================
// Conversion Helpers
// ============================================================================

impl From<&crate::entities::VaultSchema> for SchemaInfo {
    fn from(schema: &crate::entities::VaultSchema) -> Self {
        Self {
            id: schema.id,
            vault_id: schema.vault_id,
            version: schema.version.to_string(),
            description: schema.description.clone(),
            status: schema.status,
            author_user_id: schema.author_user_id,
            created_at: schema.created_at.to_rfc3339(),
            activated_at: schema.activated_at.map(|t| t.to_rfc3339()),
        }
    }
}

impl From<crate::entities::VaultSchema> for SchemaInfo {
    fn from(schema: crate::entities::VaultSchema) -> Self {
        Self::from(&schema)
    }
}

impl From<&crate::entities::VaultSchema> for SchemaDetail {
    fn from(schema: &crate::entities::VaultSchema) -> Self {
        Self {
            id: schema.id,
            vault_id: schema.vault_id,
            version: schema.version.to_string(),
            definition: schema.definition.clone(),
            description: schema.description.clone(),
            status: schema.status,
            error_message: schema.error_message.clone(),
            author_user_id: schema.author_user_id,
            parent_version_id: schema.parent_version_id,
            created_at: schema.created_at.to_rfc3339(),
            activated_at: schema.activated_at.map(|t| t.to_rfc3339()),
            deactivated_at: schema.deactivated_at.map(|t| t.to_rfc3339()),
        }
    }
}

impl From<crate::entities::VaultSchema> for SchemaDetail {
    fn from(schema: crate::entities::VaultSchema) -> Self {
        Self::from(&schema)
    }
}

/// Parse a version string to SchemaVersion
impl TryFrom<&str> for SchemaVersion {
    type Error = crate::error::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}
