use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::{SchemaDeploymentStatus, SchemaVersion, VaultSchema},
    error::{Error, Result},
};

/// Repository for VaultSchema entity operations
///
/// Key schema:
/// - vault_schema:{id} -> VaultSchema data
/// - vault_schema:vault:{vault_id}:{idx} -> schema_id (for vault's schemas listing)
/// - vault_schema:vault_version:{vault_id}:{version_string} -> schema_id (for version lookup)
/// - vault_schema:vault_active:{vault_id} -> schema_id (for active schema lookup)
pub struct VaultSchemaRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> VaultSchemaRepository<S> {
    /// Create a new vault schema repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for schema by ID
    fn schema_key(id: i64) -> Vec<u8> {
        format!("vault_schema:{id}").into_bytes()
    }

    /// Generate key for vault's schema index
    fn vault_schema_index_key(vault_id: i64, schema_id: i64) -> Vec<u8> {
        format!("vault_schema:vault:{vault_id}:{schema_id}").into_bytes()
    }

    /// Generate key for vault-version unique constraint
    fn vault_version_index_key(vault_id: i64, version: &SchemaVersion) -> Vec<u8> {
        format!("vault_schema:vault_version:{vault_id}:{version}").into_bytes()
    }

    /// Generate key for vault's active schema
    fn vault_active_schema_key(vault_id: i64) -> Vec<u8> {
        format!("vault_schema:vault_active:{vault_id}").into_bytes()
    }

    /// Create a new schema version
    pub async fn create(&self, schema: VaultSchema) -> Result<()> {
        // Serialize schema
        let schema_data = serde_json::to_vec(&schema)
            .map_err(|e| Error::Internal(format!("Failed to serialize schema: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Check for duplicate version within vault
        let version_key = Self::vault_version_index_key(schema.vault_id, &schema.version);
        if self
            .storage
            .get(&version_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to check duplicate version: {e}")))?
            .is_some()
        {
            return Err(Error::AlreadyExists(format!(
                "Schema version {} already exists for this vault",
                schema.version
            )));
        }

        // Store schema record
        txn.set(Self::schema_key(schema.id), schema_data);

        // Store vault schema index
        txn.set(
            Self::vault_schema_index_key(schema.vault_id, schema.id),
            schema.id.to_le_bytes().to_vec(),
        );

        // Store version index
        txn.set(version_key, schema.id.to_le_bytes().to_vec());

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit schema creation: {e}")))?;

        Ok(())
    }

    /// Get a schema by ID
    pub async fn get(&self, id: i64) -> Result<Option<VaultSchema>> {
        let key = Self::schema_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get schema: {e}")))?;

        match data {
            Some(bytes) => {
                let schema: VaultSchema = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("Failed to deserialize schema: {e}")))?;
                Ok(Some(schema))
            },
            None => Ok(None),
        }
    }

    /// Get a schema by vault and version
    pub async fn get_by_version(
        &self,
        vault_id: i64,
        version: &SchemaVersion,
    ) -> Result<Option<VaultSchema>> {
        let index_key = Self::vault_version_index_key(vault_id, version);
        let data = self
            .storage
            .get(&index_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get schema by version: {e}")))?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::Internal("Invalid schema index data".to_string()));
                }
                let id = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// Get the active schema for a vault
    pub async fn get_active(&self, vault_id: i64) -> Result<Option<VaultSchema>> {
        let key = Self::vault_active_schema_key(vault_id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get active schema: {e}")))?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::Internal("Invalid active schema index data".to_string()));
                }
                let id = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
                self.get(id).await
            },
            None => Ok(None),
        }
    }

    /// List all schemas for a vault, ordered by version (newest first)
    pub async fn list_by_vault(&self, vault_id: i64) -> Result<Vec<VaultSchema>> {
        let start = format!("vault_schema:vault:{vault_id}:").into_bytes();
        let end = format!("vault_schema:vault:{vault_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get vault schemas: {e}")))?;

        let mut schemas = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(schema) = self.get(id).await? {
                schemas.push(schema);
            }
        }

        // Sort by version descending (newest first)
        schemas.sort_by(|a, b| b.version.cmp(&a.version));

        Ok(schemas)
    }

    /// Update a schema
    pub async fn update(&self, schema: VaultSchema) -> Result<()> {
        // Verify schema exists
        self.get(schema.id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Schema {} not found", schema.id)))?;

        // Serialize updated schema
        let schema_data = serde_json::to_vec(&schema)
            .map_err(|e| Error::Internal(format!("Failed to serialize schema: {e}")))?;

        // Update schema record
        self.storage
            .set(Self::schema_key(schema.id), schema_data)
            .await
            .map_err(|e| Error::Internal(format!("Failed to update schema: {e}")))?;

        Ok(())
    }

    /// Activate a schema version (and deactivate the current active one)
    pub async fn activate(&self, schema_id: i64) -> Result<VaultSchema> {
        // Get the schema to activate
        let mut schema = self
            .get(schema_id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Schema {schema_id} not found")))?;

        if !schema.can_activate() {
            return Err(Error::Validation(format!(
                "Schema in status {:?} cannot be activated",
                schema.status
            )));
        }

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Deactivate the current active schema if any
        if let Some(mut current_active) = self.get_active(schema.vault_id).await? {
            if current_active.id != schema_id {
                current_active.mark_superseded();
                let current_data = serde_json::to_vec(&current_active)
                    .map_err(|e| Error::Internal(format!("Failed to serialize schema: {e}")))?;
                txn.set(Self::schema_key(current_active.id), current_data);
            }
        }

        // Activate the new schema
        schema.activate();
        let schema_data = serde_json::to_vec(&schema)
            .map_err(|e| Error::Internal(format!("Failed to serialize schema: {e}")))?;

        // Update schema record
        txn.set(Self::schema_key(schema.id), schema_data);

        // Update active schema index
        txn.set(Self::vault_active_schema_key(schema.vault_id), schema.id.to_le_bytes().to_vec());

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit schema activation: {e}")))?;

        Ok(schema)
    }

    /// Rollback to a previous schema version
    pub async fn rollback(&self, schema_id: i64) -> Result<VaultSchema> {
        // Get the schema to rollback to
        let schema = self
            .get(schema_id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Schema {schema_id} not found")))?;

        // Get the current active schema
        let current_active = self
            .get_active(schema.vault_id)
            .await?
            .ok_or_else(|| Error::Validation("No active schema to rollback from".to_string()))?;

        if current_active.id == schema_id {
            return Err(Error::Validation(
                "Cannot rollback to the currently active schema".to_string(),
            ));
        }

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Mark current active as rolled back
        let mut rolled_back = current_active;
        rolled_back.mark_rolled_back();
        let rolled_back_data = serde_json::to_vec(&rolled_back)
            .map_err(|e| Error::Internal(format!("Failed to serialize schema: {e}")))?;
        txn.set(Self::schema_key(rolled_back.id), rolled_back_data);

        // Reactivate the target schema
        let mut reactivated = schema;
        reactivated.activate();
        let reactivated_data = serde_json::to_vec(&reactivated)
            .map_err(|e| Error::Internal(format!("Failed to serialize schema: {e}")))?;
        txn.set(Self::schema_key(reactivated.id), reactivated_data.clone());

        // Update active schema index
        txn.set(
            Self::vault_active_schema_key(reactivated.vault_id),
            reactivated.id.to_le_bytes().to_vec(),
        );

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit schema rollback: {e}")))?;

        // Re-deserialize to get the updated state
        let result: VaultSchema = serde_json::from_slice(&reactivated_data)
            .map_err(|e| Error::Internal(format!("Failed to deserialize schema: {e}")))?;

        Ok(result)
    }

    /// Get the latest version number for a vault
    pub async fn get_latest_version(&self, vault_id: i64) -> Result<Option<SchemaVersion>> {
        let schemas = self.list_by_vault(vault_id).await?;
        Ok(schemas.first().map(|s| s.version.clone()))
    }

    /// Count schemas for a vault
    pub async fn count_by_vault(&self, vault_id: i64) -> Result<usize> {
        let schemas = self.list_by_vault(vault_id).await?;
        Ok(schemas.len())
    }

    /// Delete a schema (for cleanup - normally schemas are retained for history)
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get the schema first to clean up indexes
        let schema =
            self.get(id).await?.ok_or_else(|| Error::NotFound(format!("Schema {id} not found")))?;

        // Cannot delete active schema
        if schema.is_active() {
            return Err(Error::Validation("Cannot delete an active schema".to_string()));
        }

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Delete schema record
        txn.delete(Self::schema_key(id));

        // Delete vault schema index
        txn.delete(Self::vault_schema_index_key(schema.vault_id, schema.id));

        // Delete version index
        txn.delete(Self::vault_version_index_key(schema.vault_id, &schema.version));

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit schema deletion: {e}")))?;

        Ok(())
    }

    /// List schemas by status for a vault
    pub async fn list_by_vault_and_status(
        &self,
        vault_id: i64,
        status: SchemaDeploymentStatus,
    ) -> Result<Vec<VaultSchema>> {
        let all_schemas = self.list_by_vault(vault_id).await?;
        Ok(all_schemas.into_iter().filter(|s| s.status == status).collect())
    }
}

#[cfg(test)]
mod tests {
    use inferadb_control_storage::{Backend, MemoryBackend};

    use super::*;

    fn create_test_repo() -> VaultSchemaRepository<Backend> {
        VaultSchemaRepository::new(Backend::Memory(MemoryBackend::new()))
    }

    fn create_test_schema(
        id: i64,
        vault_id: i64,
        version: SchemaVersion,
        definition: &str,
    ) -> Result<VaultSchema> {
        VaultSchema::new(
            id,
            vault_id,
            version,
            definition.to_string(),
            999, // author_user_id
            "Test schema".to_string(),
            None,
        )
    }

    #[tokio::test]
    async fn test_create_and_get_schema() {
        let repo = create_test_repo();
        let schema =
            create_test_schema(1, 100, SchemaVersion::initial(), "entity User {}").unwrap();

        repo.create(schema.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, 1);
        assert_eq!(retrieved.vault_id, 100);
        assert_eq!(retrieved.version, SchemaVersion::initial());
    }

    #[tokio::test]
    async fn test_duplicate_version_rejected() {
        let repo = create_test_repo();
        let schema1 =
            create_test_schema(1, 100, SchemaVersion::initial(), "entity User {}").unwrap();
        let schema2 =
            create_test_schema(2, 100, SchemaVersion::initial(), "entity Group {}").unwrap();

        repo.create(schema1).await.unwrap();

        let result = repo.create(schema2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn test_get_by_version() {
        let repo = create_test_repo();
        let v1 = SchemaVersion::new(1, 0, 0);
        let v2 = SchemaVersion::new(2, 0, 0);

        let schema1 = create_test_schema(1, 100, v1.clone(), "entity User {}").unwrap();
        let schema2 = create_test_schema(2, 100, v2.clone(), "entity Group {}").unwrap();

        repo.create(schema1).await.unwrap();
        repo.create(schema2).await.unwrap();

        let retrieved = repo.get_by_version(100, &v1).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, 1);

        let retrieved = repo.get_by_version(100, &v2).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, 2);

        // Non-existent version
        let retrieved = repo.get_by_version(100, &SchemaVersion::new(3, 0, 0)).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_by_vault_ordered_by_version() {
        let repo = create_test_repo();
        let v1 = SchemaVersion::new(1, 0, 0);
        let v2 = SchemaVersion::new(1, 1, 0);
        let v3 = SchemaVersion::new(2, 0, 0);

        let schema1 = create_test_schema(1, 100, v1, "entity User {}").unwrap();
        let schema2 = create_test_schema(2, 100, v2, "entity Group {}").unwrap();
        let schema3 = create_test_schema(3, 100, v3, "entity Folder {}").unwrap();

        // Create in random order
        repo.create(schema2).await.unwrap();
        repo.create(schema1).await.unwrap();
        repo.create(schema3).await.unwrap();

        let schemas = repo.list_by_vault(100).await.unwrap();
        assert_eq!(schemas.len(), 3);

        // Should be ordered newest first
        assert_eq!(schemas[0].version, SchemaVersion::new(2, 0, 0));
        assert_eq!(schemas[1].version, SchemaVersion::new(1, 1, 0));
        assert_eq!(schemas[2].version, SchemaVersion::new(1, 0, 0));
    }

    #[tokio::test]
    async fn test_activate_schema() {
        let repo = create_test_repo();
        let mut schema =
            create_test_schema(1, 100, SchemaVersion::initial(), "entity User {}").unwrap();

        // Mark as deployed so it can be activated
        schema.mark_deployed();
        repo.create(schema).await.unwrap();

        // Activate it
        let activated = repo.activate(1).await.unwrap();
        assert!(activated.is_active());

        // Verify it's the active schema
        let active = repo.get_active(100).await.unwrap();
        assert!(active.is_some());
        assert_eq!(active.unwrap().id, 1);
    }

    #[tokio::test]
    async fn test_activate_supersedes_previous() {
        let repo = create_test_repo();
        let v1 = SchemaVersion::new(1, 0, 0);
        let v2 = SchemaVersion::new(2, 0, 0);

        let mut schema1 = create_test_schema(1, 100, v1, "entity User {}").unwrap();
        let mut schema2 = create_test_schema(2, 100, v2, "entity Group {}").unwrap();

        schema1.mark_deployed();
        schema2.mark_deployed();

        repo.create(schema1).await.unwrap();
        repo.create(schema2).await.unwrap();

        // Activate first schema
        repo.activate(1).await.unwrap();
        assert!(repo.get(1).await.unwrap().unwrap().is_active());

        // Activate second schema - should supersede first
        repo.activate(2).await.unwrap();

        let first = repo.get(1).await.unwrap().unwrap();
        let second = repo.get(2).await.unwrap().unwrap();

        assert!(!first.is_active());
        assert_eq!(first.status, SchemaDeploymentStatus::Superseded);
        assert!(second.is_active());

        // Active should be second
        let active = repo.get_active(100).await.unwrap().unwrap();
        assert_eq!(active.id, 2);
    }

    #[tokio::test]
    async fn test_rollback() {
        let repo = create_test_repo();
        let v1 = SchemaVersion::new(1, 0, 0);
        let v2 = SchemaVersion::new(2, 0, 0);

        let mut schema1 = create_test_schema(1, 100, v1, "entity User {}").unwrap();
        let mut schema2 = create_test_schema(2, 100, v2, "entity Group {}").unwrap();

        schema1.mark_deployed();
        schema2.mark_deployed();

        repo.create(schema1).await.unwrap();
        repo.create(schema2).await.unwrap();

        // Activate schemas in order
        repo.activate(1).await.unwrap();
        repo.activate(2).await.unwrap();

        // Rollback to first schema
        let rolled_back_to = repo.rollback(1).await.unwrap();
        assert!(rolled_back_to.is_active());
        assert_eq!(rolled_back_to.id, 1);

        let second = repo.get(2).await.unwrap().unwrap();
        assert_eq!(second.status, SchemaDeploymentStatus::RolledBack);

        // Active should be first again
        let active = repo.get_active(100).await.unwrap().unwrap();
        assert_eq!(active.id, 1);
    }

    #[tokio::test]
    async fn test_cannot_activate_validating_schema() {
        let repo = create_test_repo();
        let schema =
            create_test_schema(1, 100, SchemaVersion::initial(), "entity User {}").unwrap();

        // Schema is in Validating status by default
        repo.create(schema).await.unwrap();

        let result = repo.activate(1).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Validation(_)));
    }

    #[tokio::test]
    async fn test_cannot_delete_active_schema() {
        let repo = create_test_repo();
        let mut schema =
            create_test_schema(1, 100, SchemaVersion::initial(), "entity User {}").unwrap();

        schema.mark_deployed();
        repo.create(schema).await.unwrap();
        repo.activate(1).await.unwrap();

        let result = repo.delete(1).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Validation(_)));
    }

    #[tokio::test]
    async fn test_delete_inactive_schema() {
        let repo = create_test_repo();
        let mut schema =
            create_test_schema(1, 100, SchemaVersion::initial(), "entity User {}").unwrap();

        schema.mark_failed("Syntax error".to_string());
        repo.create(schema).await.unwrap();

        repo.delete(1).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_get_latest_version() {
        let repo = create_test_repo();
        let v1 = SchemaVersion::new(1, 0, 0);
        let v2 = SchemaVersion::new(1, 2, 3);

        let schema1 = create_test_schema(1, 100, v1, "entity User {}").unwrap();
        let schema2 = create_test_schema(2, 100, v2.clone(), "entity Group {}").unwrap();

        repo.create(schema1).await.unwrap();
        repo.create(schema2).await.unwrap();

        let latest = repo.get_latest_version(100).await.unwrap();
        assert_eq!(latest, Some(v2));

        // Empty vault
        let latest = repo.get_latest_version(999).await.unwrap();
        assert!(latest.is_none());
    }

    #[tokio::test]
    async fn test_list_by_status() {
        let repo = create_test_repo();

        let mut schema1 =
            create_test_schema(1, 100, SchemaVersion::new(1, 0, 0), "entity User {}").unwrap();
        let mut schema2 =
            create_test_schema(2, 100, SchemaVersion::new(2, 0, 0), "entity Group {}").unwrap();
        let mut schema3 =
            create_test_schema(3, 100, SchemaVersion::new(3, 0, 0), "entity Folder {}").unwrap();

        schema1.mark_deployed();
        schema2.mark_failed("Error".to_string());
        schema3.mark_deployed();

        repo.create(schema1).await.unwrap();
        repo.create(schema2).await.unwrap();
        repo.create(schema3).await.unwrap();

        let deployed =
            repo.list_by_vault_and_status(100, SchemaDeploymentStatus::Deployed).await.unwrap();
        assert_eq!(deployed.len(), 2);

        let failed =
            repo.list_by_vault_and_status(100, SchemaDeploymentStatus::Failed).await.unwrap();
        assert_eq!(failed.len(), 1);
    }
}
