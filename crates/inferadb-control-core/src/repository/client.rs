use inferadb_control_storage::StorageBackend;
use inferadb_control_types::{
    entities::Client,
    error::{Error, Result},
};

/// Repository for Client entity operations
///
/// Key schema:
/// - client:{id} -> Client data
/// - client:org:{org_id}:{idx} -> client_id (for org listing)
/// - client:name:{org_id}:{name_lowercase} -> client_id (for duplicate name checking)
pub struct ClientRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> ClientRepository<S> {
    /// Create a new client repository
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Generate key for client by ID
    fn client_key(id: i64) -> Vec<u8> {
        format!("client:{id}").into_bytes()
    }

    /// Generate key for client by organization index
    fn client_org_index_key(org_id: i64, idx: i64) -> Vec<u8> {
        format!("client:org:{org_id}:{idx}").into_bytes()
    }

    /// Generate key for client by name (for duplicate checking)
    fn client_name_index_key(org_id: i64, name: &str) -> Vec<u8> {
        format!("client:name:{}:{}", org_id, name.to_lowercase()).into_bytes()
    }

    /// Create a new client
    pub async fn create(&self, client: Client) -> Result<()> {
        // Serialize client
        let client_data = serde_json::to_vec(&client)
            .map_err(|e| Error::Internal(format!("Failed to serialize client: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Check for duplicate name within organization
        let name_key = Self::client_name_index_key(client.organization_id, &client.name);
        if self
            .storage
            .get(&name_key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to check duplicate client name: {e}")))?
            .is_some()
        {
            return Err(Error::AlreadyExists(format!(
                "A client named '{}' already exists in this organization",
                client.name
            )));
        }

        // Store client record
        txn.set(Self::client_key(client.id), client_data.clone());

        // Store organization index
        txn.set(
            Self::client_org_index_key(client.organization_id, client.id),
            client.id.to_le_bytes().to_vec(),
        );

        // Store name index
        txn.set(name_key, client.id.to_le_bytes().to_vec());

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit client creation: {e}")))?;

        Ok(())
    }

    /// Get a client by ID
    pub async fn get(&self, id: i64) -> Result<Option<Client>> {
        let key = Self::client_key(id);
        let data = self
            .storage
            .get(&key)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get client: {e}")))?;

        match data {
            Some(bytes) => {
                let client: Client = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("Failed to deserialize client: {e}")))?;
                Ok(Some(client))
            },
            None => Ok(None),
        }
    }

    /// List all clients for an organization (including soft-deleted)
    pub async fn list_by_organization(&self, org_id: i64) -> Result<Vec<Client>> {
        let prefix = format!("client:org:{org_id}:");
        let start = prefix.clone().into_bytes();
        let end = format!("client:org:{org_id}~").into_bytes();

        let kvs = self
            .storage
            .get_range(start..end)
            .await
            .map_err(|e| Error::Internal(format!("Failed to get organization clients: {e}")))?;

        let mut clients = Vec::new();
        for kv in kvs {
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());
            if let Some(client) = self.get(id).await? {
                clients.push(client);
            }
        }

        Ok(clients)
    }

    /// List active (non-deleted) clients for an organization
    pub async fn list_active_by_organization(&self, org_id: i64) -> Result<Vec<Client>> {
        let all_clients = self.list_by_organization(org_id).await?;
        Ok(all_clients.into_iter().filter(|c| !c.is_deleted()).collect())
    }

    /// Update a client
    pub async fn update(&self, client: Client) -> Result<()> {
        // Get the existing client to clean up old indexes if name changed
        let existing = self
            .get(client.id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Client {} not found", client.id)))?;

        // Serialize updated client
        let client_data = serde_json::to_vec(&client)
            .map_err(|e| Error::Internal(format!("Failed to serialize client: {e}")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // If name changed, update name index
        if existing.name != client.name {
            // Delete old name index
            txn.delete(Self::client_name_index_key(existing.organization_id, &existing.name));

            // Check for duplicate new name
            let new_name_key = Self::client_name_index_key(client.organization_id, &client.name);
            if self
                .storage
                .get(&new_name_key)
                .await
                .map_err(|e| {
                    Error::Internal(format!("Failed to check duplicate client name: {e}"))
                })?
                .is_some()
            {
                return Err(Error::AlreadyExists(format!(
                    "A client named '{}' already exists in this organization",
                    client.name
                )));
            }

            // Store new name index
            txn.set(new_name_key, client.id.to_le_bytes().to_vec());
        }

        // Update client record
        txn.set(Self::client_key(client.id), client_data);

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit client update: {e}")))?;

        Ok(())
    }

    /// Delete a client (removes all indexes)
    pub async fn delete(&self, id: i64) -> Result<()> {
        // Get the client first to clean up indexes
        let client =
            self.get(id).await?.ok_or_else(|| Error::NotFound(format!("Client {id} not found")))?;

        // Use transaction for atomicity
        let mut txn = self
            .storage
            .transaction()
            .await
            .map_err(|e| Error::Internal(format!("Failed to start transaction: {e}")))?;

        // Delete client record
        txn.delete(Self::client_key(id));

        // Delete organization index
        txn.delete(Self::client_org_index_key(client.organization_id, client.id));

        // Delete name index
        txn.delete(Self::client_name_index_key(client.organization_id, &client.name));

        // Commit transaction
        txn.commit()
            .await
            .map_err(|e| Error::Internal(format!("Failed to commit client deletion: {e}")))?;

        Ok(())
    }

    /// Count clients in an organization
    pub async fn count_by_organization(&self, org_id: i64) -> Result<usize> {
        let clients = self.list_by_organization(org_id).await?;
        Ok(clients.len())
    }

    /// Count active (non-deleted) clients in an organization
    pub async fn count_active_by_organization(&self, org_id: i64) -> Result<usize> {
        let clients = self.list_active_by_organization(org_id).await?;
        Ok(clients.len())
    }
}

#[cfg(test)]
mod tests {
    use inferadb_control_storage::Backend;

    use super::*;

    fn create_test_repo() -> ClientRepository<Backend> {
        ClientRepository::new(Backend::memory())
    }

    fn create_test_client(id: i64, org_id: i64, name: &str) -> Result<Client> {
        Client::new(id, org_id, None, name.to_string(), None, 999)
    }

    #[tokio::test]
    async fn test_create_and_get_client() {
        let repo = create_test_repo();
        let client = create_test_client(1, 100, "Test Client").unwrap();

        repo.create(client.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap();
        assert_eq!(retrieved, Some(client));
    }

    #[tokio::test]
    async fn test_duplicate_name_rejected() {
        let repo = create_test_repo();
        let client1 = create_test_client(1, 100, "Test Client").unwrap();
        let client2 = create_test_client(2, 100, "Test Client").unwrap();

        repo.create(client1).await.unwrap();

        let result = repo.create(client2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn test_list_by_organization() {
        let repo = create_test_repo();
        let client1 = create_test_client(1, 100, "Client 1").unwrap();
        let client2 = create_test_client(2, 100, "Client 2").unwrap();
        let client3 = create_test_client(3, 200, "Client 3").unwrap();

        repo.create(client1).await.unwrap();
        repo.create(client2).await.unwrap();
        repo.create(client3).await.unwrap();

        let org_100_clients = repo.list_by_organization(100).await.unwrap();
        assert_eq!(org_100_clients.len(), 2);

        let org_200_clients = repo.list_by_organization(200).await.unwrap();
        assert_eq!(org_200_clients.len(), 1);
    }

    #[tokio::test]
    async fn test_update_client_name() {
        let repo = create_test_repo();
        let mut client = create_test_client(1, 100, "Original Name").unwrap();

        repo.create(client.clone()).await.unwrap();

        client.name = "Updated Name".to_string();
        repo.update(client.clone()).await.unwrap();

        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "Updated Name");
    }

    #[tokio::test]
    async fn test_update_client_name_duplicate() {
        let repo = create_test_repo();
        let client1 = create_test_client(1, 100, "Client 1").unwrap();
        let mut client2 = create_test_client(2, 100, "Client 2").unwrap();

        repo.create(client1).await.unwrap();
        repo.create(client2.clone()).await.unwrap();

        // Try to rename client2 to client1's name
        client2.name = "Client 1".to_string();
        let result = repo.update(client2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn test_soft_delete_client() {
        let repo = create_test_repo();
        let mut client = create_test_client(1, 100, "Test Client").unwrap();

        repo.create(client.clone()).await.unwrap();

        // Soft delete
        client.mark_deleted();
        repo.update(client.clone()).await.unwrap();

        // Client should still be retrievable
        let retrieved = repo.get(1).await.unwrap().unwrap();
        assert!(retrieved.is_deleted());

        // But not in active list
        let active = repo.list_active_by_organization(100).await.unwrap();
        assert_eq!(active.len(), 0);

        // Still in full list
        let all = repo.list_by_organization(100).await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_client() {
        let repo = create_test_repo();
        let client = create_test_client(1, 100, "Test Client").unwrap();

        repo.create(client).await.unwrap();
        assert!(repo.get(1).await.unwrap().is_some());

        repo.delete(1).await.unwrap();
        assert!(repo.get(1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_count_clients() {
        let repo = create_test_repo();
        let client1 = create_test_client(1, 100, "Client 1").unwrap();
        let mut client2 = create_test_client(2, 100, "Client 2").unwrap();
        let client3 = create_test_client(3, 100, "Client 3").unwrap();

        repo.create(client1).await.unwrap();
        repo.create(client2.clone()).await.unwrap();
        repo.create(client3).await.unwrap();

        assert_eq!(repo.count_by_organization(100).await.unwrap(), 3);
        assert_eq!(repo.count_active_by_organization(100).await.unwrap(), 3);

        // Soft delete one
        client2.mark_deleted();
        repo.update(client2).await.unwrap();

        assert_eq!(repo.count_by_organization(100).await.unwrap(), 3);
        assert_eq!(repo.count_active_by_organization(100).await.unwrap(), 2);
    }
}
