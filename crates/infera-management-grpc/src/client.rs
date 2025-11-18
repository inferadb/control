use infera_management_core::Result;

/// gRPC client for communicating with @server API
///
/// This is a stub implementation for Phase 5. In production, this would:
/// - Connect to @server via gRPC
/// - Authenticate using Client Assertion (JWT signed with system Ed25519 key)
/// - Send CreateVault/DeleteVault RPCs
/// - Handle retries and failures
///
/// For now, all operations succeed immediately (mocked)
pub struct ServerApiClient {
    #[allow(dead_code)]
    endpoint: String,
}

impl ServerApiClient {
    /// Create a new server API client
    pub fn new(endpoint: String) -> Result<Self> {
        Ok(Self { endpoint })
    }

    /// Create a vault on @server
    ///
    /// In production this would:
    /// 1. Generate a client assertion JWT
    /// 2. Call CreateVault RPC with vault_id and organization_id
    /// 3. Return success or error
    ///
    /// For now: Always succeeds (stub)
    pub async fn create_vault(&self, _vault_id: i64, _organization_id: i64) -> Result<()> {
        // TODO: Implement actual gRPC call to @server
        // For now, simulate success
        Ok(())
    }

    /// Delete a vault on @server
    ///
    /// In production this would:
    /// 1. Generate a client assertion JWT
    /// 2. Call DeleteVault RPC with vault_id
    /// 3. Return success or error
    ///
    /// For now: Always succeeds (stub)
    pub async fn delete_vault(&self, _vault_id: i64) -> Result<()> {
        // TODO: Implement actual gRPC call to @server
        // For now, simulate success
        Ok(())
    }
}
