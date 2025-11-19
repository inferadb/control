use crate::handlers::auth::Result;
use crate::middleware::{require_admin_or_owner, require_member, OrganizationContext};
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use infera_management_core::{
    keypair, Client, ClientCertificate, Error as CoreError, IdGenerator, PrivateKeyEncryptor,
    RepositoryContext,
};
use serde::{Deserialize, Serialize};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateClientResponse {
    pub client: ClientInfo,
}

#[derive(Debug, Serialize)]
pub struct ClientInfo {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub is_active: bool,
    pub organization_id: i64,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct GetClientResponse {
    pub client: ClientDetail,
}

#[derive(Debug, Serialize)]
pub struct ClientDetail {
    pub id: i64,
    pub name: String,
    pub is_active: bool,
    pub organization_id: i64,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ListClientsResponse {
    pub clients: Vec<ClientDetail>,
    /// Pagination metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<crate::pagination::PaginationMeta>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateClientRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateClientResponse {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteClientResponse {
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateCertificateRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreateCertificateResponse {
    pub certificate: CertificateInfo,
    pub private_key: String, // Unencrypted private key (base64) - only returned once!
}

#[derive(Debug, Serialize)]
pub struct CertificateInfo {
    pub id: i64,
    pub kid: String,
    pub name: String,
    pub public_key: String,
    pub is_active: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct GetCertificateResponse {
    pub certificate: CertificateDetail,
}

#[derive(Debug, Serialize)]
pub struct CertificateDetail {
    pub id: i64,
    pub kid: String,
    pub name: String,
    pub public_key: String,
    pub is_active: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ListCertificatesResponse {
    pub certificates: Vec<CertificateDetail>,
}

#[derive(Debug, Serialize)]
pub struct RevokeCertificateResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteCertificateResponse {
    pub message: String,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn client_to_detail(client: Client) -> ClientDetail {
    ClientDetail {
        id: client.id,
        name: client.name,
        is_active: client.deleted_at.is_none(),
        organization_id: client.organization_id,
        created_at: client.created_at.to_rfc3339(),
    }
}

fn cert_to_detail(cert: ClientCertificate) -> CertificateDetail {
    CertificateDetail {
        id: cert.id,
        kid: cert.kid,
        name: cert.name,
        public_key: cert.public_key,
        is_active: cert.revoked_at.is_none() && cert.deleted_at.is_none(),
        created_at: cert.created_at.to_rfc3339(),
    }
}

// ============================================================================
// Client Management Endpoints
// ============================================================================

/// Create a new client
///
/// POST /v1/organizations/:org/clients
/// Required role: ADMIN or OWNER
pub async fn create_client(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Json(payload): Json<CreateClientRequest>,
) -> Result<(StatusCode, Json<CreateClientResponse>)> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    // Verify organization exists
    let repos = RepositoryContext::new((*state.storage).clone());
    repos
        .org
        .get(org_ctx.organization_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    // Generate ID for the client
    let client_id = IdGenerator::next_id();

    // Create client entity
    let client = Client::new(
        client_id,
        org_ctx.organization_id,
        payload.name,
        org_ctx.member.user_id,
    )?;

    // Save to repository
    repos.client.create(client.clone()).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateClientResponse {
            client: ClientInfo {
                id: client.id,
                name: client.name.clone(),
                description: payload.description.unwrap_or_default(),
                is_active: client.deleted_at.is_none(),
                organization_id: client.organization_id,
                created_at: client.created_at.to_rfc3339(),
            },
        }),
    ))
}

/// List all clients in an organization
///
/// GET /v1/organizations/:org/clients?limit=50&offset=0
/// Required role: MEMBER or higher
pub async fn list_clients(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    pagination: crate::pagination::PaginationQuery,
) -> Result<Json<ListClientsResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    let params = pagination.0.validate();

    let repos = RepositoryContext::new((*state.storage).clone());
    let all_clients = repos
        .client
        .list_active_by_organization(org_ctx.organization_id)
        .await?;

    // Apply pagination
    let total = all_clients.len();
    let clients: Vec<ClientDetail> = all_clients
        .into_iter()
        .map(client_to_detail)
        .skip(params.offset)
        .take(params.limit)
        .collect();

    let pagination_meta = crate::pagination::PaginationMeta::from_total(
        total,
        params.offset,
        params.limit,
        clients.len(),
    );

    Ok(Json(ListClientsResponse {
        clients,
        pagination: Some(pagination_meta),
    }))
}

/// Get a specific client
///
/// GET /v1/organizations/:org/clients/:client
/// Required role: MEMBER or higher
pub async fn get_client(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, client_id)): Path<(i64, i64)>,
) -> Result<Json<GetClientResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());
    let client = repos
        .client
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    // Verify client belongs to this organization
    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    Ok(Json(GetClientResponse {
        client: client_to_detail(client),
    }))
}

/// Update a client
///
/// PATCH /v1/organizations/:org/clients/:client
/// Required role: ADMIN or OWNER
pub async fn update_client(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, client_id)): Path<(i64, i64)>,
    Json(payload): Json<UpdateClientRequest>,
) -> Result<Json<UpdateClientResponse>> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());
    let mut client = repos
        .client
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    // Verify client belongs to this organization
    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    // Validate and update name
    Client::validate_name(&payload.name)?;
    client.name = payload.name.clone();

    // Save changes
    repos.client.update(client.clone()).await?;

    Ok(Json(UpdateClientResponse {
        id: client.id,
        name: client.name,
    }))
}

/// Delete a client (soft delete)
///
/// DELETE /v1/organizations/:org/clients/:client
/// Required role: ADMIN or OWNER
pub async fn delete_client(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, client_id)): Path<(i64, i64)>,
) -> Result<Json<DeleteClientResponse>> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    let repos = RepositoryContext::new((*state.storage).clone());
    let mut client = repos
        .client
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    // Verify client belongs to this organization
    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    // Soft delete
    client.mark_deleted();
    repos.client.update(client).await?;

    Ok(Json(DeleteClientResponse {
        message: "Client deleted successfully".to_string(),
    }))
}

/// Deactivate a client (soft delete)
///
/// POST /v1/organizations/:org/clients/:client/deactivate
/// Required role: ADMIN or OWNER
pub async fn deactivate_client(
    state: State<AppState>,
    org_ctx: Extension<OrganizationContext>,
    path: Path<(i64, i64)>,
) -> Result<Json<DeleteClientResponse>> {
    // Just call delete_client (which does soft delete)
    delete_client(state, org_ctx, path).await
}

// ============================================================================
// Certificate Management Endpoints
// ============================================================================

/// Create a new certificate for a client
///
/// POST /v1/organizations/:org/clients/:client/certificates
/// Required role: ADMIN or OWNER
pub async fn create_certificate(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, client_id)): Path<(i64, i64)>,
    Json(payload): Json<CreateCertificateRequest>,
) -> Result<(StatusCode, Json<CreateCertificateResponse>)> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    // Verify client exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let client = repos
        .client
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    if client.is_deleted() {
        return Err(CoreError::Validation(
            "Cannot create certificate for deleted client".to_string(),
        )
        .into());
    }

    // Generate Ed25519 key pair
    let (public_key_base64, private_key_bytes) = keypair::generate();

    // Encrypt private key for storage
    let master_secret = state
        .config
        .auth
        .key_encryption_secret
        .as_ref()
        .ok_or_else(|| CoreError::Internal("Key encryption secret not configured".to_string()))?
        .as_bytes();
    let encryptor = PrivateKeyEncryptor::new(master_secret)?;

    let private_key_encrypted = encryptor.encrypt(&private_key_bytes)?;

    // Generate ID for the certificate
    let cert_id = IdGenerator::next_id();

    // Create certificate entity
    let cert = ClientCertificate::new(
        cert_id,
        client_id,
        org_ctx.organization_id,
        public_key_base64.clone(),
        private_key_encrypted,
        payload.name,
        org_ctx.member.user_id,
    )?;

    // Save to repository
    repos.client_certificate.create(cert.clone()).await?;

    // Return private key (base64 encoded) - this is the ONLY time it will be available unencrypted
    let private_key_base64 = BASE64.encode(&private_key_bytes);

    Ok((
        StatusCode::CREATED,
        Json(CreateCertificateResponse {
            certificate: CertificateInfo {
                id: cert.id,
                kid: cert.kid.clone(),
                name: cert.name.clone(),
                public_key: public_key_base64,
                is_active: cert.revoked_at.is_none() && cert.deleted_at.is_none(),
                created_at: cert.created_at.to_rfc3339(),
            },
            private_key: private_key_base64,
        }),
    ))
}

/// List all certificates for a client
///
/// GET /v1/organizations/:org/clients/:client/certificates
/// Required role: MEMBER or higher
pub async fn list_certificates(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, client_id)): Path<(i64, i64)>,
) -> Result<Json<ListCertificatesResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    // Verify client exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let client = repos
        .client
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    let certs = repos.client_certificate.list_by_client(client_id).await?;

    Ok(Json(ListCertificatesResponse {
        certificates: certs.into_iter().map(cert_to_detail).collect(),
    }))
}

/// Get a specific certificate
///
/// GET /v1/organizations/:org/clients/:client/certificates/:cert
/// Required role: MEMBER or higher
pub async fn get_certificate(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, client_id, cert_id)): Path<(i64, i64, i64)>,
) -> Result<Json<GetCertificateResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    // Verify client exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let client = repos
        .client
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    // Get certificate
    let cert = repos
        .client_certificate
        .get(cert_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Certificate not found".to_string()))?;

    // Verify certificate belongs to this client
    if cert.client_id != client_id {
        return Err(CoreError::NotFound("Certificate not found".to_string()).into());
    }

    Ok(Json(GetCertificateResponse {
        certificate: cert_to_detail(cert),
    }))
}

/// Revoke a certificate
///
/// POST /v1/organizations/:org/clients/:client/certificates/:cert/revoke
/// Required role: ADMIN or OWNER
pub async fn revoke_certificate(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, client_id, cert_id)): Path<(i64, i64, i64)>,
) -> Result<Json<RevokeCertificateResponse>> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    // Verify client exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let client = repos
        .client
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    // Get certificate
    let mut cert = repos
        .client_certificate
        .get(cert_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Certificate not found".to_string()))?;

    // Verify certificate belongs to this client
    if cert.client_id != client_id {
        return Err(CoreError::NotFound("Certificate not found".to_string()).into());
    }

    if cert.is_revoked() {
        return Err(CoreError::Validation("Certificate is already revoked".to_string()).into());
    }

    // Revoke the certificate
    cert.mark_revoked(org_ctx.member.user_id);
    repos.client_certificate.update(cert).await?;

    Ok(Json(RevokeCertificateResponse {
        message: "Certificate revoked successfully".to_string(),
    }))
}

/// Delete a certificate
///
/// DELETE /v1/organizations/:org/clients/:client/certificates/:cert
/// Required role: ADMIN or OWNER
pub async fn delete_certificate(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, client_id, cert_id)): Path<(i64, i64, i64)>,
) -> Result<Json<DeleteCertificateResponse>> {
    // Require admin or owner role
    require_admin_or_owner(&org_ctx)?;

    // Verify client exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let client = repos
        .client
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    // Get certificate
    let cert = repos
        .client_certificate
        .get(cert_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Certificate not found".to_string()))?;

    // Verify certificate belongs to this client
    if cert.client_id != client_id {
        return Err(CoreError::NotFound("Certificate not found".to_string()).into());
    }

    // Delete the certificate
    repos.client_certificate.delete(cert_id).await?;

    Ok(Json(DeleteCertificateResponse {
        message: "Certificate deleted successfully".to_string(),
    }))
}
