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
    keypair, Client, ClientCertificate, ClientCertificateRepository, ClientRepository,
    Error as CoreError, IdGenerator, OrganizationRepository, PrivateKeyEncryptor,
};
use serde::{Deserialize, Serialize};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreateClientResponse {
    pub id: i64,
    pub name: String,
    pub organization_id: i64,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ClientResponse {
    pub id: i64,
    pub name: String,
    pub organization_id: i64,
    pub created_at: String,
    pub created_by_user_id: i64,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListClientsResponse {
    pub clients: Vec<ClientResponse>,
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
    pub id: i64,
    pub kid: String,
    pub name: String,
    pub public_key: String,
    pub private_key: String, // Unencrypted private key (base64) - only returned once!
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct CertificateResponse {
    pub id: i64,
    pub kid: String,
    pub name: String,
    pub public_key: String,
    pub created_at: String,
    pub created_by_user_id: i64,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub revoked_by_user_id: Option<i64>,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListCertificatesResponse {
    pub certificates: Vec<CertificateResponse>,
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

fn client_to_response(client: Client) -> ClientResponse {
    ClientResponse {
        id: client.id,
        name: client.name,
        organization_id: client.organization_id,
        created_at: client.created_at.to_rfc3339(),
        created_by_user_id: client.created_by_user_id,
        deleted_at: client.deleted_at.map(|dt| dt.to_rfc3339()),
    }
}

fn cert_to_response(cert: ClientCertificate) -> CertificateResponse {
    CertificateResponse {
        id: cert.id,
        kid: cert.kid,
        name: cert.name,
        public_key: cert.public_key,
        created_at: cert.created_at.to_rfc3339(),
        created_by_user_id: cert.created_by_user_id,
        last_used_at: cert.last_used_at.map(|dt| dt.to_rfc3339()),
        revoked_at: cert.revoked_at.map(|dt| dt.to_rfc3339()),
        revoked_by_user_id: cert.revoked_by_user_id,
        deleted_at: cert.deleted_at.map(|dt| dt.to_rfc3339()),
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
    let org_repo = OrganizationRepository::new((*state.storage).clone());
    org_repo
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
    let client_repo = ClientRepository::new((*state.storage).clone());
    client_repo.create(client.clone()).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateClientResponse {
            id: client.id,
            name: client.name,
            organization_id: client.organization_id,
            created_at: client.created_at.to_rfc3339(),
        }),
    ))
}

/// List all clients in an organization
///
/// GET /v1/organizations/:org/clients
/// Required role: MEMBER or higher
pub async fn list_clients(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
) -> Result<Json<ListClientsResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    let client_repo = ClientRepository::new((*state.storage).clone());
    let clients = client_repo
        .list_active_by_organization(org_ctx.organization_id)
        .await?;

    Ok(Json(ListClientsResponse {
        clients: clients.into_iter().map(client_to_response).collect(),
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
) -> Result<Json<ClientResponse>> {
    // Require member role or higher
    require_member(&org_ctx)?;

    let client_repo = ClientRepository::new((*state.storage).clone());
    let client = client_repo
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    // Verify client belongs to this organization
    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    Ok(Json(client_to_response(client)))
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

    let client_repo = ClientRepository::new((*state.storage).clone());
    let mut client = client_repo
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
    client_repo.update(client.clone()).await?;

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

    let client_repo = ClientRepository::new((*state.storage).clone());
    let mut client = client_repo
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    // Verify client belongs to this organization
    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    // Soft delete
    client.mark_deleted();
    client_repo.update(client).await?;

    Ok(Json(DeleteClientResponse {
        message: "Client deleted successfully".to_string(),
    }))
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
    let client_repo = ClientRepository::new((*state.storage).clone());
    let client = client_repo
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
    let cert_repo = ClientCertificateRepository::new((*state.storage).clone());
    cert_repo.create(cert.clone()).await?;

    // Return private key (base64 encoded) - this is the ONLY time it will be available unencrypted
    let private_key_base64 = BASE64.encode(&private_key_bytes);

    Ok((
        StatusCode::CREATED,
        Json(CreateCertificateResponse {
            id: cert.id,
            kid: cert.kid,
            name: cert.name,
            public_key: public_key_base64,
            private_key: private_key_base64,
            created_at: cert.created_at.to_rfc3339(),
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
    let client_repo = ClientRepository::new((*state.storage).clone());
    let client = client_repo
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    let cert_repo = ClientCertificateRepository::new((*state.storage).clone());
    let certs = cert_repo.list_by_client(client_id).await?;

    Ok(Json(ListCertificatesResponse {
        certificates: certs.into_iter().map(cert_to_response).collect(),
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
    let client_repo = ClientRepository::new((*state.storage).clone());
    let client = client_repo
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    // Get certificate
    let cert_repo = ClientCertificateRepository::new((*state.storage).clone());
    let mut cert = cert_repo
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
    cert_repo.update(cert).await?;

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
    let client_repo = ClientRepository::new((*state.storage).clone());
    let client = client_repo
        .get(client_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

    if client.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Client not found".to_string()).into());
    }

    // Get certificate
    let cert_repo = ClientCertificateRepository::new((*state.storage).clone());
    let cert = cert_repo
        .get(cert_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Certificate not found".to_string()))?;

    // Verify certificate belongs to this client
    if cert.client_id != client_id {
        return Err(CoreError::NotFound("Certificate not found".to_string()).into());
    }

    // Delete the certificate
    cert_repo.delete(cert_id).await?;

    Ok(Json(DeleteCertificateResponse {
        message: "Certificate deleted successfully".to_string(),
    }))
}
