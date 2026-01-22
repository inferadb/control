use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chrono::{Duration, Utc};
use inferadb_control_core::{
    Error as CoreError, IdGenerator, MasterKey, PrivateKeyEncryptor, RepositoryContext, keypair,
};
use inferadb_control_types::{
    dto::{
        CertificateDetail, CertificateInfo, ClientDetail, ClientInfo, CreateCertificateRequest,
        CreateCertificateResponse, CreateClientRequest, CreateClientResponse, DeleteClientResponse,
        GetCertificateResponse, GetClientResponse, ListCertificatesResponse, ListClientsResponse,
        RevokeCertificateResponse, RotateCertificateRequest, RotateCertificateResponse,
        UpdateClientRequest, UpdateClientResponse,
    },
    entities::{AuditEventType, AuditResourceType, Client, ClientCertificate},
};
use inferadb_storage::auth::PublicSigningKey;
use serde_json::json;

use crate::{
    AppState,
    audit::{AuditEventParams, log_audit_event},
    handlers::auth::Result,
    middleware::{OrganizationContext, require_admin_or_owner, require_member},
};

// ============================================================================
// Helper Functions
// ============================================================================

fn client_to_detail(client: Client) -> ClientDetail {
    ClientDetail {
        id: client.id,
        name: client.name,
        description: client.description,
        vault_id: client.vault_id,
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
        payload.vault_id,
        payload.name,
        payload.description,
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
                description: client.description,
                vault_id: client.vault_id,
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
    let all_clients = repos.client.list_active_by_organization(org_ctx.organization_id).await?;

    // Apply pagination
    let total = all_clients.len();
    let clients: Vec<ClientDetail> = all_clients
        .into_iter()
        .map(client_to_detail)
        .skip(params.offset)
        .take(params.limit)
        .collect();

    let pagination_meta = inferadb_control_types::PaginationMeta::from_total(
        total,
        params.offset,
        params.limit,
        clients.len(),
    );

    Ok(Json(ListClientsResponse { clients, pagination: Some(pagination_meta) }))
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

    Ok(Json(GetClientResponse { client: client_to_detail(client) }))
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

    // Update fields if provided
    if let Some(name) = payload.name {
        client.set_name(name)?;
    }
    if let Some(description) = payload.description {
        client.set_description(description);
    }
    if let Some(vault_id) = payload.vault_id {
        client.set_vault_id(Some(vault_id));
    }

    // Save changes
    repos.client.update(client.clone()).await?;

    Ok(Json(UpdateClientResponse { client: client_to_detail(client) }))
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

    Ok(Json(DeleteClientResponse { message: "Client deleted successfully".to_string() }))
}

// ============================================================================
// Certificate Management Endpoints
// ============================================================================

/// Create a new certificate for a client
///
/// POST /v1/organizations/:org/clients/:client/certificates
/// Required role: ADMIN or OWNER
///
/// This handler:
/// 1. Generates an Ed25519 keypair
/// 2. Stores the encrypted private key in Control's database
/// 3. Writes the public key to Ledger (in the org's namespace)
/// 4. Returns the private key to the caller (one-time only)
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
    tracing::debug!("Generating Ed25519 keypair for certificate");
    let (public_key_base64, private_key_bytes) = keypair::generate();

    // Encrypt private key for storage
    tracing::debug!("Loading master key for encryption");
    let master_key = MasterKey::load_or_generate(state.config.key_file.as_deref())?;
    let encryptor = PrivateKeyEncryptor::from_master_key(&master_key)?;

    tracing::debug!("Encrypting private key");
    let private_key_encrypted = encryptor.encrypt(&private_key_bytes)?;

    // Generate ID for the certificate
    tracing::debug!("Generating certificate ID");
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

    tracing::debug!(
        cert_id = cert.id,
        client_id = cert.client_id,
        org_id = org_ctx.organization_id,
        kid = %cert.kid,
        "Created certificate entity with kid"
    );

    // Save to repository
    repos.client_certificate.create(cert.clone()).await?;

    tracing::debug!(
        cert_id = cert.id,
        kid = %cert.kid,
        "Certificate saved to repository"
    );

    // Write public key to Ledger (in the org's namespace)
    // This enables Engine to validate tokens without Control connectivity
    let now = Utc::now();
    let public_signing_key = PublicSigningKey {
        kid: cert.kid.clone(),
        public_key: public_key_base64.clone(),
        client_id,
        cert_id: cert.id,
        created_at: now,
        valid_from: now,
        valid_until: None,
        active: true,
        revoked_at: None,
    };

    // org_id maps directly to namespace_id in Ledger
    let namespace_id = org_ctx.organization_id;
    let signing_key_store = state.storage.signing_key_store();

    tracing::debug!(
        namespace_id = namespace_id,
        kid = %cert.kid,
        "Writing public signing key to Ledger"
    );

    // Time the Ledger write operation for metrics
    let ledger_start = std::time::Instant::now();
    signing_key_store.create_key(namespace_id, &public_signing_key).await.map_err(|e| {
        tracing::error!(
            error = %e,
            kid = %cert.kid,
            "Failed to write public signing key to Ledger"
        );
        CoreError::Internal(format!("Failed to register signing key in Ledger: {e}"))
    })?;
    let ledger_duration = ledger_start.elapsed().as_secs_f64();

    // Record metrics for signing key registration
    inferadb_control_core::metrics::record_signing_key_registered(namespace_id, ledger_duration);

    tracing::debug!(
        namespace_id = namespace_id,
        kid = %cert.kid,
        duration_ms = ledger_duration * 1000.0,
        "Public signing key written to Ledger"
    );

    // Log audit event for certificate creation
    log_audit_event(
        &state,
        AuditEventType::ClientCertificateCreated,
        AuditEventParams {
            organization_id: Some(org_ctx.organization_id),
            user_id: Some(org_ctx.member.user_id),
            client_id: Some(client_id),
            resource_type: Some(AuditResourceType::ClientCertificate),
            resource_id: Some(cert.id),
            event_data: Some(json!({
                "kid": cert.kid,
                "created_by": org_ctx.member.user_id,
            })),
            ..Default::default()
        },
    )
    .await;

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

    Ok(Json(GetCertificateResponse { certificate: cert_to_detail(cert) }))
}

/// Revoke a certificate
///
/// DELETE /v1/organizations/:org/clients/:client/certificates/:cert
/// Required role: ADMIN or OWNER
///
/// Revokes the certificate, preventing it from being used for authentication.
/// The certificate record is retained for audit purposes and will be automatically
/// cleaned up after 90 days by a background job.
///
/// This handler:
/// 1. Marks the certificate as revoked in Control's database
/// 2. Revokes the public key in Ledger (propagates within cache TTL)
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

    // Revoke the certificate in Control's database
    cert.mark_revoked(org_ctx.member.user_id);
    repos.client_certificate.update(cert.clone()).await?;

    // Revoke the public key in Ledger
    // org_id maps directly to namespace_id in Ledger
    let namespace_id = org_ctx.organization_id;
    let signing_key_store = state.storage.signing_key_store();

    tracing::debug!(
        namespace_id = namespace_id,
        kid = %cert.kid,
        "Revoking public signing key in Ledger"
    );

    // Time the Ledger revoke operation for metrics
    let ledger_start = std::time::Instant::now();
    signing_key_store
        .revoke_key(namespace_id, &cert.kid, Some("Certificate revoked by user"))
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                kid = %cert.kid,
                "Failed to revoke public signing key in Ledger"
            );
            CoreError::Internal(format!("Failed to revoke signing key in Ledger: {e}"))
        })?;
    let ledger_duration = ledger_start.elapsed().as_secs_f64();

    // Record metrics for signing key revocation
    inferadb_control_core::metrics::record_signing_key_revoked(
        namespace_id,
        "user_requested",
        ledger_duration,
    );

    tracing::debug!(
        namespace_id = namespace_id,
        kid = %cert.kid,
        duration_ms = ledger_duration * 1000.0,
        "Public signing key revoked in Ledger"
    );

    // Log audit event for certificate revocation
    log_audit_event(
        &state,
        AuditEventType::ClientCertificateRevoked,
        AuditEventParams {
            organization_id: Some(org_ctx.organization_id),
            user_id: Some(org_ctx.member.user_id),
            client_id: Some(client_id),
            resource_type: Some(AuditResourceType::ClientCertificate),
            resource_id: Some(cert_id),
            event_data: Some(json!({
                "kid": cert.kid,
                "revoked_by": org_ctx.member.user_id,
            })),
            ..Default::default()
        },
    )
    .await;

    Ok(Json(RevokeCertificateResponse { message: "Certificate revoked successfully".to_string() }))
}

/// Rotate a certificate with a grace period
///
/// POST /v1/organizations/:org/clients/:client/certificates/:cert/rotate
/// Required role: ADMIN or OWNER
///
/// Creates a new certificate that becomes valid after the grace period,
/// allowing the old certificate to remain valid during the overlap. This
/// enables zero-downtime key rotation for clients.
///
/// The old certificate is not modified and remains valid until it expires
/// or is explicitly revoked. The new certificate's `valid_from` is set to
/// `now + grace_period_seconds`.
///
/// # Grace Period
///
/// The grace period (default: 300 seconds / 5 minutes) gives clients time
/// to switch to the new certificate. During this period:
/// - Old certificate: Valid and can be used for authentication
/// - New certificate: Exists but `valid_from` is in the future
///
/// After the grace period:
/// - Old certificate: Still valid (unless revoked or expired)
/// - New certificate: Now valid and can be used for authentication
///
/// This handler:
/// 1. Validates the existing certificate exists and is active
/// 2. Generates a new Ed25519 keypair
/// 3. Stores the new certificate in Control's database
/// 4. Writes the new public key to Ledger with `valid_from` in the future
/// 5. Returns both the new private key and info about the rotated certificate
pub async fn rotate_certificate(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Path((_org_id, client_id, cert_id)): Path<(i64, i64, i64)>,
    Json(payload): Json<RotateCertificateRequest>,
) -> Result<(StatusCode, Json<RotateCertificateResponse>)> {
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
            "Cannot rotate certificate for deleted client".to_string(),
        )
        .into());
    }

    // Get the certificate to rotate
    let old_cert = repos
        .client_certificate
        .get(cert_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Certificate not found".to_string()))?;

    // Verify certificate belongs to this client
    if old_cert.client_id != client_id {
        return Err(CoreError::NotFound("Certificate not found".to_string()).into());
    }

    // Cannot rotate a revoked certificate
    if old_cert.is_revoked() {
        return Err(CoreError::Validation("Cannot rotate a revoked certificate".to_string()).into());
    }

    // Generate new Ed25519 key pair
    tracing::debug!("Generating Ed25519 keypair for rotated certificate");
    let (public_key_base64, private_key_bytes) = keypair::generate();

    // Encrypt private key for storage
    tracing::debug!("Loading master key for encryption");
    let master_key = MasterKey::load_or_generate(state.config.key_file.as_deref())?;
    let encryptor = PrivateKeyEncryptor::from_master_key(&master_key)?;

    tracing::debug!("Encrypting private key");
    let private_key_encrypted = encryptor.encrypt(&private_key_bytes)?;

    // Generate ID for the new certificate
    tracing::debug!("Generating certificate ID");
    let new_cert_id = IdGenerator::next_id();

    // Create new certificate entity
    let new_cert = ClientCertificate::new(
        new_cert_id,
        client_id,
        org_ctx.organization_id,
        public_key_base64.clone(),
        private_key_encrypted,
        payload.name,
        org_ctx.member.user_id,
    )?;

    tracing::debug!(
        new_cert_id = new_cert.id,
        old_cert_id = old_cert.id,
        client_id = new_cert.client_id,
        org_id = org_ctx.organization_id,
        kid = %new_cert.kid,
        grace_period_seconds = payload.grace_period_seconds,
        "Created rotated certificate entity"
    );

    // Save new certificate to repository
    repos.client_certificate.create(new_cert.clone()).await?;

    tracing::debug!(
        new_cert_id = new_cert.id,
        kid = %new_cert.kid,
        "Rotated certificate saved to repository"
    );

    // Calculate valid_from with grace period
    let now = Utc::now();
    let valid_from = now + Duration::seconds(payload.grace_period_seconds as i64);

    // Write public key to Ledger with valid_from in the future
    let public_signing_key = PublicSigningKey {
        kid: new_cert.kid.clone(),
        public_key: public_key_base64.clone(),
        client_id,
        cert_id: new_cert.id,
        created_at: now,
        valid_from,
        valid_until: None,
        active: true,
        revoked_at: None,
    };

    // org_id maps directly to namespace_id in Ledger
    let namespace_id = org_ctx.organization_id;
    let signing_key_store = state.storage.signing_key_store();

    tracing::debug!(
        namespace_id = namespace_id,
        kid = %new_cert.kid,
        valid_from = %valid_from,
        "Writing rotated public signing key to Ledger"
    );

    // Time the Ledger write operation for metrics
    let ledger_start = std::time::Instant::now();
    signing_key_store.create_key(namespace_id, &public_signing_key).await.map_err(|e| {
        tracing::error!(
            error = %e,
            kid = %new_cert.kid,
            "Failed to write rotated public signing key to Ledger"
        );
        CoreError::Internal(format!("Failed to register signing key in Ledger: {e}"))
    })?;
    let ledger_duration = ledger_start.elapsed().as_secs_f64();

    // Record metrics for signing key rotation
    inferadb_control_core::metrics::record_signing_key_rotated(namespace_id, ledger_duration);

    tracing::info!(
        namespace_id = namespace_id,
        old_kid = %old_cert.kid,
        new_kid = %new_cert.kid,
        valid_from = %valid_from,
        duration_ms = ledger_duration * 1000.0,
        "Certificate rotated successfully"
    );

    // Log audit event for certificate rotation
    log_audit_event(
        &state,
        AuditEventType::ClientCertificateRotated,
        AuditEventParams {
            organization_id: Some(org_ctx.organization_id),
            user_id: Some(org_ctx.member.user_id),
            client_id: Some(client_id),
            resource_type: Some(AuditResourceType::ClientCertificate),
            resource_id: Some(new_cert.id),
            event_data: Some(json!({
                "new_kid": new_cert.kid,
                "old_kid": old_cert.kid,
                "old_cert_id": old_cert.id,
                "grace_period_seconds": payload.grace_period_seconds,
                "valid_from": valid_from.to_rfc3339(),
                "rotated_by": org_ctx.member.user_id,
            })),
            ..Default::default()
        },
    )
    .await;

    // Return private key (base64 encoded) - this is the ONLY time it will be available
    let private_key_base64 = BASE64.encode(&private_key_bytes);

    Ok((
        StatusCode::CREATED,
        Json(RotateCertificateResponse {
            certificate: CertificateInfo {
                id: new_cert.id,
                kid: new_cert.kid.clone(),
                name: new_cert.name.clone(),
                public_key: public_key_base64,
                is_active: true,
                created_at: new_cert.created_at.to_rfc3339(),
            },
            valid_from: valid_from.to_rfc3339(),
            rotated_from: CertificateInfo {
                id: old_cert.id,
                kid: old_cert.kid.clone(),
                name: old_cert.name.clone(),
                public_key: old_cert.public_key.clone(),
                is_active: old_cert.revoked_at.is_none() && old_cert.deleted_at.is_none(),
                created_at: old_cert.created_at.to_rfc3339(),
            },
            private_key: private_key_base64,
        }),
    ))
}
