//! Client (app) and certificate (assertion) management handlers.
//!
//! All operations delegate to Ledger SDK via the service layer.
//! "Clients" in the Control API map to "apps" in Ledger terminology.
//! "Certificates" map to "client assertions" in Ledger.

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use inferadb_control_core::service;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{AppSlug, ClientAssertionId, OrganizationSlug};
use serde::{Deserialize, Serialize};

use crate::{
    handlers::auth::{AppState, Result},
    middleware::UserClaims,
};

// ── Request Types ─────────────────────────────────────────────────────

/// Request body for creating a client.
#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    pub description: Option<String>,
}

/// Request body for updating a client.
#[derive(Debug, Deserialize)]
pub struct UpdateClientRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// Request body for creating a certificate (client assertion).
#[derive(Debug, Deserialize)]
pub struct CreateCertificateRequest {
    pub name: String,
    /// ISO 8601 expiration timestamp.
    pub expires_at: String,
}

// ── Response Types ────────────────────────────────────────────────────

/// Client summary response.
#[derive(Debug, Serialize)]
pub struct ClientResponse {
    pub slug: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<CredentialsResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Credential configuration response.
#[derive(Debug, Serialize)]
pub struct CredentialsResponse {
    pub client_secret_enabled: bool,
    pub mtls_ca_enabled: bool,
    pub mtls_self_signed_enabled: bool,
    pub client_assertion_enabled: bool,
}

/// Wrapper for a single client.
#[derive(Debug, Serialize)]
pub struct SingleClientResponse {
    pub client: ClientResponse,
}

/// List of clients.
#[derive(Debug, Serialize)]
pub struct ListClientsResponse {
    pub clients: Vec<ClientResponse>,
}

/// Delete client response.
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

/// Certificate (assertion) response.
#[derive(Debug, Serialize)]
pub struct CertificateResponse {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// List of certificates.
#[derive(Debug, Serialize)]
pub struct ListCertificatesResponse {
    pub certificates: Vec<CertificateResponse>,
}

/// Created certificate response (includes private key PEM).
#[derive(Debug, Serialize)]
pub struct CreateCertificateResponse {
    pub certificate: CertificateResponse,
    pub private_key_pem: String,
}

/// Rotate client secret response.
#[derive(Debug, Serialize)]
pub struct RotateSecretResponse {
    pub secret: String,
}

// ── Helpers ───────────────────────────────────────────────────────────

fn system_time_to_rfc3339(t: &Option<std::time::SystemTime>) -> Option<String> {
    t.map(|st| DateTime::<Utc>::from(st).to_rfc3339())
}

fn app_info_to_response(info: &inferadb_ledger_sdk::AppInfo) -> ClientResponse {
    ClientResponse {
        slug: info.slug.value(),
        name: info.name.clone(),
        description: info.description.clone(),
        enabled: info.enabled,
        credentials: info.credentials.as_ref().map(|c| CredentialsResponse {
            client_secret_enabled: c.client_secret_enabled,
            mtls_ca_enabled: c.mtls_ca_enabled,
            mtls_self_signed_enabled: c.mtls_self_signed_enabled,
            client_assertion_enabled: c.client_assertion_enabled,
        }),
        created_at: system_time_to_rfc3339(&info.created_at),
        updated_at: system_time_to_rfc3339(&info.updated_at),
    }
}

fn assertion_to_response(
    info: &inferadb_ledger_sdk::AppClientAssertionInfo,
) -> CertificateResponse {
    CertificateResponse {
        id: info.id.value(),
        name: info.name.clone(),
        enabled: info.enabled,
        expires_at: system_time_to_rfc3339(&info.expires_at),
        created_at: system_time_to_rfc3339(&info.created_at),
    }
}

fn require_ledger(
    state: &AppState,
) -> std::result::Result<&inferadb_ledger_sdk::LedgerClient, CoreError> {
    state
        .ledger
        .as_ref()
        .map(|arc| arc.as_ref())
        .ok_or_else(|| CoreError::internal("Ledger client not configured"))
}

// ── Client Handlers ──────────────────────────────────────────────────

/// POST /v1/organizations/:org/clients
///
/// Creates a new client (app) in the organization.
pub async fn create_client(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Json(payload): Json<CreateClientRequest>,
) -> Result<(StatusCode, Json<SingleClientResponse>)> {
    let ledger = require_ledger(&state)?;

    let info = service::app::create_app(
        ledger,
        OrganizationSlug::new(org),
        claims.user_slug,
        &payload.name,
        payload.description,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(SingleClientResponse { client: app_info_to_response(&info) })))
}

/// GET /v1/organizations/:org/clients
///
/// Lists all clients (apps) in the organization.
pub async fn list_clients(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
) -> Result<Json<ListClientsResponse>> {
    let ledger = require_ledger(&state)?;

    let apps =
        service::app::list_apps(ledger, OrganizationSlug::new(org), claims.user_slug).await?;

    Ok(Json(ListClientsResponse { clients: apps.iter().map(app_info_to_response).collect() }))
}

/// GET /v1/organizations/:org/clients/:client
///
/// Returns details of a specific client (app).
pub async fn get_client(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, client)): Path<(u64, u64)>,
) -> Result<Json<SingleClientResponse>> {
    let ledger = require_ledger(&state)?;

    let info = service::app::get_app(
        ledger,
        OrganizationSlug::new(org),
        claims.user_slug,
        AppSlug::new(client),
    )
    .await?;

    Ok(Json(SingleClientResponse { client: app_info_to_response(&info) }))
}

/// PATCH /v1/organizations/:org/clients/:client
///
/// Updates a client (app). Ledger enforces role requirements.
pub async fn update_client(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, client)): Path<(u64, u64)>,
    Json(payload): Json<UpdateClientRequest>,
) -> Result<Json<SingleClientResponse>> {
    let ledger = require_ledger(&state)?;

    let info = service::app::update_app(
        ledger,
        OrganizationSlug::new(org),
        claims.user_slug,
        AppSlug::new(client),
        payload.name,
        payload.description,
    )
    .await?;

    Ok(Json(SingleClientResponse { client: app_info_to_response(&info) }))
}

/// DELETE /v1/organizations/:org/clients/:client
///
/// Deletes a client (app). Ledger enforces role requirements.
pub async fn delete_client(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, client)): Path<(u64, u64)>,
) -> Result<Json<MessageResponse>> {
    let ledger = require_ledger(&state)?;

    service::app::delete_app(
        ledger,
        OrganizationSlug::new(org),
        claims.user_slug,
        AppSlug::new(client),
    )
    .await?;

    Ok(Json(MessageResponse { message: "Client deleted successfully".to_string() }))
}

// ── Certificate (Assertion) Handlers ─────────────────────────────────

/// POST /v1/organizations/:org/clients/:client/certificates
///
/// Creates a new certificate (client assertion) for a client. Returns the
/// private key PEM — this is the only time it will be available.
pub async fn create_certificate(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, client)): Path<(u64, u64)>,
    Json(payload): Json<CreateCertificateRequest>,
) -> Result<(StatusCode, Json<CreateCertificateResponse>)> {
    let ledger = require_ledger(&state)?;

    let expires_at: DateTime<Utc> = payload
        .expires_at
        .parse()
        .map_err(|_| CoreError::validation("Invalid expires_at timestamp; expected ISO 8601"))?;
    let expires_at_system = std::time::SystemTime::from(expires_at);

    let result = service::app::create_app_client_assertion(
        ledger,
        OrganizationSlug::new(org),
        claims.user_slug,
        AppSlug::new(client),
        &payload.name,
        expires_at_system,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateCertificateResponse {
            certificate: assertion_to_response(&result.assertion),
            private_key_pem: result.private_key_pem,
        }),
    ))
}

/// GET /v1/organizations/:org/clients/:client/certificates
///
/// Lists all certificates (client assertions) for a client.
pub async fn list_certificates(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, client)): Path<(u64, u64)>,
) -> Result<Json<ListCertificatesResponse>> {
    let ledger = require_ledger(&state)?;

    let assertions = service::app::list_app_client_assertions(
        ledger,
        OrganizationSlug::new(org),
        claims.user_slug,
        AppSlug::new(client),
    )
    .await?;

    Ok(Json(ListCertificatesResponse {
        certificates: assertions.iter().map(assertion_to_response).collect(),
    }))
}

/// GET /v1/organizations/:org/clients/:client/certificates/:cert
///
/// Returns details of a specific certificate (client assertion).
pub async fn get_certificate(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, client, cert_id)): Path<(u64, u64, u64)>,
) -> Result<Json<CertificateResponse>> {
    let ledger = require_ledger(&state)?;

    let assertions = service::app::list_app_client_assertions(
        ledger,
        OrganizationSlug::new(org),
        claims.user_slug,
        AppSlug::new(client),
    )
    .await?;

    let assertion = assertions
        .iter()
        .find(|a| a.id.value() == cert_id as i64)
        .ok_or_else(|| CoreError::not_found("Certificate not found"))?;

    Ok(Json(assertion_to_response(assertion)))
}

/// DELETE /v1/organizations/:org/clients/:client/certificates/:cert
///
/// Revokes a certificate (deletes a client assertion).
pub async fn revoke_certificate(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, client, cert_id)): Path<(u64, u64, u64)>,
) -> Result<Json<MessageResponse>> {
    let ledger = require_ledger(&state)?;

    service::app::delete_app_client_assertion(
        ledger,
        OrganizationSlug::new(org),
        claims.user_slug,
        AppSlug::new(client),
        ClientAssertionId::new(cert_id as i64),
    )
    .await?;

    Ok(Json(MessageResponse { message: "Certificate revoked successfully".to_string() }))
}

/// POST /v1/organizations/:org/clients/:client/certificates/rotate
///
/// Rotates the client secret for a client. Returns the new plaintext secret.
pub async fn rotate_certificate(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((org, client)): Path<(u64, u64)>,
) -> Result<Json<RotateSecretResponse>> {
    let ledger = require_ledger(&state)?;

    let secret = service::app::rotate_app_client_secret(
        ledger,
        OrganizationSlug::new(org),
        claims.user_slug,
        AppSlug::new(client),
    )
    .await?;

    Ok(Json(RotateSecretResponse { secret }))
}
