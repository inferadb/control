//! Client (app) and certificate (assertion) management handlers.
//!
//! All operations delegate to Ledger SDK via the service layer.
//! "Clients" in the Control API map to "apps" in Ledger terminology.
//! "Certificates" map to "client assertions" in Ledger.

use std::time::Instant;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use inferadb_control_core::SdkResultExt;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{AppSlug, ClientAssertionId, OrganizationSlug};
use serde::{Deserialize, Serialize};

use super::common::{
    MessageResponse, require_ledger, safe_id_cast, system_time_to_rfc3339, validate_description,
    validate_name,
};
use crate::{
    handlers::state::{AppState, Result},
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

/// Certificate (assertion) response.
#[derive(Debug, Serialize)]
pub struct CertificateResponse {
    pub slug: u64,
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
) -> std::result::Result<CertificateResponse, CoreError> {
    Ok(CertificateResponse {
        slug: safe_id_cast(info.id.value())?,
        name: info.name.clone(),
        enabled: info.enabled,
        expires_at: system_time_to_rfc3339(&info.expires_at),
        created_at: system_time_to_rfc3339(&info.created_at),
    })
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
    validate_name(&payload.name)?;
    validate_description(&payload.description)?;
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let info = ledger
        .create_app(
            OrganizationSlug::new(org),
            claims.user_slug,
            &payload.name,
            payload.description,
        )
        .await
        .map_sdk_err_instrumented("create_app", start)?;

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

    let start = Instant::now();
    let apps = ledger
        .list_apps(OrganizationSlug::new(org), claims.user_slug)
        .await
        .map_sdk_err_instrumented("list_apps", start)?;

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

    let start = Instant::now();
    let info = ledger
        .get_app(OrganizationSlug::new(org), claims.user_slug, AppSlug::new(client))
        .await
        .map_sdk_err_instrumented("get_app", start)?;

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
    if let Some(ref name) = payload.name {
        validate_name(name)?;
    }
    validate_description(&payload.description)?;
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let info = ledger
        .update_app(
            OrganizationSlug::new(org),
            claims.user_slug,
            AppSlug::new(client),
            payload.name,
            payload.description,
        )
        .await
        .map_sdk_err_instrumented("update_app", start)?;

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

    let start = Instant::now();
    ledger
        .delete_app(OrganizationSlug::new(org), claims.user_slug, AppSlug::new(client))
        .await
        .map_sdk_err_instrumented("delete_app", start)?;

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

    let start = Instant::now();
    let result = ledger
        .create_app_client_assertion(
            OrganizationSlug::new(org),
            claims.user_slug,
            AppSlug::new(client),
            &payload.name,
            expires_at_system,
        )
        .await
        .map_sdk_err_instrumented("create_app_client_assertion", start)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateCertificateResponse {
            certificate: assertion_to_response(&result.assertion)?,
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

    let start = Instant::now();
    let assertions = ledger
        .list_app_client_assertions(
            OrganizationSlug::new(org),
            claims.user_slug,
            AppSlug::new(client),
        )
        .await
        .map_sdk_err_instrumented("list_app_client_assertions", start)?;

    Ok(Json(ListCertificatesResponse {
        certificates: assertions
            .iter()
            .map(assertion_to_response)
            .collect::<std::result::Result<Vec<_>, _>>()?,
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

    let start = Instant::now();
    let assertions = ledger
        .list_app_client_assertions(
            OrganizationSlug::new(org),
            claims.user_slug,
            AppSlug::new(client),
        )
        .await
        .map_sdk_err_instrumented("list_app_client_assertions", start)?;

    let assertion = assertions
        .iter()
        .find(|a| safe_id_cast(a.id.value()).ok() == Some(cert_id))
        .ok_or_else(|| CoreError::not_found("Certificate not found"))?;

    Ok(Json(assertion_to_response(assertion)?))
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

    let start = Instant::now();
    ledger
        .delete_app_client_assertion(
            OrganizationSlug::new(org),
            claims.user_slug,
            AppSlug::new(client),
            ClientAssertionId::new(
                i64::try_from(cert_id)
                    .map_err(|_| CoreError::not_found("Certificate not found"))?,
            ),
        )
        .await
        .map_sdk_err_instrumented("delete_app_client_assertion", start)?;

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

    let start = Instant::now();
    let secret = ledger
        .rotate_app_client_secret(
            OrganizationSlug::new(org),
            claims.user_slug,
            AppSlug::new(client),
        )
        .await
        .map_sdk_err_instrumented("rotate_app_client_secret", start)?;

    Ok(Json(RotateSecretResponse { secret }))
}
