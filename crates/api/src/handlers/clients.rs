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

/// Client summary.
#[derive(Debug, Serialize)]
pub struct ClientResponse {
    /// Client slug identifier.
    pub slug: u64,
    /// Display name.
    pub name: String,
    /// Optional human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the client is enabled for authentication.
    pub enabled: bool,
    /// Credential methods configured for this client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<CredentialsResponse>,
    /// RFC 3339 creation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// RFC 3339 last-update timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Credential configuration for a client.
#[derive(Debug, Serialize)]
pub struct CredentialsResponse {
    /// Whether client secret authentication is enabled.
    pub client_secret_enabled: bool,
    /// Whether mTLS with CA-issued certificates is enabled.
    pub mtls_ca_enabled: bool,
    /// Whether mTLS with self-signed certificates is enabled.
    pub mtls_self_signed_enabled: bool,
    /// Whether JWT client assertion (RFC 7523) is enabled.
    pub client_assertion_enabled: bool,
}

/// Wrapper for a single client.
#[derive(Debug, Serialize)]
pub struct SingleClientResponse {
    pub client: ClientResponse,
}

/// Response containing clients for an organization.
#[derive(Debug, Serialize)]
pub struct ListClientsResponse {
    pub clients: Vec<ClientResponse>,
}

/// Certificate (client assertion) response.
#[derive(Debug, Serialize)]
pub struct CertificateResponse {
    /// Certificate slug identifier.
    pub slug: u64,
    /// Friendly name (e.g., `"prod-cert"`).
    pub name: String,
    /// Whether the certificate is active.
    pub enabled: bool,
    /// RFC 3339 expiration timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// RFC 3339 creation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// Response containing certificates for a client.
#[derive(Debug, Serialize)]
pub struct ListCertificatesResponse {
    pub certificates: Vec<CertificateResponse>,
}

/// Response for a newly created certificate, including the private key PEM.
///
/// The private key is only available in this response and cannot be retrieved later.
#[derive(Debug, Serialize)]
pub struct CreateCertificateResponse {
    pub certificate: CertificateResponse,
    pub private_key_pem: String,
}

/// Response containing the new client secret after rotation.
#[derive(Debug, Serialize)]
pub struct RotateSecretResponse {
    pub secret: String,
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Converts a Ledger [`AppInfo`](inferadb_ledger_sdk::AppInfo) to an API response.
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

/// Converts a Ledger [`AppClientAssertionInfo`](inferadb_ledger_sdk::AppClientAssertionInfo) to an
/// API response.
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

/// POST /control/v1/organizations/{org}/clients
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

/// GET /control/v1/organizations/{org}/clients
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

/// GET /control/v1/organizations/{org}/clients/{client}
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

/// PATCH /control/v1/organizations/{org}/clients/{client}
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

/// DELETE /control/v1/organizations/{org}/clients/{client}
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

/// POST /control/v1/organizations/{org}/clients/{client}/certificates
///
/// Creates a new certificate (client assertion) for a client. Returns the
/// private key PEM. The private key is only available in this response.
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

/// GET /control/v1/organizations/{org}/clients/{client}/certificates
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

/// GET /control/v1/organizations/{org}/clients/{client}/certificates/{cert}
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

/// DELETE /control/v1/organizations/{org}/clients/{client}/certificates/{cert}
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

/// POST /control/v1/organizations/{org}/clients/{client}/secret/rotate
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::SystemTime;

    use inferadb_ledger_sdk::{AppClientAssertionInfo, AppCredentialsInfo, AppInfo, AppSlug};
    use inferadb_ledger_types::ClientAssertionId;

    use super::*;

    fn sample_app_info() -> AppInfo {
        AppInfo {
            slug: AppSlug::new(500),
            name: "Test App".to_string(),
            description: Some("A test application".to_string()),
            enabled: true,
            credentials: Some(AppCredentialsInfo {
                client_secret_enabled: true,
                mtls_ca_enabled: false,
                mtls_self_signed_enabled: false,
                client_assertion_enabled: true,
            }),
            created_at: Some(SystemTime::now()),
            updated_at: Some(SystemTime::now()),
        }
    }

    fn sample_assertion_info() -> AppClientAssertionInfo {
        AppClientAssertionInfo {
            id: ClientAssertionId::new(42),
            name: "prod-cert".to_string(),
            enabled: true,
            expires_at: Some(SystemTime::now()),
            created_at: Some(SystemTime::now()),
        }
    }

    // ── app_info_to_response ─────────────────────────────────────────

    #[test]
    fn app_info_to_response_maps_all_fields() {
        let info = sample_app_info();
        let resp = app_info_to_response(&info);
        assert_eq!(resp.slug, 500);
        assert_eq!(resp.name, "Test App");
        assert_eq!(resp.description.as_deref(), Some("A test application"));
        assert!(resp.enabled);
        assert!(resp.credentials.is_some());
        assert!(resp.created_at.is_some());
        assert!(resp.updated_at.is_some());
    }

    #[test]
    fn app_info_to_response_without_credentials() {
        let mut info = sample_app_info();
        info.credentials = None;
        let resp = app_info_to_response(&info);
        assert!(resp.credentials.is_none());
    }

    #[test]
    fn app_info_to_response_without_description() {
        let mut info = sample_app_info();
        info.description = None;
        let resp = app_info_to_response(&info);
        assert!(resp.description.is_none());
    }

    #[test]
    fn app_info_to_response_without_timestamps() {
        let mut info = sample_app_info();
        info.created_at = None;
        info.updated_at = None;
        let resp = app_info_to_response(&info);
        assert!(resp.created_at.is_none());
        assert!(resp.updated_at.is_none());
    }

    #[test]
    fn app_info_to_response_credentials_fields() {
        let info = sample_app_info();
        let resp = app_info_to_response(&info);
        let creds = resp.credentials.unwrap();
        assert!(creds.client_secret_enabled);
        assert!(!creds.mtls_ca_enabled);
        assert!(!creds.mtls_self_signed_enabled);
        assert!(creds.client_assertion_enabled);
    }

    // ── assertion_to_response ────────────────────────────────────────

    #[test]
    fn assertion_to_response_maps_fields() {
        let info = sample_assertion_info();
        let resp = assertion_to_response(&info).unwrap();
        assert_eq!(resp.slug, 42);
        assert_eq!(resp.name, "prod-cert");
        assert!(resp.enabled);
        assert!(resp.expires_at.is_some());
        assert!(resp.created_at.is_some());
    }

    #[test]
    fn assertion_to_response_without_timestamps() {
        let mut info = sample_assertion_info();
        info.expires_at = None;
        info.created_at = None;
        let resp = assertion_to_response(&info).unwrap();
        assert!(resp.expires_at.is_none());
        assert!(resp.created_at.is_none());
    }

    #[test]
    fn assertion_to_response_negative_id_returns_error() {
        let info = AppClientAssertionInfo {
            id: ClientAssertionId::new(-1),
            name: "bad".to_string(),
            enabled: false,
            expires_at: None,
            created_at: None,
        };
        assert!(assertion_to_response(&info).is_err());
    }

    // ── Response type serialization ──────────────────────────────────

    #[test]
    fn client_response_omits_null_optional_fields() {
        let resp = ClientResponse {
            slug: 1,
            name: "App".to_string(),
            description: None,
            enabled: true,
            credentials: None,
            created_at: None,
            updated_at: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("description").is_none());
        assert!(json.get("credentials").is_none());
        assert!(json.get("created_at").is_none());
        assert!(json.get("updated_at").is_none());
    }

    #[test]
    fn certificate_response_omits_null_optional_fields() {
        let resp = CertificateResponse {
            slug: 1,
            name: "cert".to_string(),
            enabled: true,
            expires_at: None,
            created_at: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("expires_at").is_none());
        assert!(json.get("created_at").is_none());
    }

    #[test]
    fn rotate_secret_response_serializes() {
        let resp = RotateSecretResponse { secret: "new-secret-value".to_string() };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["secret"], "new-secret-value");
    }

    #[test]
    fn create_certificate_response_serializes() {
        let resp = CreateCertificateResponse {
            certificate: CertificateResponse {
                slug: 10,
                name: "my-cert".to_string(),
                enabled: true,
                expires_at: Some("2027-01-01T00:00:00Z".to_string()),
                created_at: Some("2026-01-01T00:00:00Z".to_string()),
            },
            private_key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
                .to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["certificate"]["slug"], 10);
        assert!(json["private_key_pem"].as_str().unwrap().contains("PRIVATE KEY"));
    }

    // ── Request type deserialization ─────────────────────────────────

    #[test]
    fn create_client_request_deserializes() {
        let json = r#"{"name": "My App"}"#;
        let req: CreateClientRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "My App");
        assert!(req.description.is_none());
    }

    #[test]
    fn create_client_request_deserializes_with_description() {
        let json = r#"{"name": "My App", "description": "A thing"}"#;
        let req: CreateClientRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.description.as_deref(), Some("A thing"));
    }

    #[test]
    fn update_client_request_deserializes_partial() {
        let json = r#"{"name": "New Name"}"#;
        let req: UpdateClientRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("New Name"));
        assert!(req.description.is_none());
    }

    #[test]
    fn create_certificate_request_deserializes() {
        let json = r#"{"name": "prod", "expires_at": "2027-01-01T00:00:00Z"}"#;
        let req: CreateCertificateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "prod");
        assert_eq!(req.expires_at, "2027-01-01T00:00:00Z");
    }
}
