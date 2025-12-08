use serde::{Deserialize, Serialize};

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
    pub pagination: Option<crate::PaginationMeta>,
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
