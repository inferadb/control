use bon::Builder;
use serde::{Deserialize, Deserializer, Serialize};

/// Helper to deserialize either string or integer as Option<i64>
/// This is needed because Terraform sends IDs as strings, but our API expects i64
fn deserialize_optional_string_or_number<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    use std::fmt;

    use serde::de::{self, Visitor};

    struct OptionalStringOrNumber;

    impl<'de> Visitor<'de> for OptionalStringOrNumber {
        type Value = Option<i64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("null, a string, or a number")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value as i64))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.is_empty() {
                Ok(None)
            } else {
                value.parse::<i64>().map(Some).map_err(de::Error::custom)
            }
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&value)
        }
    }

    deserializer.deserialize_any(OptionalStringOrNumber)
}

#[derive(Debug, Deserialize, Builder)]
#[builder(on(String, into))]
pub struct CreateClientRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_number")]
    pub vault_id: Option<i64>,
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
    pub vault_id: Option<i64>,
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
    pub description: String,
    pub vault_id: Option<i64>,
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
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string_or_number")]
    pub vault_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UpdateClientResponse {
    pub client: ClientDetail,
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

/// Request to rotate a certificate with a grace period.
///
/// Rotation creates a new certificate that becomes valid after the grace period,
/// allowing the old certificate to remain valid during the overlap. This enables
/// zero-downtime key rotation for clients.
#[derive(Debug, Deserialize)]
pub struct RotateCertificateRequest {
    /// Name for the new certificate
    pub name: String,
    /// Grace period in seconds before the new key becomes valid (default: 300)
    #[serde(default = "default_grace_period_seconds")]
    pub grace_period_seconds: u64,
}

fn default_grace_period_seconds() -> u64 {
    300 // 5 minutes
}

/// Response from rotating a certificate.
///
/// Contains the new certificate info and private key. The old certificate
/// remains valid until the new certificate's `valid_from` time.
#[derive(Debug, Serialize)]
pub struct RotateCertificateResponse {
    /// The new rotated certificate
    pub certificate: CertificateInfo,
    /// The new certificate's `valid_from` timestamp (RFC 3339)
    pub valid_from: String,
    /// The old certificate that was rotated (remains valid during grace period)
    pub rotated_from: CertificateInfo,
    /// Unencrypted private key (base64) - only returned once!
    pub private_key: String,
}
