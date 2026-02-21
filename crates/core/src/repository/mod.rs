use inferadb_control_types::Error;

pub mod audit_log;
pub mod authorization_code;
pub mod client;
pub mod client_certificate;
pub mod jti_replay_protection;
pub mod organization;
pub mod organization_invitation;
pub mod passkey_credential;
pub mod secure_token;
pub mod team;
pub mod user;
pub mod user_email;
pub mod user_email_verification_token;
pub mod user_password_reset_token;
pub mod user_session;
pub mod vault;
pub mod vault_refresh_token;
pub mod vault_schema;

pub use audit_log::{AuditLogFilters, AuditLogRepository};
pub use authorization_code::AuthorizationCodeRepository;
pub use client::ClientRepository;
pub use client_certificate::ClientCertificateRepository;
pub use jti_replay_protection::JtiReplayProtectionRepository;
pub use organization::{OrganizationMemberRepository, OrganizationRepository};
pub use organization_invitation::OrganizationInvitationRepository;
pub use passkey_credential::PasskeyCredentialRepository;
pub use secure_token::SecureTokenRepository;
pub use team::{
    OrganizationTeamMemberRepository, OrganizationTeamPermissionRepository,
    OrganizationTeamRepository,
};
pub use user::UserRepository;
pub use user_email::UserEmailRepository;
pub use user_email_verification_token::UserEmailVerificationTokenRepository;
pub use user_password_reset_token::UserPasswordResetTokenRepository;
pub use user_session::UserSessionRepository;
pub use vault::{VaultRepository, VaultTeamGrantRepository, VaultUserGrantRepository};
pub use vault_refresh_token::VaultRefreshTokenRepository;
pub use vault_schema::VaultSchemaRepository;

/// Parses an i64 from a byte slice.
///
/// Returns an error if the slice doesn't contain exactly 8 bytes.
#[inline]
pub(crate) fn parse_i64_id(bytes: &[u8]) -> Result<i64, Error> {
    let arr: [u8; 8] = bytes.try_into().map_err(|_| {
        Error::storage(format!("invalid id bytes: expected 8, got {}", bytes.len()))
    })?;
    Ok(i64::from_le_bytes(arr))
}
