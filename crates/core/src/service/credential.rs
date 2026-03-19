//! Credential management service wrapping Ledger SDK credential operations.
//!
//! Covers passkey, TOTP, and recovery code credential types.
//! WebAuthn ceremony validation remains in Control (Decision 5);
//! this service only handles the Ledger-side storage and verification.

use inferadb_control_types::error::Result;
use inferadb_ledger_sdk::{
    CredentialData, CredentialType, LedgerClient, PasskeyCredentialInfo, RecoveryCodeResult,
    TokenPair, UserCredentialInfo,
};
use inferadb_ledger_types::{UserCredentialId, UserSlug};

use super::error::SdkResultExt;

/// Lists credentials for a user, optionally filtered by type.
pub async fn list_user_credentials(
    ledger: &LedgerClient,
    user: UserSlug,
    credential_type: Option<CredentialType>,
) -> Result<Vec<UserCredentialInfo>> {
    ledger.list_user_credentials(user, credential_type).await.map_sdk_err()
}

/// Creates a new credential for a user.
pub async fn create_user_credential(
    ledger: &LedgerClient,
    user: UserSlug,
    name: &str,
    data: CredentialData,
) -> Result<UserCredentialInfo> {
    ledger.create_user_credential(user, name, data).await.map_sdk_err()
}

/// Updates credential metadata or passkey-specific fields.
pub async fn update_user_credential(
    ledger: &LedgerClient,
    user: UserSlug,
    credential_id: UserCredentialId,
    name: Option<String>,
    enabled: Option<bool>,
    passkey_data: Option<PasskeyCredentialInfo>,
) -> Result<UserCredentialInfo> {
    ledger
        .update_user_credential(user, credential_id, name, enabled, passkey_data)
        .await
        .map_sdk_err()
}

/// Deletes a credential. Rejects if it's the user's last credential.
pub async fn delete_user_credential(
    ledger: &LedgerClient,
    user: UserSlug,
    credential_id: UserCredentialId,
) -> Result<()> {
    ledger.delete_user_credential(user, credential_id).await.map_sdk_err()
}

/// Creates a TOTP challenge after primary auth (passkey or email).
/// Returns a 32-byte challenge nonce.
pub async fn create_totp_challenge(
    ledger: &LedgerClient,
    user: UserSlug,
    primary_method: &str,
) -> Result<Vec<u8>> {
    ledger.create_totp_challenge(user, primary_method).await.map_sdk_err()
}

/// Verifies a TOTP code against a pending challenge.
/// On success, creates a session and returns a token pair.
pub async fn verify_totp(
    ledger: &LedgerClient,
    user: UserSlug,
    totp_code: &str,
    challenge_nonce: Vec<u8>,
) -> Result<TokenPair> {
    ledger.verify_totp(user, totp_code, challenge_nonce).await.map_sdk_err()
}

/// Consumes a recovery code to bypass TOTP.
/// Returns token pair and remaining code count.
pub async fn consume_recovery_code(
    ledger: &LedgerClient,
    user: UserSlug,
    code: &str,
    challenge_nonce: Vec<u8>,
) -> Result<RecoveryCodeResult> {
    ledger.consume_recovery_code(user, code, challenge_nonce).await.map_sdk_err()
}
