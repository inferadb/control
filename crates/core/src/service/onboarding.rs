//! Email-code onboarding service wrapping Ledger SDK onboarding operations.
//!
//! Implements the 3-step passwordless authentication flow:
//! 1. `initiate_email_verification` — generates a 6-char code (sent via SMTP)
//! 2. `verify_email_code` — returns session, TOTP challenge, or onboarding token
//! 3. `complete_registration` — creates user + org, returns session

use inferadb_control_types::error::Result;
use inferadb_ledger_sdk::{
    EmailVerificationCode, EmailVerificationResult, LedgerClient, RegistrationResult,
};
use inferadb_ledger_types::Region;

use super::error::SdkResultExt;

/// Initiates email verification, returning a 6-char code to send via SMTP.
pub async fn initiate_email_verification(
    ledger: &LedgerClient,
    email: &str,
    region: Region,
) -> Result<EmailVerificationCode> {
    ledger
        .initiate_email_verification(email, region)
        .await
        .map_sdk_err()
}

/// Verifies the email code.
///
/// Returns one of:
/// - `ExistingUser` — user exists, session created (no TOTP)
/// - `TotpRequired` — user exists with TOTP enabled, challenge nonce returned
/// - `NewUser` — new user, onboarding token returned for `complete_registration`
pub async fn verify_email_code(
    ledger: &LedgerClient,
    email: &str,
    code: &str,
    region: Region,
) -> Result<EmailVerificationResult> {
    ledger
        .verify_email_code(email, code, region)
        .await
        .map_sdk_err()
}

/// Completes registration for a new user after email verification.
///
/// Creates user + default organization, returns session tokens.
pub async fn complete_registration(
    ledger: &LedgerClient,
    onboarding_token: &str,
    email: &str,
    region: Region,
    name: &str,
    organization_name: &str,
) -> Result<RegistrationResult> {
    ledger
        .complete_registration(onboarding_token, email, region, name, organization_name)
        .await
        .map_sdk_err()
}
