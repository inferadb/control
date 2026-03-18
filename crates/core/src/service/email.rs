//! Email management service wrapping Ledger SDK email operations.

use inferadb_control_types::error::Result;
use inferadb_ledger_sdk::{LedgerClient, UserEmailInfo};
use inferadb_ledger_types::{UserEmailId, UserSlug};

use super::error::SdkResultExt;

/// Creates a new email address for a user.
///
/// The Ledger returns a `UserEmailInfo` containing a verification token that
/// must be sent to the user via SMTP.
pub async fn create_user_email(
    ledger: &LedgerClient,
    user: UserSlug,
    email: &str,
    email_hmac: &str,
) -> Result<UserEmailInfo> {
    ledger.create_user_email(user, email, email_hmac).await.map_sdk_err()
}

/// Lists all email addresses for a user.
pub async fn list_user_emails(ledger: &LedgerClient, user: UserSlug) -> Result<Vec<UserEmailInfo>> {
    ledger.search_user_email(Some(user), None).await.map_sdk_err()
}

/// Deletes an email address for a user.
pub async fn delete_user_email(
    ledger: &LedgerClient,
    user: UserSlug,
    email_id: UserEmailId,
) -> Result<()> {
    ledger.delete_user_email(user, email_id).await.map_sdk_err()
}

/// Verifies an email address using a verification token.
pub async fn verify_user_email(ledger: &LedgerClient, token: &str) -> Result<UserEmailInfo> {
    ledger.verify_user_email(token).await.map_sdk_err()
}
