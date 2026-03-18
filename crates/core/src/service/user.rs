//! User management service wrapping Ledger SDK user operations.

use inferadb_control_types::error::Result;
use inferadb_ledger_sdk::{LedgerClient, UserInfo};
use inferadb_ledger_types::UserSlug;

use super::error::SdkResultExt;

/// Gets a user by their slug.
pub async fn get_user(ledger: &LedgerClient, user: UserSlug) -> Result<UserInfo> {
    ledger.get_user(user).await.map_sdk_err()
}

/// Updates a user's display name.
pub async fn update_user_name(
    ledger: &LedgerClient,
    user: UserSlug,
    name: String,
) -> Result<UserInfo> {
    ledger.update_user(user, Some(name), None, None).await.map_sdk_err()
}

/// Soft-deletes a user. Ledger handles all cascading (sessions, memberships, emails, etc.).
pub async fn delete_user(
    ledger: &LedgerClient,
    user: UserSlug,
    deleted_by: &str,
) -> Result<UserInfo> {
    ledger.delete_user(user, deleted_by).await.map_sdk_err()
}
