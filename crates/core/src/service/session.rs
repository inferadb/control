//! Session and token management service wrapping Ledger SDK token operations.
//!
//! Provides typed wrappers for creating sessions, refreshing tokens, and revoking
//! sessions. All state is managed by Ledger — Control is stateless.

use inferadb_ledger_sdk::LedgerClient;
use inferadb_ledger_types::UserSlug;
use inferadb_control_types::error::Result;

use super::error::SdkResultExt;

/// Creates a user session, returning an access + refresh token pair.
pub async fn create_user_session(
    ledger: &LedgerClient,
    user: UserSlug,
) -> Result<inferadb_ledger_sdk::token::TokenPair> {
    ledger.create_user_session(user).await.map_sdk_err()
}

/// Refreshes a token pair using an opaque refresh token.
///
/// The old refresh token is invalidated (rotate-on-use).
pub async fn refresh_token(
    ledger: &LedgerClient,
    refresh_token: &str,
) -> Result<inferadb_ledger_sdk::token::TokenPair> {
    ledger.refresh_token(refresh_token).await.map_sdk_err()
}

/// Revokes a single token and its entire family.
pub async fn revoke_token(ledger: &LedgerClient, refresh_token: &str) -> Result<()> {
    ledger.revoke_token(refresh_token).await.map_sdk_err()
}

/// Revokes all sessions for a user. Returns the number of sessions revoked.
pub async fn revoke_all_user_sessions(ledger: &LedgerClient, user: UserSlug) -> Result<u64> {
    ledger.revoke_all_user_sessions(user).await.map_sdk_err()
}
