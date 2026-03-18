//! Session management handlers (removed).
//!
//! Session management is now handled entirely by Ledger's token service:
//! - Token revocation: `auth_v2::logout` (single session) and `auth_v2::revoke_all`
//! - Token refresh: `auth_v2::refresh`
//!
//! The old session list/revoke/revoke-others handlers have been removed because
//! Ledger's token model does not expose a "list active sessions" API.
