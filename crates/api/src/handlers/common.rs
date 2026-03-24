//! Shared types and helpers used across handler modules.

use std::time::Instant;

use chrono::{DateTime, Utc};
use inferadb_control_core::SdkResultExt;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{LedgerClient, OrganizationSlug, UserSlug};
use serde::{Deserialize, Serialize};

use super::state::AppState;
use crate::middleware::UserClaims;

// ── Org Membership Cache ────────────────────────────────────────────

/// Cached organization membership verification.
///
/// Avoids a Ledger round-trip on every vault/schema/audit-log request by
/// caching successful `get_organization` results for 30 seconds, keyed on
/// `(user_slug, org_slug)`.
#[derive(Clone)]
pub struct OrgMembershipCache {
    inner: moka::future::Cache<(u64, u64), ()>,
}

impl OrgMembershipCache {
    /// Evicts a user's cached membership for an organization.
    ///
    /// Called after member removal or leave to prevent stale access.
    pub async fn invalidate(&self, user: u64, org: u64) {
        self.inner.invalidate(&(user, org)).await;
    }
}

impl Default for OrgMembershipCache {
    fn default() -> Self {
        Self {
            inner: moka::future::Cache::builder()
                .time_to_live(std::time::Duration::from_secs(30))
                .max_capacity(4096)
                .build(),
        }
    }
}

// ── Shared Request Types ────────────────────────────────────────────

/// Cursor-based pagination query parameters.
///
/// Used by all list endpoints for consistent pagination behavior.
#[derive(Debug, Deserialize)]
pub struct CursorPaginationQuery {
    /// Number of items per page (default 50, max 100).
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// Opaque cursor for the next page (base64-encoded).
    pub page_token: Option<String>,
}

/// Returns the default page size (50) for serde deserialization.
fn default_page_size() -> u32 {
    50
}

impl CursorPaginationQuery {
    /// Returns the page size clamped to the allowed range (1-100).
    pub fn validated_page_size(&self) -> u32 {
        self.page_size.clamp(1, 100)
    }

    /// Decodes the base64-encoded page token into raw bytes.
    pub fn decoded_page_token(&self) -> Option<Vec<u8>> {
        use base64::Engine;
        self.page_token
            .as_deref()
            .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok())
    }
}

// ── Shared Response Types ───────────────────────────────────────────

/// Generic message response used by mutation handlers.
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// ── Shared Helpers ──────────────────────────────────────────────────

/// Extracts a reference to the Ledger client from app state.
///
/// Returns `Error::internal` if the Ledger client is not configured.
pub fn require_ledger(
    state: &AppState,
) -> std::result::Result<&inferadb_ledger_sdk::LedgerClient, CoreError> {
    state.ledger.as_deref().ok_or_else(|| CoreError::internal("Ledger client not configured"))
}

/// Encodes a page token (raw bytes) to a base64 string for API responses.
pub fn encode_page_token(token: &Option<Vec<u8>>) -> Option<String> {
    use base64::Engine;
    token.as_ref().map(|t| base64::engine::general_purpose::STANDARD.encode(t))
}

/// Converts an optional [`SystemTime`](std::time::SystemTime) to an RFC 3339 string.
pub fn system_time_to_rfc3339(t: &Option<std::time::SystemTime>) -> Option<String> {
    t.map(|st| DateTime::<Utc>::from(st).to_rfc3339())
}

/// Verifies the caller is a member of the specified organization.
///
/// This is the sole authorization gate for vault/schema operations —
/// Ledger does NOT enforce org membership on those endpoints.
/// Results are cached for 30 seconds to avoid redundant gRPC round-trips.
pub async fn verify_org_membership(
    ledger: &LedgerClient,
    org: OrganizationSlug,
    user: UserSlug,
    cache: &OrgMembershipCache,
) -> std::result::Result<(), CoreError> {
    let key = (user.value(), org.value());
    if cache.inner.get(&key).await.is_some() {
        return Ok(());
    }

    let start = Instant::now();
    ledger.get_organization(org, user).await.map_sdk_err_instrumented("get_organization", start)?;
    cache.inner.insert(key, ()).await;
    Ok(())
}

/// Convenience wrapper around [`verify_org_membership`] for common handler parameters.
///
/// Extracts the org slug and user from `AppState` and `UserClaims`.
pub async fn verify_org_membership_from_claims(
    state: &AppState,
    ledger: &LedgerClient,
    org: u64,
    claims: &UserClaims,
) -> std::result::Result<(), CoreError> {
    verify_org_membership(
        ledger,
        OrganizationSlug::new(org),
        claims.user_slug,
        &state.org_membership_cache,
    )
    .await
}

// ── Input Validation ──────────────────────────────────────────────────

/// Validates a name field (organization, team, client, vault, etc.).
///
/// Allows 1-128 characters after trimming: alphanumeric (including Unicode),
/// hyphens, underscores, spaces, periods, and apostrophes.
pub fn validate_name(name: &str) -> std::result::Result<(), CoreError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 128 {
        return Err(CoreError::validation("name must be between 1 and 128 characters"));
    }
    if !name.chars().all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | ' ' | '.' | '\'')) {
        return Err(CoreError::validation(
            "name may only contain alphanumeric characters, hyphens, underscores, spaces, periods, and apostrophes",
        ));
    }
    Ok(())
}

/// Validates an optional description field.
///
/// Allows up to 1024 characters when present.
pub fn validate_description(desc: &Option<String>) -> std::result::Result<(), CoreError> {
    if let Some(d) = desc
        && d.chars().count() > 1024
    {
        return Err(CoreError::validation("description must be 1024 characters or fewer"));
    }
    Ok(())
}

/// Validates an email address.
///
/// Checks for exactly one `@` with non-empty local and domain parts.
/// Rejects control characters to prevent log injection.
pub fn validate_email(email: &str) -> std::result::Result<(), CoreError> {
    // RFC 5321 limits email addresses to 254 octets
    if email.len() > 254 {
        return Err(CoreError::validation("email address too long"));
    }
    if email.chars().any(|c| c.is_control()) {
        return Err(CoreError::validation("invalid email address"));
    }
    let Some((local, domain)) = email.split_once('@') else {
        return Err(CoreError::validation("invalid email address"));
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err(CoreError::validation("invalid email address"));
    }
    Ok(())
}

/// Casts an `i64` entity ID to `u64`.
///
/// Returns an internal error if the value is negative.
pub fn safe_id_cast(value: i64) -> std::result::Result<u64, CoreError> {
    u64::try_from(value).map_err(|_| CoreError::internal("invalid entity identifier"))
}
