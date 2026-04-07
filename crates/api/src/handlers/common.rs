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

/// Returns the default page size (50).
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

    // try_get_with deduplicates concurrent requests for the same (user, org)
    // into a single Ledger call. Only successful results are cached; errors
    // are not persisted (each failure retries on the next request).
    cache
        .inner
        .try_get_with(key, async move {
            let start = Instant::now();
            ledger
                .get_organization(org, user)
                .await
                .map_sdk_err_instrumented("get_organization", start)?;
            Ok::<(), CoreError>(())
        })
        .await
        .map_err(|arc_err| {
            // try_get_with wraps the error in Arc. Reconstruct using status code
            // to preserve the correct HTTP mapping.
            let status = arc_err.status_code();
            let msg = arc_err.to_string();
            match status {
                400 => CoreError::validation(msg),
                401 => CoreError::auth(msg),
                403 => CoreError::authz(msg),
                404 => CoreError::not_found(msg),
                429 => CoreError::rate_limit(msg),
                503 => CoreError::unavailable(msg),
                _ => CoreError::internal("failed to verify organization membership"),
            }
        })
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

/// Returns `true` for characters disallowed in descriptions:
/// control characters (except common whitespace) and Unicode bidi overrides.
fn is_disallowed_char(c: char) -> bool {
    // Control characters (Cc) except newline, carriage return, and tab
    (c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    // Unicode bidirectional overrides/embeddings/isolates (Cf subset)
    || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Validates an optional description field.
///
/// Allows up to 1024 characters when present, including newlines and tabs.
/// Rejects control characters and Unicode bidirectional overrides to prevent
/// log injection and display spoofing.
pub fn validate_description(desc: &Option<String>) -> std::result::Result<(), CoreError> {
    if let Some(d) = desc {
        if d.chars().count() > 1024 {
            return Err(CoreError::validation("description must be 1024 characters or fewer"));
        }
        if d.chars().any(is_disallowed_char) {
            return Err(CoreError::validation("description contains disallowed characters"));
        }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result)]
mod tests {
    use super::*;

    // ── validate_name ──────────────────────────────────────────────

    #[test]
    fn test_validate_name_valid_inputs_return_ok() {
        let cases = [
            ("hello", "alphanumeric"),
            ("Hello World", "spaces"),
            ("test-name", "hyphens"),
            ("test_name", "underscores"),
            ("O'Brien", "apostrophes"),
            ("v1.0", "periods"),
            ("Ünïcödé", "unicode alphanumeric"),
            ("a", "single char"),
        ];

        for (input, label) in cases {
            assert!(validate_name(input).is_ok(), "expected ok for {label}: {input:?}");
        }
    }

    #[test]
    fn test_validate_name_at_max_length_returns_ok() {
        let name = "a".repeat(128);

        assert!(validate_name(&name).is_ok());
    }

    #[test]
    fn test_validate_name_empty_returns_validation_error() {
        let err = validate_name("").unwrap_err();

        assert!(matches!(err, CoreError::Validation { .. }));
    }

    #[test]
    fn test_validate_name_whitespace_only_returns_validation_error() {
        let err = validate_name("   ").unwrap_err();

        assert!(matches!(err, CoreError::Validation { .. }));
    }

    #[test]
    fn test_validate_name_over_max_length_returns_validation_error() {
        let long = "a".repeat(129);

        let err = validate_name(&long).unwrap_err();

        assert!(matches!(err, CoreError::Validation { .. }));
    }

    #[test]
    fn test_validate_name_disallowed_characters_return_validation_error() {
        let cases = [
            ("test<script>", "angle brackets"),
            ("name@org", "at sign"),
            ("name#1", "hash"),
            ("name&co", "ampersand"),
            ("test\ttab", "tab"),
        ];

        for (input, label) in cases {
            assert!(
                matches!(validate_name(input), Err(CoreError::Validation { .. })),
                "expected validation error for {label}: {input:?}"
            );
        }
    }

    // ── validate_description ───────────────────────────────────────

    #[test]
    fn test_validate_description_valid_inputs_return_ok() {
        let cases: &[Option<String>] = &[
            None,
            Some(String::new()),
            Some("short description".to_string()),
            Some("line one\nline two\ttab".to_string()),
            Some("line\r\nbreak".to_string()),
            Some("x".repeat(1024)),
        ];

        for (i, input) in cases.iter().enumerate() {
            assert!(validate_description(input).is_ok(), "expected ok for case {i}: {input:?}");
        }
    }

    #[test]
    fn test_validate_description_over_max_length_returns_validation_error() {
        let long = "x".repeat(1025);

        let err = validate_description(&Some(long)).unwrap_err();

        assert!(matches!(err, CoreError::Validation { .. }));
    }

    #[test]
    fn test_validate_description_disallowed_characters_return_validation_error() {
        let cases = [
            ("has null\x00byte", "null byte"),
            ("has \x01 soh", "SOH control char"),
            ("bidi \u{202A} override", "bidi LRE"),
            ("bidi \u{202E} override", "bidi RLO"),
            ("bidi \u{2066} isolate", "bidi LRI"),
        ];

        for (input, label) in cases {
            assert!(
                matches!(
                    validate_description(&Some(input.to_string())),
                    Err(CoreError::Validation { .. })
                ),
                "expected validation error for {label}: {input:?}"
            );
        }
    }

    // ── validate_email ─────────────────────────────────────────────

    #[test]
    fn test_validate_email_valid_addresses_return_ok() {
        let cases = ["user@example.com", "test+tag@sub.domain.com"];

        for input in cases {
            assert!(validate_email(input).is_ok(), "expected ok for {input:?}");
        }
    }

    #[test]
    fn test_validate_email_invalid_addresses_return_validation_error() {
        let cases = [
            ("", "empty"),
            ("user", "no at sign"),
            ("@domain.com", "empty local part"),
            ("user@", "empty domain"),
            ("user@domain", "domain without dot"),
            ("user\x00@example.com", "null byte"),
        ];

        for (input, label) in cases {
            assert!(
                matches!(validate_email(input), Err(CoreError::Validation { .. })),
                "expected validation error for {label}: {input:?}"
            );
        }
    }

    #[test]
    fn test_validate_email_exceeding_254_bytes_returns_validation_error() {
        let local = "a".repeat(64);
        let domain = format!("{}.com", "b".repeat(200));
        let email = format!("{local}@{domain}");
        assert!(email.len() > 254);

        let err = validate_email(&email).unwrap_err();

        assert!(matches!(err, CoreError::Validation { .. }));
    }

    // ── CursorPaginationQuery ──────────────────────────────────────

    #[test]
    fn test_validated_page_size_clamps_to_range() {
        let cases: &[(u32, u32)] = &[
            (0, 1),     // below min clamps to 1
            (1, 1),     // at min boundary
            (50, 50),   // mid-range passthrough
            (100, 100), // at max boundary
            (101, 100), // above max clamps to 100
            (999, 100), // far above max clamps to 100
        ];

        for &(input, expected) in cases {
            let q = CursorPaginationQuery { page_size: input, page_token: None };

            assert_eq!(
                q.validated_page_size(),
                expected,
                "page_size {input} should clamp to {expected}"
            );
        }
    }

    #[test]
    fn test_decoded_page_token_none_returns_none() {
        let q = CursorPaginationQuery { page_size: 50, page_token: None };

        assert!(q.decoded_page_token().is_none());
    }

    #[test]
    fn test_decoded_page_token_valid_base64_returns_bytes() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"cursor_value");
        let q = CursorPaginationQuery { page_size: 50, page_token: Some(encoded) };

        assert_eq!(q.decoded_page_token().unwrap(), b"cursor_value");
    }

    #[test]
    fn test_decoded_page_token_invalid_base64_returns_none() {
        let q = CursorPaginationQuery { page_size: 50, page_token: Some("!!!invalid".to_string()) };

        assert!(q.decoded_page_token().is_none());
    }

    #[test]
    fn test_decoded_page_token_empty_payload_returns_empty_bytes() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"");
        let q = CursorPaginationQuery { page_size: 50, page_token: Some(encoded) };

        assert_eq!(q.decoded_page_token().unwrap(), b"");
    }

    // ── encode_page_token ──────────────────────────────────────────

    #[test]
    fn test_encode_page_token_none_returns_none() {
        assert!(encode_page_token(&None).is_none());
    }

    #[test]
    fn test_encode_page_token_bytes_returns_base64() {
        use base64::Engine;
        let expected = base64::engine::general_purpose::STANDARD.encode(b"hello");

        let result = encode_page_token(&Some(b"hello".to_vec()));

        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn test_encode_page_token_roundtrips_with_decode() {
        use base64::Engine;
        let original = b"cursor_data_123";

        let encoded = encode_page_token(&Some(original.to_vec())).unwrap();
        let decoded = base64::engine::general_purpose::STANDARD.decode(&encoded).unwrap();

        assert_eq!(decoded, original);
    }

    // ── system_time_to_rfc3339 ─────────────────────────────────────

    #[test]
    fn test_system_time_to_rfc3339_none_returns_none() {
        assert!(system_time_to_rfc3339(&None).is_none());
    }

    #[test]
    fn test_system_time_to_rfc3339_epoch_returns_1970_rfc3339() {
        let t = std::time::SystemTime::UNIX_EPOCH;

        let result = system_time_to_rfc3339(&Some(t)).unwrap();

        assert!(result.starts_with("1970-01-01T00:00:00"));
    }

    // ── safe_id_cast ───────────────────────────────────────────────

    #[test]
    fn test_safe_id_cast_valid_values_return_ok() {
        let cases: &[(i64, u64)] = &[(0, 0), (42, 42), (i64::MAX, i64::MAX as u64)];

        for &(input, expected) in cases {
            assert_eq!(safe_id_cast(input).unwrap(), expected, "safe_id_cast({input})");
        }
    }

    #[test]
    fn test_safe_id_cast_negative_values_return_internal_error() {
        let cases = [-1i64, i64::MIN];

        for input in cases {
            let err = safe_id_cast(input).unwrap_err();

            assert!(
                matches!(err, CoreError::Internal { .. }),
                "safe_id_cast({input}) should return Internal error"
            );
        }
    }

    // ── require_ledger ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_require_ledger_no_ledger_returns_internal_error() {
        let state = AppState::new_test();

        let result = require_ledger(&state);

        assert!(matches!(result, Err(CoreError::Internal { .. })));
    }

    // ── OrgMembershipCache ─────────────────────────────────────────

    #[tokio::test]
    async fn test_org_membership_cache_invalidate_nonexistent_key_succeeds() {
        let cache = OrgMembershipCache::default();

        cache.invalidate(1, 2).await;
        // No panic = success; invalidating a missing key is a no-op.
    }

    // ── is_disallowed_char ─────────────────────────────────────────

    #[test]
    fn test_is_disallowed_char_allowed_characters_return_false() {
        let cases = [
            ('\n', "newline"),
            ('\r', "carriage return"),
            ('\t', "tab"),
            ('a', "regular letter"),
            (' ', "space"),
        ];

        for (ch, label) in cases {
            assert!(!is_disallowed_char(ch), "expected allowed for {label} ({ch:?})");
        }
    }

    #[test]
    fn test_is_disallowed_char_disallowed_characters_return_true() {
        let cases = [
            ('\x00', "null"),
            ('\x01', "SOH"),
            ('\u{202A}', "bidi LRE"),
            ('\u{202C}', "bidi PDF"),
            ('\u{202E}', "bidi RLO"),
            ('\u{2066}', "bidi LRI"),
            ('\u{2069}', "bidi PDI"),
        ];

        for (ch, label) in cases {
            assert!(is_disallowed_char(ch), "expected disallowed for {label} ({ch:?})");
        }
    }
}
