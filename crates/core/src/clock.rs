//! Clock skew validation against NTP.
//!
//! Provides [`ClockValidator`] which queries NTP servers to detect clock drift,
//! classifying the result as [`SkewSeverity::Normal`], [`SkewSeverity::Warning`],
//! or [`SkewSeverity::Critical`].

use std::time::Duration as StdDuration;

use chrono::{DateTime, TimeDelta, Utc};
use inferadb_control_types::error::{Error, Result};

/// Warning threshold in milliseconds (100ms).
const WARNING_SKEW_MS: i64 = 100;

/// Default critical threshold in milliseconds (1 second).
const DEFAULT_MAX_SKEW_MS: i64 = 1000;

/// Timeout for NTP queries.
const NTP_TIMEOUT: StdDuration = StdDuration::from_secs(5);

/// Default NTP servers to query.
const DEFAULT_NTP_SERVERS: &[&str] = &["pool.ntp.org", "time.google.com"];

/// Severity level for measured clock skew.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkewSeverity {
    /// Skew < 100ms.
    Normal,
    /// Skew between 100ms and the configured threshold.
    Warning,
    /// Skew exceeds the configured threshold.
    Critical,
}

/// Clock skew validator for multi-instance coordination.
///
/// Distributed systems require synchronized clocks for:
/// - Snowflake ID ordering across instances
/// - TTL-based token expiration consistency
/// - Lease timing in distributed coordination
///
/// Queries NTP servers asynchronously via `rsntp`, falling back to
/// system tools (`chronyc`, `ntpdate`) when direct NTP is unavailable.
pub struct ClockValidator {
    max_skew_ms: i64,
    ntp_servers: Vec<String>,
    /// When false, skip chronyc/ntpdate system fallbacks (useful in tests
    /// where only the SNTP path should be exercised).
    system_fallbacks: bool,
}

impl ClockValidator {
    /// Creates a clock validator with default settings (1s threshold).
    pub fn new() -> Self {
        Self {
            max_skew_ms: DEFAULT_MAX_SKEW_MS,
            ntp_servers: DEFAULT_NTP_SERVERS.iter().map(|s| (*s).to_string()).collect(),
            system_fallbacks: true,
        }
    }

    /// Creates a clock validator with a custom skew threshold in seconds.
    pub fn with_max_skew(max_skew_seconds: i64) -> Self {
        Self {
            max_skew_ms: max_skew_seconds * 1000,
            ntp_servers: DEFAULT_NTP_SERVERS.iter().map(|s| (*s).to_string()).collect(),
            system_fallbacks: true,
        }
    }

    /// Validates the system clock against NTP.
    ///
    /// Queries NTP time via:
    /// 1. Direct SNTP query using `rsntp`
    /// 2. `chronyc tracking` output parsing (fallback)
    /// 3. `ntpdate -q` output parsing (fallback)
    ///
    /// Classifies the measured skew as Normal (< 100ms),
    /// Warning (100ms to threshold), or Critical (>= threshold).
    ///
    /// # Errors
    ///
    /// Returns an error if the measured skew exceeds the critical threshold.
    /// Returns `Ok` with `SkewSeverity::Normal` if NTP is unreachable (soft failure).
    pub async fn validate(&self) -> Result<ClockStatus> {
        let system_time = Utc::now();

        match self.query_ntp_time(system_time).await {
            Ok(ntp_time) => self.evaluate_skew(system_time, ntp_time),
            Err(e) => {
                tracing::warn!("Failed to query NTP time: {e}. Skipping clock validation.");
                Ok(ClockStatus {
                    system_time,
                    ntp_time: None,
                    skew_ms: 0,
                    severity: SkewSeverity::Normal,
                    within_threshold: true,
                })
            },
        }
    }

    /// Evaluates the skew between system time and NTP time.
    ///
    /// Contains the testable core of clock validation: classifies the skew,
    /// records it as a metric, and returns an error if critical.
    fn evaluate_skew(
        &self,
        system_time: DateTime<Utc>,
        ntp_time: DateTime<Utc>,
    ) -> Result<ClockStatus> {
        let skew_ms = (system_time - ntp_time).num_milliseconds().abs();
        let skew_seconds_f64 = skew_ms as f64 / 1000.0;

        crate::metrics::set_clock_skew(skew_seconds_f64);

        let severity = classify_skew(skew_ms, self.max_skew_ms);
        let within_threshold = severity != SkewSeverity::Critical;

        match severity {
            SkewSeverity::Normal => {
                tracing::debug!(skew_ms, "Clock skew within normal range");
            },
            SkewSeverity::Warning => {
                tracing::warn!(
                    skew_ms,
                    threshold_ms = self.max_skew_ms,
                    "Elevated clock skew detected"
                );
            },
            SkewSeverity::Critical => {
                tracing::error!(
                    skew_ms,
                    threshold_ms = self.max_skew_ms,
                    "Critical clock skew exceeds threshold"
                );
                return Err(Error::config(format!(
                    "Clock skew {skew_ms}ms exceeds threshold {}ms. \
                     System time: {system_time}, NTP time: {ntp_time}",
                    self.max_skew_ms
                )));
            },
        }

        Ok(ClockStatus {
            system_time,
            ntp_time: Some(ntp_time),
            skew_ms,
            severity,
            within_threshold,
        })
    }

    /// Queries NTP time from available sources (async, non-blocking).
    ///
    /// Accepts the system time captured at the start of validation to ensure
    /// consistent offset calculations even if NTP queries take time.
    async fn query_ntp_time(&self, system_time: DateTime<Utc>) -> Result<DateTime<Utc>> {
        // 1. Direct SNTP query via rsntp
        if let Some(time) = self.query_rsntp().await {
            return Ok(time);
        }

        if self.system_fallbacks {
            // 2. Parse chronyc tracking output
            if let Some(offset_secs) = self.query_chronyc().await {
                let offset_ms = (offset_secs * 1000.0) as i64;
                return Ok(system_time - TimeDelta::milliseconds(offset_ms));
            }

            // 3. Parse ntpdate output
            if let Some(offset_secs) = self.query_ntpdate().await {
                let offset_ms = (offset_secs * 1000.0) as i64;
                return Ok(system_time - TimeDelta::milliseconds(offset_ms));
            }
        }

        Err(Error::config(
            "No NTP source available. Install chrony or ntpdate for clock validation.".to_string(),
        ))
    }

    /// Queries NTP time via rsntp async client.
    async fn query_rsntp(&self) -> Option<DateTime<Utc>> {
        let client = rsntp::AsyncSntpClient::new();

        for server in &self.ntp_servers {
            match tokio::time::timeout(NTP_TIMEOUT, client.synchronize(server.as_str())).await {
                Ok(Ok(result)) => match result.datetime().into_chrono_datetime() {
                    Ok(ntp_time) => return Some(ntp_time),
                    Err(e) => {
                        tracing::debug!(error = %e, "Failed to convert NTP timestamp");
                    },
                },
                Ok(Err(e)) => {
                    tracing::debug!(server = server.as_str(), error = %e, "SNTP query failed");
                },
                Err(_) => {
                    tracing::debug!(server = server.as_str(), "SNTP query timed out");
                },
            }
        }

        None
    }

    /// Queries clock offset via `chronyc tracking` (non-blocking, with timeout).
    async fn query_chronyc(&self) -> Option<f64> {
        let output = tokio::time::timeout(
            NTP_TIMEOUT,
            tokio::process::Command::new("chronyc").arg("tracking").output(),
        )
        .await
        .ok()?
        .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_chrony_offset(&stdout)
    }

    /// Queries clock offset via `ntpdate -q` (non-blocking, with timeout).
    async fn query_ntpdate(&self) -> Option<f64> {
        let server = self.ntp_servers.first().map(String::as_str).unwrap_or("pool.ntp.org");

        let output = tokio::time::timeout(
            NTP_TIMEOUT,
            tokio::process::Command::new("ntpdate").args(["-q", server]).output(),
        )
        .await
        .ok()?
        .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_ntpdate_offset(&stdout)
    }
}

impl Default for ClockValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Classifies skew magnitude into severity levels.
fn classify_skew(skew_ms: i64, max_skew_ms: i64) -> SkewSeverity {
    if skew_ms >= max_skew_ms {
        SkewSeverity::Critical
    } else if skew_ms >= WARNING_SKEW_MS {
        SkewSeverity::Warning
    } else {
        SkewSeverity::Normal
    }
}

/// Parses the clock offset from `chronyc tracking` output.
///
/// Extracts the offset from the "System time" line:
/// ```text
/// System time     : 0.000012345 seconds fast of NTP time
/// System time     : 0.000012345 seconds slow of NTP time
/// ```
///
/// Returns the offset in seconds (positive = system ahead of NTP).
fn parse_chrony_offset(output: &str) -> Option<f64> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("System time") {
            let after_colon = rest.split(':').nth(1)?.trim();
            let parts: Vec<&str> = after_colon.split_whitespace().collect();
            // Expected: ["0.000012345", "seconds", "fast"/"slow", "of", "NTP", "time"]
            if parts.len() >= 3 {
                let offset: f64 = parts[0].parse().ok()?;
                return Some(if parts[2] == "fast" { offset } else { -offset });
            }
        }
    }
    None
}

/// Parses the clock offset from `ntpdate -q` output.
///
/// Extracts the offset from lines like:
/// ```text
/// server 192.168.1.1, stratum 2, offset -0.003163, delay 0.02567
/// ```
///
/// Returns the offset in seconds.
fn parse_ntpdate_offset(output: &str) -> Option<f64> {
    for line in output.lines() {
        if let Some(offset_start) = line.find("offset ") {
            let after_offset = &line[offset_start + 7..];
            let offset_str = after_offset.split(',').next()?.trim();
            return offset_str.parse().ok();
        }
    }
    None
}

/// Result of a clock validation check.
#[derive(Debug, Clone)]
pub struct ClockStatus {
    /// System time when validation was performed.
    pub system_time: DateTime<Utc>,
    /// NTP time if available.
    pub ntp_time: Option<DateTime<Utc>>,
    /// Absolute clock skew in milliseconds.
    pub skew_ms: i64,
    /// Severity classification of the measured skew.
    pub severity: SkewSeverity,
    /// Whether skew is within the configured threshold.
    pub within_threshold: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chrono::TimeDelta;

    use super::*;

    // ── ClockValidator construction ──

    #[test]
    fn test_new_default_threshold_and_servers() {
        let v = ClockValidator::new();

        assert_eq!(v.max_skew_ms, DEFAULT_MAX_SKEW_MS);
        assert_eq!(v.ntp_servers.len(), 2);
        assert!(v.system_fallbacks);
    }

    #[test]
    fn test_default_trait_matches_new() {
        let v = ClockValidator::default();

        assert_eq!(v.max_skew_ms, DEFAULT_MAX_SKEW_MS);
        assert_eq!(v.ntp_servers.len(), 2);
    }

    #[test]
    fn test_with_max_skew_converts_seconds_to_milliseconds() {
        let v = ClockValidator::with_max_skew(5);

        assert_eq!(v.max_skew_ms, 5000);
    }

    // ── Skew classification (table-driven) ──

    #[test]
    fn test_classify_skew_boundaries() {
        let cases = [
            // (skew_ms, max_skew_ms, expected)
            (0, 1000, SkewSeverity::Normal, "zero skew"),
            (50, 1000, SkewSeverity::Normal, "well below warning"),
            (99, 1000, SkewSeverity::Normal, "just below warning threshold"),
            (100, 1000, SkewSeverity::Warning, "exactly at warning threshold"),
            (500, 1000, SkewSeverity::Warning, "mid-range warning"),
            (999, 1000, SkewSeverity::Warning, "just below critical threshold"),
            (1000, 1000, SkewSeverity::Critical, "exactly at critical threshold"),
            (2000, 1000, SkewSeverity::Critical, "well above critical threshold"),
        ];

        for (skew_ms, max_skew_ms, expected, label) in cases {
            assert_eq!(
                classify_skew(skew_ms, max_skew_ms),
                expected,
                "classify_skew({skew_ms}, {max_skew_ms}) [{label}]"
            );
        }
    }

    #[test]
    fn test_classify_skew_custom_threshold_shifts_boundaries() {
        // With a 5s threshold, 2s is warning (not critical)
        assert_eq!(classify_skew(2000, 5000), SkewSeverity::Warning);
        // At 5s exactly, becomes critical
        assert_eq!(classify_skew(5000, 5000), SkewSeverity::Critical);
    }

    // ── evaluate_skew ──

    #[test]
    fn test_evaluate_skew_zero_returns_normal() {
        let v = ClockValidator::new();
        let now = Utc::now();

        let status = v.evaluate_skew(now, now).unwrap();

        assert_eq!(status.severity, SkewSeverity::Normal);
        assert_eq!(status.skew_ms, 0);
        assert!(status.within_threshold);
        assert_eq!(status.ntp_time, Some(now));
    }

    #[test]
    fn test_evaluate_skew_small_offset_returns_normal() {
        let v = ClockValidator::new();
        let now = Utc::now();
        let ntp_time = now + TimeDelta::milliseconds(50);

        let status = v.evaluate_skew(now, ntp_time).unwrap();

        assert_eq!(status.severity, SkewSeverity::Normal);
        assert!(status.skew_ms < WARNING_SKEW_MS);
        assert!(status.within_threshold);
    }

    #[test]
    fn test_evaluate_skew_moderate_offset_returns_warning() {
        let v = ClockValidator::new();
        let now = Utc::now();
        let ntp_time = now + TimeDelta::milliseconds(500);

        let status = v.evaluate_skew(now, ntp_time).unwrap();

        assert_eq!(status.severity, SkewSeverity::Warning);
        assert_eq!(status.skew_ms, 500);
        assert!(status.within_threshold);
    }

    #[test]
    fn test_evaluate_skew_critical_returns_error_with_details() {
        let v = ClockValidator::new();
        let now = Utc::now();
        let ntp_time = now + TimeDelta::seconds(3);

        let err = v.evaluate_skew(now, ntp_time).unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("3000ms"), "error should contain measured skew");
        assert!(msg.contains("1000ms"), "error should contain threshold");
    }

    #[test]
    fn test_evaluate_skew_negative_direction_uses_absolute_value() {
        let v = ClockValidator::new();
        let now = Utc::now();
        let ntp_time = now - TimeDelta::milliseconds(500);

        let status = v.evaluate_skew(now, ntp_time).unwrap();

        assert_eq!(status.severity, SkewSeverity::Warning);
        assert_eq!(status.skew_ms, 500);
    }

    #[test]
    fn test_evaluate_skew_custom_threshold_allows_larger_skew() {
        let v = ClockValidator::with_max_skew(5);
        let now = Utc::now();
        let ntp_time = now + TimeDelta::seconds(2);

        let status = v.evaluate_skew(now, ntp_time).unwrap();

        assert_eq!(status.severity, SkewSeverity::Warning);
        assert!(status.within_threshold);
    }

    #[test]
    fn test_evaluate_skew_custom_threshold_critical_returns_error() {
        let v = ClockValidator::with_max_skew(5);
        let now = Utc::now();
        let ntp_time = now + TimeDelta::seconds(6);

        let err = v.evaluate_skew(now, ntp_time).unwrap_err();

        assert!(err.to_string().contains("6000ms"));
    }

    // ── chronyc output parsing (table-driven) ──

    #[test]
    fn test_parse_chrony_offset_fast_returns_positive() {
        let output = "\
Reference ID    : A1B2C3D4 (ntp.example.com)
Stratum         : 2
Ref time (UTC)  : Thu Jan 01 00:00:00 2026
System time     : 0.000123456 seconds fast of NTP time
Last offset     : +0.000012345 seconds
RMS offset      : 0.000123456 seconds
Frequency       : 1.234 ppm slow
Residual freq   : +0.001 ppm
Skew            : 0.123 ppm
Root delay      : 0.012345678 seconds
Root dispersion : 0.001234567 seconds
Update interval : 64.0 seconds
Leap status     : Normal";

        let offset = parse_chrony_offset(output).unwrap();

        assert!((offset - 0.000123456).abs() < 1e-10);
    }

    #[test]
    fn test_parse_chrony_offset_slow_returns_negative() {
        let output = "System time     : 0.005000000 seconds slow of NTP time";

        let offset = parse_chrony_offset(output).unwrap();

        assert!((offset - (-0.005)).abs() < 1e-10);
    }

    #[test]
    fn test_parse_chrony_offset_missing_system_time_returns_none() {
        let output = "Reference ID    : A1B2C3D4\nStratum         : 2";

        assert!(parse_chrony_offset(output).is_none());
    }

    #[test]
    fn test_parse_chrony_offset_malformed_number_returns_none() {
        let output = "System time     : not_a_number seconds fast of NTP time";

        assert!(parse_chrony_offset(output).is_none());
    }

    // ── ntpdate output parsing (table-driven) ──

    #[test]
    fn test_parse_ntpdate_offset_negative_value() {
        let output = "server 192.168.1.1, stratum 2, offset -0.003163, delay 0.02567\n\
                       21 Feb 14:30:00 ntpdate[12345]: adjust time server 192.168.1.1 offset -0.003163 sec";

        let offset = parse_ntpdate_offset(output).unwrap();

        assert!((offset - (-0.003163)).abs() < 1e-10);
    }

    #[test]
    fn test_parse_ntpdate_offset_positive_value() {
        let output = "server 10.0.0.1, stratum 1, offset 0.123456, delay 0.001";

        let offset = parse_ntpdate_offset(output).unwrap();

        assert!((offset - 0.123456).abs() < 1e-10);
    }

    #[test]
    fn test_parse_ntpdate_offset_no_offset_field_returns_none() {
        let output = "no server suitable for synchronization found";

        assert!(parse_ntpdate_offset(output).is_none());
    }

    #[test]
    fn test_parse_ntpdate_offset_malformed_number_returns_none() {
        let output = "server 10.0.0.1, offset not_a_number, delay 0.001";

        assert!(parse_ntpdate_offset(output).is_none());
    }

    #[test]
    fn test_parse_ntpdate_offset_empty_input_returns_none() {
        assert!(parse_ntpdate_offset("").is_none());
    }

    #[test]
    fn test_parse_chrony_offset_empty_input_returns_none() {
        assert!(parse_chrony_offset("").is_none());
    }

    // ── Async validation ──

    #[tokio::test]
    async fn test_validate_unreachable_ntp_returns_ok_with_no_ntp_time() {
        let v = ClockValidator {
            max_skew_ms: DEFAULT_MAX_SKEW_MS,
            ntp_servers: vec!["192.0.2.1".to_string()], // RFC 5737 TEST-NET, won't resolve
            system_fallbacks: false,
        };

        let status = v.validate().await.unwrap();

        assert!(status.within_threshold);
        assert!(status.ntp_time.is_none());
        assert_eq!(status.skew_ms, 0);
        assert_eq!(status.severity, SkewSeverity::Normal);
    }
}
