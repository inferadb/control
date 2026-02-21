use std::time::Duration as StdDuration;

use chrono::{DateTime, TimeDelta, Utc};
use inferadb_control_types::error::{Error, Result};

/// Warning threshold in milliseconds (100ms)
const WARNING_SKEW_MS: i64 = 100;

/// Default critical threshold in milliseconds (1 second)
const DEFAULT_MAX_SKEW_MS: i64 = 1000;

/// Timeout for NTP queries
const NTP_TIMEOUT: StdDuration = StdDuration::from_secs(5);

/// Default NTP servers to query
const DEFAULT_NTP_SERVERS: &[&str] = &["pool.ntp.org", "time.google.com"];

/// Clock skew severity classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkewSeverity {
    /// Skew < 100ms
    Normal,
    /// Skew between 100ms and the configured threshold
    Warning,
    /// Skew exceeds the configured threshold
    Critical,
}

/// Clock skew validator for multi-instance coordination
///
/// Distributed systems require synchronized clocks for:
/// - Snowflake ID ordering across instances
/// - TTL-based token expiration consistency
/// - Lease timing in leader election
///
/// Queries NTP servers asynchronously via `rsntp`, falling back to
/// system tools (`chronyc`, `ntpdate`) when direct NTP is unavailable.
pub struct ClockValidator {
    max_skew_ms: i64,
    ntp_servers: Vec<String>,
}

impl ClockValidator {
    /// Create a clock validator with default settings (1s threshold)
    pub fn new() -> Self {
        Self {
            max_skew_ms: DEFAULT_MAX_SKEW_MS,
            ntp_servers: DEFAULT_NTP_SERVERS.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// Create a clock validator with a custom skew threshold in seconds
    pub fn with_max_skew(max_skew_seconds: i64) -> Self {
        Self {
            max_skew_ms: max_skew_seconds * 1000,
            ntp_servers: DEFAULT_NTP_SERVERS.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// Validate system clock against NTP
    ///
    /// Queries NTP time via:
    /// 1. Direct SNTP query using `rsntp`
    /// 2. `chronyc tracking` output parsing (fallback)
    /// 3. `ntpdate -q` output parsing (fallback)
    ///
    /// Classifies the measured skew as Normal (< 100ms),
    /// Warning (100ms to threshold), or Critical (>= threshold).
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

    /// Evaluate the skew between system time and NTP time
    ///
    /// Pure function containing the testable core of clock validation.
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

    /// Query NTP time from available sources (async, non-blocking)
    ///
    /// Accepts the system time captured at the start of validation to ensure
    /// consistent offset calculations even if NTP queries take time.
    async fn query_ntp_time(&self, system_time: DateTime<Utc>) -> Result<DateTime<Utc>> {
        // 1. Direct SNTP query via rsntp
        if let Some(time) = self.query_rsntp().await {
            return Ok(time);
        }

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

        Err(Error::config(
            "No NTP source available. Install chrony or ntpdate for clock validation.".to_string(),
        ))
    }

    /// Query NTP time via rsntp async client
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

    /// Query clock offset via `chronyc tracking` (non-blocking, with timeout)
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

    /// Query clock offset via `ntpdate -q` (non-blocking, with timeout)
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

/// Classify skew magnitude into severity levels
fn classify_skew(skew_ms: i64, max_skew_ms: i64) -> SkewSeverity {
    if skew_ms >= max_skew_ms {
        SkewSeverity::Critical
    } else if skew_ms >= WARNING_SKEW_MS {
        SkewSeverity::Warning
    } else {
        SkewSeverity::Normal
    }
}

/// Parse the clock offset from `chronyc tracking` output
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

/// Parse the clock offset from `ntpdate -q` output
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

/// Clock validation status
#[derive(Debug, Clone)]
pub struct ClockStatus {
    /// System time when validation was performed
    pub system_time: DateTime<Utc>,
    /// NTP time if available
    pub ntp_time: Option<DateTime<Utc>>,
    /// Absolute clock skew in milliseconds
    pub skew_ms: i64,
    /// Severity classification of the measured skew
    pub severity: SkewSeverity,
    /// Whether skew is within the configured threshold
    pub within_threshold: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chrono::TimeDelta;

    use super::*;

    // ── ClockValidator construction ──

    #[test]
    fn test_default_threshold() {
        let v = ClockValidator::new();
        assert_eq!(v.max_skew_ms, DEFAULT_MAX_SKEW_MS);
        assert_eq!(v.ntp_servers.len(), 2);
    }

    #[test]
    fn test_custom_threshold() {
        let v = ClockValidator::with_max_skew(5);
        assert_eq!(v.max_skew_ms, 5000);
    }

    // ── Skew classification ──

    #[test]
    fn test_classify_normal_skew() {
        assert_eq!(classify_skew(0, 1000), SkewSeverity::Normal);
        assert_eq!(classify_skew(50, 1000), SkewSeverity::Normal);
        assert_eq!(classify_skew(99, 1000), SkewSeverity::Normal);
    }

    #[test]
    fn test_classify_warning_skew() {
        assert_eq!(classify_skew(100, 1000), SkewSeverity::Warning);
        assert_eq!(classify_skew(500, 1000), SkewSeverity::Warning);
        assert_eq!(classify_skew(999, 1000), SkewSeverity::Warning);
    }

    #[test]
    fn test_classify_critical_skew() {
        assert_eq!(classify_skew(1000, 1000), SkewSeverity::Critical);
        assert_eq!(classify_skew(2000, 1000), SkewSeverity::Critical);
        assert_eq!(classify_skew(10000, 1000), SkewSeverity::Critical);
    }

    // ── evaluate_skew (mocked NTP responses) ──

    #[test]
    fn test_evaluate_normal_skew() {
        let v = ClockValidator::new();
        let now = Utc::now();
        let ntp_time = now + TimeDelta::milliseconds(50);

        let status = v.evaluate_skew(now, ntp_time).unwrap();
        assert!(status.within_threshold);
        assert_eq!(status.severity, SkewSeverity::Normal);
        assert!(status.skew_ms < WARNING_SKEW_MS);
    }

    #[test]
    fn test_evaluate_warning_skew() {
        let v = ClockValidator::new();
        let now = Utc::now();
        let ntp_time = now + TimeDelta::milliseconds(500);

        let status = v.evaluate_skew(now, ntp_time).unwrap();
        assert!(status.within_threshold);
        assert_eq!(status.severity, SkewSeverity::Warning);
        assert_eq!(status.skew_ms, 500);
    }

    #[test]
    fn test_evaluate_critical_skew_returns_error() {
        let v = ClockValidator::new();
        let now = Utc::now();
        let ntp_time = now + TimeDelta::seconds(3);

        let err = v.evaluate_skew(now, ntp_time).unwrap_err();
        assert!(err.to_string().contains("3000ms"));
        assert!(err.to_string().contains("1000ms"));
    }

    #[test]
    fn test_evaluate_custom_threshold() {
        let v = ClockValidator::with_max_skew(5);
        let now = Utc::now();

        // 2s skew is warning (threshold is 5s)
        let ntp_time = now + TimeDelta::seconds(2);
        let status = v.evaluate_skew(now, ntp_time).unwrap();
        assert!(status.within_threshold);
        assert_eq!(status.severity, SkewSeverity::Warning);

        // 6s skew is critical
        let ntp_time = now + TimeDelta::seconds(6);
        let err = v.evaluate_skew(now, ntp_time).unwrap_err();
        assert!(err.to_string().contains("6000ms"));
    }

    #[test]
    fn test_evaluate_zero_skew() {
        let v = ClockValidator::new();
        let now = Utc::now();

        let status = v.evaluate_skew(now, now).unwrap();
        assert!(status.within_threshold);
        assert_eq!(status.severity, SkewSeverity::Normal);
        assert_eq!(status.skew_ms, 0);
    }

    #[test]
    fn test_evaluate_negative_direction_skew() {
        let v = ClockValidator::new();
        let now = Utc::now();
        // NTP behind system time → same absolute skew
        let ntp_time = now - TimeDelta::milliseconds(500);

        let status = v.evaluate_skew(now, ntp_time).unwrap();
        assert_eq!(status.severity, SkewSeverity::Warning);
        assert_eq!(status.skew_ms, 500);
    }

    // ── chronyc output parsing ──

    #[test]
    fn test_parse_chrony_fast() {
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
    fn test_parse_chrony_slow() {
        let output = "System time     : 0.005000000 seconds slow of NTP time";
        let offset = parse_chrony_offset(output).unwrap();
        assert!((offset - (-0.005)).abs() < 1e-10);
    }

    #[test]
    fn test_parse_chrony_missing() {
        let output = "Reference ID    : A1B2C3D4\nStratum         : 2";
        assert!(parse_chrony_offset(output).is_none());
    }

    #[test]
    fn test_parse_chrony_malformed() {
        let output = "System time     : not_a_number seconds fast of NTP time";
        assert!(parse_chrony_offset(output).is_none());
    }

    // ── ntpdate output parsing ──

    #[test]
    fn test_parse_ntpdate_negative_offset() {
        let output = "server 192.168.1.1, stratum 2, offset -0.003163, delay 0.02567\n\
                       21 Feb 14:30:00 ntpdate[12345]: adjust time server 192.168.1.1 offset -0.003163 sec";
        let offset = parse_ntpdate_offset(output).unwrap();
        assert!((offset - (-0.003163)).abs() < 1e-10);
    }

    #[test]
    fn test_parse_ntpdate_positive_offset() {
        let output = "server 10.0.0.1, stratum 1, offset 0.123456, delay 0.001";
        let offset = parse_ntpdate_offset(output).unwrap();
        assert!((offset - 0.123456).abs() < 1e-10);
    }

    #[test]
    fn test_parse_ntpdate_missing() {
        let output = "no server suitable for synchronization found";
        assert!(parse_ntpdate_offset(output).is_none());
    }

    #[test]
    fn test_parse_ntpdate_malformed() {
        let output = "server 10.0.0.1, offset not_a_number, delay 0.001";
        assert!(parse_ntpdate_offset(output).is_none());
    }

    // ── Async validation (integration-like) ──

    #[tokio::test]
    async fn test_validate_soft_fails_without_ntp() {
        let v = ClockValidator {
            max_skew_ms: DEFAULT_MAX_SKEW_MS,
            ntp_servers: vec!["192.0.2.1".to_string()], // RFC 5737 TEST-NET, won't resolve
        };

        // Should soft-fail and return OK with no NTP data
        let status = v.validate().await.unwrap();
        assert!(status.within_threshold);
        assert!(status.ntp_time.is_none());
    }
}
