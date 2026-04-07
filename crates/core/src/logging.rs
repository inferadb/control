//! Structured logging initialization for InferaDB Control.
//!
//! Configures tracing-subscriber with format options (full, pretty, compact,
//! JSON) and optional OpenTelemetry export.

use std::io::IsTerminal;

use tracing_subscriber::{
    EnvFilter, Layer, fmt, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

/// Log output format options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Standard single-line format (matches server default).
    /// Output: `<timestamp>  INFO target: message key=value`
    Full,
    /// Human-readable multi-line format with colors (for development debugging).
    Pretty,
    /// Compact single-line format without timestamp details.
    Compact,
    /// JSON format (for production log aggregation).
    Json,
}

// Clippy sees only one cfg branch at a time and thinks this is derivable,
// but we intentionally return different defaults: Full in debug, Json in release.
#[allow(clippy::derivable_impls)]
impl Default for LogFormat {
    fn default() -> Self {
        #[cfg(debug_assertions)]
        {
            LogFormat::Full
        }
        #[cfg(not(debug_assertions))]
        {
            LogFormat::Json
        }
    }
}

/// Configuration for logging behavior.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Output format.
    pub format: LogFormat,
    /// Whether to include file/line numbers.
    pub include_location: bool,
    /// Whether to include target module.
    pub include_target: bool,
    /// Whether to include thread IDs.
    pub include_thread_id: bool,
    /// Whether to log span events (enter/exit/close).
    pub log_spans: bool,
    /// Whether to use ANSI colors (None = auto-detect based on TTY).
    pub ansi: Option<bool>,
    /// Environment filter (e.g., "info,inferadb_control=debug").
    pub filter: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::default(),
            include_location: cfg!(debug_assertions),
            include_target: false,
            include_thread_id: false,
            log_spans: cfg!(debug_assertions),
            ansi: None, // Auto-detect
            filter: None,
        }
    }
}

/// Initializes structured logging from a [`LogConfig`].
///
/// Configures tracing-subscriber with the specified format, filters, and
/// output options.
///
/// # Errors
///
/// Returns an error if the env filter is invalid or the subscriber
/// cannot be initialized (e.g., a global subscriber is already set).
///
/// # Examples
///
/// ```no_run
/// use inferadb_control_core::logging::{LogConfig, LogFormat, init_logging};
///
/// // Development: Pretty format with colors
/// let config = LogConfig {
///     format: LogFormat::Pretty,
///     ..Default::default()
/// };
/// init_logging(config).unwrap();
///
/// // Production: JSON format
/// let config = LogConfig {
///     format: LogFormat::Json,
///     filter: Some("info".to_string()),
///     ..Default::default()
/// };
/// init_logging(config).unwrap();
/// ```
pub fn init_logging(config: LogConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let env_filter = if let Some(filter) = &config.filter {
        EnvFilter::try_new(filter)?
    } else {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,inferadb_control=debug"))
    };

    // Auto-detect ANSI support based on TTY, or use explicit setting
    let ansi = config.ansi.unwrap_or_else(|| std::io::stdout().is_terminal());

    let fmt_span = if config.log_spans { FmtSpan::NEW | FmtSpan::CLOSE } else { FmtSpan::NONE };

    match config.format {
        LogFormat::Full => {
            // Standard format matching server's default output style
            let fmt_layer = fmt::layer().with_target(config.include_target).with_filter(env_filter);

            tracing_subscriber::registry().with(fmt_layer).try_init()?;
        },
        LogFormat::Pretty => {
            let fmt_layer = fmt::layer()
                .pretty()
                .with_ansi(ansi)
                .with_target(config.include_target)
                .with_thread_ids(config.include_thread_id)
                .with_file(config.include_location)
                .with_line_number(config.include_location)
                .with_span_events(fmt_span)
                .with_filter(env_filter);

            tracing_subscriber::registry().with(fmt_layer).try_init()?;
        },
        LogFormat::Compact => {
            let fmt_layer = fmt::layer()
                .compact()
                .with_ansi(ansi)
                .with_target(config.include_target)
                .with_thread_ids(config.include_thread_id)
                .with_file(config.include_location)
                .with_line_number(config.include_location)
                .with_span_events(fmt_span)
                .with_filter(env_filter);

            tracing_subscriber::registry().with(fmt_layer).try_init()?;
        },
        LogFormat::Json => {
            let fmt_layer = fmt::layer()
                .json()
                .with_target(config.include_target)
                .with_current_span(true)
                .with_span_list(true)
                .with_thread_ids(config.include_thread_id)
                .with_thread_names(config.include_thread_id)
                .with_filter(env_filter);

            tracing_subscriber::registry().with(fmt_layer).try_init()?;
        },
    }

    tracing::debug!(
        format = ?config.format,
        location = config.include_location,
        target = config.include_target,
        ansi = ansi,
        "Logging initialized"
    );

    Ok(())
}

/// Initializes structured logging with a log level string.
///
/// Uses JSON formatting when `json` is true, or the standard
/// single-line format when false.
///
/// # Arguments
///
/// * `log_level` - Log level string (trace, debug, info, warn, error)
/// * `json` - Whether to use JSON formatting (true for production, false for development)
///
/// # Examples
///
/// ```no_run
/// use inferadb_control_core::logging;
///
/// // Production mode with JSON formatting
/// logging::init("info", true);
///
/// // Development mode with compact formatting
/// logging::init("debug", false);
/// ```
pub fn init(log_level: &str, json: bool) {
    let log_config = LogConfig {
        format: if json { LogFormat::Json } else { LogFormat::Full },
        filter: Some(log_level.to_string()),
        include_location: false,
        include_target: json, // Include target only in JSON mode for log aggregation
        include_thread_id: json, // Include thread info in JSON mode
        log_spans: false,
        ansi: None, // Auto-detect
    };

    if let Err(e) = init_logging(log_config) {
        eprintln!("Failed to initialize logging: {e}");
    }
}

/// Initializes structured logging with optional OpenTelemetry tracing.
///
/// Configures tracing-subscriber for log output and, when `otlp_endpoint` is
/// provided, exports traces to the OTLP collector at 10% sampling.
///
/// # Arguments
///
/// * `log_level` - Log level string (trace, debug, info, warn, error)
/// * `otlp_endpoint` - Optional OTLP endpoint for tracing
/// * `json` - Whether to use JSON formatting
/// * `service_name` - Name of the service for tracing
///
/// # Errors
///
/// Returns an error if the OTLP exporter or tracer provider fails to initialize.
#[cfg(feature = "opentelemetry")]
pub fn init_with_tracing(
    log_level: &str,
    otlp_endpoint: Option<&str>,
    json: bool,
    service_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};

    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(log_level))
        .unwrap_or_else(|_| EnvFilter::new("info,inferadb_control=debug"));

    // Build the base logging layer
    let fmt_layer = if json {
        // Production: JSON structured logging (include target for log aggregation)
        fmt::layer()
            .json()
            .with_target(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_filter(env_filter.clone())
            .boxed()
    } else {
        // Development: Standard format without target (cleaner output)
        fmt::layer().with_target(false).with_filter(env_filter.clone()).boxed()
    };

    let subscriber = tracing_subscriber::registry().with(fmt_layer);

    // Set up OpenTelemetry if endpoint is configured
    if let Some(endpoint) = otlp_endpoint {
        // Build the OTLP exporter
        let exporter =
            SpanExporter::builder().with_tonic().with_endpoint(endpoint.to_string()).build()?;

        // Build the resource with service name
        let resource = opentelemetry_sdk::Resource::builder()
            .with_service_name(service_name.to_string())
            .build();

        // Build the tracer provider with 10% sampling
        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_sampler(Sampler::TraceIdRatioBased(0.1))
            .with_id_generator(RandomIdGenerator::default())
            .with_resource(resource)
            .build();

        // Create the OpenTelemetry layer
        let telemetry_layer = tracing_opentelemetry::layer()
            .with_tracer(tracer_provider.tracer(service_name.to_string()));

        // Initialize with both logging and tracing layers
        subscriber.with(telemetry_layer).init();

        tracing::info!(
            service = service_name,
            otlp_endpoint = endpoint,
            sample_rate = 0.1,
            "Tracing initialized with OpenTelemetry"
        );
    } else {
        // Initialize with logging only
        subscriber.init();

        tracing::info!(service = service_name, "Tracing initialized without OpenTelemetry");
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Once;

    use super::*;

    static INIT: Once = Once::new();

    fn init_test_logging() {
        INIT.call_once(|| {
            let _ = init_logging(LogConfig {
                format: LogFormat::Compact,
                include_location: false,
                include_target: false,
                include_thread_id: false,
                log_spans: true,
                ansi: Some(false),
                filter: Some("debug".to_string()),
            });
        });
    }

    // ── LogFormat ──

    #[test]
    fn test_log_format_default_matches_build_profile() {
        let format = LogFormat::default();

        #[cfg(debug_assertions)]
        assert_eq!(format, LogFormat::Full);
        #[cfg(not(debug_assertions))]
        assert_eq!(format, LogFormat::Json);
    }

    #[test]
    fn test_log_format_variants_are_distinct() {
        let variants = [LogFormat::Full, LogFormat::Pretty, LogFormat::Compact, LogFormat::Json];

        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "{a:?} should differ from {b:?}");
                }
            }
        }
    }

    // ── LogConfig defaults ──

    #[test]
    fn test_log_config_default_target_and_thread_disabled() {
        let config = LogConfig::default();

        assert!(!config.include_target);
        assert!(!config.include_thread_id);
        assert!(config.ansi.is_none());
        assert!(config.filter.is_none());
    }

    #[test]
    fn test_log_config_default_location_matches_build_profile() {
        let config = LogConfig::default();

        #[cfg(debug_assertions)]
        {
            assert!(config.include_location);
            assert!(config.log_spans);
        }
        #[cfg(not(debug_assertions))]
        {
            assert!(!config.include_location);
            assert!(!config.log_spans);
        }
    }

    // ── LogConfig construction ──

    #[test]
    fn test_log_config_custom_fields_are_preserved() {
        let config = LogConfig {
            format: LogFormat::Json,
            include_location: true,
            include_target: true,
            include_thread_id: true,
            log_spans: true,
            ansi: Some(false),
            filter: Some("warn".to_string()),
        };

        assert_eq!(config.format, LogFormat::Json);
        assert!(config.include_location);
        assert!(config.include_target);
        assert!(config.include_thread_id);
        assert!(config.log_spans);
        assert_eq!(config.ansi, Some(false));
        assert_eq!(config.filter, Some("warn".to_string()));
    }

    #[test]
    fn test_log_config_clone_preserves_all_fields() {
        let config = LogConfig {
            format: LogFormat::Json,
            include_location: true,
            include_target: true,
            include_thread_id: true,
            log_spans: true,
            ansi: Some(true),
            filter: Some("trace".to_string()),
        };

        let cloned = config.clone();

        assert_eq!(cloned.format, config.format);
        assert_eq!(cloned.include_location, config.include_location);
        assert_eq!(cloned.include_target, config.include_target);
        assert_eq!(cloned.include_thread_id, config.include_thread_id);
        assert_eq!(cloned.log_spans, config.log_spans);
        assert_eq!(cloned.ansi, config.ansi);
        assert_eq!(cloned.filter, config.filter);
    }

    // ── init_logging ──

    #[test]
    fn test_init_logging_succeeds_without_panic() {
        init_test_logging();
    }

    #[test]
    fn test_init_logging_duplicate_subscriber_silently_handled() {
        // The first call succeeds (or already happened). The second fails because
        // a global subscriber is already set -- but init() swallows the error.
        init("warn", true);
        init("info", false);
    }

    // ── init() convenience function ──

    #[test]
    fn test_init_json_true_does_not_panic() {
        init("warn", true);
    }

    #[test]
    fn test_init_json_false_does_not_panic() {
        init("info", false);
    }
}
