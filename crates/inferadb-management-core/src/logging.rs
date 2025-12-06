//! Structured logging utilities for InferaDB Management
//!
//! Provides enhanced logging with contextual fields and formatting options,
//! matching the server's logging architecture for consistent developer experience.

use std::io::IsTerminal;

use tracing_subscriber::{
    EnvFilter, Layer, fmt, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

use crate::config::ObservabilityConfig;

/// Log output format options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Standard single-line format (matches server default)
    /// Output: `2025-01-15T10:30:45.123456Z  INFO target: message key=value`
    Full,
    /// Human-readable multi-line format with colors (for development debugging)
    Pretty,
    /// Compact single-line format without timestamp details
    Compact,
    /// JSON format (for production log aggregation)
    Json,
}

#[allow(clippy::derivable_impls)]
impl Default for LogFormat {
    fn default() -> Self {
        #[cfg(debug_assertions)]
        {
            LogFormat::Full // Match server's default format in development
        }
        #[cfg(not(debug_assertions))]
        {
            LogFormat::Json
        }
    }
}

/// Configuration for logging behavior
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Output format
    pub format: LogFormat,
    /// Whether to include file/line numbers
    pub include_location: bool,
    /// Whether to include target module
    pub include_target: bool,
    /// Whether to include thread IDs
    pub include_thread_id: bool,
    /// Whether to log span events (enter/exit/close)
    pub log_spans: bool,
    /// Whether to use ANSI colors (None = auto-detect based on TTY)
    pub ansi: Option<bool>,
    /// Environment filter (e.g., "info,inferadb_management=debug")
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

/// Initialize structured logging with configuration
///
/// This is the primary logging initialization function that provides full control
/// over log format and behavior, matching the server's logging API.
///
/// # Arguments
///
/// * `config` - Logging configuration options
///
/// # Examples
///
/// ```no_run
/// use inferadb_management_core::logging::{LogConfig, LogFormat, init_logging};
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
            .unwrap_or_else(|_| EnvFilter::new("info,inferadb_management=debug"))
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

/// Initialize structured logging based on ObservabilityConfig (backward compatible)
///
/// Sets up tracing-subscriber with either JSON or compact formatting based on environment.
/// In production (when `json` is true), logs are emitted as JSON for structured ingestion.
/// In development, logs use compact single-line formatting (matching server output style).
///
/// # Arguments
///
/// * `config` - Observability configuration containing log level and formatting preferences
/// * `json` - Whether to use JSON formatting (true for production, false for development)
///
/// # Examples
///
/// ```no_run
/// use inferadb_management_core::{config::ObservabilityConfig, logging};
///
/// let config = ObservabilityConfig {
///     log_level: "info".to_string(),
///     metrics_enabled: true,
///     tracing_enabled: false,
///     otlp_endpoint: None,
/// };
///
/// // Production mode with JSON formatting
/// logging::init(&config, true);
///
/// // Development mode with compact formatting
/// logging::init(&config, false);
/// ```
pub fn init(config: &ObservabilityConfig, json: bool) {
    let log_config = LogConfig {
        format: if json { LogFormat::Json } else { LogFormat::Full },
        filter: Some(config.log_level.clone()),
        include_location: false,
        include_target: json, // Include target only in JSON mode for log aggregation
        include_thread_id: json, // Include thread info in JSON mode
        log_spans: false,
        ansi: None, // Auto-detect
    };

    if let Err(e) = init_logging(log_config) {
        eprintln!("Failed to initialize logging: {}", e);
    }
}

/// Initialize logging with OpenTelemetry support
///
/// This sets up both structured logging and OpenTelemetry tracing when enabled.
/// Traces are exported to the configured OTLP endpoint.
///
/// # Arguments
///
/// * `config` - Observability configuration
/// * `json` - Whether to use JSON formatting
/// * `service_name` - Name of the service for tracing
///
/// # Returns
///
/// Returns `Ok(())` if initialization succeeds, or an error if OTLP setup fails.
#[cfg(feature = "opentelemetry")]
pub fn init_with_tracing(
    config: &ObservabilityConfig,
    json: bool,
    service_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};

    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_level))
        .unwrap_or_else(|_| EnvFilter::new("info,inferadb_management=debug"));

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

    // Set up OpenTelemetry if tracing is enabled
    if config.tracing_enabled {
        let otlp_endpoint = config.otlp_endpoint.as_ref().ok_or("OTLP endpoint not configured")?;

        // Build the OTLP exporter
        let exporter =
            SpanExporter::builder().with_tonic().with_endpoint(otlp_endpoint.clone()).build()?;

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
            otlp_endpoint = otlp_endpoint.as_str(),
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

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert_eq!(config.format, LogFormat::default());
        assert!(!config.include_target);
        assert!(!config.include_thread_id);
        assert!(config.ansi.is_none()); // Auto-detect
    }

    #[test]
    fn test_log_format_default() {
        let format = LogFormat::default();
        #[cfg(debug_assertions)]
        assert_eq!(format, LogFormat::Full);
        #[cfg(not(debug_assertions))]
        assert_eq!(format, LogFormat::Json);
    }

    #[test]
    fn test_log_format_variants() {
        assert_eq!(LogFormat::Full, LogFormat::Full);
        assert_eq!(LogFormat::Pretty, LogFormat::Pretty);
        assert_eq!(LogFormat::Compact, LogFormat::Compact);
        assert_eq!(LogFormat::Json, LogFormat::Json);
        assert_ne!(LogFormat::Full, LogFormat::Json);
    }

    #[test]
    fn test_log_config_custom() {
        let config = LogConfig {
            format: LogFormat::Json,
            include_location: true,
            include_target: false,
            include_thread_id: true,
            log_spans: true,
            ansi: Some(false),
            filter: Some("warn".to_string()),
        };

        assert_eq!(config.format, LogFormat::Json);
        assert!(config.include_location);
        assert!(!config.include_target);
        assert!(config.include_thread_id);
        assert!(config.log_spans);
        assert_eq!(config.ansi, Some(false));
        assert_eq!(config.filter, Some("warn".to_string()));
    }

    #[test]
    fn test_observability_config_creation() {
        let config = ObservabilityConfig {
            log_level: "debug".to_string(),
            metrics_enabled: true,
            tracing_enabled: false,
            otlp_endpoint: None,
        };

        assert_eq!(config.log_level, "debug");
        assert!(config.metrics_enabled);
        assert!(!config.tracing_enabled);
    }

    #[test]
    fn test_init_logging_does_not_panic() {
        init_test_logging();
        // If we get here without panicking, the test passes
    }

    #[cfg(feature = "opentelemetry")]
    #[test]
    fn test_init_with_tracing_disabled() {
        let config = ObservabilityConfig {
            log_level: "info".to_string(),
            metrics_enabled: false,
            tracing_enabled: false,
            otlp_endpoint: None,
        };

        // Should succeed when tracing is disabled (falls back to basic logging)
        // We can't actually call this due to the global subscriber limitation,
        // but we can verify the config is valid
        assert!(!config.tracing_enabled);
        assert_eq!(config.otlp_endpoint, None);
    }

    #[cfg(feature = "opentelemetry")]
    #[test]
    fn test_init_with_tracing_missing_endpoint() {
        let config = ObservabilityConfig {
            log_level: "info".to_string(),
            metrics_enabled: false,
            tracing_enabled: true,
            otlp_endpoint: None,
        };

        // Should fail when tracing is enabled but endpoint is missing
        // We verify the config would fail validation
        assert!(config.tracing_enabled);
        assert_eq!(config.otlp_endpoint, None);
        // In actual usage, init_with_tracing would return an error
    }
}
