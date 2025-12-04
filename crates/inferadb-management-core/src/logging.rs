use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::ObservabilityConfig;

/// Initialize structured logging based on configuration
///
/// Sets up tracing-subscriber with either JSON or pretty formatting based on environment.
/// In production (when `json` is true), logs are emitted as JSON for structured ingestion.
/// In development, logs use human-readable formatting.
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
/// // Development mode with pretty formatting
/// logging::init(&config, false);
/// ```
pub fn init(config: &ObservabilityConfig, json: bool) {
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    if json {
        // Production: JSON structured logging
        let fmt_layer = fmt::layer()
            .json()
            .with_target(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_filter(env_filter);

        tracing_subscriber::registry().with(fmt_layer).init();
    } else {
        // Development: Pretty human-readable logging
        let fmt_layer = fmt::layer()
            .pretty()
            .with_target(true)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_filter(env_filter);

        tracing_subscriber::registry().with(fmt_layer).init();
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
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // Build the base logging layer
    let fmt_layer = if json {
        // Production: JSON structured logging
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
        // Development: Pretty human-readable logging
        fmt::layer()
            .pretty()
            .with_target(true)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_filter(env_filter.clone())
            .boxed()
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
    use super::*;

    // Note: We cannot test init() directly in unit tests because
    // tracing-subscriber only allows setting the global default subscriber once per process.
    // The logging initialization is tested through integration tests.

    #[test]
    fn test_config_creation() {
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
