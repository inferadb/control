use crate::config::ObservabilityConfig;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

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
/// use infera_management_core::{config::ObservabilityConfig, logging};
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
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::trace::Sampler;
    use tracing_opentelemetry::OpenTelemetryLayer;

    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // Set up OpenTelemetry if tracing is enabled
    if config.tracing_enabled {
        let otlp_endpoint = config
            .otlp_endpoint
            .as_ref()
            .ok_or("OTLP endpoint not configured")?;

        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(otlp_endpoint),
            )
            .with_trace_config(
                opentelemetry_sdk::trace::Config::default()
                    .with_sampler(Sampler::TraceIdRatioBased(0.1)) // 10% sampling
                    .with_resource(opentelemetry_sdk::Resource::new(vec![
                        opentelemetry::KeyValue::new("service.name", service_name.to_string()),
                    ])),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)?;

        let telemetry_layer = OpenTelemetryLayer::new(tracer.tracer(service_name));

        if json {
            let fmt_layer = fmt::layer()
                .json()
                .with_target(true)
                .with_current_span(true)
                .with_span_list(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_filter(env_filter.clone());

            tracing_subscriber::registry()
                .with(fmt_layer)
                .with(telemetry_layer)
                .init();
        } else {
            let fmt_layer = fmt::layer()
                .pretty()
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_filter(env_filter.clone());

            tracing_subscriber::registry()
                .with(fmt_layer)
                .with(telemetry_layer)
                .init();
        }
    } else {
        // Fallback to basic logging if tracing is not enabled
        init(config, json);
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
}
