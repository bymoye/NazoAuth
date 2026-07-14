use std::time::Duration;

use anyhow::{Context, bail};
use opentelemetry::{KeyValue, global, trace::TracerProvider as _};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::{
    Resource, logs::SdkLoggerProvider, metrics::SdkMeterProvider, trace::SdkTracerProvider,
};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::ConfigSource;

const SERVICE_NAME: &str = "nazo-oauth-server";
const DEFAULT_OTLP_HTTP_ENDPOINT: &str = "http://localhost:4318";

pub(crate) struct ObservabilityGuard {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
    logger_provider: Option<SdkLoggerProvider>,
}

impl Drop for ObservabilityGuard {
    fn drop(&mut self) {
        if let Some(logger_provider) = self.logger_provider.take() {
            let _ = logger_provider.shutdown();
        }
        if let Some(meter_provider) = self.meter_provider.take() {
            let _ = meter_provider.shutdown();
        }
        if let Some(tracer_provider) = self.tracer_provider.take() {
            let _ = tracer_provider.shutdown();
        }
    }
}

pub(crate) fn init(config: &ConfigSource) -> anyhow::Result<ObservabilityGuard> {
    let env_filter = EnvFilter::try_new(config.string("RUST_LOG", "info"))
        .context("RUST_LOG must be a valid tracing filter")?;
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(true);
    let Some(otel_config) = OtelConfig::from_config(config)? else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
        return Ok(ObservabilityGuard {
            tracer_provider: None,
            meter_provider: None,
            logger_provider: None,
        });
    };

    let resource = Resource::builder()
        .with_service_name(SERVICE_NAME)
        .with_attributes([KeyValue::new("service.version", env!("CARGO_PKG_VERSION"))])
        .build();

    let trace_exporter = otel_http_span_exporter(&otel_config)?;
    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(trace_exporter)
        .build();
    let tracer = tracer_provider.tracer(SERVICE_NAME);

    let metric_exporter = otel_http_metric_exporter(&otel_config)?;
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource.clone())
        .with_periodic_exporter(metric_exporter)
        .build();
    global::set_meter_provider(meter_provider.clone());

    let log_exporter = otel_http_log_exporter(&otel_config)?;
    let logger_provider = SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(log_exporter)
        .build();

    let trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let metrics_layer = tracing_opentelemetry::MetricsLayer::new(meter_provider.clone());
    let log_layer = OpenTelemetryTracingBridge::new(&logger_provider);
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(trace_layer)
        .with(metrics_layer)
        .with(log_layer)
        .init();

    tracing::info!(
        monotonic_counter.otel_pipeline_start = 1_u64,
        otel.endpoint = otel_config.endpoint.as_str(),
        "OpenTelemetry OTLP pipeline enabled"
    );

    Ok(ObservabilityGuard {
        tracer_provider: Some(tracer_provider),
        meter_provider: Some(meter_provider),
        logger_provider: Some(logger_provider),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OtelConfig {
    endpoint: String,
    timeout: Option<Duration>,
}

impl OtelConfig {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Option<Self>> {
        let enabled = config.bool("OTEL_ENABLED", false)?;
        if !enabled {
            return Ok(None);
        }
        let endpoint = config.optional_string("OTEL_EXPORTER_OTLP_ENDPOINT");
        let protocol = config.string("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf");
        if protocol != "http/protobuf" {
            bail!("OTEL_EXPORTER_OTLP_PROTOCOL must be http/protobuf");
        }
        let endpoint = endpoint.unwrap_or_else(|| DEFAULT_OTLP_HTTP_ENDPOINT.to_owned());
        validate_otlp_endpoint(&endpoint)?;
        let timeout = config
            .optional_string("OTEL_EXPORTER_OTLP_TIMEOUT")
            .map(|value| {
                value
                    .parse::<u64>()
                    .context("OTEL_EXPORTER_OTLP_TIMEOUT must be milliseconds")
                    .map(Duration::from_millis)
            })
            .transpose()?;
        Ok(Some(Self { endpoint, timeout }))
    }

    fn signal_endpoint(&self, signal_path: &str) -> String {
        format!(
            "{}/{}",
            self.endpoint.trim_end_matches('/'),
            signal_path.trim_start_matches('/')
        )
    }
}

fn validate_otlp_endpoint(endpoint: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(endpoint).context("OTEL_EXPORTER_OTLP_ENDPOINT must be a URL")?;
    if !matches!(url.scheme(), "http" | "https") || !url.has_host() {
        bail!("OTEL_EXPORTER_OTLP_ENDPOINT must be an absolute http(s) URL");
    }
    Ok(())
}

fn otel_http_span_exporter(
    config: &OtelConfig,
) -> anyhow::Result<opentelemetry_otlp::SpanExporter> {
    let mut builder = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(config.signal_endpoint("/v1/traces"));
    if let Some(timeout) = config.timeout {
        builder = builder.with_timeout(timeout);
    }
    builder
        .build()
        .context("failed to build OTLP span exporter")
}

fn otel_http_metric_exporter(
    config: &OtelConfig,
) -> anyhow::Result<opentelemetry_otlp::MetricExporter> {
    let mut builder = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(config.signal_endpoint("/v1/metrics"));
    if let Some(timeout) = config.timeout {
        builder = builder.with_timeout(timeout);
    }
    builder
        .build()
        .context("failed to build OTLP metric exporter")
}

fn otel_http_log_exporter(config: &OtelConfig) -> anyhow::Result<opentelemetry_otlp::LogExporter> {
    let mut builder = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(config.signal_endpoint("/v1/logs"));
    if let Some(timeout) = config.timeout {
        builder = builder.with_timeout(timeout);
    }
    builder.build().context("failed to build OTLP log exporter")
}

#[cfg(test)]
#[path = "../../tests/in_source/src/bootstrap/observability/tests/observability.rs"]
mod tests;
