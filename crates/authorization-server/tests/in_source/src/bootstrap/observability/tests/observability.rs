use super::*;

#[test]
fn otel_config_is_disabled_by_default() {
    let config = ConfigSource::from_pairs_for_test([]);

    assert!(OtelConfig::from_config(&config).unwrap().is_none());
}

#[test]
fn otel_config_explicit_false_overrides_inherited_endpoint() {
    let config = ConfigSource::from_pairs_for_test([
        ("OTEL_ENABLED", "false"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318"),
    ]);

    assert!(OtelConfig::from_config(&config).unwrap().is_none());
}

#[test]
fn otel_config_accepts_explicit_endpoint_and_timeout() {
    let config = ConfigSource::from_pairs_for_test([
        ("OTEL_ENABLED", "true"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318"),
        ("OTEL_EXPORTER_OTLP_TIMEOUT", "2500"),
    ]);

    let otel = OtelConfig::from_config(&config).unwrap().unwrap();

    assert_eq!(otel.endpoint, "http://collector:4318");
    assert_eq!(otel.timeout, Some(Duration::from_millis(2_500)));
    assert_eq!(
        otel.signal_endpoint("/v1/traces"),
        "http://collector:4318/v1/traces"
    );
}

#[test]
fn otel_config_rejects_unsupported_protocol_and_bad_endpoint() {
    let protocol = ConfigSource::from_pairs_for_test([
        ("OTEL_ENABLED", "true"),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
    ]);
    assert!(OtelConfig::from_config(&protocol).is_err());

    let endpoint = ConfigSource::from_pairs_for_test([
        ("OTEL_ENABLED", "true"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4318"),
    ]);
    assert!(OtelConfig::from_config(&endpoint).is_err());
}
