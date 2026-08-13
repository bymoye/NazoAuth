use super::*;
use nazo_auth::DynamicRegistrationSecretPort;
use nazo_http_actix::{
    DynamicRegistrationDependencyError, DynamicRegistrationRateLimitError,
    DynamicRegistrationRequestGuard,
};

use crate::{
    config::ConfigSource, runtime_modules::test_support::runtime_module_registry_for_test,
    settings::Settings,
};

use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};

#[test]
fn dynamic_registration_initial_access_digest_is_lowercase_sha256() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn dynamic_registration_secret_port_hashes_and_compares_without_plaintext_reuse() {
    let secrets = ServerDynamicRegistrationTokens;
    let token = secrets.random_token();
    let hash = secrets.token_hash(&token);

    assert!(!token.is_empty());
    assert_ne!(hash, token);
    assert!(secrets.constant_time_eq(hash.as_bytes(), hash.as_bytes()));
    assert!(!secrets.constant_time_eq(hash.as_bytes(), token.as_bytes()));
}

#[test]
fn dynamic_registration_config_copies_security_and_rate_limit_settings() {
    let config = ConfigSource::from_pairs_for_test([
        ("ISSUER", "https://issuer.example"),
        ("DEFAULT_AUDIENCE", "https://resource.example"),
        (
            "PAIRWISE_SUBJECT_SECRET",
            "pairwise-subject-secret-for-tests-000000000001",
        ),
        (
            "CLIENT_SECRET_PEPPER",
            "client-secret-pepper-for-tests-000000000001",
        ),
        (
            "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
            "initial-access-token",
        ),
        ("RATE_LIMIT_WINDOW_SECONDS", "37"),
        ("TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS", "11"),
        ("TRUSTED_PROXY_CIDRS", "203.0.113.0/24"),
    ]);
    let settings = Settings::from_config(&config).expect("dynamic registration settings");
    let dynamic = DynamicRegistrationConfig::from(&settings);

    assert_eq!(dynamic.issuer, "https://issuer.example");
    assert_eq!(dynamic.default_audience, "https://resource.example");
    assert_eq!(
        dynamic.pairwise_subject_secret.as_deref(),
        Some("pairwise-subject-secret-for-tests-000000000001")
    );
    assert_eq!(
        dynamic.initial_access_token.as_deref(),
        Some("initial-access-token")
    );
    assert_eq!(dynamic.rate_limit_window_seconds, 37);
    assert_eq!(dynamic.rate_limit_max_requests, 11);
    assert_eq!(dynamic.trusted_proxy_cidrs.len(), 1);
}

fn unavailable_dynamic_registration_guard(
    settings: &Settings,
) -> ServerDynamicRegistrationRequestGuard {
    let pool = nazo_postgres::create_pool(
        "postgres://dynamic-registration-test:dynamic-registration-test@127.0.0.1:1/nazo"
            .to_owned(),
        1,
    )
    .expect("pool construction should not connect");
    let runtime = runtime_module_registry_for_test(pool.clone(), settings)
        .expect("runtime module fixture should build");
    let mut builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url("redis://127.0.0.1:1").expect("unavailable Valkey URL"),
    );
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = std::time::Duration::from_millis(100);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = std::time::Duration::from_millis(100);
        connection.internal_command_timeout = std::time::Duration::from_millis(100);
        connection.max_command_attempts = 1;
    });
    let valkey = builder.build().expect("Valkey client should build");
    let valkey = nazo_valkey::ValkeyConnection::from_existing_client(valkey);
    ServerDynamicRegistrationRequestGuard::new(
        nazo_valkey::RateLimitStore::new(&valkey),
        &DynamicRegistrationConfig::from(settings),
        runtime,
        nazo_postgres::ConformanceLeaseRepository::new(pool),
    )
}

#[tokio::test]
async fn dynamic_registration_guard_fails_closed_for_unavailable_dependencies() {
    let config = ConfigSource::from_pairs_for_test([(
        "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
        "initial-token",
    )]);
    let settings = Settings::from_config(&config).expect("enabled dynamic registration settings");
    let guard = unavailable_dynamic_registration_guard(&settings);

    assert!(guard.accepts_new_requests());
    assert_eq!(
        guard.enforce_rate_limit("203.0.113.77").await,
        Err(DynamicRegistrationRateLimitError::Unavailable)
    );
    assert_eq!(
        guard
            .conformance_lease_for_initial_access_token("initial-token")
            .await,
        Err(DynamicRegistrationDependencyError::Unavailable)
    );
}

#[test]
fn dynamic_registration_guard_rejects_new_requests_when_module_is_disabled() {
    let settings = Settings::from_config(&ConfigSource::default()).expect("settings");
    let guard = unavailable_dynamic_registration_guard(&settings);

    assert!(!guard.accepts_new_requests());
}
