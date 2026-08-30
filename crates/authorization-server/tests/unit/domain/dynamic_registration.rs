use super::*;
use nazo_auth::{
    DynamicRegistrationSecretPort, RequestRateLimitBucket, RequestRateLimitError,
    RequestRateLimitFuture, RequestRateLimitPort,
};
use nazo_http_actix::{DynamicRegistrationRateLimitError, DynamicRegistrationRequestGuard};

use crate::{
    config::ConfigSource,
    runtime_modules::test_support::runtime_module_registry_with_modules_for_test,
    settings::Settings,
};

#[derive(Clone, Copy)]
struct FakeRateLimiter(Result<u64, RequestRateLimitError>);

impl RequestRateLimitPort for FakeRateLimiter {
    fn increment<'a>(
        &'a self,
        bucket: RequestRateLimitBucket,
        _subject: &'a str,
        window_seconds: u64,
    ) -> RequestRateLimitFuture<'a> {
        Box::pin(async move {
            assert_eq!(bucket, RequestRateLimitBucket::TokenManagement);
            assert!(window_seconds > 0);
            self.0
        })
    }
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
        ("TRANSPORT_MODE", "trusted-proxy"),
        ("TRUSTED_PROXY_CIDRS", "203.0.113.0/24"),
        ("MTLS_CERTIFICATE_SOURCE", "disabled"),
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

fn dynamic_registration_guard(
    settings: &Settings,
    enabled: bool,
    rate_limit_result: Result<u64, RequestRateLimitError>,
) -> ServerDynamicRegistrationRequestGuard {
    let pool = nazo_postgres::create_pool(
        "postgres://dynamic-registration-test:dynamic-registration-test@127.0.0.1:1/nazo"
            .to_owned(),
        1,
    )
    .expect("pool construction should not connect");
    let mut active_modules = crate::test_support::persisted_runtime_modules_fixture();
    if enabled {
        active_modules.insert(nazo_runtime_modules::ModuleId::DynamicClientRegistration);
    }
    let runtime =
        runtime_module_registry_with_modules_for_test(pool.clone(), settings, active_modules)
            .expect("runtime module fixture should build");
    ServerDynamicRegistrationRequestGuard::new(
        Arc::new(FakeRateLimiter(rate_limit_result)),
        &DynamicRegistrationConfig::from(settings),
        runtime,
    )
}

#[tokio::test]
async fn dynamic_registration_guard_fails_closed_for_unavailable_dependencies() {
    let config = ConfigSource::from_pairs_for_test([(
        "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
        "initial-token",
    )]);
    let settings = Settings::from_config(&config).expect("enabled dynamic registration settings");
    let guard = dynamic_registration_guard(&settings, true, Err(RequestRateLimitError));

    assert!(guard.accepts_new_requests());
    assert_eq!(
        guard.enforce_rate_limit("203.0.113.77").await,
        Err(DynamicRegistrationRateLimitError::Unavailable)
    );
}

#[test]
fn dynamic_registration_guard_rejects_new_requests_when_module_is_disabled() {
    let settings = Settings::from_config(&ConfigSource::default()).expect("settings");
    let guard = dynamic_registration_guard(&settings, false, Ok(1));

    assert!(!guard.accepts_new_requests());
}

#[tokio::test]
async fn dynamic_registration_guard_preserves_fixed_window_threshold() {
    let config = ConfigSource::from_pairs_for_test([
        ("TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS", "1"),
        ("RATE_LIMIT_WINDOW_SECONDS", "37"),
    ]);
    let settings = Settings::from_config(&config).expect("dynamic registration settings");
    let guard = dynamic_registration_guard(&settings, true, Ok(2));

    assert_eq!(
        guard.enforce_rate_limit("203.0.113.77").await,
        Err(DynamicRegistrationRateLimitError::Limited {
            retry_after_seconds: 37,
        })
    );
}
