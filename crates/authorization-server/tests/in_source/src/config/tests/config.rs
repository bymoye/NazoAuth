use super::*;

fn temp_config_dir(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nazo_config_{label}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn yaml_sequence_becomes_comma_separated_value() {
    let value = YamlValue::Sequence(vec![
        YamlValue::String("http://127.0.0.1:3000".to_owned()),
        YamlValue::String("http://localhost:3000".to_owned()),
    ]);

    assert_eq!(
        yaml_value_to_string("CORS_ALLOWED_ORIGINS", &value).unwrap(),
        "http://127.0.0.1:3000,http://localhost:3000"
    );
}

#[test]
fn yaml_mapping_value_is_rejected_instead_of_stringified() {
    let value = YamlValue::Mapping(Default::default());

    let err = yaml_value_to_string("ISSUER", &value).unwrap_err();

    assert!(err.to_string().contains("ISSUER must be a scalar"));
}

#[test]
fn invalid_numeric_config_is_error() {
    let mut source = ConfigSource::default();
    source
        .file_values
        .insert("SESSION_TTL_SECONDS".to_owned(), "soon".to_owned());

    let err = source
        .parse::<u64>("SESSION_TTL_SECONDS", 28_800)
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("SESSION_TTL_SECONDS must be a valid")
    );
}

#[test]
fn invalid_boolean_config_is_error() {
    let mut source = ConfigSource::default();
    source.file_values.insert(
        "EMAIL_CODE_DEV_RESPONSE_ENABLED".to_owned(),
        "maybe".to_owned(),
    );

    let err = source
        .bool("EMAIL_CODE_DEV_RESPONSE_ENABLED", false)
        .unwrap_err();

    assert_eq!(
        err.to_string(),
        "EMAIL_CODE_DEV_RESPONSE_ENABLED must be a boolean value"
    );
}

#[test]
fn dotenv_file_is_rejected() {
    let path = temp_config_dir("dotenv");
    std::fs::write(path.join(".env"), "BIND=127.0.0.1:8000\n").unwrap();

    let result = ConfigSource::load_from_dir(&path);
    let _ = std::fs::remove_dir_all(&path);

    assert_eq!(
        result.unwrap_err().to_string(),
        ".env is not supported; use .env.yaml"
    );
}

#[test]
fn unknown_yaml_key_is_rejected_with_the_key_name() {
    let path = temp_config_dir("unknown_yaml_key");
    std::fs::write(path.join(".env.yaml"), "COOKIE_SECUR: true\n").unwrap();

    let result = ConfigSource::load_from_dir(&path);
    let _ = std::fs::remove_dir_all(&path);

    let error = result.expect_err("unknown YAML keys must fail startup");
    assert!(error.to_string().contains("COOKIE_SECUR"));
}

#[test]
fn removed_oidc_federation_gate_is_accepted_as_a_deprecated_no_op() {
    let path = temp_config_dir("deprecated_oidc_federation");
    std::fs::write(
        path.join(".env.yaml"),
        "ENABLE_OIDC_FEDERATION: true\nISSUER: https://issuer.example\n",
    )
    .unwrap();

    let source = ConfigSource::load_from_dir(&path).unwrap();
    let _ = std::fs::remove_dir_all(&path);

    assert!(source.get("ENABLE_OIDC_FEDERATION").is_none());
    assert_eq!(
        source.required_string("ISSUER").unwrap(),
        "https://issuer.example"
    );
}

#[test]
fn missing_config_file_can_be_replaced_by_whitelisted_environment() {
    let path = temp_config_dir("env_only");

    let result = ConfigSource::load_from_dir_with_env(
        &path,
        [
            (
                "PUBLIC_BASE_URL".to_owned(),
                "https://auth.example".to_owned(),
            ),
            ("ISSUER".to_owned(), "https://issuer.example".to_owned()),
            (
                "FRONTEND_BASE_URL".to_owned(),
                "https://frontend.example".to_owned(),
            ),
        ],
    );
    let _ = std::fs::remove_dir_all(&path);

    let source = result.unwrap();
    assert_eq!(
        source.required_string("PUBLIC_BASE_URL").unwrap(),
        "https://auth.example"
    );
    assert_eq!(
        source.required_string("ISSUER").unwrap(),
        "https://issuer.example"
    );
    assert_eq!(
        source.required_string("FRONTEND_BASE_URL").unwrap(),
        "https://frontend.example"
    );
}

#[test]
fn environment_overrides_yaml_by_allowlist() {
    let mut source = ConfigSource::default();
    source
        .file_values
        .insert("ISSUER".to_owned(), "https://yaml.example".to_owned());
    source
        .merge_env([
            ("ISSUER".to_owned(), "https://env.example".to_owned()),
            ("DPOP_NONCE_POLICY".to_owned(), "optional".to_owned()),
            ("DATA_DIR".to_owned(), "/srv/nazo-oauth".to_owned()),
            ("OTEL_ENABLED".to_owned(), "true".to_owned()),
            (
                "OTEL_EXPORTER_OTLP_ENDPOINT".to_owned(),
                "http://collector:4318".to_owned(),
            ),
            (
                "SIGNING_EXTERNAL_COMMAND".to_owned(),
                "/usr/local/bin/kms-signer,--profile,prod".to_owned(),
            ),
            ("VALKEY_COMMAND_TIMEOUT_MS".to_owned(), "1000".to_owned()),
            ("DATABASE_MAX_CONNECTIONS".to_owned(), "24".to_owned()),
            ("PERF_METRICS_ENABLED".to_owned(), "true".to_owned()),
            ("UNKNOWN_ENV".to_owned(), "ignored".to_owned()),
        ])
        .unwrap();

    assert_eq!(source.string("ISSUER", ""), "https://env.example");
    assert_eq!(source.string("DPOP_NONCE_POLICY", ""), "optional");
    assert_eq!(source.string("DATA_DIR", ""), "/srv/nazo-oauth");
    assert_eq!(source.string("OTEL_ENABLED", ""), "true");
    assert_eq!(
        source.string("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
        "http://collector:4318"
    );
    assert_eq!(
        source.string("SIGNING_EXTERNAL_COMMAND", ""),
        "/usr/local/bin/kms-signer,--profile,prod"
    );
    assert_eq!(source.string("VALKEY_COMMAND_TIMEOUT_MS", ""), "1000");
    assert_eq!(source.string("DATABASE_MAX_CONNECTIONS", ""), "24");
    assert_eq!(source.string("PERF_METRICS_ENABLED", ""), "true");
    assert!(source.get("UNKNOWN_ENV").is_none());
}

#[test]
fn canonical_config_keys_are_locked_to_the_reviewed_baseline() {
    assert_eq!(
        ENV_CONFIG_KEYS,
        &[
            "ACCESS_TOKEN_TTL_SECONDS",
            "AUTH_CODE_TTL_SECONDS",
            "AUTH_RATE_LIMIT_MAX_REQUESTS",
            "AUTHORIZATION_SERVER_PROFILE",
            "AVATAR_MAX_BYTES",
            "AVATAR_STORAGE_DIR",
            "BIND",
            "CLIENT_DELIVERY_TTL_SECONDS",
            "CLIENT_IP_HEADER_MODE",
            "CLIENT_SECRET_PEPPER",
            "CIBA_AUTOMATED_DECISION_TOKEN",
            "CIBA_AUTH_REQ_ID_TTL_SECONDS",
            "CIBA_POLL_INTERVAL_SECONDS",
            "CIBA_SECURITY_PROFILE",
            "COOKIE_SECURE",
            "CORS_ALLOWED_ORIGINS",
            "CSRF_COOKIE_NAME",
            "DATABASE_URL",
            "DATABASE_MAX_CONNECTIONS",
            "DATA_DIR",
            "DEFAULT_AUDIENCE",
            "DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS",
            "DEVICE_AUTHORIZATION_TTL_SECONDS",
            "DPOP_NONCE_POLICY",
            "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
            "ENABLE_AUTHORIZATION_DETAILS",
            "ENABLE_CIBA",
            "ENABLE_DEVICE_AUTHORIZATION_GRANT",
            "ENABLE_DYNAMIC_CLIENT_REGISTRATION",
            "ENABLE_FRONTCHANNEL_LOGOUT",
            "ENABLE_FAPI_HTTP_SIGNATURES",
            "ENABLE_LEGACY_AUDIENCE_PARAM",
            "ENABLE_NATIVE_SSO",
            "ENABLE_PAR_REQUEST_OBJECT",
            "ENABLE_REQUEST_OBJECT",
            "ENABLE_REQUEST_URI_PARAMETER",
            "ENABLE_SESSION_MANAGEMENT",
            "EMAIL_CODE_DEV_RESPONSE_ENABLED",
            "EMAIL_CODE_PEER_COOLDOWN_SECONDS",
            "EMAIL_CODE_SEND_COOLDOWN_SECONDS",
            "EMAIL_CODE_TTL_SECONDS",
            "EMAIL_DELIVERY",
            "EMAIL_FROM",
            "EMAIL_SMTP_HOST",
            "EMAIL_SMTP_PASSWORD",
            "EMAIL_SMTP_PORT",
            "EMAIL_SMTP_TLS",
            "EMAIL_SMTP_USERNAME",
            "FRONTEND_BASE_URL",
            "FEDERATION_PROVIDER_CONFIGS",
            "FEDERATION_SAML_GATEWAY_AUDIENCE",
            "FEDERATION_SAML_GATEWAY_ENABLED",
            "FEDERATION_SAML_GATEWAY_ISSUER",
            "FEDERATION_SAML_GATEWAY_SECRET",
            "FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS",
            "ID_TOKEN_TTL_SECONDS",
            "ISSUER",
            "JWK_KEYS_DIR",
            "LOGIN_FAILURE_EMAIL_MAX_ATTEMPTS",
            "LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS",
            "LOGIN_FAILURE_WINDOW_SECONDS",
            "MTLS_ENDPOINT_BASE_URL",
            "SIGNING_EXTERNAL_COMMAND",
            "SIGNING_EXTERNAL_TIMEOUT_MS",
            "OTEL_ENABLED",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_PROTOCOL",
            "OTEL_EXPORTER_OTLP_TIMEOUT",
            "PAIRWISE_SUBJECT_SECRET",
            "PAR_TTL_SECONDS",
            "PASSKEY_RP_ID",
            "PASSKEY_RP_NAME",
            "PASSKEY_ORIGIN",
            "PASSKEY_REQUIRE_USER_VERIFICATION",
            "PASSKEY_REQUIRE_USER_HANDLE",
            "PASSKEY_STRICT_BASE64",
            "PASSWORD_HASH_MAX_CONCURRENCY",
            "PASSWORD_HASH_QUEUE_TIMEOUT_MS",
            "PERF_METRICS_ENABLED",
            "PUBLIC_BASE_URL",
            "PROTECTED_RESOURCE_IDENTIFIER",
            "RATE_LIMIT_WINDOW_SECONDS",
            "REFRESH_TOKEN_TTL_SECONDS",
            "REQUEST_OBJECT_JTI_POLICY",
            "REQUIRE_PUSHED_AUTHORIZATION_REQUESTS",
            "RUST_LOG",
            "SCIM_BEARER_TOKEN",
            "SESSION_COOKIE_NAME",
            "SESSION_TTL_SECONDS",
            "SIGNING_KEY_PREPUBLISH_SECONDS",
            "SIGNING_KEY_ROTATION_INTERVAL_SECONDS",
            "SUBJECT_TYPE",
            "TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS",
            "TOKEN_RATE_LIMIT_MAX_REQUESTS",
            "TRUSTED_PROXY_CIDRS",
            "VALKEY_COMMAND_TIMEOUT_MS",
            "VALKEY_URL",
        ]
    );
}

#[test]
fn invalid_environment_type_is_error() {
    let mut source = ConfigSource::default();
    source
        .merge_env([("SESSION_TTL_SECONDS".to_owned(), "soon".to_owned())])
        .unwrap();

    let err = source
        .parse::<u64>("SESSION_TTL_SECONDS", 28_800)
        .unwrap_err();

    assert!(
        err.to_string()
            .contains("SESSION_TTL_SECONDS must be a valid")
    );
}

#[test]
fn database_url_uses_documented_default_when_unset() {
    let source = ConfigSource::default();

    assert_eq!(database_url(&source), DEFAULT_DATABASE_URL);
    assert_eq!(
        database_max_connections(&source).unwrap(),
        DEFAULT_DATABASE_MAX_CONNECTIONS
    );
}

#[test]
fn database_url_uses_whitelisted_environment_value() {
    let mut source = ConfigSource::default();
    source
        .merge_env([
            (
                "DATABASE_URL".to_owned(),
                "postgresql://nazo:secret@db.internal:5432/oauth".to_owned(),
            ),
            ("DATABASE_MAX_CONNECTIONS".to_owned(), "48".to_owned()),
        ])
        .unwrap();

    assert_eq!(
        database_url(&source),
        "postgresql://nazo:secret@db.internal:5432/oauth"
    );
    assert_eq!(database_max_connections(&source).unwrap(), 48);
}

#[test]
fn database_max_connections_rejects_zero() {
    let source = ConfigSource::from_pairs_for_test([("DATABASE_MAX_CONNECTIONS", "0")]);

    let err = database_max_connections(&source).unwrap_err();

    assert_eq!(
        err.to_string(),
        "DATABASE_MAX_CONNECTIONS must be greater than zero"
    );
}

#[test]
fn database_url_does_not_rewrite_unsupported_legacy_driver_scheme() {
    let source = ConfigSource::from_pairs_for_test([(
        "DATABASE_URL",
        "postgresql+psycopg://nazo:secret@db.internal:5432/oauth",
    )]);

    assert_eq!(
        database_url(&source),
        "postgresql+psycopg://nazo:secret@db.internal:5432/oauth"
    );
}
