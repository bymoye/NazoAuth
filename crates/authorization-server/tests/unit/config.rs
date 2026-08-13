impl ConfigSource {
    pub(crate) fn from_pairs_for_test(
        values: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> Self {
        Self {
            file_values: values
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect(),
            env_values: HashMap::new(),
            generated_values: HashMap::new(),
            config_dir: PathBuf::from("."),
        }
    }

    pub(crate) fn from_owned_pairs_for_test(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        // 动态端点测试需要在运行时生成配置值；生产加载仍只走文件和环境变量。
        Self {
            file_values: values.into_iter().collect(),
            env_values: HashMap::new(),
            generated_values: HashMap::new(),
            config_dir: PathBuf::from("."),
        }
    }

    fn load_from_dir(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::load_from_dir_with_env(path, std::iter::empty::<(String, String)>())
    }

    fn load_from_dir_with_env(
        path: impl AsRef<Path>,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> anyhow::Result<Self> {
        Self::load_from_dir_with_env_mode(path, env, true, true)
    }

    fn merge_env(&mut self, env: impl IntoIterator<Item = (String, String)>) -> anyhow::Result<()> {
        self.merge_env_with_worker_policy(env, true)
    }
}

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
fn scalar_accessors_trim_values_and_apply_defaults_without_inventing_required_values() {
    let mut source = ConfigSource::default();
    source.file_values.insert(
        "PUBLIC_BASE_URL".to_owned(),
        "  https://auth.example  ".to_owned(),
    );
    source
        .file_values
        .insert("ISSUER".to_owned(), "   ".to_owned());
    source
        .file_values
        .insert("SESSION_TTL_SECONDS".to_owned(), "42".to_owned());
    source
        .file_values
        .insert("COOKIE_SECURE".to_owned(), "YES".to_owned());

    assert_eq!(
        source.required_string("PUBLIC_BASE_URL").unwrap(),
        "https://auth.example"
    );
    assert!(source.optional_string("ISSUER").is_none());
    assert_eq!(source.string("MISSING", "fallback"), "fallback");
    assert_eq!(source.parse::<u64>("SESSION_TTL_SECONDS", 9).unwrap(), 42);
    assert_eq!(source.parse::<u64>("MISSING", 9).unwrap(), 9);
    assert!(source.bool("COOKIE_SECURE", false).unwrap());
    assert!(!source.bool("MISSING", false).unwrap());
    assert_eq!(
        source.required_string("ISSUER").unwrap_err().to_string(),
        "ISSUER is required"
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
fn first_server_run_creates_the_local_configuration_once() {
    let path = temp_config_dir("first_server_run");

    let result = prepare_server_config_in(&path).unwrap();
    let config_path = path.join(CONFIG_FILE);

    assert_eq!(
        result,
        ServerConfigPreparation::Created(config_path.clone())
    );
    assert_eq!(
        std::fs::read_to_string(&config_path).unwrap(),
        INITIAL_CONFIG
    );
    assert_eq!(
        prepare_server_config_in(&path).unwrap(),
        ServerConfigPreparation::Ready
    );
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn existing_server_config_is_never_overwritten() {
    let path = temp_config_dir("existing_server_config");
    let config_path = path.join(CONFIG_FILE);
    std::fs::write(&config_path, "PUBLIC_BASE_URL: https://auth.example\n").unwrap();

    let result = prepare_server_config_in(&path).unwrap();

    assert_eq!(result, ServerConfigPreparation::Ready);
    assert_eq!(
        std::fs::read_to_string(&config_path).unwrap(),
        "PUBLIC_BASE_URL: https://auth.example\n"
    );
    let _ = std::fs::remove_dir_all(&path);
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
fn removed_stable_module_flags_are_rejected_instead_of_becoming_hidden_policy() {
    for key in [
        "ENABLE_REQUEST_OBJECT",
        "ENABLE_PAR_REQUEST_OBJECT",
        "ENABLE_DEVICE_AUTHORIZATION_GRANT",
        "ENABLE_DYNAMIC_CLIENT_REGISTRATION",
        "ENABLE_CIBA",
        "ENABLE_FRONTCHANNEL_LOGOUT",
        "ENABLE_SESSION_MANAGEMENT",
    ] {
        let path = temp_config_dir("removed_module_flag");
        std::fs::write(path.join(CONFIG_FILE), format!("{key}: true\n")).unwrap();
        let error = ConfigSource::load_from_dir(&path)
            .expect_err("removed stable module flags must not be accepted");
        assert!(error.to_string().contains(key), "{key}");
        let _ = std::fs::remove_dir_all(&path);
    }
    let path = temp_config_dir("removed_module_env");
    let error = ConfigSource::load_from_dir_with_env(
        &path,
        [("ENABLE_CIBA".to_owned(), "false".to_owned())],
    )
    .expect_err("removed stable module environment flags must not be ignored");
    assert!(error.to_string().contains("ENABLE_CIBA was removed"));
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn yaml_document_must_be_a_mapping_with_non_empty_string_keys() {
    let sequence = temp_config_dir("yaml_top_level_sequence");
    std::fs::write(sequence.join(CONFIG_FILE), "- ISSUER\n").unwrap();
    let error = ConfigSource::load_from_dir(&sequence).unwrap_err();
    assert!(error.to_string().contains("top-level key/value mapping"));
    let _ = std::fs::remove_dir_all(&sequence);

    let numeric_key = temp_config_dir("yaml_numeric_key");
    std::fs::write(numeric_key.join(CONFIG_FILE), "1: value\n").unwrap();
    let error = ConfigSource::load_from_dir(&numeric_key).unwrap_err();
    assert!(error.to_string().contains("non-string or empty key"));
    let _ = std::fs::remove_dir_all(&numeric_key);

    let empty_key = temp_config_dir("yaml_empty_key");
    std::fs::write(empty_key.join(CONFIG_FILE), "'': value\n").unwrap();
    let error = ConfigSource::load_from_dir(&empty_key).unwrap_err();
    assert!(error.to_string().contains("non-string or empty key"));
    let _ = std::fs::remove_dir_all(&empty_key);
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
fn generated_secrets_are_stable_and_are_lower_precedence_than_explicit_values() {
    let path = temp_config_dir("generated_secrets");
    std::fs::write(
        path.join(CONFIG_FILE),
        "DATA_DIR: state\nSUBJECT_TYPE: pairwise\n",
    )
    .unwrap();

    let first = ConfigSource::load_from_dir(&path).unwrap();
    let second = ConfigSource::load_from_dir(&path).unwrap();

    for key in [
        "CLIENT_SECRET_PEPPER",
        "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
        "PAIRWISE_SUBJECT_SECRET",
        "MFA_TOTP_ENCRYPTION_KEY",
        "TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY",
    ] {
        assert!(first.required_string(key).unwrap().len() >= 32);
        assert_eq!(first.get(key), second.get(key));
    }
    let response_key = first
        .required_string("TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY")
        .unwrap();
    let digest = blake3::hash(response_key.as_bytes()).to_hex().to_string();
    assert_eq!(
        first
            .required_string("TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_ID")
            .unwrap(),
        format!("generated-{}", &digest[..16])
    );
    let mfa_key = first.required_string("MFA_TOTP_ENCRYPTION_KEY").unwrap();
    let mfa_digest = blake3::hash(mfa_key.as_bytes()).to_hex().to_string();
    assert_eq!(
        first.required_string("MFA_TOTP_ENCRYPTION_KEY_ID").unwrap(),
        format!("generated-{}", &mfa_digest[..16])
    );
    let explicit = ConfigSource::load_from_dir_with_env(
        &path,
        [(
            "CLIENT_SECRET_PEPPER".to_owned(),
            "explicit-client-secret-pepper-value-123456".to_owned(),
        )],
    )
    .unwrap();
    assert_eq!(
        explicit.required_string("CLIENT_SECRET_PEPPER").unwrap(),
        "explicit-client-secret-pepper-value-123456"
    );
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn configured_capabilities_receive_durable_service_owned_secrets() {
    let path = temp_config_dir("generated_capability_secrets");
    std::fs::write(
        path.join(CONFIG_FILE),
        concat!(
            "DATA_DIR: state\n",
            "CIBA_AUTOMATED_DECISION_MODE: header\n",
            "ENABLE_OPENID4VCI_ISSUER: true\n",
            "ENABLE_OPENID4VP_VERIFIER: true\n",
        ),
    )
    .unwrap();

    let source = ConfigSource::load_from_dir(&path).unwrap();
    for key in [
        "CIBA_AUTOMATED_DECISION_TOKEN",
        "OPENID4VC_DATA_ENCRYPTION_KEY",
        "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN",
        "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN",
    ] {
        assert!(source.required_string(key).unwrap().len() >= 32, "{key}");
    }
    let second = ConfigSource::load_from_dir(&path).unwrap();
    for key in [
        "CIBA_AUTOMATED_DECISION_TOKEN",
        "OPENID4VC_DATA_ENCRYPTION_KEY",
        "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN",
        "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN",
    ] {
        assert_eq!(source.get(key), second.get(key), "{key} must be stable");
    }
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn server_config_excludes_worker_only_yaml_and_environment_values() {
    let path = temp_config_dir("worker_config_isolation");
    std::fs::write(
        path.join(CONFIG_FILE),
        concat!(
            "PUBLIC_BASE_URL: https://auth.example\n",
            "AUDIT_ANCHOR_URL: https://anchor-from-yaml.example\n",
            "AUDIT_ANCHOR_TOKEN: yaml-worker-secret\n",
        ),
    )
    .unwrap();

    let source = ConfigSource::load_from_dir_with_env_filtered(
        &path,
        [
            (
                "AUDIT_ANCHOR_URL".to_owned(),
                "https://anchor-from-env.example".to_owned(),
            ),
            (
                "AUDIT_ANCHOR_DATABASE_URL".to_owned(),
                "postgresql://worker-only.example/oauth".to_owned(),
            ),
            ("ISSUER".to_owned(), "https://issuer.example".to_owned()),
        ],
        false,
        false,
        false,
    )
    .unwrap();

    assert_eq!(
        source.get("PUBLIC_BASE_URL").as_deref(),
        Some("https://auth.example")
    );
    assert_eq!(
        source.get("ISSUER").as_deref(),
        Some("https://issuer.example")
    );
    for key in [
        "AUDIT_ANCHOR_URL",
        "AUDIT_ANCHOR_TOKEN",
        "AUDIT_ANCHOR_DATABASE_URL",
    ] {
        assert!(source.get(key).is_none(), "{key} must remain worker-only");
    }
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn generated_secret_creation_is_concurrency_safe() {
    let path = temp_config_dir("generated_secret_concurrency");
    std::fs::write(path.join(CONFIG_FILE), "DATA_DIR: state\n").unwrap();

    let handles = (0..8)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || {
                ConfigSource::load_from_dir(path)
                    .unwrap()
                    .required_string("CLIENT_SECRET_PEPPER")
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let values = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();

    assert!(values.iter().all(|value| value == &values[0]));
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn malformed_persisted_generated_secret_fails_closed() {
    let path = temp_config_dir("malformed_generated_secret");
    std::fs::write(path.join(CONFIG_FILE), "DATA_DIR: state\n").unwrap();
    let secrets = path.join("state").join(GENERATED_SECRETS_DIR);
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::write(secrets.join("client-secret-pepper"), "short").unwrap();

    let error = ConfigSource::load_from_dir(&path).unwrap_err();

    assert!(error.to_string().contains("restore it from backup"));
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn explicit_yaml_scalar_overrides_environment_secret_file_fallback() {
    let path = temp_config_dir("secret_file_precedence");
    let database_url_file = path.join("database-url");
    std::fs::write(
        path.join(CONFIG_FILE),
        "DATABASE_URL: postgresql://yaml.example/oauth\nDATA_DIR: state\n",
    )
    .unwrap();
    std::fs::write(&database_url_file, "postgresql://file.example/oauth\n").unwrap();

    let source = ConfigSource::load_from_dir_with_env(
        &path,
        [(
            "DATABASE_URL_FILE".to_owned(),
            database_url_file.display().to_string(),
        )],
    )
    .unwrap();

    assert_eq!(database_url(&source), "postgresql://yaml.example/oauth");
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn environment_secret_file_supplies_an_absent_scalar() {
    let path = temp_config_dir("secret_file_fallback");
    let database_url_file = path.join("database-url");
    std::fs::write(path.join(CONFIG_FILE), "DATA_DIR: state\n").unwrap();
    std::fs::write(&database_url_file, "postgresql://file.example/oauth\n").unwrap();

    let source = ConfigSource::load_from_dir_with_env(
        &path,
        [(
            "DATABASE_URL_FILE".to_owned(),
            database_url_file.display().to_string(),
        )],
    )
    .unwrap();

    assert_eq!(database_url(&source), "postgresql://file.example/oauth");
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn yaml_secret_file_path_is_resolved_and_trimmed() {
    let path = temp_config_dir("yaml_secret_file");
    std::fs::write(
        path.join(CONFIG_FILE),
        "DATA_DIR: state\nDATABASE_URL_FILE: database-url\n",
    )
    .unwrap();
    std::fs::write(
        path.join("database-url"),
        "  postgresql://file.example/oauth  \n",
    )
    .unwrap();

    let source = ConfigSource::load_from_dir(&path).unwrap();

    assert_eq!(database_url(&source), "postgresql://file.example/oauth");
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn secret_file_inputs_fail_closed_for_empty_path_missing_file_and_empty_file() {
    let empty_path = temp_config_dir("empty_secret_path");
    std::fs::write(empty_path.join(CONFIG_FILE), "DATA_DIR: state\n").unwrap();
    let error = ConfigSource::load_from_dir_with_env(
        &empty_path,
        [("DATABASE_URL_FILE".to_owned(), "   ".to_owned())],
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "DATABASE_URL_FILE must not be empty");
    let _ = std::fs::remove_dir_all(&empty_path);

    let missing = temp_config_dir("missing_secret_file");
    std::fs::write(missing.join(CONFIG_FILE), "DATA_DIR: state\n").unwrap();
    let error = ConfigSource::load_from_dir_with_env(
        &missing,
        [("DATABASE_URL_FILE".to_owned(), "absent".to_owned())],
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed to read DATABASE_URL_FILE")
    );
    let _ = std::fs::remove_dir_all(&missing);

    let empty = temp_config_dir("empty_secret_file");
    std::fs::write(empty.join(CONFIG_FILE), "DATA_DIR: state\n").unwrap();
    std::fs::write(empty.join("database-url"), " \n").unwrap();
    let error = ConfigSource::load_from_dir_with_env(
        &empty,
        [("DATABASE_URL_FILE".to_owned(), "database-url".to_owned())],
    )
    .unwrap_err();
    assert!(error.to_string().contains("points to an empty secret file"));
    let _ = std::fs::remove_dir_all(&empty);
}

#[test]
fn runtime_secret_helper_returns_the_stable_persisted_path_and_value() {
    let path = temp_config_dir("runtime_secret_helper");
    let (created_path, first) =
        read_or_create_runtime_secret(&path, "nested/controller-key").unwrap();
    let (same_path, second) =
        read_or_create_runtime_secret(&path, "nested/controller-key").unwrap();

    assert_eq!(created_path, path.join("nested/controller-key"));
    assert_eq!(same_path, created_path);
    assert_eq!(first, second);
    assert!(first.len() >= 32);
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn instance_identity_helper_persists_an_ed25519_seed_without_reusing_token_size() {
    let path = temp_config_dir("instance_identity_helper");
    let (created_path, first) =
        read_or_create_instance_identity_key(&path, "instance/identity.key").unwrap();
    let (_, second) = read_or_create_instance_identity_key(&path, "instance/identity.key").unwrap();

    assert_eq!(created_path, path.join("instance/identity.key"));
    assert_eq!(first, second);
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(first)
            .unwrap()
            .len(),
        32
    );
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn generated_secret_creation_reports_an_invalid_parent_without_partial_state() {
    let path = temp_config_dir("invalid_secret_parent");
    let blocking_file = path.join("not-a-directory");
    std::fs::write(&blocking_file, "blocking file").unwrap();

    let error = read_or_create_generated_secret(&blocking_file.join("secret")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("failed to create generated secret directory")
    );
    assert_eq!(
        std::fs::read_to_string(&blocking_file).unwrap(),
        "blocking file"
    );
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn migration_config_does_not_materialize_unrelated_application_secrets() {
    let path = temp_config_dir("migration_config_no_application_secrets");
    let database_url_file = path.join("database-url");
    std::fs::write(
        path.join(CONFIG_FILE),
        "DATA_DIR: state\nCLIENT_SECRET_PEPPER_FILE: deliberately-absent\n",
    )
    .unwrap();
    std::fs::write(&database_url_file, "postgresql://file.example/oauth\n").unwrap();

    let source = ConfigSource::load_for_migrations_from_dir_with_env(
        &path,
        [(
            "DATABASE_URL_FILE".to_owned(),
            database_url_file.display().to_string(),
        )],
    )
    .unwrap();

    assert_eq!(database_url(&source), "postgresql://file.example/oauth");
    assert!(!path.join("state").exists());
    assert!(source.get("CLIENT_SECRET_PEPPER").is_none());
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn migration_config_accepts_deployment_identity_without_materializing_state() {
    let path = temp_config_dir("migration_config_deployment_identity");
    std::fs::write(
        path.join(CONFIG_FILE),
        concat!(
            "DEPLOYMENT_ID: deployment-ci\n",
            "RUNTIME_INSTANCE_ID: runtime-ci\n",
            "INSTANCE_IDENTITY_DIR: runtime-instance\n",
        ),
    )
    .unwrap();

    let source = ConfigSource::load_for_migrations_from_dir_with_env(&path, []).unwrap();

    assert_eq!(
        source.get("DEPLOYMENT_ID").as_deref(),
        Some("deployment-ci")
    );
    assert_eq!(
        source.get("RUNTIME_INSTANCE_ID").as_deref(),
        Some("runtime-ci")
    );
    let expected_identity_dir = std::fs::canonicalize(&path)
        .unwrap()
        .join("runtime-instance")
        .display()
        .to_string();
    assert_eq!(
        source.get("INSTANCE_IDENTITY_DIR").as_deref(),
        Some(expected_identity_dir.as_str())
    );
    assert!(!path.join("runtime-instance").exists());
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn metadata_only_config_does_not_read_secret_files_or_expose_secret_values() {
    let path = temp_config_dir("metadata_config_no_secret_reads");
    std::fs::write(
        path.join(CONFIG_FILE),
        "DATA_DIR: state\nDATABASE_URL_FILE: deliberately-absent\n",
    )
    .unwrap();

    let source = ConfigSource::load_from_dir_with_env_mode(&path, [], false, false).unwrap();

    assert_eq!(
        source.get("DATABASE_URL_FILE").as_deref(),
        Some("deliberately-absent")
    );
    assert!(source.get("DATABASE_URL").is_none());
    assert!(source.get("CLIENT_SECRET_PEPPER").is_none());
    assert!(!path.join("state").exists());
    let _ = std::fs::remove_dir_all(&path);
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
            ("PATH".to_owned(), "/usr/bin".to_owned()),
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
    assert!(source.get("PATH").is_none());
}

#[test]
fn unknown_nazoauth_environment_key_is_rejected_without_rejecting_system_environment() {
    let mut source = ConfigSource::default();
    source
        .merge_env([("PATH".to_owned(), "/usr/bin".to_owned())])
        .unwrap();

    let error = source
        .merge_env([("NAZOAUTH_UNKNOWN_CONFIG".to_owned(), "value".to_owned())])
        .expect_err("unknown NazoAuth environment keys must fail startup");
    assert!(
        error
            .to_string()
            .contains("unknown NazoAuth environment config key NAZOAUTH_UNKNOWN_CONFIG")
    );
}

#[test]
fn relative_persistent_paths_are_anchored_to_the_configuration_directory() {
    let path = temp_config_dir("relative_persistent_paths");
    std::fs::write(
        path.join(CONFIG_FILE),
        "DATA_DIR: state\nUI_CACHE_DIR: cache/ui\n",
    )
    .unwrap();

    let source = ConfigSource::load_from_dir(&path).unwrap();
    let canonical_path = std::fs::canonicalize(&path).unwrap();
    assert_eq!(
        source.string("DATA_DIR", ""),
        canonical_path.join("state").display().to_string()
    );
    assert_eq!(
        source.string("UI_CACHE_DIR", ""),
        canonical_path.join("cache/ui").display().to_string()
    );
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn relative_persistent_paths_cannot_escape_the_configuration_directory() {
    let path = temp_config_dir("relative_persistent_path_escape");
    std::fs::write(path.join(CONFIG_FILE), "DATA_DIR: ../outside\n").unwrap();

    let error = ConfigSource::load_from_dir(&path)
        .expect_err("relative persistent roots must stay below the config directory");
    assert!(
        error
            .to_string()
            .contains("DATA_DIR relative path escapes configuration directory")
    );
    let _ = std::fs::remove_dir_all(&path);
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
            "AUDIT_ANCHOR_BATCH_SIZE",
            "AUDIT_ANCHOR_DATABASE_MAX_CONNECTIONS",
            "AUDIT_ANCHOR_DATABASE_URL",
            "AUDIT_ANCHOR_DATABASE_URL_FILE",
            "AUDIT_ANCHOR_FRESHNESS_SECONDS",
            "AUDIT_ANCHOR_LOCK_TIMEOUT_SECONDS",
            "AUDIT_ANCHOR_MAX_LAG_SECONDS",
            "AUDIT_ANCHOR_MODE",
            "AUDIT_ANCHOR_POLL_INTERVAL_SECONDS",
            "AUDIT_ANCHOR_REQUEST_TIMEOUT_SECONDS",
            "AUDIT_ANCHOR_STATUS_FILE",
            "AUDIT_ANCHOR_TOKEN",
            "AUDIT_ANCHOR_TOKEN_FILE",
            "AUDIT_ANCHOR_URL",
            "AVATAR_MAX_BYTES",
            "AVATAR_STORAGE_DIR",
            "BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS",
            "BIND",
            "CLIENT_DELIVERY_TTL_SECONDS",
            "CLIENT_IP_HEADER_MODE",
            "CLIENT_SECRET_PEPPER",
            "CLIENT_SECRET_PEPPER_FILE",
            "CIBA_AUTOMATED_DECISION_TOKEN",
            "CIBA_AUTOMATED_DECISION_TOKEN_FILE",
            "CIBA_AUTOMATED_DECISION_MODE",
            "CIBA_AUTH_REQ_ID_TTL_SECONDS",
            "CIBA_NOTIFICATION_PRIVATE_ORIGINS",
            "CIBA_PING_TLS_TRUST_BUNDLE",
            "CIBA_POLL_INTERVAL_SECONDS",
            "CIBA_SECURITY_PROFILE",
            "COOKIE_SECURE",
            "CORS_ALLOWED_ORIGINS",
            "CSRF_COOKIE_NAME",
            "DATABASE_URL",
            "DATABASE_URL_FILE",
            "DATABASE_MAX_CONNECTIONS",
            "DATA_DIR",
            "DEFAULT_AUDIENCE",
            "DEPLOYMENT_ID",
            "DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS",
            "DEVICE_AUTHORIZATION_TTL_SECONDS",
            "DPOP_NONCE_POLICY",
            "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
            "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN_FILE",
            "ENABLE_AUTHORIZATION_DETAILS",
            "ENABLE_FAPI_HTTP_SIGNATURES",
            "ENABLE_NATIVE_SSO",
            "ENABLE_OPENID4VCI_ISSUER",
            "ENABLE_OPENID4VP_VERIFIER",
            "ENABLE_SCIM_SECURITY_EVENTS",
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
            "FAPI_RESOURCE_DPOP_NONCE_POLICY",
            "ID_TOKEN_TTL_SECONDS",
            "INSTANCE_IDENTITY_DIR",
            "ISSUER",
            "JWK_KEYS_DIR",
            "LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS",
            "LOGIN_FAILURE_WINDOW_SECONDS",
            "MTLS_ENDPOINT_BASE_URL",
            "MTLS_CERTIFICATE_SOURCE",
            "MFA_TOTP_ENCRYPTION_KEY",
            "MFA_TOTP_ENCRYPTION_KEY_FILE",
            "MFA_TOTP_ENCRYPTION_KEY_ID",
            "MFA_TOTP_PREVIOUS_ENCRYPTION_KEY",
            "MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_FILE",
            "MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_ID",
            "TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY",
            "TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_FILE",
            "TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_ID",
            "TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY",
            "TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_FILE",
            "TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_ID",
            "OPENID4VC_DATA_ENCRYPTION_KEY",
            "OPENID4VC_DATA_ENCRYPTION_KEY_FILE",
            "OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON",
            "OPENID4VC_CLIENT_ATTESTATION_ISSUER",
            "OPENID4VC_KEY_ATTESTATION_JWKS_JSON",
            "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE",
            "OPENID4VC_TRUST_ANCHORS_FILE",
            "OPENID4VC_REVOCATION_POLICY",
            "OPENID4VC_REVOCATION_SNAPSHOT_FILE",
            "OPENID4VC_REVOCATION_RELOAD_INTERVAL_SECONDS",
            "OPENID4VC_TRANSACTION_TTL_SECONDS",
            "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON",
            "OPENID4VCI_DEFERRED_CREDENTIAL_CONFIGURATIONS",
            "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN",
            "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN_FILE",
            "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN",
            "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN_FILE",
            "OPENID4VP_WALLET_AUTHORIZATION_ORIGINS",
            "SIGNING_EXTERNAL_COMMAND",
            "SIGNING_EXTERNAL_TIMEOUT_MS",
            "OTEL_ENABLED",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_PROTOCOL",
            "OTEL_EXPORTER_OTLP_TIMEOUT",
            "PAIRWISE_SUBJECT_SECRET",
            "PAIRWISE_SUBJECT_SECRET_FILE",
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
            "REMOTE_CLIENT_DOCUMENT_PRIVATE_ORIGINS",
            "REQUIRE_PUSHED_AUTHORIZATION_REQUESTS",
            "RUST_LOG",
            "RUNTIME_INSTANCE_ID",
            "SCIM_EVENT_RETENTION_SECONDS",
            "SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE",
            "SESSION_COOKIE_NAME",
            "SESSION_TTL_SECONDS",
            "SIGNING_KEY_PREPUBLISH_SECONDS",
            "SIGNING_KEY_ROTATION_INTERVAL_SECONDS",
            "SUBJECT_TYPE",
            "TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS",
            "TOKEN_RATE_LIMIT_MAX_REQUESTS",
            "TLS_BIND",
            "TLS_CERTIFICATE_FILE",
            "TLS_CLIENT_CA_FILE",
            "TLS_PRIVATE_KEY_FILE",
            "TRUSTED_PROXY_CIDRS",
            "UI_CACHE_DIR",
            "UI_STATIC_DIR",
            "VALKEY_COMMAND_TIMEOUT_MS",
            "VALKEY_URL",
            "VALKEY_URL_FILE",
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
