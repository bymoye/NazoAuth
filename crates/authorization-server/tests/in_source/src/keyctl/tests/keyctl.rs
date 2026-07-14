use super::*;
use serde_json::{Value, json};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

#[test]
fn key_record_status_labels_preserve_cli_output_contract() {
    assert_eq!(
        key_record_status_label(nazo_key_management::KeyRecordStatus::Active),
        "active"
    );
    assert_eq!(
        key_record_status_label(nazo_key_management::KeyRecordStatus::Prepublished),
        "prepublished"
    );
    assert_eq!(
        key_record_status_label(nazo_key_management::KeyRecordStatus::Grace),
        "grace"
    );
    assert_eq!(
        key_record_status_label(nazo_key_management::KeyRecordStatus::Retired),
        "retired"
    );
}

#[test]
fn register_external_parser_requires_complete_metadata() {
    let options = parse_register_external_args(vec![
        "--kid".to_owned(),
        "rs256-kms-2026".to_owned(),
        "--alg".to_owned(),
        "RS256".to_owned(),
        "--key-ref".to_owned(),
        "kms://key/1".to_owned(),
        "--public-jwk".to_owned(),
        "/tmp/public.jwk".to_owned(),
    ])
    .unwrap();

    assert_eq!(options.kid, "rs256-kms-2026");
    assert_eq!(options.alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(options.key_ref, "kms://key/1");
    assert_eq!(options.public_jwk_file, PathBuf::from("/tmp/public.jwk"));

    for args in [
        vec!["--kid", "kid", "--alg", "RS256", "--key-ref", "ref"],
        vec!["--kid", "kid", "--alg", "RS256", "--public-jwk", "/tmp/jwk"],
        vec![
            "--kid",
            "kid",
            "--key-ref",
            "ref",
            "--public-jwk",
            "/tmp/jwk",
        ],
    ] {
        let err = expect_register_external_error(args.into_iter().map(str::to_owned).collect());
        assert!(
            err.to_string().contains("register-external requires"),
            "missing external signing metadata must be rejected, got {err}"
        );
    }

    let err = expect_register_external_error(vec![
        "--kid".to_owned(),
        "kid".to_owned(),
        "--alg".to_owned(),
        "none".to_owned(),
        "--key-ref".to_owned(),
        "ref".to_owned(),
        "--public-jwk".to_owned(),
        "/tmp/jwk".to_owned(),
    ]);
    assert!(
        err.to_string().contains("unsupported signing alg none"),
        "alg=none must never be accepted for external signing keys"
    );

    let err = expect_register_external_error(vec!["--kid".to_owned()]);
    assert!(
        err.to_string().contains("missing value for --kid"),
        "dangling CLI flags must fail before partial key registration"
    );

    let err = expect_register_external_error(vec![
        "--kid".to_owned(),
        "kid".to_owned(),
        "--alg".to_owned(),
        "RS256".to_owned(),
        "--key-ref".to_owned(),
        "ref".to_owned(),
        "--public-jwk".to_owned(),
        "/tmp/jwk".to_owned(),
        "--unexpected".to_owned(),
        "value".to_owned(),
    ]);
    assert!(
        err.to_string()
            .contains("unknown register-external option --unexpected"),
        "unknown external-key options must not be silently ignored"
    );
}

#[tokio::test]
async fn run_without_command_reports_usage_before_loading_configuration() {
    let err = run(["nazo-oauth-keyctl".to_owned()]).await.unwrap_err();

    assert_error_contains(
        err,
        "usage: nazo-oauth-keyctl <list|register-external|validate>",
    );
}

#[tokio::test]
async fn run_dispatch_rejects_unknown_and_malformed_cli_subcommands_fail_closed() {
    let err = run(["nazo-oauth-keyctl".to_owned(), "unknown".to_owned()])
        .await
        .unwrap_err();
    assert_error_contains(err, "unknown keyctl command unknown");

    let err = run(["nazo-oauth-keyctl".to_owned(), "activate".to_owned()])
        .await
        .unwrap_err();
    assert_error_contains(err, "unknown keyctl command activate");

    let err = run([
        "nazo-oauth-keyctl".to_owned(),
        "retire".to_owned(),
        "active".to_owned(),
    ])
    .await
    .unwrap_err();
    assert_error_contains(err, "unknown keyctl command retire");

    let err = run([
        "nazo-oauth-keyctl".to_owned(),
        "retire".to_owned(),
        "active".to_owned(),
        "--when".to_owned(),
        "2026-01-01T00:00:00Z".to_owned(),
    ])
    .await
    .unwrap_err();
    assert_error_contains(err, "unknown keyctl command retire");

    let err = run([
        "nazo-oauth-keyctl".to_owned(),
        "generate".to_owned(),
        "--alg".to_owned(),
        "HS256".to_owned(),
    ])
    .await
    .unwrap_err();
    assert_error_contains(err, "unknown keyctl command generate");

    let err = run([
        "nazo-oauth-keyctl".to_owned(),
        "register-external".to_owned(),
        "--kid".to_owned(),
        "external".to_owned(),
    ])
    .await
    .unwrap_err();
    assert_error_contains(err, "register-external requires");
}

#[test]
fn run_list_and_validate_fail_closed_without_keyset_in_isolated_workspace() {
    with_temp_cwd("run-missing-keyset", |_dir| {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime should build");

        let err = runtime
            .block_on(run(["nazo-oauth-keyctl".to_owned(), "list".to_owned()]))
            .unwrap_err();
        assert_missing_keyset_error(err);

        let err = runtime
            .block_on(run(["nazo-oauth-keyctl".to_owned(), "validate".to_owned()]))
            .unwrap_err();
        assert_missing_keyset_error(err);
    });
}

#[tokio::test]
async fn list_keys_accepts_supported_keyset_states() {
    let dir = temp_keys_dir("list");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let settings = test_settings(dir.clone());
    let keyset = keyset_with_keys(
        "active",
        vec![
            local_key("active", "EdDSA", "active.pem", None),
            local_key("previous", "RS256", "previous.pem", None),
            local_key("grace", "RS256", "grace.pem", Some(future())),
            local_key("retired", "PS256", "retired.pem", Some(past())),
            json!({
                "kid": "external",
                "alg": "ES256",
                "backend": "external-command",
                "key_ref": "kms://key/external",
                "public_jwk": public_jwk("external", "ES256", "sig"),
                "created_at": "2026-01-01T00:00:00Z",
                "retire_at": null,
            }),
        ],
    );
    write_test_keyset(&settings, &keyset).await;

    list_keys(&settings).await.unwrap();

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn register_external_key_persists_only_valid_public_signing_metadata() {
    let dir = temp_keys_dir("external");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let settings = test_settings(dir.clone());
    let jwk_file = dir.join("public.jwk.json");
    tokio::fs::write(
        &jwk_file,
        serde_json::to_string(&public_jwk("external", "RS256", "sig")).unwrap(),
    )
    .await
    .unwrap();

    register_external_key(
        &settings,
        RegisterExternalKeyOptions {
            kid: "external".to_owned(),
            alg: jsonwebtoken::Algorithm::RS256,
            key_ref: "kms://key/1".to_owned(),
            public_jwk_file: jwk_file,
        },
    )
    .await
    .unwrap();

    let keyset = read_test_keyset(&settings).await;
    assert_eq!(keyset["active_kid"], "external");
    let entry = &keyset["keys"][0];
    assert_eq!(entry["backend"], "external-command");
    assert_eq!(entry["key_ref"], "kms://key/1");
    assert_eq!(entry["public_jwk"]["kid"], "external");
    nazo_key_management::KeyManager::validate(&settings.key_settings())
        .await
        .expect("registered external key must be loadable by production keyset validator");

    let bad_jwk = dir.join("bad-public.jwk.json");
    tokio::fs::write(
        &bad_jwk,
        serde_json::to_string(&public_jwk("other", "RS256", "sig")).unwrap(),
    )
    .await
    .unwrap();
    let err = register_external_key(
        &settings,
        RegisterExternalKeyOptions {
            kid: "external-2".to_owned(),
            alg: jsonwebtoken::Algorithm::RS256,
            key_ref: "kms://key/2".to_owned(),
            public_jwk_file: bad_jwk,
        },
    )
    .await
    .unwrap_err();
    assert_error_contains(err, "public_jwk kid mismatch");

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn register_external_key_preserves_active_key_and_rejects_duplicate_kids() {
    let dir = temp_keys_dir("external-existing");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let settings = test_settings(dir.clone());
    write_test_keyset(
        &settings,
        &keyset_with_keys(
            "active",
            vec![local_key("active", "EdDSA", "active.pem", None)],
        ),
    )
    .await;

    let external_jwk = dir.join("external-public.jwk.json");
    tokio::fs::write(
        &external_jwk,
        serde_json::to_string(&public_jwk("external", "RS256", "sig")).unwrap(),
    )
    .await
    .unwrap();

    register_external_key(
        &settings,
        RegisterExternalKeyOptions {
            kid: "external".to_owned(),
            alg: jsonwebtoken::Algorithm::RS256,
            key_ref: "kms://key/external".to_owned(),
            public_jwk_file: external_jwk,
        },
    )
    .await
    .unwrap();

    let keyset = read_test_keyset(&settings).await;
    assert_eq!(
        keyset["active_kid"], "active",
        "registering a standby key must not silently rotate the active signer"
    );
    let keys = keyset["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    let external = keys.iter().find(|key| key["kid"] == "external").unwrap();
    assert_eq!(external["backend"], "external-command");
    assert_eq!(external["key_ref"], "kms://key/external");

    let duplicate_jwk = dir.join("duplicate-public.jwk.json");
    tokio::fs::write(
        &duplicate_jwk,
        serde_json::to_string(&public_jwk("active", "RS256", "sig")).unwrap(),
    )
    .await
    .unwrap();
    let err = register_external_key(
        &settings,
        RegisterExternalKeyOptions {
            kid: "active".to_owned(),
            alg: jsonwebtoken::Algorithm::RS256,
            key_ref: "kms://key/duplicate".to_owned(),
            public_jwk_file: duplicate_jwk,
        },
    )
    .await
    .unwrap_err();
    assert_error_contains(err, "duplicate key kid active");

    let keyset = read_test_keyset(&settings).await;
    assert_eq!(keyset["active_kid"], "active");
    assert_eq!(
        keyset["keys"].as_array().unwrap().len(),
        2,
        "duplicate registration attempts must not partially append invalid keys"
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn validate_keyset_requires_existing_file_and_accepts_valid_stored_keyset() {
    let dir = temp_keys_dir("validate");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let settings = test_settings(dir.clone());

    let err = validate_keyset(&settings).await.unwrap_err();
    assert_error_contains(err, "keyset.json does not exist");

    nazo_key_management::KeyManager::load_or_create(settings.key_settings())
        .await
        .unwrap();

    validate_keyset(&settings).await.unwrap();

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

fn keyset_with_keys(active_kid: &str, keys: Vec<Value>) -> Value {
    json!({
        "active_kid": active_kid,
        "keys": keys,
    })
}

async fn write_test_keyset(settings: &Settings, value: &Value) {
    tokio::fs::create_dir_all(&settings.keys.jwk_keys_dir)
        .await
        .unwrap();
    tokio::fs::write(
        settings.keys.jwk_keys_dir.join("keyset.json"),
        serde_json::to_vec_pretty(value).unwrap(),
    )
    .await
    .unwrap();
}

async fn read_test_keyset(settings: &Settings) -> Value {
    serde_json::from_slice(
        &tokio::fs::read(settings.keys.jwk_keys_dir.join("keyset.json"))
            .await
            .unwrap(),
    )
    .unwrap()
}

fn local_key(kid: &str, alg: &str, file: &str, retire_at: Option<String>) -> Value {
    json!({
        "kid": kid,
        "alg": alg,
        "file": file,
        "created_at": "2026-01-01T00:00:00Z",
        "retire_at": retire_at,
    })
}

fn public_jwk(kid: &str, alg: &str, key_use: &str) -> Value {
    json!({
        "kty": "RSA",
        "kid": kid,
        "alg": alg,
        "use": key_use,
        "n": "modulus",
        "e": "AQAB"
    })
}

fn past() -> String {
    (chrono::Utc::now() - chrono::Duration::seconds(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn future() -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(60))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn assert_error_contains(error: anyhow::Error, expected: &str) {
    assert!(
        error.to_string().contains(expected),
        "expected error to contain {expected:?}, got {error}"
    );
}

fn assert_missing_keyset_error(error: anyhow::Error) {
    let message = error.to_string();
    assert!(
        message.contains("keyset.json does not exist") || message.contains("failed to read"),
        "expected missing or unreadable keyset error, got {error}"
    );
}

fn expect_register_external_error(args: Vec<String>) -> anyhow::Error {
    match parse_register_external_args(args) {
        Ok(_) => panic!("register-external parser unexpectedly accepted invalid input"),
        Err(error) => error,
    }
}

fn temp_keys_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "nazo_keyctl_{label}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn keyctl_cwd_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn with_temp_cwd<T>(label: &str, f: impl FnOnce(&Path) -> T) -> T {
    let _guard = keyctl_cwd_lock()
        .lock()
        .expect("keyctl cwd lock should not be poisoned");
    let original = std::env::current_dir().expect("current dir should be readable");
    let dir = temp_keys_dir(label);
    std::fs::create_dir_all(&dir).expect("temp cwd should be creatable");
    std::env::set_current_dir(&dir).expect("temp cwd should become current dir");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&dir)));

    std::env::set_current_dir(&original).expect("original cwd should be restored");
    let _ = std::fs::remove_dir_all(&dir);

    match result {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn test_settings(jwk_keys_dir: PathBuf) -> Settings {
    let mut settings =
        Settings::from_config(&crate::config::ConfigSource::default()).expect("settings");
    settings.storage.avatar_storage_dir = jwk_keys_dir.join("avatars");
    settings.keys.jwk_keys_dir = jwk_keys_dir;
    settings.keys.signing_external_command = vec!["/bin/false".to_owned()];
    settings
}
