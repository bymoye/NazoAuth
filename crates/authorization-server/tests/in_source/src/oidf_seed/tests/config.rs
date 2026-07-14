use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

fn temp_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nazo_oidf_{label}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn string_value_returns_value_for_existing_key() {
    let value = json!({"client_id": "client-1"});
    assert_eq!(string_value(&value, "client_id").unwrap(), "client-1");
}

#[test]
fn string_value_errors_for_missing_key() {
    let value = json!({"client_id": "client-1"});
    let err = string_value(&value, "missing").unwrap_err();
    assert!(err.to_string().contains("missing string field missing"));
}

#[test]
fn string_value_errors_for_non_string_value() {
    let value = json!({"answer": 42});
    let err = string_value(&value, "answer").unwrap_err();
    assert!(err.to_string().contains("missing string field answer"));
}

#[test]
fn public_jwks_strips_private_key_fields() {
    let private_jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "client-key",
            "n": "modulus",
            "e": "AQAB",
            "d": "private-d",
            "p": "private-p",
            "q": "private-q",
            "dp": "private-dp",
            "dq": "private-dq",
            "qi": "private-qi",
            "oth": [{"r": "private-oth"}]
        }]
    });
    let public = public_jwks(&private_jwks).unwrap();
    let key = public["keys"][0].as_object().unwrap();
    assert_eq!(key.get("kid").and_then(Value::as_str), Some("client-key"));
    assert_eq!(key.get("n").and_then(Value::as_str), Some("modulus"));
    for field in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
        assert!(!key.contains_key(field), "public JWKS leaked {field}");
    }
}

#[test]
fn public_jwks_errors_for_missing_keys_array() {
    let invalid = json!({"not_keys": []});
    let err = public_jwks(&invalid).unwrap_err();
    assert!(err.to_string().contains("must contain keys array"));
}

#[test]
fn public_jwks_errors_for_non_array_keys() {
    let invalid = json!({"keys": "not-an-array"});
    let err = public_jwks(&invalid).unwrap_err();
    assert!(err.to_string().contains("must contain keys array"));
}

#[test]
fn plan_config_files_filters_and_sorts() {
    let dir = temp_dir("plan-list");
    fs::write(dir.join("z-plan-config.json"), "{}").unwrap();
    fs::write(dir.join("ignored.json"), "{}").unwrap();
    fs::write(dir.join("a-plan-config.json"), "{}").unwrap();
    fs::write(dir.join("plan-config.json.bak"), "{}").unwrap();

    let files = plan_config_files(&dir).unwrap();
    fs::remove_dir_all(&dir).unwrap();

    assert_eq!(
        files,
        vec![
            "a-plan-config.json".to_owned(),
            "z-plan-config.json".to_owned()
        ]
    );
}

#[test]
fn plan_config_files_returns_empty_for_no_matches() {
    let dir = temp_dir("plan-empty");
    fs::write(dir.join("ignored.json"), "{}").unwrap();

    let files = plan_config_files(&dir).unwrap();
    fs::remove_dir_all(&dir).unwrap();

    assert!(files.is_empty());
}

#[test]
fn plan_config_files_filters_by_suffix() {
    let dir = temp_dir("plan-suffix");
    fs::write(dir.join("a-plan-config.json"), "{}").unwrap();
    fs::write(dir.join("other.json"), "{}").unwrap();
    fs::write(dir.join("readme.txt"), "").unwrap();

    let files = plan_config_files(&dir).unwrap();
    fs::remove_dir_all(&dir).unwrap();

    assert_eq!(files, vec!["a-plan-config.json".to_owned()]);
}

fn certificate_pem(bytes: &[u8]) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        STANDARD.encode(bytes)
    )
}

fn expected_thumbprint(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

#[test]
fn mtls_thumbprint_returns_thumbprint_for_client() {
    let cert = certificate_pem(b"\x01\x02\x03\x04");
    let plan = json!({"mtls": { "cert": cert }});
    assert_eq!(
        mtls_thumbprint(&plan, "client").unwrap(),
        Some(expected_thumbprint(b"\x01\x02\x03\x04"))
    );
}

#[test]
fn mtls_thumbprint_uses_mtls2_for_client2() {
    let cert = certificate_pem(b"\x05\x06\x07\x08");
    let plan = json!({"mtls2": { "cert": cert }});
    assert_eq!(
        mtls_thumbprint(&plan, "client2").unwrap(),
        Some(expected_thumbprint(b"\x05\x06\x07\x08"))
    );
}

#[test]
fn mtls_thumbprint_returns_none_when_missing() {
    assert_eq!(mtls_thumbprint(&json!({}), "client").unwrap(), None);
}

#[test]
fn mtls_thumbprint_errors_for_missing_end_marker() {
    let plan = json!({"mtls": { "cert": "-----BEGIN CERTIFICATE-----\nAQID" }});
    let err = mtls_thumbprint(&plan, "client").unwrap_err();
    assert!(err.to_string().contains("missing END marker"));
}

#[test]
fn mtls_thumbprint_errors_for_invalid_base64() {
    let plan = json!({
        "mtls": {
            "cert": "-----BEGIN CERTIFICATE-----\nnot-base64!!\n-----END CERTIFICATE-----"
        }
    });
    let err = mtls_thumbprint(&plan, "client").unwrap_err();
    assert!(err.to_string().contains("base64 decode failed"));
}

#[test]
fn client_scopes_uses_default_when_scope_missing() {
    let client = serde_json::Map::new();
    assert_eq!(
        client_scopes(&client),
        json!(["openid", "profile", "email", "offline_access"])
    );
}

#[test]
fn client_scopes_parses_custom_scopes() {
    let mut client = serde_json::Map::new();
    client.insert(
        "scope".to_owned(),
        Value::String(" openid  payments   accounts ".to_owned()),
    );
    assert_eq!(
        client_scopes(&client),
        json!(["openid", "payments", "accounts"])
    );
}

#[test]
fn client_scopes_filters_empty_scopes() {
    let mut client = serde_json::Map::new();
    client.insert("scope".to_owned(), Value::String("   ".to_owned()));
    assert_eq!(client_scopes(&client), json!([]));
}

#[test]
fn read_plan_config_reads_valid_json() {
    let dir = temp_dir("read-valid");
    fs::write(dir.join("plan-config.json"), r#"{"client_id":"client-1"}"#).unwrap();
    let value = read_plan_config(&dir, "plan-config.json").unwrap();
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(value["client_id"], "client-1");
}

#[test]
fn read_plan_config_errors_for_invalid_json() {
    let dir = temp_dir("read-invalid");
    fs::write(dir.join("bad.json"), "{").unwrap();
    let err = read_plan_config(&dir, "bad.json").unwrap_err();
    fs::remove_dir_all(&dir).unwrap();
    assert!(err.to_string().contains("bad.json"));
}

#[test]
fn read_plan_config_errors_for_missing_file() {
    let dir = temp_dir("read-missing");
    let err = read_plan_config(&dir, "missing.json").unwrap_err();
    fs::remove_dir_all(&dir).unwrap();
    assert!(err.to_string().contains("missing.json"));
}

#[test]
fn certificate_pem_thumbprint_computes_sha256_of_der() {
    let cert = certificate_pem(b"\x01\x02\x03\x04");
    let thumbprint = certificate_pem_thumbprint(&cert).unwrap();
    assert_eq!(thumbprint, expected_thumbprint(b"\x01\x02\x03\x04"));
}

#[test]
fn certificate_pem_thumbprint_errors_for_missing_begin() {
    let err = certificate_pem_thumbprint("no begin marker").unwrap_err();
    assert!(err.to_string().contains("missing BEGIN marker"));
}

#[test]
fn certificate_pem_thumbprint_errors_for_missing_end() {
    let err = certificate_pem_thumbprint("-----BEGIN CERTIFICATE-----\nAQID").unwrap_err();
    assert!(err.to_string().contains("missing END marker"));
}

#[test]
fn certificate_pem_thumbprint_errors_for_invalid_base64() {
    let err =
        certificate_pem_thumbprint("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----")
            .unwrap_err();
    assert!(err.to_string().contains("base64 decode failed"));
}
