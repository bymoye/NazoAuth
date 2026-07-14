use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, jwk::Jwk};
use openssl::rsa::Rsa;
use p256::elliptic_curve::{Generate, pkcs8::EncodePrivateKey};
use serde_json::{Value, json};

#[test]
fn algorithm_name_allows_only_asymmetric_jwt_signing_algorithms() {
    assert_eq!(algorithm_name(Algorithm::EdDSA), Some("EdDSA"));
    assert_eq!(algorithm_name(Algorithm::RS256), Some("RS256"));
    assert_eq!(algorithm_name(Algorithm::ES256), Some("ES256"));
    assert_eq!(algorithm_name(Algorithm::PS256), Some("PS256"));
    assert_eq!(algorithm_name(Algorithm::HS256), None);
}

#[test]
fn decoding_key_accepts_only_matching_public_rsa_key_metadata() {
    let jwk = rsa_jwk("RS256");
    assert!(decoding_key(&jwk, Algorithm::RS256).is_some());

    for invalid in [
        with_field(&jwk, "alg", json!("PS256")),
        with_field(&jwk, "kty", json!("EC")),
        with_field(&jwk, "use", json!("enc")),
        with_field(&jwk, "d", json!("private")),
        with_field(&jwk, "n", json!(URL_SAFE_NO_PAD.encode([1_u8; 128]))),
        with_field(&jwk, "e", json!("")),
    ] {
        assert!(
            decoding_key(&invalid, Algorithm::RS256).is_none(),
            "resource verifier must reject RSA keys with mismatched or unsafe metadata: {invalid}"
        );
    }
}

#[test]
fn decoding_key_accepts_only_matching_public_ec_key_metadata() {
    let jwk = es256_jwk();
    assert!(decoding_key(&jwk, Algorithm::ES256).is_some());

    for invalid in [
        with_field(&jwk, "alg", json!("RS256")),
        with_field(&jwk, "kty", json!("RSA")),
        with_field(&jwk, "crv", json!("P-384")),
        with_field(&jwk, "d", json!("private")),
        with_field(&jwk, "x", json!(URL_SAFE_NO_PAD.encode([1_u8; 31]))),
        with_field(&jwk, "y", json!(URL_SAFE_NO_PAD.encode([2_u8; 31]))),
    ] {
        assert!(
            decoding_key(&invalid, Algorithm::ES256).is_none(),
            "resource verifier must reject EC keys outside P-256 public signing shape: {invalid}"
        );
    }
}

#[test]
fn decoding_key_accepts_only_matching_public_eddsa_key_metadata() {
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
        "x": URL_SAFE_NO_PAD.encode([7_u8; 32])
    });
    assert!(decoding_key(&jwk, Algorithm::EdDSA).is_some());

    for invalid in [
        with_field(&jwk, "alg", json!("RS256")),
        with_field(&jwk, "kty", json!("RSA")),
        with_field(&jwk, "crv", json!("Ed448")),
        with_field(&jwk, "d", json!("private")),
        with_field(&jwk, "x", json!(URL_SAFE_NO_PAD.encode([7_u8; 31]))),
    ] {
        assert!(
            decoding_key(&invalid, Algorithm::EdDSA).is_none(),
            "resource verifier must reject OKP keys outside Ed25519 public signing shape: {invalid}"
        );
    }
}

#[test]
fn decoding_key_rejects_unsupported_or_missing_algorithm_metadata() {
    let jwk = rsa_jwk("RS256");
    assert!(decoding_key(&jwk, Algorithm::HS256).is_none());
    assert!(decoding_key(&without_field(&jwk, "alg"), Algorithm::RS256).is_none());
}

fn rsa_jwk(alg: &str) -> Value {
    let der = Rsa::generate(2048).unwrap().private_key_to_der().unwrap();
    let key = EncodingKey::from_rsa_der(&der);
    let mut value =
        serde_json::to_value(Jwk::from_encoding_key(&key, Algorithm::RS256).unwrap()).unwrap();
    value["alg"] = json!(alg);
    value["use"] = json!("sig");
    value
}

fn es256_jwk() -> Value {
    let secret_key = p256::SecretKey::generate();
    let der = secret_key.to_pkcs8_der().unwrap();
    let key = EncodingKey::from_ec_der(der.as_bytes());
    let mut value =
        serde_json::to_value(Jwk::from_encoding_key(&key, Algorithm::ES256).unwrap()).unwrap();
    value["alg"] = json!("ES256");
    value["use"] = json!("sig");
    value
}

fn with_field(value: &Value, field: &str, replacement: Value) -> Value {
    let mut value = value.clone();
    value[field] = replacement;
    value
}

fn without_field(value: &Value, field: &str) -> Value {
    let mut value = value.clone();
    value.as_object_mut().unwrap().remove(field);
    value
}
