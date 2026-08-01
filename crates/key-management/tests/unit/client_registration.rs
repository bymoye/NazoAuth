use p256::{
    SecretKey,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use serde_json::json;

use super::*;

#[test]
fn client_secret_digest_preserves_persisted_v1_format() {
    assert_eq!(
        client_secret_digest("secret", "pepper", "salt"),
        "client-secret-v1:salt:9H5GZ-kyQt1opgZoNCnaRK1w3aTK1xF1-HoStANbmzM"
    );
}

#[test]
fn client_jwks_reject_private_key_material() {
    let error = validate_client_jwks(&json!({
        "keys": [{
            "kid": "private",
            "use": "sig",
            "alg": "RS256",
            "kty": "RSA",
            "n": "AQ",
            "e": "AQAB",
            "d": "private"
        }]
    }))
    .expect_err("private key material must be rejected");
    assert_eq!(error, "jwks 不能包含私钥材料或对称密钥材料");
}

#[test]
fn client_jwks_accept_supported_ecdh_encryption_keys() {
    let jwks = json!({
        "keys": [
            p256_encryption_jwk("ecdh-direct", "ECDH-ES"),
            p256_encryption_jwk("ecdh-a128kw", "ECDH-ES+A128KW"),
            p256_encryption_jwk("ecdh-a256kw", "ECDH-ES+A256KW")
        ]
    });

    validate_client_jwks(&jwks).expect("supported ECDH encryption keys should be accepted");
    assert_eq!(
        client_jwks_matching_encryption_key_count(&jwks, "ECDH-ES"),
        1
    );
    assert_eq!(
        client_jwks_matching_encryption_key_count(&jwks, "ECDH-ES+A128KW"),
        1
    );
    assert_eq!(
        client_jwks_matching_encryption_key_count(&jwks, "ECDH-ES+A256KW"),
        1
    );
}

#[test]
fn algorithm_specific_signing_key_selection_requires_matching_public_material() {
    let signing = p256_signing_jwk("signing", "ES256");
    let jwks = json!({"keys": [signing]});

    assert!(client_jwks_contains_signing_key_for_algorithm(
        &jwks, "ES256"
    ));
    assert!(!client_jwks_contains_signing_key_for_algorithm(
        &jwks, "RS256"
    ));
    assert!(!client_jwks_contains_signing_key_for_algorithm(
        &json!({"keys": [p256_encryption_jwk("enc", "ECDH-ES")]}),
        "ECDH-ES"
    ));
    assert!(!client_jwks_contains_signing_key_for_algorithm(
        &json!({"keys": [{"use": "sig", "alg": "none"}]}),
        "none"
    ));
    assert!(!client_jwks_contains_signing_key_for_algorithm(
        &json!({"not_keys": []}),
        "ES256"
    ));
}

#[test]
fn client_jwks_reject_symmetric_jwe_keys() {
    let error = validate_client_jwks(&json!({
        "keys": [{
            "kid": "sym",
            "use": "enc",
            "alg": "A256KW",
            "kty": "oct",
            "k": URL_SAFE_NO_PAD.encode([0xA5_u8; 32])
        }]
    }))
    .expect_err("symmetric keys must not enter client jwks");

    assert_eq!(error, "jwks 不能包含私钥材料或对称密钥材料");
}

#[test]
fn client_jwks_reject_unsupported_ecdh_key_wrap_width() {
    let error = validate_client_jwks(&json!({
        "keys": [p256_encryption_jwk("ecdh-a192kw", "ECDH-ES+A192KW")]
    }))
    .expect_err("unsupported ECDH key-wrap width must be rejected");

    assert_eq!(error, "jwks 公钥材料与 alg 不匹配");
}

#[test]
fn client_jwks_accepts_optional_key_ids_but_rejects_duplicate_values() {
    let mut without_kid = p256_encryption_jwk("unused", "ECDH-ES");
    without_kid
        .as_object_mut()
        .expect("fixture is an object")
        .remove("kid");
    validate_client_jwks(&json!({"keys": [without_kid]}))
        .expect("RFC 7517 defines kid as optional");

    let mut empty_kid = p256_encryption_jwk("unused", "ECDH-ES");
    empty_kid["kid"] = Value::String(String::new());
    assert_eq!(
        validate_client_jwks(&json!({"keys": [empty_kid]})),
        Err("jwks kid 不能为空或包含首尾空白".to_owned())
    );

    let error = validate_client_jwks(&json!({
        "keys": [
            p256_encryption_jwk("duplicate", "ECDH-ES"),
            p256_encryption_jwk("duplicate", "ECDH-ES+A256KW")
        ]
    }))
    .expect_err("duplicate key identifiers make key selection ambiguous");
    assert_eq!(error, "jwks kid 不能重复: duplicate");
}

#[test]
fn rfc4514_distinguished_names_are_parsed_and_compared_canonically() {
    validate_rfc4514_dn("CN=client-1,O=Example").expect("a valid RFC 4514 name is accepted");
    assert!(rfc4514_dn_matches(
        "CN=client-1,O=Example",
        "CN=CLIENT-1,O=example"
    ));
    assert!(!rfc4514_dn_matches(
        "CN=client-1,O=Example",
        "CN=other,O=Example"
    ));
    assert!(validate_rfc4514_dn("not-a-distinguished-name").is_err());
    assert!(validate_rfc4514_dn(" CN=client-1").is_err());
}

fn p256_encryption_jwk(kid: &str, alg: &str) -> Value {
    let key = SecretKey::generate();
    let point = key.public_key().to_sec1_point(false);
    json!({
        "kid": kid,
        "use": "enc",
        "alg": alg,
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x coordinate")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y coordinate"))
    })
}

fn p256_signing_jwk(kid: &str, alg: &str) -> Value {
    let key = SecretKey::generate();
    let point = key.public_key().to_sec1_point(false);
    json!({
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x coordinate")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y coordinate"))
    })
}
