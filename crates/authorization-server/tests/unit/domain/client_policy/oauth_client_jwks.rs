use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::Utc;
use nazo_key_management::{validate_client_jwks, validate_self_signed_mtls_jwks};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509Name};
use serde_json::json;

fn test_x5c(common_name: &str, not_before_offset: i64, not_after_offset: i64) -> String {
    let key: PKey<Private> =
        PKey::from_rsa(Rsa::generate(2048).expect("test rsa key")).expect("test pkey");
    let mut name = X509Name::builder().expect("x509 name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .expect("test common name");
    let name = name.build();
    let mut builder = X509Builder::new().expect("x509 builder");
    builder.set_version(2).expect("x509 version");
    builder.set_subject_name(&name).expect("x509 subject");
    builder.set_issuer_name(&name).expect("x509 issuer");
    builder.set_pubkey(&key).expect("x509 pubkey");
    let now = Utc::now().timestamp();
    let not_before = Asn1Time::from_unix(now + not_before_offset).expect("x509 not_before");
    let not_after = Asn1Time::from_unix(now + not_after_offset).expect("x509 not_after");
    builder
        .set_not_before(&not_before)
        .expect("set x509 not_before");
    builder
        .set_not_after(&not_after)
        .expect("set x509 not_after");
    builder
        .sign(&key, MessageDigest::sha256())
        .expect("sign test cert");
    STANDARD.encode(builder.build().to_der().expect("cert der"))
}

#[test]
fn self_signed_mtls_jwks_requires_a_current_parseable_x5c_certificate() {
    let invalid = json!({ "keys": [{ "kid": "invalid", "x5c": ["not-a-certificate"] }] });
    assert!(!validate_self_signed_mtls_jwks(&invalid));

    let current = json!({
        "keys": [{
            "kid": "current",
            "x5c": [test_x5c("client-current", -60, 3600)]
        }]
    });
    assert!(validate_self_signed_mtls_jwks(&current));

    let expired = json!({
        "keys": [{
            "kid": "expired",
            "x5c": [test_x5c("client-expired", -7200, -3600)]
        }]
    });
    assert!(!validate_self_signed_mtls_jwks(&expired));
}

#[test]
fn client_jwks_allows_one_unidentified_key_class_but_rejects_empty_or_duplicate_kids() {
    let empty = json!({ "keys": [] });
    let error = validate_client_jwks(&empty).expect_err("empty jwks keys must fail closed");
    assert!(
        error.to_string().contains("jwks.keys 不能为空"),
        "unexpected error: {error}"
    );

    let missing_kid = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "sig"
        }]
    });
    validate_client_jwks(&missing_kid)
        .expect("RFC 7517 defines kid as optional when selection remains unambiguous");

    let empty_kid = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "sig",
            "kid": ""
        }]
    });
    let error = validate_client_jwks(&empty_kid).expect_err("an explicit empty kid must fail");
    assert!(
        error.to_string().contains("kid"),
        "unexpected error: {error}"
    );

    let duplicate_kid = json!({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
                "alg": "EdDSA",
                "use": "sig",
                "kid": "key-1"
            },
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode([8u8; 32]),
                "alg": "EdDSA",
                "use": "sig",
                "kid": "key-1"
            }
        ]
    });
    let error =
        validate_client_jwks(&duplicate_kid).expect_err("duplicate JWK kid must fail closed");
    assert!(
        error.to_string().contains("jwks kid 不能重复: key-1"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_jwks_accepts_encryption_keys_for_introspection_jwe() {
    let encryption_use = json!({
        "keys": [{
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
            "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
            "alg": "RSA-OAEP-256",
            "use": "enc",
            "kid": "enc-key"
        }]
    });
    validate_client_jwks(&encryption_use)
        .expect("registered client JWKS may include RSA encryption keys for RFC 9701 JWE");
}

#[test]
fn client_jwks_requires_declared_algorithm() {
    let missing_alg = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "use": "sig",
            "kid": "no-alg"
        }]
    });
    let error = validate_client_jwks(&missing_alg).expect_err("registered JWKs must declare alg");
    assert!(
        error.to_string().contains("jwks 公钥必须声明 alg"),
        "unexpected error: {error}"
    );

    let unsupported_alg = json!({
        "keys": [{
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
            "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
            "alg": "HS256",
            "use": "sig",
            "kid": "unsupported-alg"
        }]
    });
    let error =
        validate_client_jwks(&unsupported_alg).expect_err("unsupported JWS alg must fail closed");
    assert!(
        error.to_string().contains("jwks alg 必须是"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_jwks_rejects_encryption_algorithm_key_type_mismatch() {
    let jwks = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "RSA-OAEP-256",
            "use": "enc",
            "kid": "wrong-enc-alg"
        }]
    });

    let error = validate_client_jwks(&jwks)
        .expect_err("declared JWE algorithm must match JWK key type and material");
    assert!(
        error.to_string().contains("jwks 公钥材料与 alg 不匹配"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_jwks_rejects_private_key_material() {
    let private_jwk = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "d": URL_SAFE_NO_PAD.encode([8u8; 32]),
            "kid": "key-1"
        }]
    });

    let error = validate_client_jwks(&private_jwk).expect_err("registered JWK must not contain d");
    assert!(
        error.to_string().contains("jwks 不能包含私钥材料"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_jwks_accepts_supported_public_key_algorithms() {
    let jwks = json!({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
                "alg": "EdDSA",
                "use": "sig",
                "kid": "ed-key"
            },
            {
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
                "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
                "alg": "RS256",
                "use": "sig",
                "kid": "rs-key"
            },
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ",
                "y": "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4",
                "alg": "ES256",
                "use": "sig",
                "kid": "es-key"
            },
            {
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode([0x92u8; 256]),
                "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
                "alg": "PS256",
                "use": "sig",
                "kid": "ps-key"
            },
            {
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode([0x93u8; 256]),
                "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
                "alg": "RSA-OAEP-256",
                "use": "enc",
                "kid": "enc-key"
            }
        ]
    });

    validate_client_jwks(&jwks)
        .expect("supported public signing keys should be accepted for private_key_jwt");
}

#[test]
fn client_jwks_rejects_algorithm_key_type_mismatch() {
    let jwks = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "RS256",
            "use": "sig",
            "kid": "wrong-alg"
        }]
    });

    let error = validate_client_jwks(&jwks)
        .expect_err("declared JWS algorithm must match JWK key type and material");
    assert!(
        error.to_string().contains("jwks 公钥材料与 alg 不匹配"),
        "unexpected error: {error}"
    );
}
