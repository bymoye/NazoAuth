use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer as OpenSslSigner};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde_json::{Value, json};

use super::{JwkSignatureVerificationError, public_decoding_key, verify_jwk_signature};

const PRIVATE_KEY: [u8; 32] = [17; 32];

fn public_jwk() -> Value {
    let verifying = SigningKey::from_bytes(&PRIVATE_KEY).verifying_key();
    json!({
        "kid": "key-1",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
        "key_ops": ["verify"],
        "x": URL_SAFE_NO_PAD.encode(verifying.as_bytes()),
    })
}

fn ec_public_jwk() -> Value {
    let signing = P256SigningKey::from_slice(&[3; 32]).unwrap();
    let point = signing.verifying_key().to_sec1_point(false);
    json!({
        "kid": "ec-key",
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    })
}

fn rsa_keypair() -> (PKey<openssl::pkey::Private>, Value) {
    let rsa = Rsa::generate(2048).unwrap();
    let jwk = json!({
        "kid": "rsa-key",
        "kty": "RSA",
        "alg": "RS256",
        "n": URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
        "e": URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
    });
    (PKey::from_rsa(rsa).unwrap(), jwk)
}

#[test]
fn verifies_a_valid_ed25519_signature() {
    let input = b"@method: GET";
    let signature = SigningKey::from_bytes(&PRIVATE_KEY).sign(input);

    verify_jwk_signature(
        &json!({"keys": [public_jwk()]}),
        "key-1",
        "ed25519",
        input,
        &signature.to_bytes(),
    )
    .unwrap();
}

#[test]
fn verifies_valid_es256_and_rejects_an_invalid_signature() {
    let signing = P256SigningKey::from_slice(&[3; 32]).unwrap();
    let input = b"@method: POST";
    let signature: P256Signature = signing.sign(input);
    let jwks = json!({"keys": [ec_public_jwk()]});

    verify_jwk_signature(
        &jwks,
        "ec-key",
        "ecdsa-p256-sha256",
        input,
        signature.to_bytes().as_slice(),
    )
    .unwrap();
    assert_eq!(
        verify_jwk_signature(
            &jwks,
            "ec-key",
            "ecdsa-p256-sha256",
            b"altered",
            signature.to_bytes().as_slice(),
        ),
        Err(JwkSignatureVerificationError::InvalidSignature)
    );
}

#[test]
fn verifies_valid_rsa_and_rejects_an_invalid_signature() {
    let (key, jwk) = rsa_keypair();
    let input = b"@method: GET";
    let mut signer = OpenSslSigner::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(input).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    let jwks = json!({"keys": [jwk]});

    verify_jwk_signature(&jwks, "rsa-key", "rsa-v1_5-sha256", input, &signature).unwrap();
    assert_eq!(
        verify_jwk_signature(&jwks, "rsa-key", "rsa-v1_5-sha256", b"altered", &signature,),
        Err(JwkSignatureVerificationError::InvalidSignature)
    );
}

#[test]
fn requires_one_unique_kid_and_a_supported_algorithm() {
    let key = public_jwk();
    assert_eq!(
        verify_jwk_signature(
            &json!({"keys": [key.clone()]}),
            "missing",
            "ed25519",
            b"x",
            b"x"
        ),
        Err(JwkSignatureVerificationError::KeyNotFound)
    );
    assert_eq!(
        verify_jwk_signature(
            &json!({"keys": [key.clone(), key]}),
            "key-1",
            "ed25519",
            b"x",
            b"x"
        ),
        Err(JwkSignatureVerificationError::AmbiguousKey)
    );
    assert_eq!(
        verify_jwk_signature(&json!({"keys": []}), "key-1", "unknown", b"x", b"x"),
        Err(JwkSignatureVerificationError::UnsupportedAlgorithm)
    );
}

#[test]
fn rejects_private_material_and_non_verification_metadata() {
    for member in ["k", "d", "p", "q", "dp", "dq", "qi", "oth"] {
        let mut key = public_jwk();
        key[member] = json!("private");
        assert!(
            public_decoding_key(&key, jsonwebtoken::Algorithm::EdDSA).is_none(),
            "accepted private JWK member {member}"
        );
    }
    for key_ops in [
        json!(["sign", "verify"]),
        json!(["verify", "encrypt"]),
        json!(["verify", "decrypt"]),
        json!(["sign"]),
        json!(["encrypt"]),
        json!([]),
        json!(["verify", "verify"]),
        json!(["verify", 7]),
        json!("verify"),
    ] {
        let mut key = public_jwk();
        key["key_ops"] = key_ops;
        assert!(public_decoding_key(&key, jsonwebtoken::Algorithm::EdDSA).is_none());
    }
    for (member, value) in [
        ("use", json!("enc")),
        ("use", json!(7)),
        ("alg", json!("RS256")),
    ] {
        let mut key = public_jwk();
        key[member] = value;
        assert!(public_decoding_key(&key, jsonwebtoken::Algorithm::EdDSA).is_none());
    }
}

#[test]
fn accepts_supported_public_key_shapes_without_optional_alg() {
    let mut ed = public_jwk();
    ed.as_object_mut().unwrap().remove("alg");
    assert!(public_decoding_key(&ed, jsonwebtoken::Algorithm::EdDSA).is_some());
    assert!(public_decoding_key(&ec_public_jwk(), jsonwebtoken::Algorithm::ES256).is_some());

    let rsa = json!({
        "kty": "RSA",
        "n": URL_SAFE_NO_PAD.encode(vec![0xff; 256]),
        "e": "AQAB",
    });
    assert!(public_decoding_key(&rsa, jsonwebtoken::Algorithm::RS256).is_some());
}

#[test]
fn rejects_incompatible_public_key_shapes() {
    let mut ec = ec_public_jwk();
    ec["crv"] = json!("P-384");
    assert!(public_decoding_key(&ec, jsonwebtoken::Algorithm::ES256).is_none());

    let mut ed = public_jwk();
    ed["x"] = json!(URL_SAFE_NO_PAD.encode([1; 31]));
    assert!(public_decoding_key(&ed, jsonwebtoken::Algorithm::EdDSA).is_none());
}

#[test]
fn rsa_policy_counts_unsigned_modulus_bits() {
    let mut modulus = vec![0xff; 256];
    let mut jwk = json!({
        "kty": "RSA",
        "n": URL_SAFE_NO_PAD.encode(&modulus),
        "e": "AQAB",
    });
    assert!(public_decoding_key(&jwk, jsonwebtoken::Algorithm::RS256).is_some());

    modulus.insert(0, 0);
    jwk["n"] = json!(URL_SAFE_NO_PAD.encode(&modulus));
    assert!(public_decoding_key(&jwk, jsonwebtoken::Algorithm::RS256).is_some());

    jwk["n"] = json!(URL_SAFE_NO_PAD.encode(vec![0xff; 255]));
    assert!(public_decoding_key(&jwk, jsonwebtoken::Algorithm::RS256).is_none());

    jwk["n"] = json!(URL_SAFE_NO_PAD.encode(vec![0xff; 256]));
    for exponent in [[1_u8].as_slice(), [2_u8].as_slice()] {
        jwk["e"] = json!(URL_SAFE_NO_PAD.encode(exponent));
        assert!(public_decoding_key(&jwk, jsonwebtoken::Algorithm::RS256).is_none());
    }
}
