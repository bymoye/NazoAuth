use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use coset::{CborSerializable, CoseKeyBuilder, iana};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use nazo_digital_credentials::CredentialTrustError;
use nazo_openid4vci::{ProofError, Proofs};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use p256::pkcs8::EncodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use serde_json::{Value, json};

use nazo_openid4vci::ProofValidatorPort as _;

use super::{
    Openid4vcClientAttestationValidator, Openid4vcProofValidator,
    client_attestation::client_instance_key_thumbprint,
    credential_crypto::{
        mdoc_failed_assessments_accepted, mdoc_holder_key, standard_device_authentication_bytes,
    },
    crypto_helpers::{
        algorithm_name, cbor_to_json, decoding_key, decoding_key_trust, json_to_cbor,
        jwk_to_cose_key, jwk_to_ec2_cose_key, p256_public_key_from_jwk, parse_pem_certificates,
        parse_x509, timestamp_claim, verify_openid4vc_chain,
    },
    proof_validator::KeyAttestationContext,
};

fn es256_test_key(seed: u8) -> (Value, EncodingKey) {
    let signing_key = SigningKey::from_slice(&[seed; 32]).expect("valid P-256 test key");
    let point = signing_key.verifying_key().to_sec1_point(false);
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x coordinate")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y coordinate")),
    });
    let document = signing_key.to_pkcs8_der().expect("P-256 PKCS#8 key");
    (jwk, EncodingKey::from_ec_der(document.as_bytes()))
}

fn key_attestation_fixture(
    claims: Value,
) -> (
    Openid4vcProofValidator,
    String,
    nazo_openid4vci::ProofTypeMetadata,
) {
    let (mut attester_jwk, attester_key) = es256_test_key(13);
    attester_jwk["kid"] = json!("attester-key");
    attester_jwk["alg"] = json!("ES256");
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("key-attestation+jwt".to_owned());
    header.kid = Some("attester-key".to_owned());
    let encoded = encode(&header, &claims, &attester_key).expect("key attestation JWT");
    let validator = Openid4vcProofValidator::new(json!({"keys": [attester_jwk]}))
        .expect("key attestation validator");
    let metadata = nazo_openid4vci::ProofTypeMetadata {
        proof_signing_alg_values_supported: vec!["ES256".to_owned()],
        key_attestations_required: None,
    };
    (validator, encoded, metadata)
}

fn validate_key_attestation(
    validator: &Openid4vcProofValidator,
    encoded: &str,
    expected_nonce: &str,
    metadata: &nazo_openid4vci::ProofTypeMetadata,
    now: chrono::DateTime<Utc>,
    context: KeyAttestationContext,
) -> Result<Value, ProofError> {
    validator.validate_key_attestation_with(
        &validator.key_attestation_jwks,
        encoded,
        expected_nonce,
        metadata,
        now,
        context,
    )
}

fn proof_metadata(
    required: Option<std::collections::BTreeMap<String, Vec<String>>>,
) -> nazo_openid4vci::ProofTypeMetadata {
    nazo_openid4vci::ProofTypeMetadata {
        proof_signing_alg_values_supported: vec!["ES256".to_owned()],
        key_attestations_required: required,
    }
}

fn signed_jwt_proof(
    jwk: Option<&Value>,
    key: &EncodingKey,
    claims: &Value,
    typ: Option<&str>,
    algorithm: Algorithm,
    key_attestation: Option<&str>,
) -> String {
    let mut header = Header::new(algorithm);
    header.typ = typ.map(ToOwned::to_owned);
    if let Some(jwk) = jwk {
        header.jwk = Some(serde_json::from_value(jwk.clone()).expect("proof JWK"));
    }
    if let Some(key_attestation) = key_attestation {
        header
            .extras
            .insert("key_attestation".to_owned(), key_attestation.to_owned());
    }
    encode(&header, claims, key).expect("proof JWT")
}

fn signed_client_attestation_jwt(
    claims: &Value,
    key: &EncodingKey,
    typ: &str,
    algorithm: Algorithm,
    kid: Option<&str>,
) -> String {
    let mut header = Header::new(algorithm);
    header.typ = Some(typ.to_owned());
    header.kid = kid.map(ToOwned::to_owned);
    encode(&header, claims, key).expect("client attestation JWT")
}

async fn validate_jwt_proof(
    validator: &Openid4vcProofValidator,
    proof: String,
    metadata: &nazo_openid4vci::ProofTypeMetadata,
) -> Result<Vec<nazo_openid4vci::ValidatedProof>, ProofError> {
    validator
        .validate(
            &Proofs(std::collections::BTreeMap::from([(
                "jwt".to_owned(),
                vec![Value::String(proof)],
            )])),
            "wallet-client",
            "https://issuer.example",
            "expected-nonce",
            metadata,
        )
        .await
}

#[test]
fn key_attestation_rejects_missing_issued_at() {
    let now = Utc::now();
    let (validator, encoded, metadata) = key_attestation_fixture(json!({
        "nonce": "expected-nonce",
        "exp": now.timestamp() + 300,
        "attested_keys": [es256_test_key(17).0],
    }));

    assert!(matches!(
        validate_key_attestation(
            &validator,
            &encoded,
            "expected-nonce",
            &metadata,
            now,
            KeyAttestationContext::AttestationProof,
        ),
        Err(ProofError::InvalidKeyAttestation)
    ));
}

#[test]
fn key_attestation_rejects_out_of_window_issued_at() {
    let now = Utc::now();
    for issued_at in [
        (now - Duration::minutes(5) - Duration::seconds(1)).timestamp(),
        (now + Duration::seconds(61)).timestamp(),
    ] {
        let (validator, encoded, metadata) = key_attestation_fixture(json!({
            "iat": issued_at,
            "nonce": "expected-nonce",
            "exp": now.timestamp() + 300,
            "attested_keys": [es256_test_key(18).0],
        }));

        assert!(matches!(
            validate_key_attestation(
                &validator,
                &encoded,
                "expected-nonce",
                &metadata,
                now,
                KeyAttestationContext::AttestationProof,
            ),
            Err(ProofError::InvalidKeyAttestation)
        ));
    }
}

#[test]
fn attestation_proof_rejects_missing_nonce() {
    let now = Utc::now();
    let (validator, encoded, metadata) = key_attestation_fixture(json!({
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
        "attested_keys": [es256_test_key(19).0],
    }));

    assert!(matches!(
        validate_key_attestation(
            &validator,
            &encoded,
            "expected-nonce",
            &metadata,
            now,
            KeyAttestationContext::AttestationProof,
        ),
        Err(ProofError::InvalidKeyAttestation)
    ));
}

#[test]
fn attestation_proof_accepts_missing_expiration() {
    let now = Utc::now();
    let (validator, encoded, metadata) = key_attestation_fixture(json!({
        "iat": now.timestamp(),
        "nonce": "expected-nonce",
        "attested_keys": [es256_test_key(21).0],
    }));

    validate_key_attestation(
        &validator,
        &encoded,
        "expected-nonce",
        &metadata,
        now,
        KeyAttestationContext::AttestationProof,
    )
    .expect("exp is optional for an attestation proof");
}

#[tokio::test]
async fn proof_port_accepts_one_attestation_set_and_returns_each_attested_public_key() {
    let now = Utc::now();
    let first_key = es256_test_key(27).0;
    let second_key = es256_test_key(29).0;
    let (validator, encoded, metadata) = key_attestation_fixture(json!({
        "iat": now.timestamp(),
        "nonce": "expected-nonce",
        "exp": now.timestamp() + 300,
        "attested_keys": [first_key.clone(), second_key.clone()],
    }));
    let proofs = Proofs(std::collections::BTreeMap::from([(
        "attestation".to_owned(),
        vec![Value::String(encoded)],
    )]));

    let validated = validator
        .validate(
            &proofs,
            "wallet-client",
            "https://issuer.example",
            "expected-nonce",
            &metadata,
        )
        .await
        .expect("the attestation proof should validate");

    assert_eq!(validated.len(), 2);
    assert_eq!(validated[0].proof_type, "attestation");
    assert_eq!(validated[0].holder_binding, json!({"jwk": first_key}));
    assert_eq!(validated[1].holder_binding, json!({"jwk": second_key}));
}

#[test]
fn key_attestation_rejects_expired_optional_expiration() {
    let now = Utc::now();
    let (validator, encoded, metadata) = key_attestation_fixture(json!({
        "iat": now.timestamp(),
        "nonce": "expected-nonce",
        "exp": now.timestamp(),
        "attested_keys": [es256_test_key(31).0],
    }));

    assert!(matches!(
        validate_key_attestation(
            &validator,
            &encoded,
            "expected-nonce",
            &metadata,
            now,
            KeyAttestationContext::AttestationProof,
        ),
        Err(ProofError::InvalidKeyAttestation)
    ));
}

#[test]
fn jwt_proof_key_attestation_requires_expiration() {
    let now = Utc::now();
    let (validator, encoded, metadata) = key_attestation_fixture(json!({
        "iat": now.timestamp(),
        "attested_keys": [es256_test_key(23).0],
    }));

    assert!(matches!(
        validate_key_attestation(
            &validator,
            &encoded,
            "expected-nonce",
            &metadata,
            now,
            KeyAttestationContext::JwtProof,
        ),
        Err(ProofError::InvalidKeyAttestation)
    ));
}

#[test]
fn jwt_proof_key_attestation_accepts_missing_nonce() {
    let now = Utc::now();
    let (validator, encoded, metadata) = key_attestation_fixture(json!({
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
        "attested_keys": [es256_test_key(25).0],
    }));

    validate_key_attestation(
        &validator,
        &encoded,
        "expected-nonce",
        &metadata,
        now,
        KeyAttestationContext::JwtProof,
    )
    .expect("the outer JWT proof already carries the required nonce");
}

#[test]
fn client_attestation_draft_07_accepts_optional_time_claims_and_binds_instance_key() {
    let now = Utc::now().timestamp();
    let (mut attester_jwk, attester_key) = es256_test_key(5);
    let (instance_jwk, instance_key) = es256_test_key(7);
    let mut attestation_header = Header::new(Algorithm::ES256);
    attestation_header.typ = Some("oauth-client-attestation+jwt".to_owned());
    attestation_header.kid = Some("attester-key".to_owned());
    let attestation = encode(
        &attestation_header,
        &json!({
            "iss": "https://attester.example",
            "sub": "wallet-client",
            "exp": now + 600,
            "cnf": {"jwk": instance_jwk.clone()},
        }),
        &attester_key,
    )
    .expect("client attestation JWT");
    let mut proof_header = Header::new(Algorithm::ES256);
    proof_header.typ = Some("oauth-client-attestation-pop+jwt".to_owned());
    let proof = encode(
        &proof_header,
        &json!({
            "iss": "wallet-client",
            "aud": "https://issuer.example",
            "iat": now,
            "jti": "fresh-proof",
        }),
        &instance_key,
    )
    .expect("client attestation PoP JWT");
    attester_jwk["kid"] = json!("attester-key");
    attester_jwk["alg"] = json!("ES256");
    let validator = Openid4vcClientAttestationValidator::new(
        "https://attester.example",
        json!({"keys": [attester_jwk]}),
    )
    .expect("client attestation validator");

    let validated = validator
        .validate(&attestation, &proof, "https://issuer.example", now)
        .expect("draft-07 optional claims must remain optional");

    assert_eq!(validated.client_id, "wallet-client");
    assert_eq!(
        validated.client_instance_key_thumbprint,
        client_instance_key_thumbprint(&instance_jwk).expect("instance JWK thumbprint")
    );
    assert_eq!(validated.replay_id, "fresh-proof");
    assert_eq!(validated.replay_ttl_seconds, 300);
}

#[test]
fn client_attestation_rejects_private_instance_key_material() {
    let (mut instance_jwk, _) = es256_test_key(11);
    instance_jwk["d"] = json!("private-material");

    assert!(client_instance_key_thumbprint(&instance_jwk).is_err());
}

#[test]
fn verified_mdoc_holder_binding_preserves_the_device_cose_key() {
    let key =
        CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, vec![7; 32], vec![11; 32])
            .build();

    let holder = mdoc_holder_key(Some(&key)).expect("device key must be retained");
    let encoded = holder
        .get("cose_key")
        .and_then(Value::as_str)
        .expect("holder binding must expose the verified COSE key");

    assert_eq!(
        URL_SAFE_NO_PAD.decode(encoded).expect("base64url COSE key"),
        key.to_vec().expect("CBOR COSE key")
    );
    assert_eq!(
        mdoc_holder_key(None),
        Err(CredentialTrustError::InvalidHolderBinding)
    );
}

#[test]
fn mdoc_holder_binding_rejects_rsa_attested_keys() {
    let modulus = vec![0x81; 256];
    let exponent = vec![0x01, 0x00, 0x01];
    let jwk = json!({
        "kty": "RSA",
        "alg": "PS256",
        "n": URL_SAFE_NO_PAD.encode(&modulus),
        "e": URL_SAFE_NO_PAD.encode(&exponent),
    });

    assert_eq!(
        jwk_to_cose_key(&jwk),
        Err(CredentialTrustError::InvalidHolderBinding)
    );
}

#[test]
fn mdoc_device_signature_uses_tagged_device_authentication_bytes() {
    let signing_key = SigningKey::from_slice(&[7; 32]).expect("valid P-256 test key");
    let point = signing_key.verifying_key().to_sec1_point(false);
    let device_key = CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        point.x().expect("P-256 x coordinate").to_vec(),
        point.y().expect("P-256 y coordinate").to_vec(),
    )
    .build();
    let session_transcript = [0x83, 0xf6, 0xf6, 0xf6];
    let device_name_spaces = [0xa0];
    let standard_payload = standard_device_authentication_bytes(
        &session_transcript,
        "org.iso.18013.5.1.mDL",
        &device_name_spaces,
    )
    .expect("DeviceAuthenticationBytes");
    let protected = coset::HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build();
    let sign1 = coset::CoseSign1Builder::new()
        .protected(protected)
        .create_detached_signature(&standard_payload, &[], |tbs| {
            let signature: Signature = signing_key.sign(tbs);
            signature.to_bytes().to_vec()
        })
        .build();
    let auth = mdoc_rs::model::types::DeviceAuth::Signature(sign1);
    let key_bytes = device_key.to_vec().expect("CBOR COSE key");

    let standard =
        mdoc_rs::device_auth::verify_device_auth(&auth, &standard_payload, &key_bytes, None)
            .expect("standard signature verification");
    assert!(standard.is_valid);

    let untagged_payload = mdoc_rs::session::build_device_authentication_bytes(
        &session_transcript,
        "org.iso.18013.5.1.mDL",
        &device_name_spaces,
    )
    .expect("untagged DeviceAuthentication");
    let untagged =
        mdoc_rs::device_auth::verify_device_auth(&auth, &untagged_payload, &key_bytes, None)
            .expect("untagged signature verification result");
    assert!(
        !untagged.is_valid,
        "the ISO DeviceAuthenticationBytes tag is part of the signed payload"
    );
}

#[test]
fn mdoc_fallback_accepts_only_independently_verified_checks() {
    let issuer = assessment(
        mdoc_rs::verifier::CheckId::IssuerCertificateValidity,
        mdoc_rs::verifier::VerificationStatus::Failed,
    );
    let device = assessment(
        mdoc_rs::verifier::CheckId::DeviceSignatureValidity,
        mdoc_rs::verifier::VerificationStatus::Failed,
    );
    let issuer_signature = assessment(
        mdoc_rs::verifier::CheckId::IssuerSignatureValidity,
        mdoc_rs::verifier::VerificationStatus::Failed,
    );

    assert!(mdoc_failed_assessments_accepted(
        [&device].into_iter(),
        true,
        true,
    ));
    assert!(!mdoc_failed_assessments_accepted(
        [&device].into_iter(),
        false,
        true,
    ));
    assert!(mdoc_failed_assessments_accepted(
        [&issuer, &device].into_iter(),
        true,
        true,
    ));
    assert!(!mdoc_failed_assessments_accepted(
        [&issuer, &issuer_signature].into_iter(),
        true,
        true,
    ));
    assert!(!mdoc_failed_assessments_accepted(
        [&issuer].into_iter(),
        true,
        false,
    ));
    assert!(!mdoc_failed_assessments_accepted(
        std::iter::empty(),
        true,
        true,
    ));
}

fn assessment(
    id: mdoc_rs::verifier::CheckId,
    status: mdoc_rs::verifier::VerificationStatus,
) -> mdoc_rs::verifier::VerificationAssessment {
    mdoc_rs::verifier::VerificationAssessment {
        status,
        check: "test assessment".to_owned(),
        reason: None,
        category: mdoc_rs::verifier::VerificationCategory::IssuerAuth,
        id,
    }
}

#[test]
fn crypto_helpers_cover_jwk_key_and_algorithm_boundaries() {
    let (jwk, _) = es256_test_key(37);
    assert!(decoding_key(&jwk, Algorithm::ES256).is_ok());
    assert!(decoding_key_trust(&jwk, Algorithm::ES256).is_ok());

    let ed_jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode([41_u8; 32]),
    });
    assert!(decoding_key(&ed_jwk, Algorithm::EdDSA).is_ok());
    assert!(decoding_key_trust(&ed_jwk, Algorithm::EdDSA).is_ok());
    assert!(matches!(
        decoding_key(&json!({}), Algorithm::ES256),
        Err(ProofError::InvalidSignature)
    ));
    assert!(matches!(
        decoding_key(&json!({"x": "bad", "y": "bad"}), Algorithm::ES256),
        Err(ProofError::InvalidSignature)
    ));
    assert!(matches!(
        decoding_key(&jwk, Algorithm::HS256),
        Err(ProofError::UnsupportedType)
    ));
    assert!(matches!(
        decoding_key_trust(&json!({}), Algorithm::ES256),
        Err(CredentialTrustError::InvalidHolderBinding)
    ));
    assert!(matches!(
        decoding_key_trust(&jwk, Algorithm::HS256),
        Err(CredentialTrustError::InvalidHolderBinding)
    ));

    assert_eq!(algorithm_name(Algorithm::ES256), Some("ES256"));
    assert_eq!(algorithm_name(Algorithm::EdDSA), Some("EdDSA"));
    assert_eq!(algorithm_name(Algorithm::HS256), None);

    let timestamp = Utc::now().timestamp();
    assert_eq!(
        timestamp_claim(&json!({"iat": timestamp}), "iat")
            .expect("valid timestamp")
            .timestamp(),
        timestamp
    );
    assert!(timestamp_claim(&json!({}), "iat").is_none());
    assert!(timestamp_claim(&json!({"iat": "now"}), "iat").is_none());
    assert!(timestamp_claim(&json!({"iat": i64::MAX}), "iat").is_none());

    assert!(jwk_to_cose_key(&jwk).is_ok());
    assert!(matches!(
        jwk_to_cose_key(&json!({"kty": "EC", "crv": "P-384"})),
        Err(CredentialTrustError::InvalidHolderBinding)
    ));
    assert!(jwk_to_ec2_cose_key(&jwk).is_ok());
    for invalid in [
        json!({"x": "not-base64", "y": "AQ"}),
        json!({"x": URL_SAFE_NO_PAD.encode([1_u8; 32])}),
    ] {
        assert!(matches!(
            jwk_to_ec2_cose_key(&invalid),
            Err(CredentialTrustError::InvalidHolderBinding)
        ));
    }
}

#[test]
fn crypto_helpers_round_trip_json_cbor_values_and_reject_invalid_shapes() {
    let value = json!({
        "null": null,
        "bool": true,
        "negative": -7,
        "unsigned": u64::MAX,
        "float": 1.25,
        "text": "hello",
        "array": [null, false, "nested"],
        "object": {"key": 3},
    });
    let cbor = json_to_cbor(&value).expect("JSON value should map to CBOR");
    assert_eq!(
        cbor_to_json(&cbor).expect("CBOR should map back to JSON"),
        value
    );

    let cbor = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("bytes".to_owned()),
            ciborium::Value::Bytes(vec![1, 2, 3]),
        ),
        (
            ciborium::Value::Text("tagged".to_owned()),
            ciborium::Value::Tag(42, Box::new(ciborium::Value::Text("tag".to_owned()))),
        ),
    ]);
    assert_eq!(
        cbor_to_json(&cbor).expect("bytes and tags should map to JSON"),
        json!({"bytes": URL_SAFE_NO_PAD.encode([1_u8, 2, 3]), "tagged": "tag"})
    );
    assert!(matches!(
        cbor_to_json(&ciborium::Value::Map(vec![(
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Null,
        ),])),
        Err(CredentialTrustError::InvalidEncoding)
    ));
    let too_negative = ciborium::value::Integer::try_from(-9_223_372_036_854_775_809_i128)
        .expect("value fits CBOR integer representation");
    assert!(matches!(
        cbor_to_json(&ciborium::Value::Integer(too_negative)),
        Err(CredentialTrustError::InvalidEncoding)
    ));
}

#[test]
fn crypto_helpers_validate_p256_and_pem_certificate_inputs() {
    let (jwk, _) = es256_test_key(43);
    assert!(p256_public_key_from_jwk(&jwk).is_ok());
    assert!(p256_public_key_from_jwk(&json!({"x": "bad", "y": "bad"})).is_err());
    assert!(
        p256_public_key_from_jwk(&json!({
            "x": URL_SAFE_NO_PAD.encode([1_u8; 31]),
            "y": URL_SAFE_NO_PAD.encode([2_u8; 32]),
        }))
        .is_err()
    );
    assert!(
        p256_public_key_from_jwk(&json!({
            "x": URL_SAFE_NO_PAD.encode([1_u8; 32]),
            "y": URL_SAFE_NO_PAD.encode([2_u8; 32]),
        }))
        .is_err()
    );

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate certificate key");
    let certificate = CertificateParams::new(vec!["issuer.example".to_owned()])
        .expect("certificate params")
        .self_signed(&key)
        .expect("self-signed certificate");
    let pem = certificate.pem();
    let certificates = parse_pem_certificates(pem.as_bytes()).expect("parse PEM certificate");
    assert_eq!(certificates, vec![certificate.der().as_ref().to_vec()]);
    let (_, parsed) = parse_x509(&certificates[0], "test certificate").expect("parse DER");
    assert_eq!(parsed.subject(), parsed.issuer());
    assert_eq!(
        parse_pem_certificates(b"not a certificate").unwrap(),
        Vec::<Vec<u8>>::new()
    );
    assert!(parse_x509(&[1, 2, 3], "bad certificate").is_err());
}

#[test]
fn crypto_helpers_verify_openid4vc_certificate_chain_and_anchor_policy() {
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
    let mut root_params = CertificateParams::default();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root = CertifiedIssuer::self_signed(root_params, root_key).expect("root certificate");

    let intermediate_key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("intermediate key");
    let mut intermediate_params = CertificateParams::default();
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let intermediate = CertifiedIssuer::signed_by(intermediate_params, intermediate_key, &root)
        .expect("intermediate certificate");

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let leaf_params =
        CertificateParams::new(vec!["issuer.example".to_owned()]).expect("leaf params");
    let leaf = leaf_params
        .signed_by(&leaf_key, &intermediate)
        .expect("leaf certificate");
    let leaf_der = leaf.der().as_ref().to_vec();
    let intermediate_der = intermediate.der().as_ref().to_vec();
    let root_der = root.der().as_ref().to_vec();
    verify_openid4vc_chain(
        &[leaf_der.clone(), intermediate_der, root_der.clone()],
        std::slice::from_ref(&root_der),
    )
    .expect("valid leaf/intermediate/root chain");
    assert!(verify_openid4vc_chain(&[leaf_der, root_der], &[]).is_err());
    assert!(verify_openid4vc_chain(&[root.der().as_ref().to_vec()], &[]).is_err());
    assert!(verify_openid4vc_chain(&[vec![1, 2, 3]], &[]).is_err());
}

#[tokio::test]
async fn proof_validator_rejects_ambiguous_and_malformed_proof_sets() {
    let now = Utc::now();
    let (validator, attestation, metadata) = key_attestation_fixture(json!({
        "iat": now.timestamp(),
        "nonce": "expected-nonce",
        "attested_keys": [es256_test_key(47).0],
    }));
    let two_types = Proofs(std::collections::BTreeMap::from([
        (
            "attestation".to_owned(),
            vec![Value::String(attestation.clone())],
        ),
        ("jwt".to_owned(), vec![Value::String(attestation.clone())]),
    ]));
    assert_eq!(
        validator
            .validate(
                &two_types,
                "wallet-client",
                "https://issuer.example",
                "expected-nonce",
                &metadata,
            )
            .await,
        Err(ProofError::UnsupportedType)
    );

    for proofs in [
        Proofs(std::collections::BTreeMap::from([(
            "attestation".to_owned(),
            vec![json!(42)],
        )])),
        Proofs(std::collections::BTreeMap::from([(
            "attestation".to_owned(),
            vec![json!("not-a-jwt")],
        )])),
        Proofs(std::collections::BTreeMap::from([
            (
                "attestation".to_owned(),
                vec![Value::String(attestation.clone())],
            ),
            ("unused".to_owned(), Vec::new()),
        ])),
    ] {
        assert!(matches!(
            validator
                .validate(
                    &proofs,
                    "wallet-client",
                    "https://issuer.example",
                    "expected-nonce",
                    &metadata,
                )
                .await,
            Err(ProofError::UnsupportedType | ProofError::InvalidKeyAttestation)
        ));
    }

    for proofs in [
        Proofs(std::collections::BTreeMap::new()),
        Proofs(std::collections::BTreeMap::from([(
            "jwt".to_owned(),
            Vec::new(),
        )])),
        Proofs(std::collections::BTreeMap::from([(
            "jwt".to_owned(),
            vec![json!(42)],
        )])),
    ] {
        assert!(matches!(
            validator
                .validate(
                    &proofs,
                    "wallet-client",
                    "https://issuer.example",
                    "expected-nonce",
                    &metadata,
                )
                .await,
            Err(ProofError::UnsupportedType | ProofError::InvalidSignature)
        ));
    }
}

#[tokio::test]
async fn proof_validator_enforces_jwt_header_key_metadata_and_claim_contracts() {
    let now = Utc::now();
    let (wallet_jwk, wallet_key) = es256_test_key(53);
    let validator = Openid4vcProofValidator::new(json!({"keys": []}))
        .expect("empty trust set is structurally valid");
    let metadata = proof_metadata(None);
    let claims = json!({
        "nonce": "expected-nonce",
        "iat": now.timestamp(),
        "aud": "https://issuer.example",
    });

    let valid = signed_jwt_proof(
        Some(&wallet_jwk),
        &wallet_key,
        &claims,
        Some("openid4vci-proof+jwt"),
        Algorithm::ES256,
        None,
    );
    assert_eq!(
        validate_jwt_proof(&validator, valid.clone(), &metadata)
            .await
            .unwrap()
            .len(),
        1
    );

    let bad_typ = signed_jwt_proof(
        Some(&wallet_jwk),
        &wallet_key,
        &claims,
        Some("JWT"),
        Algorithm::ES256,
        None,
    );
    assert_eq!(
        validate_jwt_proof(&validator, bad_typ, &metadata).await,
        Err(ProofError::UnsupportedType)
    );

    let no_jwk = signed_jwt_proof(
        None,
        &wallet_key,
        &claims,
        Some("openid4vci-proof+jwt"),
        Algorithm::ES256,
        None,
    );
    assert_eq!(
        validate_jwt_proof(&validator, no_jwk, &metadata).await,
        Err(ProofError::InvalidSignature)
    );

    let mut bad_jwk = wallet_jwk.clone();
    bad_jwk["x"] = json!("not-base64");
    let bad_jwk = signed_jwt_proof(
        Some(&bad_jwk),
        &wallet_key,
        &claims,
        Some("openid4vci-proof+jwt"),
        Algorithm::ES256,
        None,
    );
    assert_eq!(
        validate_jwt_proof(&validator, bad_jwk, &metadata).await,
        Err(ProofError::InvalidSignature)
    );

    let mut invalid_claims = claims.clone();
    invalid_claims["nonce"] = json!("wrong-nonce");
    let invalid_nonce = signed_jwt_proof(
        Some(&wallet_jwk),
        &wallet_key,
        &invalid_claims,
        Some("openid4vci-proof+jwt"),
        Algorithm::ES256,
        None,
    );
    assert_eq!(
        validate_jwt_proof(&validator, invalid_nonce, &metadata).await,
        Err(ProofError::InvalidNonce)
    );

    for iat in [
        (now - Duration::minutes(5) - Duration::seconds(1)).timestamp(),
        (now + Duration::seconds(61)).timestamp(),
    ] {
        let stale = json!({
            "nonce": "expected-nonce",
            "iat": iat,
            "aud": "https://issuer.example",
        });
        let stale = signed_jwt_proof(
            Some(&wallet_jwk),
            &wallet_key,
            &stale,
            Some("openid4vci-proof+jwt"),
            Algorithm::ES256,
            None,
        );
        assert_eq!(
            validate_jwt_proof(&validator, stale, &metadata).await,
            Err(ProofError::InvalidNonce)
        );
    }

    let hs = signed_jwt_proof(
        None,
        &EncodingKey::from_secret(b"test-secret"),
        &claims,
        Some("openid4vci-proof+jwt"),
        Algorithm::HS256,
        None,
    );
    assert_eq!(
        validate_jwt_proof(&validator, hs, &metadata).await,
        Err(ProofError::UnsupportedType)
    );
    let unsupported_metadata = nazo_openid4vci::ProofTypeMetadata {
        proof_signing_alg_values_supported: vec!["EdDSA".to_owned()],
        key_attestations_required: None,
    };
    assert_eq!(
        validate_jwt_proof(&validator, valid, &unsupported_metadata).await,
        Err(ProofError::UnsupportedType)
    );
}

#[tokio::test]
async fn proof_validator_binds_required_key_attestation_to_the_jwt_key() {
    let now = Utc::now();
    let (wallet_jwk, wallet_key) = es256_test_key(59);
    let (validator, attestation, _) = key_attestation_fixture(json!({
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
        "attested_keys": [wallet_jwk.clone()],
        "key_storage": ["iso_18045_moderate"],
    }));
    let mut required = std::collections::BTreeMap::new();
    required.insert(
        "key_storage".to_owned(),
        vec!["iso_18045_moderate".to_owned()],
    );
    let metadata = proof_metadata(Some(required));
    let claims = json!({
        "nonce": "expected-nonce",
        "iat": now.timestamp(),
        "aud": "https://issuer.example",
    });
    let proof = signed_jwt_proof(
        Some(&wallet_jwk),
        &wallet_key,
        &claims,
        Some("openid4vci-proof+jwt"),
        Algorithm::ES256,
        Some(&attestation),
    );
    let proofs = Proofs(std::collections::BTreeMap::from([(
        "jwt".to_owned(),
        vec![Value::String(proof)],
    )]));
    let validated = validator
        .validate(
            &proofs,
            "wallet-client",
            "https://issuer.example",
            "expected-nonce",
            &metadata,
        )
        .await
        .expect("matching key attestation");
    assert_eq!(validated.len(), 1);
    assert!(validated[0].key_attestation.is_some());

    let (other_jwk, other_key) = es256_test_key(61);
    let mismatched_proof = signed_jwt_proof(
        Some(&other_jwk),
        &other_key,
        &claims,
        Some("openid4vci-proof+jwt"),
        Algorithm::ES256,
        Some(&attestation),
    );
    let mismatched = Proofs(std::collections::BTreeMap::from([(
        "jwt".to_owned(),
        vec![Value::String(mismatched_proof)],
    )]));
    assert_eq!(
        validator
            .validate(
                &mismatched,
                "wallet-client",
                "https://issuer.example",
                "expected-nonce",
                &metadata,
            )
            .await,
        Err(ProofError::InvalidKeyAttestation)
    );

    let malformed_extension = signed_jwt_proof(
        Some(&wallet_jwk),
        &wallet_key,
        &claims,
        Some("openid4vci-proof+jwt"),
        Algorithm::ES256,
        Some("malformed-attestation"),
    );
    let malformed = Proofs(std::collections::BTreeMap::from([(
        "jwt".to_owned(),
        vec![Value::String(malformed_extension)],
    )]));
    assert_eq!(
        validator
            .validate(
                &malformed,
                "wallet-client",
                "https://issuer.example",
                "expected-nonce",
                &metadata,
            )
            .await,
        Err(ProofError::InvalidKeyAttestation)
    );
}

#[test]
fn key_attestation_validates_header_nonce_expiry_and_component_requirements() {
    let now = Utc::now();
    let (attester_jwk, attester_key) = es256_test_key(67);
    let mut trust_jwk = attester_jwk.clone();
    trust_jwk["kid"] = json!("attester-key");
    trust_jwk["alg"] = json!("ES256");
    let validator = Openid4vcProofValidator::new(json!({"keys": [trust_jwk]}))
        .expect("key attestation validator");
    let attested_key = es256_test_key(71).0;
    let base_claims = json!({
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
        "nonce": "expected-nonce",
        "attested_keys": [attested_key],
        "key_storage": ["iso_18045_moderate"],
    });
    let make = |claims: &Value, typ: &str, kid: Option<&str>, algorithm: Algorithm| {
        let mut header = Header::new(algorithm);
        header.typ = Some(typ.to_owned());
        header.kid = kid.map(ToOwned::to_owned);
        let signing_key = if algorithm == Algorithm::HS256 {
            EncodingKey::from_secret(b"attester-secret")
        } else {
            attester_key.clone()
        };
        encode(&header, claims, &signing_key).expect("attestation JWT")
    };
    let mut required = std::collections::BTreeMap::new();
    required.insert(
        "key_storage".to_owned(),
        vec!["iso_18045_moderate".to_owned()],
    );
    let metadata = proof_metadata(Some(required));
    validate_key_attestation(
        &validator,
        &make(
            &base_claims,
            "key-attestation+jwt",
            Some("attester-key"),
            Algorithm::ES256,
        ),
        "expected-nonce",
        &metadata,
        now,
        KeyAttestationContext::AttestationProof,
    )
    .expect("valid key attestation");

    for (typ, kid, algorithm) in [
        ("JWT", Some("attester-key"), Algorithm::ES256),
        ("key-attestation+jwt", Some("unknown"), Algorithm::ES256),
        (
            "key-attestation+jwt",
            Some("attester-key"),
            Algorithm::HS256,
        ),
    ] {
        assert!(matches!(
            validate_key_attestation(
                &validator,
                &make(&base_claims, typ, kid, algorithm),
                "expected-nonce",
                &metadata,
                now,
                KeyAttestationContext::AttestationProof,
            ),
            Err(ProofError::InvalidKeyAttestation)
        ));
    }

    for claims in [
        json!({"iat": now.timestamp(), "nonce": "expected-nonce", "attested_keys": []}),
        json!({"iat": now.timestamp(), "nonce": "wrong", "attested_keys": [es256_test_key(73).0]}),
        json!({"iat": now.timestamp(), "nonce": "expected-nonce", "attested_keys": [es256_test_key(75).0], "key_storage": ["low"]}),
        json!({"iat": now.timestamp(), "exp": "not-a-time", "attested_keys": [es256_test_key(77).0]}),
    ] {
        assert!(matches!(
            validate_key_attestation(
                &validator,
                &make(
                    &claims,
                    "key-attestation+jwt",
                    Some("attester-key"),
                    Algorithm::ES256
                ),
                "expected-nonce",
                &metadata,
                now,
                KeyAttestationContext::AttestationProof,
            ),
            Err(ProofError::InvalidKeyAttestation)
        ));
    }
}

#[test]
fn client_attestation_configuration_and_unverified_subject_are_strict() {
    let (jwk, key) = es256_test_key(79);
    assert!(Openid4vcClientAttestationValidator::new("", json!({"keys": [jwk]})).is_err());
    assert!(
        Openid4vcClientAttestationValidator::new("https://attester.example", json!({"keys": []}),)
            .is_err()
    );
    for invalid in [
        json!({"kty": "OKP", "crv": "Ed25519", "x": "AQ"}),
        json!({"kty": "EC", "crv": "P-384", "x": "AQ", "y": "Ag"}),
    ] {
        assert!(client_instance_key_thumbprint(&invalid).is_err());
    }

    let compact = signed_client_attestation_jwt(
        &json!({"sub": "wallet-client"}),
        &key,
        "oauth-client-attestation+jwt",
        Algorithm::ES256,
        None,
    );
    assert_eq!(
        Openid4vcClientAttestationValidator::unverified_client_id(&compact).as_deref(),
        Some("wallet-client")
    );
    assert_eq!(
        Openid4vcClientAttestationValidator::unverified_client_id("not-a-jwt"),
        None
    );
    let no_subject = signed_client_attestation_jwt(
        &json!({"sub": ""}),
        &key,
        "oauth-client-attestation+jwt",
        Algorithm::ES256,
        None,
    );
    assert_eq!(
        Openid4vcClientAttestationValidator::unverified_client_id(&no_subject),
        None
    );
}

fn valid_client_attestation_fixture() -> (
    Openid4vcClientAttestationValidator,
    String,
    String,
    Value,
    EncodingKey,
    i64,
) {
    let now = Utc::now().timestamp();
    let (mut attester_jwk, attester_key) = es256_test_key(83);
    attester_jwk["kid"] = json!("attester-key");
    attester_jwk["alg"] = json!("ES256");
    let (instance_jwk, instance_key) = es256_test_key(89);
    let attestation = signed_client_attestation_jwt(
        &json!({
            "iss": "https://attester.example",
            "sub": "wallet-client",
            "exp": now + 600,
            "cnf": {"jwk": instance_jwk.clone()},
        }),
        &attester_key,
        "oauth-client-attestation+jwt",
        Algorithm::ES256,
        Some("attester-key"),
    );
    let proof = signed_client_attestation_jwt(
        &json!({
            "iss": "wallet-client",
            "aud": "https://issuer.example",
            "iat": now,
            "jti": "fresh-proof",
        }),
        &instance_key,
        "oauth-client-attestation-pop+jwt",
        Algorithm::ES256,
        None,
    );
    let validator = Openid4vcClientAttestationValidator::new(
        "https://attester.example",
        json!({"keys": [attester_jwk]}),
    )
    .expect("client attestation validator");
    (
        validator,
        attestation,
        proof,
        instance_jwk,
        instance_key,
        now,
    )
}

#[test]
fn client_attestation_rejects_header_key_claim_and_replay_contract_violations() {
    let (validator, attestation, proof, instance_jwk, instance_key, now) =
        valid_client_attestation_fixture();
    validator
        .validate(&attestation, &proof, "https://issuer.example", now)
        .expect("valid client attestation fixture");

    let (mut attester_jwk, attester_key) = es256_test_key(83);
    attester_jwk["kid"] = json!("attester-key");
    attester_jwk["alg"] = json!("ES256");
    let trust = json!({"keys": [attester_jwk]});
    let instance_claim = json!({"jwk": instance_jwk.clone()});
    let attestation_claims = json!({
        "iss": "https://attester.example",
        "sub": "wallet-client",
        "exp": now + 600,
        "cnf": instance_claim,
    });
    let make_validator = |trust: Value| {
        Openid4vcClientAttestationValidator::new("https://attester.example", trust)
            .expect("validator configuration")
    };

    let wrong_type = signed_client_attestation_jwt(
        &attestation_claims,
        &attester_key,
        "JWT",
        Algorithm::ES256,
        Some("attester-key"),
    );
    assert!(
        make_validator(trust.clone())
            .validate(&wrong_type, &proof, "https://issuer.example", now)
            .is_err()
    );

    let wrong_algorithm = signed_client_attestation_jwt(
        &attestation_claims,
        &EncodingKey::from_secret(b"attester-secret"),
        "oauth-client-attestation+jwt",
        Algorithm::HS256,
        Some("attester-key"),
    );
    assert!(
        make_validator(trust.clone())
            .validate(&wrong_algorithm, &proof, "https://issuer.example", now)
            .is_err()
    );
    let unknown_kid = signed_client_attestation_jwt(
        &attestation_claims,
        &attester_key,
        "oauth-client-attestation+jwt",
        Algorithm::ES256,
        Some("unknown-kid"),
    );
    assert!(
        make_validator(trust.clone())
            .validate(&unknown_kid, &proof, "https://issuer.example", now)
            .is_err()
    );
    let mut ambiguous = trust.clone();
    ambiguous["keys"] = json!([ambiguous["keys"][0].clone(), ambiguous["keys"][0].clone()]);
    assert!(
        make_validator(ambiguous)
            .validate(&attestation, &proof, "https://issuer.example", now)
            .is_err()
    );

    let mut bad_trust_key = trust["keys"][0].clone();
    bad_trust_key["x"] = json!("invalid");
    assert!(
        make_validator(json!({"keys": [bad_trust_key]}))
            .validate(&attestation, &proof, "https://issuer.example", now)
            .is_err()
    );

    for claims in [
        json!({"sub": "wallet-client", "exp": now + 600}),
        json!({"iss": "https://wrong.example", "sub": "wallet-client", "exp": now + 600, "cnf": {"jwk": instance_jwk.clone()}}),
        json!({"iss": "https://attester.example", "sub": "", "exp": now + 600, "cnf": {"jwk": instance_jwk.clone()}}),
        json!({"iss": "https://attester.example", "sub": "wallet-client", "exp": now + 600, "cnf": {}}),
        json!({"iss": "https://attester.example", "sub": "wallet-client", "exp": now + 600, "cnf": {"jwk": {"kty": "RSA"}}}),
    ] {
        let token = signed_client_attestation_jwt(
            &claims,
            &attester_key,
            "oauth-client-attestation+jwt",
            Algorithm::ES256,
            Some("attester-key"),
        );
        assert!(
            validator
                .validate(&token, &proof, "https://issuer.example", now)
                .is_err()
        );
    }

    let future_iat = signed_client_attestation_jwt(
        &json!({
            "iss": "https://attester.example",
            "sub": "wallet-client",
            "iat": now + 61,
            "exp": now + 600,
            "cnf": {"jwk": instance_jwk.clone()},
        }),
        &attester_key,
        "oauth-client-attestation+jwt",
        Algorithm::ES256,
        Some("attester-key"),
    );
    assert!(
        validator
            .validate(&future_iat, &proof, "https://issuer.example", now)
            .is_err()
    );

    let wrong_proof_type = signed_client_attestation_jwt(
        &json!({
            "iss": "wallet-client",
            "aud": "https://issuer.example",
            "iat": now,
            "jti": "fresh-proof",
        }),
        &instance_key,
        "JWT",
        Algorithm::ES256,
        None,
    );
    assert!(
        validator
            .validate(
                &attestation,
                &wrong_proof_type,
                "https://issuer.example",
                now
            )
            .is_err()
    );

    let wrong_proof_algorithm = signed_client_attestation_jwt(
        &json!({
            "iss": "wallet-client",
            "aud": "https://issuer.example",
            "iat": now,
            "jti": "fresh-proof",
        }),
        &EncodingKey::from_secret(b"proof-secret"),
        "oauth-client-attestation-pop+jwt",
        Algorithm::HS256,
        None,
    );
    assert!(
        validator
            .validate(
                &attestation,
                &wrong_proof_algorithm,
                "https://issuer.example",
                now
            )
            .is_err()
    );

    for claims in [
        json!({"iss": "other-client", "aud": "https://issuer.example", "iat": now, "jti": "fresh-proof"}),
        json!({"iss": "wallet-client", "aud": "wrong-audience", "iat": now, "jti": "fresh-proof"}),
        json!({"iss": "wallet-client", "aud": "https://issuer.example", "iat": now, "jti": ""}),
        json!({"iss": "wallet-client", "aud": "https://issuer.example", "iat": now, "jti": "x".repeat(129)}),
        json!({"iss": "wallet-client", "aud": "https://issuer.example", "iat": now - 301, "jti": "fresh-proof"}),
        json!({"iss": "wallet-client", "aud": "https://issuer.example", "iat": now + 61, "jti": "fresh-proof"}),
    ] {
        let token = signed_client_attestation_jwt(
            &claims,
            &instance_key,
            "oauth-client-attestation-pop+jwt",
            Algorithm::ES256,
            None,
        );
        assert!(
            validator
                .validate(&attestation, &token, "https://issuer.example", now)
                .is_err()
        );
    }
}

#[tokio::test]
async fn client_attestation_validate_for_client_uses_static_trust_when_no_conformance_lease_exists()
{
    let (validator, attestation, proof, _, _, now) = valid_client_attestation_fixture();
    let validated = validator
        .validate_for_client(&attestation, &proof, "https://issuer.example", now)
        .await
        .expect("static trust fallback should validate");
    assert_eq!(validated.client_id, "wallet-client");
}

#[tokio::test]
async fn client_attestation_conformance_constructor_and_lookup_fail_closed_without_database() {
    let (mut attester_jwk, attester_key) = es256_test_key(97);
    attester_jwk["kid"] = json!("attester-key");
    attester_jwk["alg"] = json!("ES256");
    let pool = nazo_postgres::create_pool(
        "postgres://openid4vc_conformance:openid4vc_conformance@127.0.0.1:1/oauth".to_owned(),
        1,
    )
    .expect("pool construction should not connect");
    let repository = nazo_postgres::ConformanceLeaseRepository::new(pool.clone());
    let configured = Openid4vcClientAttestationValidator::with_conformance_leases(
        Some((
            "https://attester.example".to_owned(),
            json!({"keys": [attester_jwk.clone()]}),
        )),
        repository,
        uuid::Uuid::nil(),
    )
    .expect("static trust plus conformance repository should configure");
    let now = Utc::now().timestamp();
    let instance_jwk = es256_test_key(101).0;
    let instance_key = es256_test_key(101).1;
    let attestation = signed_client_attestation_jwt(
        &json!({
            "iss": "https://attester.example",
            "sub": "wallet-client",
            "exp": now + 600,
            "cnf": {"jwk": instance_jwk},
        }),
        &attester_key,
        "oauth-client-attestation+jwt",
        Algorithm::ES256,
        Some("attester-key"),
    );
    let proof = signed_client_attestation_jwt(
        &json!({
            "iss": "wallet-client",
            "aud": "https://issuer.example",
            "iat": now,
            "jti": "constructor-proof",
        }),
        &instance_key,
        "oauth-client-attestation-pop+jwt",
        Algorithm::ES256,
        None,
    );
    let validated = configured
        .validate(&attestation, &proof, "https://issuer.example", now)
        .expect("configured static trust must validate a matching attestation");
    assert_eq!(validated.client_id, "wallet-client");

    let dynamic = Openid4vcClientAttestationValidator::with_conformance_leases(
        None,
        nazo_postgres::ConformanceLeaseRepository::new(pool),
        uuid::Uuid::nil(),
    )
    .expect("dynamic conformance-only validator should configure");
    let (static_validator, attestation, proof, _, _, now) = valid_client_attestation_fixture();
    let error = dynamic
        .validate_for_client(&attestation, &proof, "https://issuer.example", now)
        .await
        .expect_err("unavailable conformance database must fail closed");
    assert!(!format!("{error:#}").is_empty());
    let validated = static_validator
        .validate_for_client(&attestation, &proof, "https://issuer.example", now)
        .await
        .expect("static validator should remain observable through its public behavior");
    assert_eq!(validated.client_id, "wallet-client");
}
