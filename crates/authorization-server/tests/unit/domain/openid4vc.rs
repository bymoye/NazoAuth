use super::*;
use jsonwebtoken::{EncodingKey, Header, encode};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use p256::pkcs8::EncodePrivateKey;

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

#[test]
fn key_attestation_rejects_missing_issued_at() {
    let now = Utc::now();
    let (validator, encoded, metadata) = key_attestation_fixture(json!({
        "nonce": "expected-nonce",
        "exp": now.timestamp() + 300,
        "attested_keys": [es256_test_key(17).0],
    }));

    assert!(matches!(
        validator.validate_key_attestation(
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
            validator.validate_key_attestation(
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
        validator.validate_key_attestation(
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

    validator
        .validate_key_attestation(
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
        validator.validate_key_attestation(
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
        validator.validate_key_attestation(
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

    validator
        .validate_key_attestation(
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
