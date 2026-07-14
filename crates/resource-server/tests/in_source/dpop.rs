use super::fixtures::*;
use super::*;
use crate::dpop::{decode_and_verify_dpop_proof, dpop_jwk_decoding_key, dpop_jwk_thumbprint};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, Header};
use serde_json::json;

#[test]
fn dpop_proof_verifier_produces_verified_sender_context() {
    let fixture = fixture();
    let dpop_fixture = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop_fixture.jkt}}), None);
    let proof_jwt = dpop_proof(
        &dpop_fixture,
        &access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-1",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    let proof = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            &access_token,
        )
        .unwrap();
    let header = dpop(&access_token);
    let verified =
        authorize_resource_request(&fixture.verifier, &[header.as_str()], None, &proof).unwrap();

    assert_eq!(verified.cnf.unwrap().jkt, Some(dpop_fixture.jkt));
}

#[test]
fn dpop_http_authorizer_verifies_proof_and_inserts_extensions() {
    let fixture = fixture();
    let dpop_fixture = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop_fixture.jkt}}), None);
    let proof_jwt = dpop_proof(
        &dpop_fixture,
        &access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-http",
        None,
        None,
    );
    let dpop_verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
    let mut request = http::Request::builder()
        .method("GET")
        .uri("/orders")
        .header(http::header::AUTHORIZATION, dpop(&access_token))
        .header("DPoP", proof_jwt)
        .body(())
        .unwrap();

    let verified = authorize_dpop_http_request(
        &fixture.verifier,
        &dpop_verifier,
        &mut request,
        "https://api.example/orders",
    )
    .unwrap();

    assert_eq!(verified.cnf.unwrap().jkt, Some(dpop_fixture.jkt.clone()));
    assert_eq!(
        request
            .extensions()
            .get::<VerifiedSenderConstraintProof>()
            .unwrap()
            .dpop_jkt,
        Some(dpop_fixture.jkt)
    );
    assert!(request.extensions().get::<VerifiedAccessToken>().is_some());
}

#[test]
fn dpop_authorizer_rejects_invalid_proof_before_token_binding() {
    let fixture = fixture();
    let dpop_fixture = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop_fixture.jkt}}), None);
    let proof_jwt = dpop_proof(
        &dpop_fixture,
        &access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-invalid",
        None,
        Some("wrong-ath"),
    );
    let dpop_verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
    let authorization = dpop(&access_token);

    let error = authorize_dpop_resource_request(
        &fixture.verifier,
        &dpop_verifier,
        &[authorization.as_str()],
        &proof_jwt,
        None,
        "GET",
        "https://api.example/orders",
    )
    .unwrap_err();

    assert_eq!(
        error,
        ResourceServerRequestError::InvalidDpopProof(
            DpopProofVerifierError::AccessTokenHashMismatch
        )
    );
}

#[test]
fn dpop_authorizer_rejects_invalid_token_before_recording_replay() {
    let fixture = fixture();
    let dpop_fixture = dpop_fixture();
    let invalid_access_token = "attacker-controlled-invalid-token";
    let proof_jwt = dpop_proof(
        &dpop_fixture,
        invalid_access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-invalid-token",
        None,
        None,
    );
    let dpop_verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
    let authorization = dpop(invalid_access_token);

    let first_error = authorize_dpop_resource_request(
        &fixture.verifier,
        &dpop_verifier,
        &[authorization.as_str()],
        &proof_jwt,
        None,
        "GET",
        "https://api.example/orders",
    )
    .unwrap_err();
    let second_error = authorize_dpop_resource_request(
        &fixture.verifier,
        &dpop_verifier,
        &[authorization.as_str()],
        &proof_jwt,
        None,
        "GET",
        "https://api.example/orders",
    )
    .unwrap_err();

    assert_eq!(
        first_error,
        ResourceServerRequestError::InvalidToken(ResourceServerVerifierError::InvalidToken)
    );
    assert_eq!(second_error, first_error);
}

#[test]
fn dpop_proof_verifier_rejects_replayed_jti() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let proof_jwt = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-replay",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap();
    let error = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::ReplayDetected);
}

#[test]
fn dpop_proof_verifier_fails_closed_when_replay_cache_is_full() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let first = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-cache-1",
        None,
        None,
    );
    let second = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-cache-2",
        None,
        None,
    );
    let verifier =
        DpopProofVerifier::new_with_replay_cache_limit(DpopProofVerifierConfig::default(), 1);

    verifier
        .verify(&first, "GET", "https://api.example/orders", access_token)
        .unwrap();
    let replay = verifier
        .verify(&first, "GET", "https://api.example/orders", access_token)
        .unwrap_err();
    let full = verifier
        .verify(&second, "GET", "https://api.example/orders", access_token)
        .unwrap_err();

    assert_eq!(replay, DpopProofVerifierError::ReplayDetected);
    assert_eq!(full, DpopProofVerifierError::ReplayCacheFull);
}

#[test]
fn dpop_proof_verifier_rejects_wrong_ath() {
    let dpop = dpop_fixture();
    let proof_jwt = dpop_proof(
        &dpop,
        "access-token",
        "GET",
        "https://api.example/orders",
        "proof-jti-ath",
        None,
        Some("wrong-ath"),
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    let error = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            "access-token",
        )
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::AccessTokenHashMismatch);
}

#[test]
fn dpop_proof_verifier_rejects_wrong_method_and_uri() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let proof_jwt = dpop_proof(
        &dpop,
        access_token,
        "POST",
        "https://api.example/orders",
        "proof-jti-method-uri",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    let wrong_method = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap_err();
    let wrong_uri = verifier
        .verify(
            &proof_jwt,
            "POST",
            "https://api.example/other",
            access_token,
        )
        .unwrap_err();

    assert_eq!(wrong_method, DpopProofVerifierError::MethodMismatch);
    assert_eq!(wrong_uri, DpopProofVerifierError::UriMismatch);
}

#[test]
fn dpop_htu_normalizes_both_proof_and_configured_target() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let proof_jwt = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "HTTPS://API.EXAMPLE:443/orders?claim=value#fragment",
        "proof-jti-normalized-htu",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://Api.Example:443/orders?configured=value#ignored",
            access_token,
        )
        .expect("scheme/host case, default ports, query, and fragment are normalized");
}

#[test]
fn dpop_htu_rejects_an_invalid_configured_target() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let proof_jwt = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-invalid-configured-target",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    assert_eq!(
        verifier
            .verify(&proof_jwt, "GET", "not an absolute URI", access_token)
            .unwrap_err(),
        DpopProofVerifierError::UriMismatch
    );
}

#[test]
fn dpop_proof_verifier_rejects_empty_jti() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let proof_jwt = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        " ",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    let error = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::MissingJti);
}

#[test]
fn dpop_proof_verifier_rejects_expired_and_future_iat() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let expired = signed_dpop_proof_with_overrides(
        &dpop,
        access_token,
        json!({"iat": Utc::now().timestamp() - 10, "jti": "expired-jti"}),
        None,
    );
    let future = signed_dpop_proof_with_overrides(
        &dpop,
        access_token,
        json!({"iat": Utc::now().timestamp() + 10, "jti": "future-jti"}),
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig {
        clock_skew_seconds: 0,
        max_age_seconds: 1,
        ..DpopProofVerifierConfig::default()
    });

    let expired_error = verifier
        .verify(&expired, "GET", "https://api.example/orders", access_token)
        .unwrap_err();
    let future_error = verifier
        .verify(&future, "GET", "https://api.example/orders", access_token)
        .unwrap_err();

    assert_eq!(expired_error, DpopProofVerifierError::Expired);
    assert_eq!(future_error, DpopProofVerifierError::NotYetValid);
}

#[test]
fn dpop_proof_verifier_rejects_wrong_type_and_unsupported_algorithm() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let wrong_type = signed_dpop_proof_with_overrides(
        &dpop,
        access_token,
        json!({"jti": "wrong-type"}),
        Some({
            let mut header = Header::new(Algorithm::RS256);
            header.typ = Some("JWT".to_owned());
            header.jwk = Some(dpop.public_jwk.clone());
            header
        }),
    );
    let unsupported_alg = DpopProofVerifier::new(DpopProofVerifierConfig {
        allowed_algs: vec![Algorithm::PS256],
        ..DpopProofVerifierConfig::default()
    });
    let valid_rs256 = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "unsupported-alg",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    assert_eq!(
        verifier
            .verify(
                &wrong_type,
                "GET",
                "https://api.example/orders",
                access_token
            )
            .unwrap_err(),
        DpopProofVerifierError::WrongType
    );
    assert_eq!(
        unsupported_alg
            .verify(
                &valid_rs256,
                "GET",
                "https://api.example/orders",
                access_token
            )
            .unwrap_err(),
        DpopProofVerifierError::UnsupportedAlgorithm
    );
}

#[test]
fn dpop_proof_verifier_rejects_missing_or_private_header_jwk() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let missing_jwk = signed_dpop_proof_with_overrides(
        &dpop,
        access_token,
        json!({"jti": "missing-jwk"}),
        Some({
            let mut header = Header::new(Algorithm::RS256);
            header.typ = Some("dpop+jwt".to_owned());
            header
        }),
    );
    assert_eq!(
        DpopProofVerifier::new(DpopProofVerifierConfig::default())
            .verify(
                &missing_jwk,
                "GET",
                "https://api.example/orders",
                access_token
            )
            .unwrap_err(),
        DpopProofVerifierError::MissingPublicJwk
    );
    for private_member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let mut private_jwk = serde_json::to_value(&dpop.public_jwk).unwrap();
        private_jwk[private_member] = json!("private-material");
        let proof = signed_dpop_proof_with_raw_jwk(&dpop, access_token, &private_jwk);

        assert_eq!(
            DpopProofVerifier::new(DpopProofVerifierConfig::default())
                .verify(&proof, "GET", "https://api.example/orders", access_token)
                .unwrap_err(),
            DpopProofVerifierError::InvalidPublicJwk,
            "private JWK member {private_member} must be rejected before typed decoding"
        );
        assert!(dpop_jwk_decoding_key(&private_jwk, Algorithm::RS256).is_none());
    }
}

#[test]
fn dpop_public_jwk_decoder_rejects_algorithm_use_and_shape_mismatches() {
    let fixture = dpop_fixture();
    let rsa = serde_json::to_value(&fixture.public_jwk).unwrap();

    let mut wrong_alg = rsa.clone();
    wrong_alg["alg"] = json!("ES256");
    assert!(dpop_jwk_decoding_key(&wrong_alg, Algorithm::RS256).is_none());

    let mut encryption_use = rsa.clone();
    encryption_use["use"] = json!("enc");
    assert!(dpop_jwk_decoding_key(&encryption_use, Algorithm::RS256).is_none());

    let mut short_modulus = rsa.clone();
    short_modulus["n"] = json!("AQID");
    assert!(dpop_jwk_decoding_key(&short_modulus, Algorithm::RS256).is_none());

    let mut missing_exponent = rsa.clone();
    missing_exponent.as_object_mut().unwrap().remove("e");
    assert!(dpop_jwk_decoding_key(&missing_exponent, Algorithm::RS256).is_none());

    assert!(dpop_jwk_decoding_key(&json!({"kty":"oct","k":"secret"}), Algorithm::RS256).is_none());

    let ed_jwk = json!({
        "kty": "OKP",
        "crv": "X25519",
        "x": URL_SAFE_NO_PAD.encode([1u8; 32]),
        "alg": "EdDSA",
        "use": "sig"
    });
    assert!(dpop_jwk_decoding_key(&ed_jwk, Algorithm::EdDSA).is_none());

    let short_ed_jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode([1u8; 31]),
        "alg": "EdDSA",
        "use": "sig"
    });
    assert!(dpop_jwk_decoding_key(&short_ed_jwk, Algorithm::EdDSA).is_none());

    let mut wrong_ec_curve = p256_public_jwk();
    wrong_ec_curve["crv"] = json!("P-384");
    assert!(dpop_jwk_decoding_key(&wrong_ec_curve, Algorithm::ES256).is_none());

    let short_ec = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode([1u8; 31]),
        "y": URL_SAFE_NO_PAD.encode([2u8; 32]),
        "alg": "ES256",
        "use": "sig"
    });
    assert!(dpop_jwk_decoding_key(&short_ec, Algorithm::ES256).is_none());

    assert!(dpop_jwk_decoding_key(&json!({"kty":"EC"}), Algorithm::PS256).is_none());
}

#[test]
fn dpop_public_jwk_decoder_accepts_supported_public_key_families() {
    let ed_seed = [7u8; 32];
    let ed_public = ed25519_dalek::SigningKey::from_bytes(&ed_seed)
        .verifying_key()
        .to_bytes();
    let ed_jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(ed_public),
        "use": "sig",
        "alg": "EdDSA"
    });
    assert!(dpop_jwk_decoding_key(&ed_jwk, Algorithm::EdDSA).is_some());

    let ec_jwk = p256_public_jwk();
    assert!(dpop_jwk_decoding_key(&ec_jwk, Algorithm::ES256).is_some());
}

#[test]
fn dpop_jwk_thumbprint_is_defined_only_for_supported_public_jwk_members() {
    let fixture = dpop_fixture();
    let rsa = serde_json::to_value(&fixture.public_jwk).unwrap();
    assert!(dpop_jwk_thumbprint(&rsa).is_some());

    let mut missing_modulus = rsa.clone();
    missing_modulus.as_object_mut().unwrap().remove("n");
    assert!(dpop_jwk_thumbprint(&missing_modulus).is_none());

    assert!(dpop_jwk_thumbprint(&json!({"kty":"oct","k":"secret"})).is_none());
    assert!(dpop_jwk_thumbprint(&json!({"kty":"EC","crv":"P-256","x":"x-only"})).is_none());
}

#[test]
fn dpop_jwk_thumbprint_covers_ec_okp_and_rsa_public_members_only() {
    let rsa = serde_json::to_value(&dpop_fixture().public_jwk).unwrap();
    let ed = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes())
    });
    let ec = p256_public_jwk();

    assert!(dpop_jwk_thumbprint(&rsa).is_some());
    assert!(dpop_jwk_thumbprint(&ed).is_some());
    assert!(dpop_jwk_thumbprint(&ec).is_some());
}

fn p256_public_jwk() -> serde_json::Value {
    use p256::elliptic_curve::{Generate, sec1::ToSec1Point};

    let secret_key = p256::SecretKey::generate();
    let public_key = secret_key.public_key();
    let point = public_key.to_sec1_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x coordinate")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y coordinate")),
        "use": "sig",
        "alg": "ES256"
    })
}

#[test]
fn dpop_proof_verifier_rejects_invalid_signature() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let mut proof = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "invalid-signature",
        None,
        None,
    );
    proof.push('x');
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    let error = verifier
        .verify(&proof, "GET", "https://api.example/orders", access_token)
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::InvalidSignature);
}

#[test]
fn dpop_proof_verifier_rejects_malformed_compact_jwt_parts() {
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
    for proof in [
        "",
        ".payload.signature",
        "header..signature",
        "header.payload.",
        "header.payload.signature.extra",
    ] {
        let error = verifier
            .verify(proof, "GET", "https://api.example/orders", "access-token")
            .unwrap_err();
        assert_eq!(error, DpopProofVerifierError::MalformedProof);
    }
}

#[test]
fn dpop_low_level_decoder_rejects_malformed_compact_jws_parts() {
    let dpop = dpop_fixture();
    let key = dpop_jwk_decoding_key(
        &serde_json::to_value(&dpop.public_jwk).unwrap(),
        Algorithm::RS256,
    )
    .expect("fixture JWK should decode");

    for proof in [
        ".payload.signature",
        "header..signature",
        "header.payload.",
        "header.payload.signature.extra",
    ] {
        let error = decode_and_verify_dpop_proof(proof, &key, Algorithm::RS256)
            .expect_err("malformed compact JWS must fail closed");
        assert_eq!(error, DpopProofVerifierError::MalformedProof);
    }
}

#[test]
fn dpop_low_level_decoder_rejects_valid_compact_jws_with_wrong_key() {
    let signer = dpop_fixture();
    let verifier_key_source = dpop_fixture();
    let proof = dpop_proof(
        &signer,
        "access-token",
        "GET",
        "https://api.example/orders",
        "wrong-key-signature",
        None,
        None,
    );
    let key = dpop_jwk_decoding_key(
        &serde_json::to_value(&verifier_key_source.public_jwk).unwrap(),
        Algorithm::RS256,
    )
    .expect("fixture JWK should decode");

    let error = decode_and_verify_dpop_proof(&proof, &key, Algorithm::RS256)
        .expect_err("JWS signed by another key must fail signature validation");

    assert_eq!(error, DpopProofVerifierError::InvalidSignature);
}

#[test]
fn dpop_proof_verifier_enforces_required_nonce() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let proof_jwt = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-nonce",
        Some("nonce-1"),
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig {
        required_nonce: Some("nonce-1".to_owned()),
        ..DpopProofVerifierConfig::default()
    });

    verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap();

    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig {
        required_nonce: Some("nonce-2".to_owned()),
        ..DpopProofVerifierConfig::default()
    });
    let error = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::NonceMismatch);
}

fn signed_dpop_proof_with_overrides(
    fixture: &DpopFixture,
    access_token: &str,
    overrides: serde_json::Value,
    header: Option<Header>,
) -> String {
    let mut claims = json!({
        "htu": "https://api.example/orders",
        "htm": "GET",
        "iat": Utc::now().timestamp(),
        "jti": "proof-jti-overrides",
        "ath": access_token_hash(access_token),
    });
    merge_object(&mut claims, overrides);
    let header = header.unwrap_or_else(|| {
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("dpop+jwt".to_owned());
        header.jwk = Some(fixture.public_jwk.clone());
        header
    });
    jsonwebtoken::encode(&header, &claims, &fixture.encoding_key).unwrap()
}

fn signed_dpop_proof_with_raw_jwk(
    fixture: &DpopFixture,
    access_token: &str,
    jwk: &serde_json::Value,
) -> String {
    let header = json!({
        "alg": "RS256",
        "typ": "dpop+jwt",
        "jwk": jwk,
    });
    let claims = json!({
        "htu": "https://api.example/orders",
        "htm": "GET",
        "iat": Utc::now().timestamp(),
        "jti": "private-header-jwk",
        "ath": access_token_hash(access_token),
    });
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = jsonwebtoken::crypto::sign(
        signing_input.as_bytes(),
        &fixture.encoding_key,
        Algorithm::RS256,
    )
    .unwrap();
    format!("{signing_input}.{signature}")
}
