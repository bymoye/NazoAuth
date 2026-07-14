use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

const NOW: i64 = 1_700_000_000;
const PRIVATE_KEY: [u8; 32] = [7; 32];

fn proof(header_jwk: Value, claim_overrides: Value) -> String {
    proof_with_type(header_jwk, "dpop+jwt", claim_overrides)
}

fn proof_with_type(header_jwk: Value, typ: &str, claim_overrides: Value) -> String {
    let mut claims = json!({
        "htm": "POST",
        "htu": "https://issuer.example/token",
        "iat": NOW,
        "jti": "proof-jti"
    });
    for (key, value) in claim_overrides.as_object().expect("claim overrides object") {
        claims[key] = value.clone();
    }
    let header = json!({"typ": typ, "alg": "EdDSA", "jwk": header_jwk});
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = SigningKey::from_bytes(&PRIVATE_KEY).sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn public_jwk() -> Value {
    let x = URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&PRIVATE_KEY)
            .verifying_key()
            .to_bytes(),
    );
    json!({"kty": "OKP", "crv": "Ed25519", "x": x})
}

fn request<'a>(proof: Option<&'a str>, expected_jkt: Option<&'a str>) -> DpopProofRequest<'a> {
    DpopProofRequest {
        proof,
        method: "POST",
        target_uris: &["https://issuer.example/token"],
        access_token: None,
        expected_jkt,
    }
}

#[test]
fn verifies_public_jwk_and_protocol_claims() {
    let proof = proof(public_jwk(), json!({}));
    let verified = verify_dpop_proof_at(request(Some(&proof), None), NOW)
        .expect("valid proof")
        .expect("proof present");

    assert_eq!(verified.jti, "proof-jti");
    assert_eq!(verified.jkt.len(), 43);
    assert_eq!(verified.audit.jti_hash.len(), 64);
}

#[test]
fn rejects_private_or_mislabelled_jwk_material() {
    let public = public_jwk();
    let x = public["x"].as_str().expect("public x");
    let private = URL_SAFE_NO_PAD.encode(PRIVATE_KEY);
    let cases = [
        json!({"kty": "OKP", "crv": "Ed25519", "x": x, "d": private}),
        json!({"kty": "OKP", "crv": "Ed25519", "x": x, "alg": "ES256"}),
        json!({"kty": "OKP", "crv": "Ed25519", "x": x, "use": "enc"}),
        json!({"kty": "OKP", "crv": "Ed25519", "x": x, "key_ops": ["sign"]}),
        json!({"kty": "OKP", "crv": "Ed25519", "x": x, "key_ops": ["verify", "sign"]}),
    ];

    for jwk in cases {
        let proof = proof(jwk, json!({}));
        assert_eq!(
            verify_dpop_proof_at(request(Some(&proof), None), NOW),
            Err(DpopError::InvalidProof)
        );
    }
}

#[test]
fn rejects_wrong_type_algorithm_curve_segments_and_signature() {
    let wrong_type = proof_with_type(public_jwk(), "JWT", json!({}));
    assert_eq!(
        DpopProofVerifier.verify_at(request(Some(&wrong_type), None), NOW),
        Err(DpopError::InvalidProof)
    );
    assert_eq!(dpop_algorithm("RS256"), None);
    assert_eq!(dpop_algorithm("PS256"), None);

    let mut wrong_curve = public_jwk();
    wrong_curve["crv"] = json!("X25519");
    let wrong_curve = proof(wrong_curve, json!({}));
    assert_eq!(
        DpopProofVerifier.verify_at(request(Some(&wrong_curve), None), NOW),
        Err(DpopError::InvalidProof)
    );

    let valid = proof(public_jwk(), json!({}));
    let extra_segment = format!("{valid}.extra");
    assert_eq!(
        DpopProofVerifier.verify_at(request(Some(&extra_segment), None), NOW),
        Err(DpopError::MalformedProof)
    );
    let mut invalid_signature = valid.into_bytes();
    let last = invalid_signature.last_mut().expect("signature byte");
    *last = if *last == b'A' { b'B' } else { b'A' };
    let invalid_signature = String::from_utf8(invalid_signature).expect("JWT ASCII");
    assert!(matches!(
        DpopProofVerifier.verify_at(request(Some(&invalid_signature), None), NOW),
        Err(DpopError::InvalidProof | DpopError::MalformedProof)
    ));
}

#[test]
fn enforces_htu_htm_iat_jti_and_ath() {
    let token = "access-token";
    let valid_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
    let cases = [
        json!({"htu": "https://issuer.example/other"}),
        json!({"htm": "GET"}),
        json!({"iat": NOW - DPOP_REPLAY_TTL_SECONDS as i64 - 1}),
        json!({"iat": NOW + DPOP_CLOCK_SKEW_SECONDS + 1}),
        json!({"jti": " "}),
        json!({"ath": "wrong"}),
    ];

    for overrides in cases {
        let proof = proof(public_jwk(), overrides);
        let mut request = request(Some(&proof), None);
        request.access_token = Some(token);
        assert_eq!(
            verify_dpop_proof_at(request, NOW),
            Err(DpopError::InvalidProof)
        );
    }

    let proof = proof(public_jwk(), json!({"ath": valid_ath}));
    let mut request = request(Some(&proof), None);
    request.access_token = Some(token);
    assert!(verify_dpop_proof_at(request, NOW).is_ok());
}

#[test]
fn htu_ignores_query_and_fragment_but_not_origin() {
    let proof_with_query = proof(
        public_jwk(),
        json!({"htu": "https://issuer.example/token?ignored=true#fragment"}),
    );
    assert!(verify_dpop_proof_at(request(Some(&proof_with_query), None), NOW).is_ok());

    let wrong_origin_proof = proof(
        public_jwk(),
        json!({"htu": "https://attacker.example/token"}),
    );
    assert_eq!(
        verify_dpop_proof_at(request(Some(&wrong_origin_proof), None), NOW),
        Err(DpopError::InvalidProof)
    );
}

#[test]
fn htu_normalizes_claim_and_configured_target_equivalently() {
    let proof = proof(public_jwk(), json!({}));
    let targets = ["HTTPS://ISSUER.EXAMPLE:443/token?ignored=true#fragment"];
    let request = DpopProofRequest {
        proof: Some(&proof),
        method: "POST",
        target_uris: &targets,
        access_token: None,
        expected_jkt: None,
    };
    assert!(DpopProofVerifier.verify_at(request, NOW).is_ok());

    let invalid_targets = ["not an endpoint URI"];
    let request = DpopProofRequest {
        target_uris: &invalid_targets,
        ..request
    };
    assert_eq!(
        DpopProofVerifier.verify_at(request, NOW),
        Err(DpopError::MalformedProof)
    );
}

#[test]
fn accepts_an_explicit_alternate_mtls_endpoint_target() {
    let proof = proof(public_jwk(), json!({"htu": "https://mtls.example/token"}));
    let targets = ["https://issuer.example/token", "https://mtls.example/token"];
    let request = DpopProofRequest {
        proof: Some(&proof),
        method: "POST",
        target_uris: &targets,
        access_token: None,
        expected_jkt: None,
    };
    assert!(DpopProofVerifier.verify_at(request, NOW).is_ok());
}

#[test]
fn binding_and_missing_proof_are_enforced() {
    assert_eq!(
        verify_dpop_proof_at(request(None, Some("expected-jkt")), NOW),
        Err(DpopError::MissingProof)
    );
    assert!(
        verify_dpop_proof_at(request(None, None), NOW)
            .expect("optional proof")
            .is_none()
    );

    let proof = proof(public_jwk(), json!({}));
    assert_eq!(
        verify_dpop_proof_at(request(Some(&proof), Some("wrong-jkt")), NOW),
        Err(DpopError::BindingMismatch)
    );
}

#[test]
fn nonce_has_256_bits_of_urlsafe_entropy() {
    let nonce = new_dpop_nonce();
    assert_eq!(URL_SAFE_NO_PAD.decode(nonce).expect("base64url").len(), 32);
}

#[test]
fn constant_time_comparison_preserves_equality_semantics() {
    assert!(constant_time_eq(b"same", b"same"));
    assert!(!constant_time_eq(b"same", b"diff"));
    assert!(!constant_time_eq(b"short", b"longer"));
}

#[test]
fn rejects_oversized_raw_jti_even_when_trimmed_payload_is_short() {
    let oversized = format!("{}x{}", " ".repeat(128), " ".repeat(128));
    let proof = proof(public_jwk(), json!({"jti": oversized}));

    assert_eq!(
        DpopProofVerifier.verify_at(request(Some(&proof), None), NOW),
        Err(DpopError::InvalidProof)
    );
}

#[derive(Clone, Default)]
struct AtomicDpopState {
    replay: Arc<Mutex<HashSet<String>>>,
    nonces: Arc<Mutex<HashSet<String>>>,
    unavailable: bool,
}

impl DpopStateStorePort for AtomicDpopState {
    fn consume_replay<'a>(
        &'a self,
        jkt: &'a str,
        jti: &'a str,
        _ttl_seconds: u64,
    ) -> DpopStateFuture<'a, bool> {
        Box::pin(async move {
            if self.unavailable {
                return Err(DpopStateStoreError);
            }
            Ok(self
                .replay
                .lock()
                .expect("replay lock")
                .insert(format!("{jkt}:{jti}")))
        })
    }

    fn issue_nonce<'a>(&'a self, nonce: &'a str, _ttl_seconds: u64) -> DpopStateFuture<'a, ()> {
        Box::pin(async move {
            if self.unavailable {
                return Err(DpopStateStoreError);
            }
            self.nonces
                .lock()
                .expect("nonce lock")
                .insert(nonce.to_owned());
            Ok(())
        })
    }

    fn consume_nonce<'a>(&'a self, nonce: &'a str) -> DpopStateFuture<'a, bool> {
        Box::pin(async move {
            if self.unavailable {
                return Err(DpopStateStoreError);
            }
            Ok(self.nonces.lock().expect("nonce lock").remove(nonce))
        })
    }
}

#[test]
fn concurrent_replay_consumption_has_exactly_one_winner() {
    futures_executor::block_on(concurrent_replay_consumption_has_exactly_one_winner_async());
}

async fn concurrent_replay_consumption_has_exactly_one_winner_async() {
    let state = AtomicDpopState::default();
    let proof = proof(public_jwk(), json!({}));
    let request = request(Some(&proof), None);

    let (left, right) = futures_util::join!(
        validate_authorization_server_dpop_at(&state, request, DpopNoncePolicy::Optional, NOW),
        validate_authorization_server_dpop_at(&state, request, DpopNoncePolicy::Optional, NOW)
    );
    let results = [left, right];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(DpopError::ReplayDetected(_))))
            .count(),
        1
    );
}

#[test]
fn required_nonce_is_issued_and_atomically_consumed() {
    futures_executor::block_on(required_nonce_is_issued_and_atomically_consumed_async());
}

async fn required_nonce_is_issued_and_atomically_consumed_async() {
    let state = AtomicDpopState::default();
    let proof_without_nonce = proof(public_jwk(), json!({}));
    let challenge = validate_authorization_server_dpop_at(
        &state,
        request(Some(&proof_without_nonce), None),
        DpopNoncePolicy::Required,
        NOW,
    )
    .await
    .expect_err("missing nonce must challenge");
    let DpopError::UseNonce(nonce) = challenge else {
        panic!("missing nonce must return use_dpop_nonce");
    };

    let proof_with_nonce = proof(public_jwk(), json!({"nonce": nonce}));
    validate_authorization_server_dpop_at(
        &state,
        request(Some(&proof_with_nonce), None),
        DpopNoncePolicy::Required,
        NOW,
    )
    .await
    .expect("issued nonce is accepted once");
    assert!(matches!(
        validate_authorization_server_dpop_at(
            &state,
            request(Some(&proof_with_nonce), None),
            DpopNoncePolicy::Required,
            NOW,
        )
        .await,
        Err(DpopError::UseNonce(_))
    ));
}

#[test]
fn state_failures_are_fail_closed_with_compatible_error_categories() {
    futures_executor::block_on(
        state_failures_are_fail_closed_with_compatible_error_categories_async(),
    );
}

async fn state_failures_are_fail_closed_with_compatible_error_categories_async() {
    let state = AtomicDpopState {
        unavailable: true,
        ..AtomicDpopState::default()
    };
    let proof_with_nonce = proof(public_jwk(), json!({"nonce": "nonce"}));
    assert_eq!(
        validate_authorization_server_dpop_at(
            &state,
            request(Some(&proof_with_nonce), None),
            DpopNoncePolicy::Required,
            NOW,
        )
        .await,
        Err(DpopError::NonceStoreUnavailable)
    );

    let proof_without_nonce = proof(public_jwk(), json!({}));
    assert_eq!(
        validate_authorization_server_dpop_at(
            &state,
            request(Some(&proof_without_nonce), None),
            DpopNoncePolicy::Optional,
            NOW,
        )
        .await,
        Err(DpopError::InvalidProof)
    );
}
