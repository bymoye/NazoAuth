use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[test]
fn par_private_key_jwt_endpoint_audiences_require_explicit_client_opt_in() {
    let private_key = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let public_jwk = private_key.public_jwk("client-kid");
    let mut client = private_key_jwt_client(json!({"keys": [public_jwk]}));
    assert!(!client.allow_client_assertion_endpoint_audience);
    let settings = test_settings();
    let req = TestRequest::post().uri("/par").to_http_request();

    let issuer_assertion = signed_client_assertion(
        &client.client_id,
        &settings.endpoint.issuer,
        "client-kid",
        &private_key,
        "par-issuer-audience",
    );
    assert!(
        verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &issuer_assertion)
            .is_ok()
    );

    let endpoint_audiences = [
        (
            format!("{}/token", settings.endpoint.issuer),
            "par-token-audience",
        ),
        (
            format!("{}/par", settings.endpoint.issuer),
            "par-endpoint-audience",
        ),
    ];
    for (audience, jti) in &endpoint_audiences {
        let assertion =
            signed_client_assertion(&client.client_id, audience, "client-kid", &private_key, jti);
        assert!(
            verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &assertion)
                .is_err(),
            "PAR client assertion audience {audience} must require explicit opt-in"
        );
    }

    client.allow_client_assertion_endpoint_audience = true;
    for (index, (audience, _)) in endpoint_audiences.iter().enumerate() {
        let assertion = signed_client_assertion(
            &client.client_id,
            audience,
            "client-kid",
            &private_key,
            &format!("par-opt-in-audience-{index}"),
        );
        assert!(
            verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &assertion)
                .is_ok(),
            "the explicit compatibility policy must admit {audience}"
        );
    }
}

#[test]
fn ciba_backchannel_client_assertion_accepts_token_endpoint_audience_when_allowed() {
    let private_key = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let public_jwk = private_key.public_jwk("client-kid");
    let mut client = private_key_jwt_client(json!({"keys": [public_jwk]}));
    client.allow_client_assertion_endpoint_audience = true;
    let settings = test_settings();
    let req = TestRequest::post().uri("/bc-authorize").to_http_request();
    let assertion = signed_client_assertion(
        &client.client_id,
        &format!("{}/token", settings.endpoint.issuer),
        "client-kid",
        &private_key,
        "ciba-token-audience-jti",
    );

    let result = verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &assertion);

    assert!(result.is_ok());
}

#[test]
fn private_key_jwt_accepts_current_and_previous_jwks_during_rotation() {
    let first = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let second = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let first_jwk = first.public_jwk("kid-1");
    let second_jwk = second.public_jwk("kid-2");
    let client = private_key_jwt_client(json!({"keys": [first_jwk, second_jwk]}));
    let settings = test_settings();
    let req = TestRequest::post().uri("/token").to_http_request();
    let first_assertion = signed_client_assertion(
        &client.client_id,
        &settings.endpoint.issuer,
        "kid-1",
        &first,
        "jti-first",
    );
    let second_assertion = signed_client_assertion(
        &client.client_id,
        &settings.endpoint.issuer,
        "kid-2",
        &second,
        "jti-second",
    );

    assert!(
        verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &first_assertion)
            .is_ok()
    );
    assert!(
        verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &second_assertion)
            .is_ok()
    );
}

#[test]
fn private_key_jwt_accepts_missing_kid_only_for_one_kidless_matching_key() {
    let private_key = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let mut public_jwk = private_key.public_jwk("temporary-kid");
    public_jwk
        .as_object_mut()
        .expect("public JWK should be an object")
        .remove("kid");
    let client = private_key_jwt_client(json!({"keys": [public_jwk]}));
    let settings = test_settings();
    let req = TestRequest::post().uri("/token").to_http_request();
    let assertion = signed_client_assertion_without_kid(
        &client.client_id,
        &settings.endpoint.issuer,
        &private_key,
        "kidless-single-key-jti",
    );

    let result = verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &assertion);

    assert!(result.is_ok());
}

#[test]
fn private_key_jwt_rejects_missing_kid_when_key_selection_is_ambiguous() {
    let first = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let second = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let mut first_jwk = first.public_jwk("first");
    let mut second_jwk = second.public_jwk("second");
    first_jwk
        .as_object_mut()
        .expect("first JWK should be an object")
        .remove("kid");
    second_jwk
        .as_object_mut()
        .expect("second JWK should be an object")
        .remove("kid");
    let client = private_key_jwt_client(json!({"keys": [first_jwk, second_jwk]}));
    let settings = test_settings();
    let req = TestRequest::post().uri("/token").to_http_request();
    let assertion = signed_client_assertion_without_kid(
        &client.client_id,
        &settings.endpoint.issuer,
        &first,
        "kidless-ambiguous-key-jti",
    );

    let result = verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &assertion);

    assert!(matches!(result, Err(ClientAssertionError::Invalid)));
}

#[test]
fn private_key_jwt_rejects_valid_signature_with_wrong_audience() {
    let private_key = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let public_jwk = private_key.public_jwk("client-kid");
    let client = private_key_jwt_client(json!({"keys": [public_jwk]}));
    let settings = test_settings();
    let req = TestRequest::post().uri("/token").to_http_request();
    let assertion = signed_client_assertion(
        &client.client_id,
        "https://attacker.example/token",
        "client-kid",
        &private_key,
        "wrong-audience-jti",
    );

    let result = verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &assertion);

    assert!(matches!(result, Err(ClientAssertionError::Invalid)));
}

#[test]
fn private_key_jwt_rejects_assertions_after_key_retirement() {
    let retired = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let active = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let active_jwk = active.public_jwk("active-kid");
    let client = private_key_jwt_client(json!({"keys": [active_jwk]}));
    let settings = test_settings();
    let req = TestRequest::post().uri("/token").to_http_request();
    let retired_assertion = signed_client_assertion(
        &client.client_id,
        &settings.endpoint.issuer,
        "retired-kid",
        &retired,
        "jti-retired",
    );

    let result =
        verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &retired_assertion);

    assert!(matches!(result, Err(ClientAssertionError::Invalid)));
}

#[test]
fn private_key_jwt_replay_key_is_client_scoped_and_hashed() {
    let first = client_assertion_replay_key("client-1", "assertion-jti");
    let same = client_assertion_replay_key("client-1", "assertion-jti");
    let other_client = client_assertion_replay_key("client-2", "assertion-jti");
    let other_jti = client_assertion_replay_key("client-1", "other-jti");

    assert_eq!(first, same);
    assert!(first.starts_with("oauth:client_assertion:jti:"));
    assert!(!first.contains("client-1"));
    assert!(!first.contains("assertion-jti"));
    assert_ne!(first, other_client);
    assert_ne!(first, other_jti);
}

#[test]
fn private_key_jwt_decode_accepts_small_future_nbf_and_iat() {
    let private_key = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let public_jwk = private_key.public_jwk("client-kid");
    let client = private_key_jwt_client(json!({"keys": [public_jwk]}));
    let settings = test_settings();
    let req = TestRequest::post().uri("/par").to_http_request();
    let now = Utc::now().timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("client-kid".to_owned());
    let assertion = private_key.encode_jwt(
        &header,
        &json!({
            "iss": client.client_id,
            "sub": client.client_id,
            "aud": settings.endpoint.issuer,
            "exp": now + 120,
            "nbf": now + 8,
            "iat": now + 8,
            "jti": "future-client-assertion-jti"
        }),
    );

    let result = verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &assertion);

    assert!(result.is_ok());
}

#[test]
fn client_jwt_algorithm_and_jwk_decoder_fail_closed_for_unsupported_shapes() {
    assert!(client_jwt_algorithm_from_name("HS256").is_none());
    assert!(supported_client_jwt_algorithm(jsonwebtoken::Algorithm::HS256).is_none());

    let mut wrong_alg = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode([1u8; 32]),
        "alg": "RS256",
        "use": "sig"
    });
    assert!(jwt_decoding_key_from_jwk(&wrong_alg, jsonwebtoken::Algorithm::EdDSA).is_none());

    wrong_alg["alg"] = json!("EdDSA");
    wrong_alg["use"] = json!("enc");
    assert!(jwt_decoding_key_from_jwk(&wrong_alg, jsonwebtoken::Algorithm::EdDSA).is_none());

    let private_key_material = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode([1u8; 32]),
        "d": URL_SAFE_NO_PAD.encode([2u8; 32]),
        "alg": "EdDSA",
        "use": "sig"
    });
    assert!(
        jwt_decoding_key_from_jwk(&private_key_material, jsonwebtoken::Algorithm::EdDSA).is_none()
    );

    let short_ed = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode([3u8; 31]),
        "alg": "EdDSA",
        "use": "sig"
    });
    assert!(jwt_decoding_key_from_jwk(&short_ed, jsonwebtoken::Algorithm::EdDSA).is_none());

    let weak_rsa = json!({
        "kty": "RSA",
        "n": URL_SAFE_NO_PAD.encode([4u8; 128]),
        "e": URL_SAFE_NO_PAD.encode([1u8, 0, 1]),
        "alg": "RS256",
        "use": "sig"
    });
    assert!(jwt_decoding_key_from_jwk(&weak_rsa, jsonwebtoken::Algorithm::RS256).is_none());

    let wrong_curve = json!({
        "kty": "EC",
        "crv": "P-384",
        "x": URL_SAFE_NO_PAD.encode([5u8; 32]),
        "y": URL_SAFE_NO_PAD.encode([6u8; 32]),
        "alg": "ES256",
        "use": "sig"
    });
    assert!(jwt_decoding_key_from_jwk(&wrong_curve, jsonwebtoken::Algorithm::ES256).is_none());

    let short_ec_coordinate = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode([7u8; 31]),
        "y": URL_SAFE_NO_PAD.encode([8u8; 32]),
        "alg": "ES256",
        "use": "sig"
    });
    assert!(
        jwt_decoding_key_from_jwk(&short_ec_coordinate, jsonwebtoken::Algorithm::ES256).is_none()
    );

    let unsupported_key_family = json!({"kty": "oct", "k": "secret"});
    assert!(
        jwt_decoding_key_from_jwk(&unsupported_key_family, jsonwebtoken::Algorithm::HS256)
            .is_none()
    );
}
