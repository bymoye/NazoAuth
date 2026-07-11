use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

#[test]
fn par_client_assertion_accepts_only_issuer_audience() {
    let expected = client_assertion_audience_candidates("https://issuer.example", "/par", false);

    assert!(audience_matches(
        &json!("https://issuer.example"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!("https://issuer.example/par"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!("https://issuer.example/token"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!(["https://issuer.example", "https://unexpected.example"]),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!("https://issuer.example/authorize"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!(["https://unexpected.example"]),
        &expected,
        false
    ));
}

#[test]
fn par_client_assertion_endpoint_audiences_require_client_policy() {
    let expected = client_assertion_audience_candidates("https://issuer.example", "/par", true);

    assert!(audience_matches(
        &json!("https://issuer.example"),
        &expected,
        false
    ));
    assert!(audience_matches(
        &json!("https://issuer.example/par"),
        &expected,
        false
    ));
    assert!(audience_matches(
        &json!("https://issuer.example/token"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!("https://issuer.example/authorize"),
        &expected,
        false
    ));
}

#[test]
fn client_assertion_audience_arrays_require_explicit_client_policy() {
    let expected = client_assertion_audience_candidates("https://issuer.example", "/par", false);

    assert!(audience_matches(
        &json!(["https://issuer.example", "https://unexpected.example"]),
        &expected,
        true
    ));
    assert!(!audience_matches(
        &json!(["https://issuer.example", "https://unexpected.example"]),
        &expected,
        false
    ));
}

#[test]
fn token_client_assertion_accepts_issuer_and_token_endpoint_audience() {
    let expected = client_assertion_audience_candidates("https://issuer.example", "/token", false);

    assert!(audience_matches(
        &json!("https://issuer.example"),
        &expected,
        false
    ));
    assert!(audience_matches(
        &json!("https://issuer.example/token"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!("https://issuer.example/par"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!(["https://issuer.example", "https://unexpected.example"]),
        &expected,
        false
    ));
    assert!(audience_matches(
        &json!(["https://issuer.example", "https://unexpected.example"]),
        &expected,
        true
    ));
    assert!(!audience_matches(
        &json!(["https://unexpected.example"]),
        &expected,
        true
    ));
}

#[test]
fn ciba_backchannel_client_assertion_accepts_token_endpoint_audience_when_allowed() {
    let private_key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let public_jwk =
        public_jwk_from_private_der("client-kid", jsonwebtoken::Algorithm::RS256, &private_key)
            .expect("client jwk should derive");
    let mut client = private_key_jwt_client(json!({"keys": [public_jwk]}));
    client.allow_client_assertion_endpoint_audience = true;
    let settings = test_settings();
    let req = TestRequest::post().uri("/bc-authorize").to_http_request();
    let assertion = signed_client_assertion(
        &client.client_id,
        &format!("{}/token", settings.issuer),
        "client-kid",
        &private_key,
        "ciba-token-audience-jti",
    );

    let result = verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &assertion);

    assert!(result.is_ok());
}

#[test]
fn ciba_backchannel_client_assertion_rejects_token_endpoint_audience_when_not_allowed() {
    let expected =
        client_assertion_audience_candidates("https://issuer.example", "/bc-authorize", false);

    assert!(audience_matches(
        &json!("https://issuer.example"),
        &expected,
        false
    ));
    assert!(audience_matches(
        &json!("https://issuer.example/bc-authorize"),
        &expected,
        false
    ));
    assert!(!audience_matches(
        &json!("https://issuer.example/token"),
        &expected,
        false
    ));
}

#[test]
fn private_key_jwt_accepts_current_and_previous_jwks_during_rotation() {
    let first = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("first key should generate")
        .private_pkcs8_der;
    let second = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("second key should generate")
        .private_pkcs8_der;
    let first_jwk = public_jwk_from_private_der("kid-1", jsonwebtoken::Algorithm::RS256, &first)
        .expect("first jwk should derive");
    let second_jwk = public_jwk_from_private_der("kid-2", jsonwebtoken::Algorithm::RS256, &second)
        .expect("second jwk should derive");
    let client = private_key_jwt_client(json!({"keys": [first_jwk, second_jwk]}));
    let settings = test_settings();
    let req = TestRequest::post().uri("/token").to_http_request();
    let first_assertion = signed_client_assertion(
        &client.client_id,
        &settings.issuer,
        "kid-1",
        &first,
        "jti-first",
    );
    let second_assertion = signed_client_assertion(
        &client.client_id,
        &settings.issuer,
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
    let private_key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let mut public_jwk = public_jwk_from_private_der(
        "temporary-kid",
        jsonwebtoken::Algorithm::RS256,
        &private_key,
    )
    .expect("client jwk should derive");
    public_jwk
        .as_object_mut()
        .expect("public JWK should be an object")
        .remove("kid");
    let client = private_key_jwt_client(json!({"keys": [public_jwk]}));
    let settings = test_settings();
    let req = TestRequest::post().uri("/token").to_http_request();
    let assertion = signed_client_assertion_without_kid(
        &client.client_id,
        &settings.issuer,
        &private_key,
        "kidless-single-key-jti",
    );

    let result = verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &assertion);

    assert!(result.is_ok());
}

#[test]
fn private_key_jwt_rejects_missing_kid_when_key_selection_is_ambiguous() {
    let first = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("first key should generate")
        .private_pkcs8_der;
    let second = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("second key should generate")
        .private_pkcs8_der;
    let mut first_jwk =
        public_jwk_from_private_der("first", jsonwebtoken::Algorithm::RS256, &first)
            .expect("first jwk should derive");
    let mut second_jwk =
        public_jwk_from_private_der("second", jsonwebtoken::Algorithm::RS256, &second)
            .expect("second jwk should derive");
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
        &settings.issuer,
        &first,
        "kidless-ambiguous-key-jti",
    );

    let result = verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &assertion);

    assert!(matches!(result, Err(ClientAssertionError::Invalid)));
}

#[test]
fn private_key_jwt_rejects_valid_signature_with_wrong_audience() {
    let private_key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let public_jwk =
        public_jwk_from_private_der("client-kid", jsonwebtoken::Algorithm::RS256, &private_key)
            .expect("client jwk should derive");
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
    let retired = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("retired key should generate")
        .private_pkcs8_der;
    let active = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("active key should generate")
        .private_pkcs8_der;
    let active_jwk =
        public_jwk_from_private_der("active-kid", jsonwebtoken::Algorithm::RS256, &active)
            .expect("active jwk should derive");
    let client = private_key_jwt_client(json!({"keys": [active_jwk]}));
    let settings = test_settings();
    let req = TestRequest::post().uri("/token").to_http_request();
    let retired_assertion = signed_client_assertion(
        &client.client_id,
        &settings.issuer,
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
fn private_key_jwt_replay_ttl_is_bounded_to_assertion_window() {
    let assertion = ValidatedClientAssertion {
        jti: "jti-1".to_owned(),
        exp: 1_000,
        kid: Some("kid-1".to_owned()),
        alg: jsonwebtoken::Algorithm::PS256,
    };

    assert_eq!(assertion.replay_ttl_seconds(900), 100);
    assert_eq!(
        assertion.replay_ttl_seconds(1_000 - CLIENT_ASSERTION_MAX_TTL_SECONDS - 1),
        CLIENT_ASSERTION_MAX_TTL_SECONDS as u64
    );
    assert_eq!(assertion.replay_ttl_seconds(1_001), 1);
}

#[test]
fn private_key_jwt_claim_validation_rejects_bad_times_and_jti() {
    let now = Utc::now().timestamp();
    let valid = ClientAssertionClaims {
        iss: "client-1".to_owned(),
        sub: "client-1".to_owned(),
        aud: json!("https://issuer.example"),
        exp: now + 120,
        nbf: Some(now),
        iat: Some(now),
        jti: "assertion-jti".to_owned(),
    };

    assert!(valid_client_assertion_times(&valid, now));
    assert!(valid_client_assertion_jti(&valid.jti));

    let mut expired = valid;
    expired.exp = now;
    assert!(!valid_client_assertion_times(&expired, now));

    let mut not_yet_valid = expired;
    not_yet_valid.exp = now + 120;
    not_yet_valid.nbf = Some(now + CLIENT_ASSERTION_CLOCK_SKEW_SECONDS + 1);
    assert!(!valid_client_assertion_times(&not_yet_valid, now));

    let mut stale_iat = not_yet_valid;
    stale_iat.nbf = Some(now);
    stale_iat.iat = Some(now - CLIENT_ASSERTION_MAX_TTL_SECONDS - 1);
    assert!(!valid_client_assertion_times(&stale_iat, now));

    assert!(!valid_client_assertion_jti(""));
    assert!(!valid_client_assertion_jti(&"x".repeat(129)));
}

#[test]
fn private_key_jwt_clock_skew_accepts_small_future_times_and_rejects_over_sixty_seconds() {
    let now = Utc::now().timestamp();
    let ten_seconds_future = ClientAssertionClaims {
        iss: "client-1".to_owned(),
        sub: "client-1".to_owned(),
        aud: json!("https://issuer.example"),
        exp: now + 120,
        nbf: Some(now + 10),
        iat: Some(now + 10),
        jti: "assertion-jti".to_owned(),
    };
    assert!(valid_client_assertion_times(&ten_seconds_future, now));

    let sixty_one_seconds_future = ClientAssertionClaims {
        iss: "client-1".to_owned(),
        sub: "client-1".to_owned(),
        aud: json!("https://issuer.example"),
        exp: now + 120,
        nbf: Some(now + 61),
        iat: Some(now + 61),
        jti: "assertion-jti".to_owned(),
    };
    assert!(!valid_client_assertion_times(
        &sixty_one_seconds_future,
        now
    ));
}

#[test]
fn private_key_jwt_decode_accepts_small_future_nbf_and_iat() {
    let private_key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let public_jwk =
        public_jwk_from_private_der("client-kid", jsonwebtoken::Algorithm::RS256, &private_key)
            .expect("client jwk should derive");
    let client = private_key_jwt_client(json!({"keys": [public_jwk]}));
    let settings = test_settings();
    let req = TestRequest::post().uri("/par").to_http_request();
    let now = Utc::now().timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("client-kid".to_owned());
    let assertion = jsonwebtoken::encode(
        &header,
        &json!({
            "iss": client.client_id,
            "sub": client.client_id,
            "aud": settings.issuer,
            "exp": now + 120,
            "nbf": now + 8,
            "iat": now + 8,
            "jti": "future-client-assertion-jti"
        }),
        &jsonwebtoken::EncodingKey::from_rsa_der(&private_key),
    )
    .expect("client assertion should sign");

    let result = verify_private_key_jwt_claims_with_settings(&settings, &req, &client, &assertion);

    assert!(result.is_ok());
}

#[test]
fn client_jwt_algorithm_and_jwk_decoder_fail_closed_for_unsupported_shapes() {
    assert!(client_jwt_algorithm_from_name("HS256").is_none());
    assert!(supported_client_jwt_algorithm_name(jsonwebtoken::Algorithm::HS256).is_none());

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
