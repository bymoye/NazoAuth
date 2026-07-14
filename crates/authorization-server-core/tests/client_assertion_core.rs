use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use uuid::Uuid;

use nazo_auth::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, ClientAssertionValidationError,
    ClientAssertionVerificationInput, OAuthClient, ValidatedClientAssertion,
    ValidatedClientRegistration, unverified_client_assertion_client_id, verify_private_key_jwt,
};

const NOW: i64 = 1_700_000_000;
const PRIVATE_KEY: [u8; 32] = [17; 32];

fn public_jwk(kid: Option<&str>) -> Value {
    let x = URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&PRIVATE_KEY)
            .verifying_key()
            .to_bytes(),
    );
    let mut jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "alg": "EdDSA",
        "use": "sig"
    });
    if let Some(kid) = kid {
        jwk["kid"] = json!(kid);
    }
    jwk
}

fn client(jwks: Value) -> OAuthClient {
    OAuthClient {
        id: Uuid::from_u128(1),
        tenant_id: Uuid::from_u128(2),
        realm_id: Uuid::from_u128(3),
        organization_id: Uuid::from_u128(4),
        registration: ValidatedClientRegistration {
            client_id: "client-1".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            scopes: Vec::new(),
            allowed_audiences: Vec::new(),
            grant_types: vec!["authorization_code".to_owned()],
            token_endpoint_auth_method: "private_key_jwt".to_owned(),
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            allow_authorization_code_without_pkce: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: Vec::new(),
            tls_client_auth_san_uri: Vec::new(),
            tls_client_auth_san_ip: Vec::new(),
            tls_client_auth_san_email: Vec::new(),
            jwks: Some(jwks),
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
        },
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}

fn assertion(claim_overrides: Value, kid: Option<&str>) -> String {
    assertion_with_algorithm(claim_overrides, kid, "EdDSA")
}

fn assertion_with_algorithm(claim_overrides: Value, kid: Option<&str>, algorithm: &str) -> String {
    let mut claims = json!({
        "iss": "client-1",
        "sub": "client-1",
        "aud": "https://issuer.example",
        "iat": NOW,
        "nbf": NOW,
        "exp": NOW + 120,
        "jti": "assertion-jti"
    });
    for (key, value) in claim_overrides.as_object().expect("claim overrides object") {
        claims[key] = value.clone();
    }
    let mut header = json!({"alg": algorithm, "typ": "JWT"});
    if let Some(kid) = kid {
        header["kid"] = json!(kid);
    }
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = SigningKey::from_bytes(&PRIVATE_KEY).sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn verify(
    client: &OAuthClient,
    assertion: &str,
) -> Result<ValidatedClientAssertion, ClientAssertionValidationError> {
    verify_at(client, assertion, "/token")
}

fn verify_at(
    client: &OAuthClient,
    assertion: &str,
    endpoint_path: &str,
) -> Result<ValidatedClientAssertion, ClientAssertionValidationError> {
    verify_private_key_jwt(ClientAssertionVerificationInput {
        issuer: "https://issuer.example",
        endpoint_path,
        client,
        assertion,
        now: NOW,
    })
}

#[test]
fn valid_assertion_returns_only_replay_and_algorithm_material() {
    assert_eq!(
        CLIENT_ASSERTION_TYPE_JWT_BEARER,
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );
    let client = client(json!({"keys": [public_jwk(Some("client-kid"))]}));
    let assertion = assertion(json!({}), Some("client-kid"));
    let verified = verify(&client, &assertion).expect("valid assertion");

    assert_eq!(verified.jti(), "assertion-jti");
    assert_eq!(verified.kid(), Some("client-kid"));
    assert_eq!(verified.expires_at(), NOW + 120);
    assert_eq!(verified.replay_ttl_seconds(NOW), 120);
    assert_eq!(verified.algorithm(), jsonwebtoken::Algorithm::EdDSA);
}

#[test]
fn endpoint_audiences_and_arrays_follow_exact_client_policy() {
    let mut client = client(json!({"keys": [public_jwk(Some("kid"))]}));
    let issuer_assertion = assertion(json!({"aud": "https://issuer.example"}), Some("kid"));
    assert!(verify_at(&client, &issuer_assertion, "/par").is_ok());

    for (endpoint_path, audience) in [
        ("/par", "https://issuer.example/par"),
        ("/par", "https://issuer.example/token"),
        ("/token", "https://issuer.example/token"),
        ("/oauth/token", "https://issuer.example/oauth/token"),
        ("/bc-authorize", "https://issuer.example/bc-authorize"),
        ("/bc-authorize", "https://issuer.example/token"),
    ] {
        let endpoint_assertion = assertion(json!({"aud": audience}), Some("kid"));
        assert_eq!(
            verify_at(&client, &endpoint_assertion, endpoint_path).unwrap_err(),
            ClientAssertionValidationError::Audience,
            "endpoint audiences must be rejected unless the client explicitly opts in"
        );
    }

    client.allow_client_assertion_endpoint_audience = true;
    for (endpoint_path, audience) in [
        ("/par", "https://issuer.example/par"),
        ("/par", "https://issuer.example/token"),
        ("/token", "https://issuer.example/token"),
        ("/bc-authorize", "https://issuer.example/bc-authorize"),
        ("/bc-authorize", "https://issuer.example/token"),
    ] {
        let endpoint_assertion = assertion(json!({"aud": audience}), Some("kid"));
        assert!(
            verify_at(&client, &endpoint_assertion, endpoint_path).is_ok(),
            "the compatibility policy must admit the endpoint audience it names"
        );
    }

    let array_assertion = assertion(
        json!({"aud": ["https://issuer.example/token", "https://other.example"]}),
        Some("kid"),
    );
    assert_eq!(
        verify(&client, &array_assertion).unwrap_err(),
        ClientAssertionValidationError::Audience
    );
    client.allow_client_assertion_audience_array = true;
    assert!(verify(&client, &array_assertion).is_ok());
    let nested = assertion(
        json!({"aud": [["https://issuer.example/token"]]}),
        Some("kid"),
    );
    assert_eq!(
        verify(&client, &nested).unwrap_err(),
        ClientAssertionValidationError::Audience
    );
}

#[test]
fn time_jti_and_party_failures_are_distinct_and_fail_closed() {
    assert_eq!(ClientAssertionValidationError::Time.audit_reason(), "time");
    let client = client(json!({"keys": [public_jwk(Some("kid"))]}));
    for (claims, expected) in [
        (json!({"exp": NOW}), ClientAssertionValidationError::Time),
        (
            json!({"exp": NOW + 301}),
            ClientAssertionValidationError::Time,
        ),
        (
            json!({"nbf": NOW + 31}),
            ClientAssertionValidationError::Time,
        ),
        (
            json!({"iat": NOW - 301}),
            ClientAssertionValidationError::Time,
        ),
        (json!({"jti": " "}), ClientAssertionValidationError::Jti),
        (
            json!({"jti": "x".repeat(129)}),
            ClientAssertionValidationError::Jti,
        ),
        (
            json!({"jti": format!(" {} ", "x".repeat(127))}),
            ClientAssertionValidationError::Jti,
        ),
        (
            json!({"sub": "other-client"}),
            ClientAssertionValidationError::IssuerSubject,
        ),
    ] {
        assert_eq!(
            verify(&client, &assertion(claims, Some("kid"))).unwrap_err(),
            expected
        );
    }
}

#[test]
fn rsa_key_strength_uses_unsigned_bit_length_and_safe_public_exponents() {
    fn rsa_jwk(modulus: &[u8], exponent: &[u8]) -> Value {
        json!({
            "kty": "RSA",
            "kid": "rsa",
            "alg": "RS256",
            "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(modulus),
            "e": URL_SAFE_NO_PAD.encode(exponent)
        })
    }

    let mut strong_modulus = vec![0_u8; 256];
    strong_modulus[0] = 0x80;
    let rs256_assertion = assertion_with_algorithm(json!({}), Some("rsa"), "RS256");
    assert_ne!(
        verify(
            &client(json!({"keys": [rsa_jwk(&strong_modulus, &[1, 0, 1])]})),
            &rs256_assertion
        )
        .unwrap_err(),
        ClientAssertionValidationError::KeyNotFound,
        "a 2048-bit modulus and exponent 65537 must reach signature verification"
    );

    let mut leading_zero_weak_modulus = vec![0_u8; 256];
    leading_zero_weak_modulus[1] = 0x80;
    for (modulus, exponent) in [
        (leading_zero_weak_modulus.as_slice(), &[1, 0, 1][..]),
        (strong_modulus.as_slice(), &[0][..]),
        (strong_modulus.as_slice(), &[1][..]),
        (strong_modulus.as_slice(), &[2][..]),
        (strong_modulus.as_slice(), &[4][..]),
    ] {
        assert_eq!(
            verify(
                &client(json!({"keys": [rsa_jwk(modulus, exponent)]})),
                &rs256_assertion
            )
            .unwrap_err(),
            ClientAssertionValidationError::KeyNotFound
        );
    }
}

#[test]
fn key_selection_rejects_private_mismatched_and_ambiguous_material() {
    assert_eq!(
        verify(
            &client(json!({"keys": [public_jwk(Some("kid"))]})),
            &assertion_with_algorithm(json!({}), Some("kid"), "HS256")
        )
        .unwrap_err(),
        ClientAssertionValidationError::InvalidAlgorithm
    );

    for private_parameter in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let mut private = public_jwk(Some("kid"));
        private[private_parameter] = json!(URL_SAFE_NO_PAD.encode(PRIVATE_KEY));
        assert_eq!(
            verify(
                &client(json!({"keys": [private]})),
                &assertion(json!({}), Some("kid"))
            )
            .unwrap_err(),
            ClientAssertionValidationError::KeyNotFound,
            "private JWK parameter {private_parameter} must be rejected"
        );
    }

    for key_ops in [
        json!(["sign"]),
        json!(["verify", "sign"]),
        json!("verify"),
        json!([]),
    ] {
        let mut jwk = public_jwk(Some("kid"));
        jwk["key_ops"] = key_ops;
        assert_eq!(
            verify(
                &client(json!({"keys": [jwk]})),
                &assertion(json!({}), Some("kid"))
            )
            .unwrap_err(),
            ClientAssertionValidationError::KeyNotFound
        );
    }
    let mut verify_only = public_jwk(Some("kid"));
    verify_only["key_ops"] = json!(["verify"]);
    assert!(
        verify(
            &client(json!({"keys": [verify_only]})),
            &assertion(json!({}), Some("kid"))
        )
        .is_ok()
    );

    let ambiguous = client(json!({"keys": [public_jwk(None), public_jwk(None)]}));
    assert_eq!(
        verify(&ambiguous, &assertion(json!({}), None)).unwrap_err(),
        ClientAssertionValidationError::KeyNotFound
    );
    let duplicate_kid = client(json!({
        "keys": [public_jwk(Some("duplicate")), public_jwk(Some("duplicate"))]
    }));
    assert_eq!(
        verify(&duplicate_kid, &assertion(json!({}), Some("duplicate"))).unwrap_err(),
        ClientAssertionValidationError::KeyNotFound
    );

    let mut invalid_duplicate = public_jwk(Some("duplicate"));
    invalid_duplicate["use"] = json!("enc");
    let duplicate_with_one_invalid = client(json!({
        "keys": [public_jwk(Some("duplicate")), invalid_duplicate]
    }));
    assert_eq!(
        verify(
            &duplicate_with_one_invalid,
            &assertion(json!({}), Some("duplicate"))
        )
        .unwrap_err(),
        ClientAssertionValidationError::KeyNotFound
    );

    for (field, invalid_value) in [("alg", json!(7)), ("use", json!(["sig"]))] {
        let mut malformed = public_jwk(Some("kid"));
        malformed[field] = invalid_value;
        assert_eq!(
            verify(
                &client(json!({"keys": [malformed]})),
                &assertion(json!({}), Some("kid"))
            )
            .unwrap_err(),
            ClientAssertionValidationError::KeyNotFound
        );
    }
}

#[test]
fn unverified_identity_is_only_a_lookup_hint_with_matching_nonempty_parties() {
    assert_eq!(
        unverified_client_assertion_client_id(&assertion(json!({}), Some("kid"))).as_deref(),
        Some("client-1")
    );
    assert!(
        unverified_client_assertion_client_id(&assertion(json!({"sub": "different"}), Some("kid")))
            .is_none()
    );
}
