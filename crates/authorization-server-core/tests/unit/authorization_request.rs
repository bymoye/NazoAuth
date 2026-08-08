use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use proptest::prelude::*;
use serde_json::json;
use uuid::Uuid;

use crate::ValidatedClientRegistration;

const JAR_SIGNING_KEY: [u8; 32] = [29; 32];

fn request_object_client(jwks: Value) -> OAuthClient {
    OAuthClient {
        id: Uuid::from_u128(1),
        tenant_id: Uuid::from_u128(2),
        realm_id: Uuid::from_u128(3),
        organization_id: Uuid::from_u128(4),
        registration: ValidatedClientRegistration {
            client_id: "client".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec!["https://client.example/cb".to_owned()],
            post_logout_redirect_uris: Vec::new(),
            scopes: vec!["openid".to_owned()],
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
            backchannel_logout_uri: None,
            backchannel_logout_session_required: true,
            backchannel_token_delivery_mode: "poll".to_owned(),
            backchannel_client_notification_endpoint: None,
            backchannel_authentication_request_signing_alg: None,
            backchannel_user_code_parameter: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: Vec::new(),
            tls_client_auth_san_uri: Vec::new(),
            tls_client_auth_san_ip: Vec::new(),
            tls_client_auth_san_email: Vec::new(),
            jwks_uri: None,
            jwks: Some(jwks),
            request_uris: Vec::new(),
            initiate_login_uri: None,
            presentation: crate::ClientPresentationMetadata::default(),
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_signing_alg: None,
            introspection_signed_response_alg: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            security_policy: None,
        },
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}

fn request_object_public_jwk() -> Value {
    let verifying_key = SigningKey::from_bytes(&JAR_SIGNING_KEY).verifying_key();
    json!({
        "kid": "jar-key",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
        "key_ops": ["verify"],
        "x": URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
    })
}

fn signed_request_object(claims: &Value, header: Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header}.{payload}");
    let signature = SigningKey::from_bytes(&JAR_SIGNING_KEY).sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn signed_request_object_json(now: i64) -> Value {
    json!({
        "client_id": "client",
        "iss": "client",
        "sub": "client",
        "aud": "https://issuer.example",
        "exp": now + 120,
        "nbf": now,
        "iat": now,
        "jti": "unique",
        "response_type": "code",
        "redirect_uri": "https://client.example/cb",
        "scope": "openid"
    })
}

fn signed_policy(now: i64) -> RequestObjectPolicy<'static> {
    RequestObjectPolicy {
        issuer: "https://issuer.example",
        client_id: "client",
        jti_policy: RequestObjectJtiPolicy::RequiredForSignedJar,
        require_integrity_protected_parameters: true,
        now,
    }
}

fn signed_claims(now: i64) -> RequestObjectClaims {
    RequestObjectClaims {
        client_id: "client".to_owned(),
        iss: Some("client".to_owned()),
        sub: Some("client".to_owned()),
        aud: Some(json!(["unrelated", "https://issuer.example/authorize"])),
        exp: Some(now + 120),
        nbf: Some(now - 1),
        iat: Some(now - 1),
        jti: Some("unique".to_owned()),
        parameters: HashMap::from([
            (
                "redirect_uri".to_owned(),
                json!("https://client.example/cb"),
            ),
            ("scope".to_owned(), json!("openid")),
        ]),
    }
}

#[test]
fn signed_request_object_is_normalized_only_after_all_claim_checks() {
    let now = 1_700_000_000;
    let outer = HashMap::from([
        ("client_id".to_owned(), "client".to_owned()),
        ("request".to_owned(), "jwt".to_owned()),
        ("scope".to_owned(), "openid".to_owned()),
        ("state".to_owned(), "unprotected".to_owned()),
    ]);
    let normalized = normalize_request_object(&outer, &signed_claims(now), signed_policy(now))
        .expect("valid signed request object");
    assert_eq!(
        normalized.parameters.get("scope").map(String::as_str),
        Some("openid")
    );
    assert!(!normalized.parameters.contains_key("state"));
    assert_eq!(
        normalized.replay.expect("replay instruction").ttl_seconds,
        120
    );
}

#[test]
fn owned_normalizer_reuses_outer_map_without_consuming_it_on_policy_failure() {
    let now = 1_700_000_000;
    let mut outer = HashMap::from([
        ("client_id".to_owned(), "client".to_owned()),
        ("request".to_owned(), "jwt".to_owned()),
        ("state".to_owned(), "outer-state".to_owned()),
    ]);
    let normalized =
        normalize_request_object_owned(&mut outer, &signed_claims(now), signed_policy(now))
            .expect("valid signed request object");
    assert!(outer.is_empty());
    assert_eq!(
        normalized.parameters.get("scope").map(String::as_str),
        Some("openid")
    );
    assert!(!normalized.parameters.contains_key("state"));

    let mut invalid_outer = HashMap::from([("request".to_owned(), "jwt".to_owned())]);
    let mut invalid_claims = signed_claims(now);
    invalid_claims.parameters.remove("redirect_uri");
    assert_eq!(
        normalize_request_object_owned(&mut invalid_outer, &invalid_claims, signed_policy(now)),
        Err(AuthorizationRequestError::SignedRequestObjectMissingRedirectUri)
    );
    assert_eq!(
        invalid_outer,
        HashMap::from([("request".to_owned(), "jwt".to_owned())])
    );
}

#[test]
fn signed_request_object_crypto_uses_strict_shared_client_jwk_policy() {
    let now = 1_700_000_000;
    let token = signed_request_object(
        &signed_request_object_json(now),
        json!({"alg": "EdDSA", "kid": "jar-key"}),
    );
    let client = request_object_client(json!({"keys": [request_object_public_jwk()]}));
    let verified = verify_request_object(RequestObjectVerificationInput {
        request_object: &token,
        client: &client,
        expected_signing_algorithm: None,
    })
    .expect("valid signed Request Object");
    assert_eq!(verified.claims.client_id, "client");

    let duplicate = request_object_client(json!({
        "keys": [request_object_public_jwk(), request_object_public_jwk()]
    }));
    assert_eq!(
        verify_request_object(RequestObjectVerificationInput {
            request_object: &token,
            client: &duplicate,
            expected_signing_algorithm: None,
        }),
        Err(RequestObjectVerificationError::InvalidKey)
    );

    for (member, value) in [
        ("d", json!("private")),
        ("k", json!("symmetric")),
        ("key_ops", json!(["sign", "verify"])),
        ("use", json!("enc")),
    ] {
        let mut key = request_object_public_jwk();
        key[member] = value;
        let client = request_object_client(json!({"keys": [key]}));
        assert_eq!(
            verify_request_object(RequestObjectVerificationInput {
                request_object: &token,
                client: &client,
                expected_signing_algorithm: None,
            }),
            Err(RequestObjectVerificationError::InvalidKey),
            "accepted invalid JWK member {member}"
        );
    }
}

#[test]
fn registered_request_object_signing_algorithm_is_enforced() {
    let now = 1_700_000_000;
    let token = signed_request_object(
        &signed_request_object_json(now),
        json!({"alg": "EdDSA", "kid": "jar-key"}),
    );
    let mut client = request_object_client(json!({"keys": [request_object_public_jwk()]}));
    client.request_object_signing_alg = Some("PS256".to_owned());

    assert_eq!(
        verify_request_object(RequestObjectVerificationInput {
            request_object: &token,
            client: &client,
            expected_signing_algorithm: client.request_object_signing_alg.as_deref(),
        }),
        Err(RequestObjectVerificationError::InvalidAlgorithm)
    );
}

#[test]
fn signed_request_object_crypto_defers_time_policy_to_injected_clock() {
    let now = 1_700_000_000;
    let token = signed_request_object(
        &signed_request_object_json(now),
        json!({"alg": "EdDSA", "kid": "jar-key"}),
    );
    let client = request_object_client(json!({"keys": [request_object_public_jwk()]}));
    let verified = verify_request_object(RequestObjectVerificationInput {
        request_object: &token,
        client: &client,
        expected_signing_algorithm: None,
    })
    .expect("signature verification must not use the process wall clock");
    assert!(
        normalize_request_object(&HashMap::new(), &verified.claims, signed_policy(now)).is_ok()
    );
    assert_eq!(
        normalize_request_object(&HashMap::new(), &verified.claims, signed_policy(now + 121)),
        Err(AuthorizationRequestError::RequestObjectClaims)
    );
}

#[test]
fn compact_shape_algorithm_key_and_signature_errors_remain_distinct() {
    let now = 1_700_000_000;
    let claims = signed_request_object_json(now);
    let client = request_object_client(json!({"keys": [request_object_public_jwk()]}));
    for (request_object, expected) in [
        ("one.two", RequestObjectVerificationError::InvalidCompact),
        ("!.payload.", RequestObjectVerificationError::InvalidHeader),
        (
            &signed_request_object(&claims, json!({"alg": "HS256", "kid": "jar-key"})),
            RequestObjectVerificationError::InvalidAlgorithm,
        ),
        (
            &signed_request_object(&claims, json!({"alg": "EdDSA"})),
            RequestObjectVerificationError::MissingKeyId,
        ),
        (
            &signed_request_object(&claims, json!({"alg": "EdDSA", "kid": " "})),
            RequestObjectVerificationError::InvalidKey,
        ),
    ] {
        assert_eq!(
            verify_request_object(RequestObjectVerificationInput {
                request_object,
                client: &client,
                expected_signing_algorithm: None,
            }),
            Err(expected)
        );
    }
    let valid = signed_request_object(&claims, json!({"alg": "EdDSA", "kid": "jar-key"}));
    let signing_input = valid.rsplit_once('.').unwrap().0;
    let invalid_signature = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode([0; 64]));
    assert_eq!(
        verify_request_object(RequestObjectVerificationInput {
            request_object: &invalid_signature,
            client: &client,
            expected_signing_algorithm: None,
        }),
        Err(RequestObjectVerificationError::InvalidSignature)
    );
}

#[test]
fn unsigned_request_objects_are_rejected_for_every_client_profile() {
    let claims = signed_request_object_json(1_700_000_000);
    let unsigned = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"alg": "none"})).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let client = request_object_client(json!({"keys": [request_object_public_jwk()]}));
    let mut sender_constrained = client.clone();
    sender_constrained.require_dpop_bound_tokens = true;
    let mut par_required = client.clone();
    par_required.require_par_request_object = true;
    for client in [&client, &sender_constrained, &par_required] {
        assert_eq!(
            verify_request_object(RequestObjectVerificationInput {
                request_object: &unsigned,
                client,
                expected_signing_algorithm: None,
            }),
            Err(RequestObjectVerificationError::InvalidAlgorithm)
        );
    }
    let signed = signed_request_object(&claims, json!({"alg": "EdDSA", "kid": "jar-key"}));
    assert_eq!(
        unverified_signed_request_object_client_id(&signed).as_deref(),
        Some("client")
    );
    let unsupported = signed_request_object(&claims, json!({"alg": "HS256", "kid": "jar-key"}));
    assert_eq!(
        unverified_signed_request_object_client_id(&unsupported).as_deref(),
        Some("client")
    );
    assert_eq!(unverified_signed_request_object_client_id(&unsigned), None);
}

#[test]
fn signed_request_object_rejects_conflicts_and_reserved_request_uri() {
    let now = 1_700_000_000;
    let claims = signed_claims(now);
    let conflicting = HashMap::from([
        ("client_id".to_owned(), "client".to_owned()),
        ("scope".to_owned(), "email".to_owned()),
    ]);
    assert_eq!(
        normalize_request_object(&conflicting, &claims, signed_policy(now)),
        Err(AuthorizationRequestError::OuterAuthorizationParametersConflict)
    );
    let mut claims = claims;
    claims
        .parameters
        .insert("request_uri".to_owned(), json!("urn:forbidden"));
    assert_eq!(
        normalize_request_object(&HashMap::new(), &claims, signed_policy(now)),
        Err(AuthorizationRequestError::RequestObjectContainsRequestUri)
    );
}

#[test]
fn oidc_signed_request_object_parameters_supersede_outer_duplicates() {
    let now = 1_700_000_000;
    let outer = HashMap::from([
        ("client_id".to_owned(), "client".to_owned()),
        ("request".to_owned(), "signed.jwt".to_owned()),
        (
            "redirect_uri".to_owned(),
            "https://attacker.example/callback".to_owned(),
        ),
        ("scope".to_owned(), "email".to_owned()),
        ("state".to_owned(), "outer-state".to_owned()),
    ]);
    let policy = RequestObjectPolicy {
        require_integrity_protected_parameters: false,
        ..signed_policy(now)
    };

    let normalized = normalize_request_object(&outer, &signed_claims(now), policy)
        .expect("baseline OIDC should accept a valid signed Request Object");

    assert_eq!(
        normalized
            .parameters
            .get("redirect_uri")
            .map(String::as_str),
        Some("https://client.example/cb")
    );
    assert_eq!(
        normalized.parameters.get("scope").map(String::as_str),
        Some("openid")
    );
    assert_eq!(
        normalized.parameters.get("state").map(String::as_str),
        Some("outer-state")
    );
    assert_eq!(
        normalized.parameters.get("request").map(String::as_str),
        Some("signed.jwt")
    );
}

#[test]
fn replay_and_dependency_failures_are_fail_closed_and_keep_error_categories() {
    assert_eq!(classify_request_object_replay(Ok(true)), Ok(()));
    assert_eq!(
        classify_request_object_replay(Ok(false)),
        Err(AuthorizationRequestError::InvalidRequestObjectReplay)
    );
    assert_eq!(
        classify_request_object_replay(Err(AuthorizationPortError::Unavailable)),
        Err(AuthorizationRequestError::Dependency(
            AuthorizationPortError::Unavailable
        ))
    );
}

#[test]
fn par_fapi_policy_requires_confidential_strong_auth_and_sender_constraint() {
    let redirect_uris = vec!["https://client.example/cb".to_owned()];
    let audiences = vec!["https://api.example".to_owned()];
    let parameters = HashMap::from([
        ("response_type".to_owned(), "code".to_owned()),
        ("redirect_uri".to_owned(), redirect_uris[0].clone()),
        ("request".to_owned(), "signed.jwt".to_owned()),
        ("code_challenge".to_owned(), "A".repeat(43)),
        ("code_challenge_method".to_owned(), "S256".to_owned()),
        (
            "resource".to_owned(),
            crate::encode_resource_indicators(&["https://api.example".to_owned()])
                .expect("resource set"),
        ),
    ]);
    let raw = RawParAdmissionPolicy {
        client_is_confidential: true,
        client_authentication_method: "private_key_jwt",
        require_dpop_bound_tokens: true,
        require_mtls_bound_tokens: false,
        require_request_object: true,
        fapi2_security: true,
    };
    let expanded = ExpandedParAdmissionPolicy {
        client_type: "confidential",
        redirect_uris: &redirect_uris,
        allowed_audiences: &audiences,
        fapi2_requires_explicit_redirect_uri: true,
    };
    assert!(validate_raw_par_admission(&parameters, raw).is_ok());
    assert!(validate_expanded_par_admission(&parameters, expanded).is_ok());
    assert_eq!(
        validate_raw_par_admission(
            &parameters,
            RawParAdmissionPolicy {
                client_is_confidential: false,
                ..raw
            }
        ),
        Err(ParAdmissionError::ConfidentialClientRequired)
    );
    assert_eq!(
        validate_raw_par_admission(
            &parameters,
            RawParAdmissionPolicy {
                require_dpop_bound_tokens: false,
                ..raw
            }
        ),
        Err(ParAdmissionError::SenderConstraintRequired)
    );
    let mut without_pkce = parameters.clone();
    without_pkce.remove("code_challenge");
    without_pkce.remove("code_challenge_method");
    assert_eq!(
        validate_expanded_par_admission(&without_pkce, expanded),
        Err(ParAdmissionError::PkceRequired)
    );
    let mut plain_pkce = parameters.clone();
    plain_pkce.insert("code_challenge_method".to_owned(), "plain".to_owned());
    assert_eq!(
        validate_expanded_par_admission(&plain_pkce, expanded),
        Err(ParAdmissionError::InvalidPkce)
    );
    let mut nested = parameters;
    nested.insert("request_uri".to_owned(), "urn:forbidden".to_owned());
    assert_eq!(
        validate_expanded_par_admission(&nested, expanded),
        Err(ParAdmissionError::RequestUriNotAllowed)
    );
}

proptest! {
    #[test]
    fn signed_request_object_time_window_is_bounded(
        age in 0_i64..1_000,
        lifetime in 1_i64..1_000,
    ) {
        let now = 1_700_000_000;
        let mut claims = signed_claims(now);
        claims.nbf = Some(now - age);
        claims.iat = Some(now - age);
        claims.exp = Some(now - age + lifetime);
        let accepted = normalize_request_object(&HashMap::new(), &claims, signed_policy(now)).is_ok();
        let expected = age <= REQUEST_OBJECT_MAX_TTL_SECONDS
            && lifetime <= REQUEST_OBJECT_MAX_TTL_SECONDS + REQUEST_OBJECT_CLOCK_SKEW_SECONDS
            && lifetime > age;
        prop_assert_eq!(accepted, expected);
    }
}
