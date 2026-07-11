use super::*;

#[test]
fn authorization_response_jwt_preserves_explicit_empty_state() {
    let input = AuthorizationResponseJwtInput {
        client_id: "client-1",
        code: Some("code-1"),
        error: None,
        state: Some(""),
        ttl: 60,
    };
    let claims = authorization_response_jwt_claims("https://issuer.example", &input, 123);

    assert_eq!(claims.get("state"), Some(&json!("")));
    assert_eq!(claims.get("code"), Some(&json!("code-1")));
    assert!(!claims.contains_key("error"));
}

#[test]
fn authorization_response_jwt_omits_absent_state_and_inapplicable_result() {
    let input = AuthorizationResponseJwtInput {
        client_id: "client-1",
        code: None,
        error: Some("invalid_request"),
        state: None,
        ttl: 60,
    };
    let claims = authorization_response_jwt_claims("https://issuer.example", &input, 123);

    assert!(!claims.contains_key("state"));
    assert!(!claims.contains_key("code"));
    assert_eq!(claims.get("error"), Some(&json!("invalid_request")));
}

#[test]
fn authorization_response_jwt_ttl_is_never_zero_or_negative() {
    for ttl in [0, -60] {
        let input = AuthorizationResponseJwtInput {
            client_id: "client-1",
            code: Some("code-1"),
            error: None,
            state: None,
            ttl,
        };
        let claims = authorization_response_jwt_claims("https://issuer.example", &input, 123);

        assert_eq!(
            claims.get("exp"),
            Some(&json!(124)),
            "JARM response JWTs must remain expiring tokens even when configuration supplies ttl {ttl}"
        );
    }
}

#[test]
fn id_token_claims_include_independent_sid_and_protect_reserved_claims() {
    let amr = vec!["password".to_owned()];
    let extra_claims = json!({
        "sid": "attacker-controlled-sid",
        "azp": "attacker-controlled-azp",
        "email": "alice@example.com"
    });
    let input = IdTokenInput {
        subject: "subject-1",
        client_id: "client-1",
        nonce: Some("nonce-1".to_owned()),
        auth_time: Some(1_000),
        amr: &amr,
        sid: Some("server-session-sid"),
        acr: Some("urn:acr:1"),
        extra_claims: Some(&extra_claims),
        ttl: 600,
        signing_alg: None,
    };

    let claims = id_token_claims("https://issuer.example", &input, 2_000);

    assert_eq!(claims.get("sid"), Some(&json!("server-session-sid")));
    assert!(!claims.contains_key("azp"));
    assert_eq!(claims.get("email"), Some(&json!("alice@example.com")));
    assert_eq!(claims.get("nonce"), Some(&json!("nonce-1")));
    assert_eq!(claims.get("auth_time"), Some(&json!(1_000)));
    assert_eq!(claims.get("amr"), Some(&json!(["password"])));
    assert_eq!(claims.get("acr"), Some(&json!("urn:acr:1")));
}

#[test]
fn id_token_extra_claims_cannot_override_registered_claims() {
    let extra_claims = json!({
        "iss": "https://attacker.example",
        "sub": "attacker-subject",
        "aud": "attacker-client",
        "exp": 9_999_999,
        "email": "alice@example.com"
    });
    let input = IdTokenInput {
        subject: "subject-1",
        client_id: "client-1",
        nonce: None,
        auth_time: None,
        amr: &[],
        sid: None,
        acr: None,
        extra_claims: Some(&extra_claims),
        ttl: 600,
        signing_alg: None,
    };

    let claims = id_token_claims("https://issuer.example", &input, 2_000);

    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    assert_eq!(claims.get("sub"), Some(&json!("subject-1")));
    assert_eq!(claims.get("aud"), Some(&json!("client-1")));
    assert_eq!(claims.get("exp"), Some(&json!(2_600)));
    assert_eq!(claims.get("email"), Some(&json!("alice@example.com")));
}

#[test]
fn backchannel_logout_token_claims_follow_oidc_shape_without_nonce() {
    let input = BackchannelLogoutTokenInput {
        client_id: "client-1",
        subject: Some("user-1"),
        sid: Some("sid-1"),
        ttl: 120,
    };

    let claims = backchannel_logout_token_claims("https://issuer.example", &input, 2_000);

    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    assert_eq!(claims.get("aud"), Some(&json!("client-1")));
    assert_eq!(claims.get("sub"), Some(&json!("user-1")));
    assert_eq!(claims.get("sid"), Some(&json!("sid-1")));
    assert_eq!(
        claims.get("events").and_then(|events| {
            events.get("http://schemas.openid.net/event/backchannel-logout")
        }),
        Some(&json!({}))
    );
    assert!(claims.get("nonce").is_none());
    assert!(claims.get("jti").and_then(Value::as_str).is_some());
}

#[test]
fn backchannel_logout_token_ttl_is_never_zero_or_negative() {
    for ttl in [0, -60] {
        let input = BackchannelLogoutTokenInput {
            client_id: "client-1",
            subject: None,
            sid: Some("sid-1"),
            ttl,
        };
        let claims = backchannel_logout_token_claims("https://issuer.example", &input, 2_000);

        assert_eq!(
            claims.get("exp"),
            Some(&json!(2_001)),
            "logout tokens must be short-lived but never already expired for ttl {ttl}"
        );
        assert!(!claims.contains_key("sub"));
        assert_eq!(claims.get("sid"), Some(&json!("sid-1")));
    }
}

#[test]
fn access_token_header_uses_active_alg_kid_and_at_jwt_type() {
    let header = access_token_header(jsonwebtoken::Algorithm::PS256, "active-kid");

    assert_eq!(header.alg, jsonwebtoken::Algorithm::PS256);
    assert_eq!(header.kid.as_deref(), Some("active-kid"));
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
}

#[test]
fn access_token_claims_follow_jwt_profile_for_user_subjects() {
    let user_id = Uuid::now_v7();
    let scopes = vec!["profile".to_owned(), "openid".to_owned()];
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenJwtInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "pairwise-subject",
            user_id: Some(user_id),
            subject_type: "user",
            client_id: "client-1",
            audiences: &["https://issuer.example/userinfo".to_owned()],
            scopes: &scopes,
            authorization_details: &json!([]),
            userinfo_claims: &["email".to_owned()],
            userinfo_claim_requests: &[],
            ttl: 300,
            dpop_jkt: Some("thumbprint-jkt"),
            mtls_x5t_s256: None,
            actor: None,
        },
        1_000,
        "jti-1",
    );

    assert_eq!(claims.iss, "https://issuer.example");
    assert_eq!(claims.aud, json!("https://issuer.example/userinfo"));
    assert_eq!(claims.exp, 1_300);
    assert_eq!(claims.iat, 1_000);
    assert_eq!(claims.nbf, 1_000);
    assert_eq!(claims.client_id, "client-1");
    assert_eq!(claims.tenant_id, DEFAULT_TENANT_ID.to_string());
    assert_eq!(claims.sub, "pairwise-subject");
    assert!(claims.user_id.is_none());
    assert_eq!(claims.subject_type, "user");
    assert_eq!(claims.scope, "openid profile");
    assert_eq!(claims.token_use, "access");
    assert_eq!(claims.jti, "jti-1");
    assert_eq!(claims.userinfo_claims, vec!["email"]);
    let cnf = claims.cnf.expect("DPoP-bound token should carry cnf");
    assert_eq!(cnf.jkt.as_deref(), Some("thumbprint-jkt"));
    assert!(cnf.x5t_s256.is_none());
}

#[test]
fn access_token_claims_keep_client_credentials_subject_separate() {
    let scopes = vec!["write".to_owned(), "read".to_owned()];
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenJwtInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "service-client",
            user_id: None,
            subject_type: "client",
            client_id: "service-client",
            audiences: &[
                "resource://default".to_owned(),
                "https://api.example".to_owned(),
            ],
            scopes: &scopes,
            authorization_details: &json!([{"type":"payment_initiation","actions":["write"]}]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 120,
            dpop_jkt: None,
            mtls_x5t_s256: Some("certificate-thumbprint"),
            actor: None,
        },
        2_000,
        "jti-2",
    );

    assert_eq!(claims.sub, "service-client");
    assert!(claims.user_id.is_none());
    assert_eq!(claims.subject_type, "client");
    assert_eq!(claims.client_id, "service-client");
    assert_eq!(
        claims.aud,
        json!(["resource://default", "https://api.example"])
    );
    assert_eq!(claims.scope, "read write");
    assert_eq!(
        claims.authorization_details,
        json!([{"type":"payment_initiation","actions":["write"]}])
    );
    let cnf = claims.cnf.expect("mTLS-bound token should carry cnf");
    assert!(cnf.jkt.is_none());
    assert_eq!(cnf.x5t_s256.as_deref(), Some("certificate-thumbprint"));
}

#[test]
fn access_token_rejects_conflicting_sender_constraints() {
    assert!(validate_access_token_sender_constraint(Some("jkt"), Some("x5t")).is_err());
}

#[tokio::test]
async fn make_jwt_rejects_conflicting_sender_constraints_before_signing() {
    let state = AppState {
        diesel_db: crate::db::create_pool(
            "postgres://nazo_token_test_invalid:nazo_token_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: std::sync::Arc::new(test_settings()),
        keyset: crate::domain::KeysetStore::new(Keyset {
            active_kid: "invalid-test-key".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    };
    let audiences = vec!["resource://default".to_owned()];
    let scopes = vec!["read".to_owned()];
    let authorization_details = json!([]);

    let result = make_jwt(
        &state,
        AccessTokenJwtInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "subject-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &audiences,
            scopes: &scopes,
            authorization_details: &authorization_details,
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 120,
            dpop_jkt: Some("jkt"),
            mtls_x5t_s256: Some("x5t"),
            actor: None,
        },
    )
    .await;

    let error = match result {
        Ok(_) => panic!("conflicting sender constraints must fail before signing"),
        Err(error) => error,
    };
    assert!(matches!(
        error.kind(),
        jsonwebtoken::errors::ErrorKind::InvalidToken
    ));
}

#[tokio::test]
async fn response_signing_uses_auxiliary_key_from_current_keyset_snapshot() {
    let auxiliary = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("auxiliary response signing key should generate");
    let public_jwk = public_jwk_from_private_der(
        "auxiliary-rs256",
        jsonwebtoken::Algorithm::RS256,
        &auxiliary.private_pkcs8_der,
    )
    .expect("auxiliary public JWK should derive");
    let state = AppState {
        diesel_db: crate::db::create_pool(
            "postgres://nazo_token_test_invalid:nazo_token_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: std::sync::Arc::new(test_settings()),
        keyset: crate::domain::KeysetStore::new(Keyset {
            active_kid: "active-eddsa".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: vec![VerificationKey {
                kid: "auxiliary-rs256".to_owned(),
                public_jwk,
                local_signing_key: Some(auxiliary.private_pkcs8_der),
            }],
        }),
    };

    let token = sign_response_jwt(
        &state,
        &json!({"sub": "subject-1"}),
        "JWT",
        Some(jsonwebtoken::Algorithm::RS256),
    )
    .await
    .expect("response signing should use the key material loaded in the snapshot");
    let header = jsonwebtoken::decode_header(&token).expect("signed response header should decode");

    assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(header.kid.as_deref(), Some("auxiliary-rs256"));
}

#[test]
fn access_token_without_sender_constraints_does_not_emit_cnf() {
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenJwtInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "subject-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &["resource://default".to_owned()],
            scopes: &["read".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 120,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
        2_000,
        "jti-3",
    );

    assert!(claims.cnf.is_none());
}
