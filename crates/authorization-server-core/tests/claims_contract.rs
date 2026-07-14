use nazo_auth::{
    AccessTokenClaimsInput, AuthorizationResponseClaimsInput, BackchannelLogoutClaimsInput,
    IdTokenClaimsInput, OidcClaimRequest, access_token_claims, authorization_response_jwt_claims,
    backchannel_logout_token_claims, id_token_claims,
};
use serde_json::{Value, json};
use uuid::Uuid;

const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);

fn normalize_generated_jti(mut claims: serde_json::Map<String, Value>) -> Value {
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .expect("claim constructor must emit a string jti");
    assert_eq!(
        Uuid::parse_str(jti)
            .expect("claim constructor must emit a UUID jti")
            .get_version_num(),
        7,
        "claim constructor must emit a UUIDv7 jti"
    );
    claims.insert("jti".to_owned(), json!("<generated-uuid-v7>"));
    Value::Object(claims)
}

#[test]
fn token_claim_constructors_are_locked_to_complete_reviewed_shapes() {
    let user_id = Uuid::parse_str("01890f3c-7b00-7000-8000-000000000001").unwrap();
    let subject = user_id.to_string();
    let audiences = vec![
        "resource://default".to_owned(),
        "https://api.example".to_owned(),
    ];
    let scopes = vec!["write".to_owned(), "read".to_owned()];
    let authorization_details = json!([
        {"type": "payment_initiation", "actions": ["write"]}
    ]);
    let actor = json!({"sub": "delegating-client"});
    let userinfo_claims = vec!["email".to_owned()];
    let userinfo_claim_requests = vec![OidcClaimRequest {
        name: "email".to_owned(),
        essential: true,
        value: Some(json!("alice@example.com")),
        values: vec![json!("alice@example.com"), json!("admin@example.com")],
    }];
    let access_claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: &subject,
            user_id: Some(user_id),
            subject_type: "user",
            client_id: "client-1",
            audiences: &audiences,
            scopes: &scopes,
            authorization_details: &authorization_details,
            userinfo_claims: &userinfo_claims,
            userinfo_claim_requests: &userinfo_claim_requests,
            ttl: 300,
            dpop_jkt: Some("thumbprint-jkt"),
            mtls_x5t_s256: None,
            actor: Some(&actor),
        },
        1_000,
        "access-jti-1",
    );

    let id_extra_claims = json!({
        "email": "alice@example.com",
        "sid": "attacker-controlled-sid"
    });
    let id_input = IdTokenClaimsInput {
        subject: "subject-1",
        client_id: "client-1",
        nonce: Some("nonce-1"),
        auth_time: Some(900),
        amr: &["password".to_owned(), "otp".to_owned()],
        sid: Some("server-session-sid"),
        acr: Some("urn:acr:2"),
        extra_claims: Some(&id_extra_claims),
        ttl: 600,
    };
    let id_claims =
        normalize_generated_jti(id_token_claims("https://issuer.example", &id_input, 1_000));

    let logout_input = BackchannelLogoutClaimsInput {
        client_id: "client-1",
        subject: Some("subject-1"),
        sid: Some("server-session-sid"),
        ttl: 120,
    };
    let logout_claims = normalize_generated_jti(backchannel_logout_token_claims(
        "https://issuer.example",
        &logout_input,
        1_000,
    ));

    let authorization_response_input = AuthorizationResponseClaimsInput {
        client_id: "client-1",
        code: Some("code-1"),
        error: None,
        state: Some(""),
        ttl: 60,
    };
    let authorization_response_claims = normalize_generated_jti(authorization_response_jwt_claims(
        "https://issuer.example",
        &authorization_response_input,
        1_000,
    ));

    for (name, actual, expected) in [
        (
            "access token",
            serde_json::to_value(access_claims).unwrap(),
            json!({
                "iss": "https://issuer.example",
                "sub": subject,
                "tenant_id": DEFAULT_TENANT_ID.to_string(),
                "user_id": user_id.to_string(),
                "subject_type": "user",
                "aud": ["resource://default", "https://api.example"],
                "client_id": "client-1",
                "scope": "read write",
                "authorization_details": [
                    {"type": "payment_initiation", "actions": ["write"]}
                ],
                "token_use": "access",
                "jti": "access-jti-1",
                "iat": 1_000,
                "nbf": 1_000,
                "exp": 1_300,
                "cnf": {"jkt": "thumbprint-jkt"},
                "act": {"sub": "delegating-client"},
                "userinfo_claims": ["email"],
                "userinfo_claim_requests": [{
                    "name": "email",
                    "essential": true,
                    "value": "alice@example.com",
                    "values": ["alice@example.com", "admin@example.com"]
                }]
            }),
        ),
        (
            "ID token",
            id_claims,
            json!({
                "iss": "https://issuer.example",
                "sub": "subject-1",
                "aud": "client-1",
                "iat": 1_000,
                "nbf": 1_000,
                "exp": 1_600,
                "jti": "<generated-uuid-v7>",
                "nonce": "nonce-1",
                "auth_time": 900,
                "amr": ["password", "otp"],
                "sid": "server-session-sid",
                "acr": "urn:acr:2",
                "email": "alice@example.com"
            }),
        ),
        (
            "backchannel logout token",
            logout_claims,
            json!({
                "iss": "https://issuer.example",
                "aud": "client-1",
                "iat": 1_000,
                "nbf": 1_000,
                "exp": 1_120,
                "jti": "<generated-uuid-v7>",
                "events": {
                    "http://schemas.openid.net/event/backchannel-logout": {}
                },
                "sub": "subject-1",
                "sid": "server-session-sid"
            }),
        ),
        (
            "authorization response JWT",
            authorization_response_claims,
            json!({
                "iss": "https://issuer.example",
                "aud": "client-1",
                "iat": 1_000,
                "nbf": 1_000,
                "exp": 1_060,
                "jti": "<generated-uuid-v7>",
                "code": "code-1",
                "state": ""
            }),
        ),
    ] {
        assert_eq!(actual, expected, "{name} claim contract changed");
    }
}

#[test]
fn authorization_response_jwt_preserves_explicit_empty_state() {
    let input = AuthorizationResponseClaimsInput {
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
    let input = AuthorizationResponseClaimsInput {
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
        let input = AuthorizationResponseClaimsInput {
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
    let input = IdTokenClaimsInput {
        subject: "subject-1",
        client_id: "client-1",
        nonce: Some("nonce-1"),
        auth_time: Some(1_000),
        amr: &amr,
        sid: Some("server-session-sid"),
        acr: Some("urn:acr:1"),
        extra_claims: Some(&extra_claims),
        ttl: 600,
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
    let input = IdTokenClaimsInput {
        subject: "subject-1",
        client_id: "client-1",
        nonce: None,
        auth_time: None,
        amr: &[],
        sid: None,
        acr: None,
        extra_claims: Some(&extra_claims),
        ttl: 600,
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
    let input = BackchannelLogoutClaimsInput {
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
        let input = BackchannelLogoutClaimsInput {
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
fn access_token_claims_follow_jwt_profile_for_user_subjects() {
    let user_id = Uuid::now_v7();
    let scopes = vec!["profile".to_owned(), "openid".to_owned()];
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
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
        AccessTokenClaimsInput {
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
fn access_token_without_sender_constraints_does_not_emit_cnf() {
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
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
