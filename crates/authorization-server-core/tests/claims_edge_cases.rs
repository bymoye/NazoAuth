use nazo_auth::{
    AccessTokenClaimsInput, AuthorizationResponseClaimsInput, BackchannelLogoutClaimsInput,
    IdTokenClaimsInput, OidcClaimRequest, access_token_claims, authorization_response_jwt_claims,
    backchannel_logout_token_claims, id_token_claims,
};
use serde_json::{Value, json};
use uuid::Uuid;

const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);

// ---------------------------------------------------------------------------
// access_token_claims
// ---------------------------------------------------------------------------

#[test]
fn access_token_claims_includes_all_required_jwt_fields() {
    let user_id = Uuid::now_v7();
    let scopes = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ];
    let audiences = vec!["https://issuer.example/userinfo".to_owned()];
    let ad = json!([{"type":"payment_initiation","actions":["write","read"]}]);

    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "alice",
            user_id: Some(user_id),
            subject_type: "user",
            client_id: "client-1",
            audiences: &audiences,
            scopes: &scopes,
            authorization_details: &ad,
            userinfo_claims: &["email".to_owned(), "name".to_owned()],
            userinfo_claim_requests: &[],
            ttl: 3600,
            dpop_jkt: Some("dpop-thumbprint"),
            mtls_x5t_s256: None,
            actor: None,
        },
        1_000_000,
        "jti-access-1",
    );

    assert_eq!(claims.iss, "https://issuer.example");
    assert_eq!(claims.sub, "alice");
    assert_eq!(claims.tenant_id, DEFAULT_TENANT_ID.to_string());
    assert!(claims.user_id.is_none());
    assert_eq!(claims.subject_type, "user");
    assert_eq!(claims.aud, json!("https://issuer.example/userinfo"));
    assert_eq!(claims.client_id, "client-1");
    assert_eq!(claims.scope, "email openid profile");
    assert_eq!(claims.authorization_details, ad);
    assert_eq!(claims.token_use, "access");
    assert_eq!(claims.jti, "jti-access-1");
    assert_eq!(claims.iat, 1_000_000);
    assert_eq!(claims.nbf, 1_000_000);
    assert_eq!(claims.exp, 1_003_600);

    let cnf = claims.cnf.expect("DPoP-bound token must carry cnf");
    assert_eq!(cnf.jkt.as_deref(), Some("dpop-thumbprint"));
    assert!(cnf.x5t_s256.is_none());

    assert_eq!(claims.userinfo_claims, vec!["email", "name"]);
}

#[test]
fn access_token_claims_include_user_id_only_for_public_user_subject() {
    let user_id = Uuid::now_v7();
    let scopes = vec!["openid".to_owned()];
    let audiences = vec!["https://issuer.example/userinfo".to_owned()];
    let ad = json!([]);

    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: &user_id.to_string(),
            user_id: Some(user_id),
            subject_type: "user",
            client_id: "client-1",
            audiences: &audiences,
            scopes: &scopes,
            authorization_details: &ad,
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 3600,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
        1_000_000,
        "jti-access-public",
    );

    assert_eq!(
        claims.user_id.as_deref(),
        Some(user_id.to_string().as_str())
    );
}

#[test]
fn access_token_claims_client_credentials_omits_user_id() {
    let scopes = vec!["read".to_owned(), "write".to_owned()];
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "service-client",
            user_id: None,
            subject_type: "client",
            client_id: "service-client",
            audiences: &["resource://api".to_owned()],
            scopes: &scopes,
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 120,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
        2_000_000,
        "jti-cc-1",
    );

    assert_eq!(claims.sub, "service-client");
    assert!(claims.user_id.is_none());
    assert_eq!(claims.subject_type, "client");
    assert_eq!(claims.client_id, "service-client");
    assert_eq!(claims.scope, "read write");
}

#[test]
fn access_token_claims_cnf_is_none_when_sender_constraints_are_absent() {
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "user-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &["resource://default".to_owned()],
            scopes: &["read".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 60,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
        0,
        "jti-nocnf",
    );

    assert!(claims.cnf.is_none());
}

#[test]
fn access_token_claims_cnf_is_none_when_both_dpop_and_mtls_are_present() {
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "user-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &["resource://default".to_owned()],
            scopes: &["read".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 60,
            dpop_jkt: Some("dpop-jkt"),
            mtls_x5t_s256: Some("mtls-x5t"),
            actor: None,
        },
        0,
        "jti-bothcnf",
    );

    assert!(
        claims.cnf.is_none(),
        "cnf must be omitted when both DPoP and mTLS are supplied (ambiguous binding)"
    );
}

#[test]
fn access_token_claims_cnf_with_mtls_x5t_only() {
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "user-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &["resource://default".to_owned()],
            scopes: &["read".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 60,
            dpop_jkt: None,
            mtls_x5t_s256: Some("mtls-cert-thumbprint"),
            actor: None,
        },
        0,
        "jti-mtls",
    );

    let cnf = claims.cnf.expect("mTLS-bound token must carry cnf");
    assert!(cnf.jkt.is_none());
    assert_eq!(cnf.x5t_s256.as_deref(), Some("mtls-cert-thumbprint"));
}

#[test]
fn access_token_claims_multiple_audiences_produces_json_array() {
    let audiences = vec![
        "resource://default".to_owned(),
        "https://api.example".to_owned(),
        "https://another".to_owned(),
    ];
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "user-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &audiences,
            scopes: &["read".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 60,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
        0,
        "jti-multiaud",
    );

    assert_eq!(
        claims.aud,
        json!([
            "resource://default",
            "https://api.example",
            "https://another"
        ])
    );
}

#[test]
fn access_token_claims_single_audience_is_json_string_not_array() {
    let audiences = vec!["resource://default".to_owned()];
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "user-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &audiences,
            scopes: &["read".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 60,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
        0,
        "jti-singleaud",
    );

    assert_eq!(claims.aud, json!("resource://default"));
}

#[test]
fn access_token_claims_empty_audience_is_empty_json_array() {
    let audiences: Vec<String> = vec![];
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "user-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &audiences,
            scopes: &["read".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 60,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
        0,
        "jti-noaud",
    );

    assert_eq!(claims.aud, json!([]));
}

#[test]
fn access_token_claims_zero_ttl_produces_exp_equal_to_iat() {
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "user-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &["resource://default".to_owned()],
            scopes: &["read".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 0,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
        500,
        "jti-zerottl",
    );

    assert_eq!(claims.iat, 500);
    assert_eq!(claims.exp, 500);
}

#[test]
fn access_token_claims_scope_is_sorted_alphabetically() {
    let scopes = vec![
        "profile".to_owned(),
        "openid".to_owned(),
        "email".to_owned(),
        "address".to_owned(),
    ];
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "user-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &["resource://default".to_owned()],
            scopes: &scopes,
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 60,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
        0,
        "jti-scopesorted",
    );

    assert_eq!(claims.scope, "address email openid profile");
}

#[test]
fn access_token_claims_empty_scope_is_empty_string() {
    let scopes: Vec<String> = vec![];
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "user-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &["resource://default".to_owned()],
            scopes: &scopes,
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 60,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
        0,
        "jti-emptyscope",
    );

    assert_eq!(claims.scope, "");
}

#[test]
fn access_token_claims_empty_authorization_details_is_empty_array() {
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "user-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &["resource://default".to_owned()],
            scopes: &["read".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 60,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
        0,
        "jti-emptyad",
    );

    assert_eq!(claims.authorization_details, json!([]));
}

#[test]
fn access_token_claims_carries_userinfo_claim_requests() {
    let requests = vec![
        OidcClaimRequest {
            name: "email".to_owned(),
            essential: true,
            value: None,
            values: vec![],
        },
        OidcClaimRequest {
            name: "name".to_owned(),
            essential: false,
            value: Some(json!("Alice")),
            values: vec![],
        },
    ];
    let claims = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "user-1",
            user_id: Some(Uuid::now_v7()),
            subject_type: "user",
            client_id: "client-1",
            audiences: &["resource://default".to_owned()],
            scopes: &["openid".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &requests,
            ttl: 60,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
        0,
        "jti-uicreq",
    );

    assert_eq!(claims.userinfo_claim_requests.len(), 2);
    assert_eq!(claims.userinfo_claim_requests[0].name, "email");
    assert!(claims.userinfo_claim_requests[0].essential);
    assert_eq!(claims.userinfo_claim_requests[1].name, "name");
    assert!(!claims.userinfo_claim_requests[1].essential);
    assert_eq!(
        claims.userinfo_claim_requests[1].value,
        Some(json!("Alice"))
    );
}

// ---------------------------------------------------------------------------
// id_token_claims
// ---------------------------------------------------------------------------

#[test]
fn id_token_claims_includes_all_fields_when_provided() {
    let amr = vec!["pwd".to_owned(), "otp".to_owned()];
    let input = IdTokenClaimsInput {
        subject: "subject-1",
        client_id: "client-1",
        nonce: Some("nonce-val"),
        auth_time: Some(1_500_000_000),
        amr: &amr,
        sid: Some("session-id-abc"),
        acr: Some("urn:mace:incommon:iap:silver"),
        extra_claims: None,
        ttl: 600,
    };

    let claims = id_token_claims("https://issuer.example", &input, 2_000_000_000);

    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    assert_eq!(claims.get("sub"), Some(&json!("subject-1")));
    assert_eq!(claims.get("aud"), Some(&json!("client-1")));
    assert_eq!(claims.get("nonce"), Some(&json!("nonce-val")));
    assert_eq!(claims.get("auth_time"), Some(&json!(1_500_000_000)));
    assert_eq!(claims.get("amr"), Some(&json!(["pwd", "otp"])));
    assert_eq!(claims.get("sid"), Some(&json!("session-id-abc")));
    assert_eq!(
        claims.get("acr"),
        Some(&json!("urn:mace:incommon:iap:silver"))
    );
    assert_eq!(claims.get("iat"), Some(&json!(2_000_000_000)));
    assert_eq!(claims.get("nbf"), Some(&json!(2_000_000_000)));
    assert_eq!(claims.get("exp"), Some(&json!(2_000_000_600)));

    let jti = claims.get("jti").and_then(Value::as_str);
    assert!(jti.is_some_and(|v| !v.is_empty()));
}

#[test]
fn id_token_claims_omits_optional_fields_when_not_provided() {
    let input = IdTokenClaimsInput {
        subject: "subject-1",
        client_id: "client-1",
        nonce: None,
        auth_time: None,
        amr: &[],
        sid: None,
        acr: None,
        extra_claims: None,
        ttl: 600,
    };

    let claims = id_token_claims("https://issuer.example", &input, 100);

    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    assert_eq!(claims.get("sub"), Some(&json!("subject-1")));
    assert_eq!(claims.get("aud"), Some(&json!("client-1")));
    assert!(claims.get("nonce").is_none());
    assert!(claims.get("auth_time").is_none());
    assert!(claims.get("amr").is_none());
    assert!(claims.get("sid").is_none());
    assert!(claims.get("acr").is_none());
    assert!(claims.get("exp").is_some());
    assert!(claims.get("jti").is_some());
}

#[test]
fn id_token_claims_filters_all_reserved_keys_from_extra_claims() {
    let extra = json!({
        "iss": "https://evil.example",
        "sub": "evil-subject",
        "aud": "evil-client",
        "iat": 9_999_999,
        "nbf": 8_888_888,
        "exp": 7_777_777,
        "jti": "evil-jti",
        "nonce": "evil-nonce",
        "auth_time": 1_234_567,
        "azp": "evil-azp",
        "amr": ["evil"],
        "sid": "evil-sid",
        "acr": "evil-acr",
        "email": "alice@example.com",
        "custom_org_id": "org-42",
    });
    let input = IdTokenClaimsInput {
        subject: "real-subject",
        client_id: "real-client",
        nonce: Some("real-nonce"),
        auth_time: Some(500),
        amr: &["real-pwd".to_owned()],
        sid: Some("real-sid"),
        acr: Some("real-acr"),
        extra_claims: Some(&extra),
        ttl: 600,
    };

    let claims = id_token_claims("https://real-issuer.example", &input, 1_000);

    // Reserved keys must NOT be overwritten
    assert_eq!(
        claims.get("iss"),
        Some(&json!("https://real-issuer.example"))
    );
    assert_eq!(claims.get("sub"), Some(&json!("real-subject")));
    assert_eq!(claims.get("aud"), Some(&json!("real-client")));
    assert_eq!(claims.get("iat"), Some(&json!(1_000)));
    assert_eq!(claims.get("nbf"), Some(&json!(1_000)));
    assert_eq!(claims.get("exp"), Some(&json!(1_600)));
    assert_eq!(claims.get("nonce"), Some(&json!("real-nonce")));
    assert_eq!(claims.get("auth_time"), Some(&json!(500)));
    assert_eq!(claims.get("amr"), Some(&json!(["real-pwd"])));
    assert_eq!(claims.get("sid"), Some(&json!("real-sid")));
    assert_eq!(claims.get("acr"), Some(&json!("real-acr")));
    assert!(
        !claims.contains_key("azp"),
        "azp must not appear even though extra_claims includes it"
    );

    // Non-reserved extra claims must be included
    assert_eq!(claims.get("email"), Some(&json!("alice@example.com")));
    assert_eq!(claims.get("custom_org_id"), Some(&json!("org-42")));
    assert_eq!(claims.len(), 14); // 11 from input + email + custom_org_id + jti
}

#[test]
fn id_token_claims_extra_claims_null_value_does_not_crash() {
    let extra = json!({"email": null, "custom": {"nested": true}});
    let input = IdTokenClaimsInput {
        subject: "sub-1",
        client_id: "client-1",
        nonce: None,
        auth_time: None,
        amr: &[],
        sid: None,
        acr: None,
        extra_claims: Some(&extra),
        ttl: 300,
    };

    let claims = id_token_claims("https://issuer.example", &input, 100);

    assert_eq!(claims.get("email"), Some(&Value::Null));
    assert_eq!(claims.get("custom"), Some(&json!({"nested": true})));
}

#[test]
fn id_token_claims_extra_claims_top_level_non_object_is_ignored() {
    let extra = json!([1, 2, 3]);
    let input = IdTokenClaimsInput {
        subject: "sub-1",
        client_id: "client-1",
        nonce: None,
        auth_time: None,
        amr: &[],
        sid: None,
        acr: None,
        extra_claims: Some(&extra),
        ttl: 300,
    };

    let claims = id_token_claims("https://issuer.example", &input, 100);

    // Only the standard claims should be present (no extra injected)
    assert_eq!(claims.len(), 7); // iss, sub, aud, iat, nbf, exp, jti
}

// ---------------------------------------------------------------------------
// backchannel_logout_token_claims
// ---------------------------------------------------------------------------

#[test]
fn backchannel_logout_token_claims_full_with_sub_and_sid() {
    let input = BackchannelLogoutClaimsInput {
        client_id: "client-1",
        subject: Some("user-42"),
        sid: Some("session-xyz"),
        ttl: 120,
    };

    let claims = backchannel_logout_token_claims("https://issuer.example", &input, 2_000_000_000);

    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    assert_eq!(claims.get("aud"), Some(&json!("client-1")));
    assert_eq!(claims.get("sub"), Some(&json!("user-42")));
    assert_eq!(claims.get("sid"), Some(&json!("session-xyz")));
}

#[test]
fn backchannel_logout_token_claims_omits_sub_when_not_provided() {
    let input = BackchannelLogoutClaimsInput {
        client_id: "client-1",
        subject: None,
        sid: Some("session-xyz"),
        ttl: 120,
    };

    let claims = backchannel_logout_token_claims("https://issuer.example", &input, 1_000);

    assert!(!claims.contains_key("sub"));
    assert_eq!(claims.get("sid"), Some(&json!("session-xyz")));
}

#[test]
fn backchannel_logout_token_claims_omits_sid_when_not_provided() {
    let input = BackchannelLogoutClaimsInput {
        client_id: "client-1",
        subject: Some("user-42"),
        sid: None,
        ttl: 120,
    };

    let claims = backchannel_logout_token_claims("https://issuer.example", &input, 1_000);

    assert_eq!(claims.get("sub"), Some(&json!("user-42")));
    assert!(!claims.contains_key("sid"));
}

#[test]
fn backchannel_logout_token_claims_omits_both_sub_and_sid_when_not_provided() {
    let input = BackchannelLogoutClaimsInput {
        client_id: "client-1",
        subject: None,
        sid: None,
        ttl: 120,
    };

    let claims = backchannel_logout_token_claims("https://issuer.example", &input, 1_000);

    assert!(!claims.contains_key("sub"));
    assert!(!claims.contains_key("sid"));
}

#[test]
fn backchannel_logout_token_claims_includes_openid_events_claim() {
    let input = BackchannelLogoutClaimsInput {
        client_id: "client-1",
        subject: Some("user-42"),
        sid: None,
        ttl: 120,
    };

    let claims = backchannel_logout_token_claims("https://issuer.example", &input, 1_000);

    let events = claims.get("events").expect("logout token must have events");
    let logout_event = events
        .get("http://schemas.openid.net/event/backchannel-logout")
        .expect("events must contain backchannel-logout");
    assert_eq!(logout_event, &json!({}));
}

#[test]
fn backchannel_logout_token_claims_exp_is_at_least_iat_plus_one() {
    for ttl in [0, -1, -100] {
        let input = BackchannelLogoutClaimsInput {
            client_id: "client-1",
            subject: Some("user-42"),
            sid: None,
            ttl,
        };
        let claims = backchannel_logout_token_claims("https://issuer.example", &input, 1_000);

        assert_eq!(
            claims.get("exp"),
            Some(&json!(1_001)),
            "exp must be iat + 1 when ttl <= 0 (got ttl {ttl})"
        );
    }
}

#[test]
fn backchannel_logout_token_claims_standard_fields_are_always_present() {
    let input = BackchannelLogoutClaimsInput {
        client_id: "client-1",
        subject: None,
        sid: None,
        ttl: 60,
    };

    let claims = backchannel_logout_token_claims("https://issuer.example", &input, 500);

    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    assert_eq!(claims.get("aud"), Some(&json!("client-1")));
    assert_eq!(claims.get("iat"), Some(&json!(500)));
    assert_eq!(claims.get("exp"), Some(&json!(560)));
    assert!(claims.get("jti").is_some());
    assert!(claims.get("events").is_some());
}

// ---------------------------------------------------------------------------
// authorization_response_jwt_claims
// ---------------------------------------------------------------------------

#[test]
fn authorization_response_jwt_with_code_only() {
    let input = AuthorizationResponseClaimsInput {
        client_id: "client-1",
        code: Some("auth-code-xyz"),
        error: None,
        state: None,
        ttl: 60,
    };

    let claims = authorization_response_jwt_claims("https://issuer.example", &input, 1_000);

    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    assert_eq!(claims.get("aud"), Some(&json!("client-1")));
    assert_eq!(claims.get("code"), Some(&json!("auth-code-xyz")));
    assert!(!claims.contains_key("error"));
    assert!(!claims.contains_key("state"));
    assert_eq!(claims.get("exp"), Some(&json!(1_060)));
}

#[test]
fn authorization_response_jwt_with_error_only() {
    let input = AuthorizationResponseClaimsInput {
        client_id: "client-1",
        code: None,
        error: Some("invalid_request"),
        state: None,
        ttl: 60,
    };

    let claims = authorization_response_jwt_claims("https://issuer.example", &input, 1_000);

    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    assert_eq!(claims.get("aud"), Some(&json!("client-1")));
    assert!(!claims.contains_key("code"));
    assert_eq!(claims.get("error"), Some(&json!("invalid_request")));
    assert!(!claims.contains_key("state"));
}

#[test]
fn authorization_response_jwt_with_state_only() {
    let input = AuthorizationResponseClaimsInput {
        client_id: "client-1",
        code: None,
        error: None,
        state: Some("state-val"),
        ttl: 60,
    };

    let claims = authorization_response_jwt_claims("https://issuer.example", &input, 1_000);

    assert!(!claims.contains_key("code"));
    assert!(!claims.contains_key("error"));
    assert_eq!(claims.get("state"), Some(&json!("state-val")));
}

#[test]
fn authorization_response_jwt_with_code_and_state() {
    let input = AuthorizationResponseClaimsInput {
        client_id: "client-1",
        code: Some("code-123"),
        error: None,
        state: Some("state-abc"),
        ttl: 60,
    };

    let claims = authorization_response_jwt_claims("https://issuer.example", &input, 1_000);

    assert_eq!(claims.get("code"), Some(&json!("code-123")));
    assert_eq!(claims.get("state"), Some(&json!("state-abc")));
    assert!(!claims.contains_key("error"));
}

#[test]
fn authorization_response_jwt_with_error_and_state() {
    let input = AuthorizationResponseClaimsInput {
        client_id: "client-1",
        code: None,
        error: Some("access_denied"),
        state: Some("state-abc"),
        ttl: 60,
    };

    let claims = authorization_response_jwt_claims("https://issuer.example", &input, 1_000);

    assert!(!claims.contains_key("code"));
    assert_eq!(claims.get("error"), Some(&json!("access_denied")));
    assert_eq!(claims.get("state"), Some(&json!("state-abc")));
}

#[test]
fn authorization_response_jwt_with_code_error_and_state() {
    let input = AuthorizationResponseClaimsInput {
        client_id: "client-1",
        code: Some("code-123"),
        error: Some("invalid_request"),
        state: Some("state-abc"),
        ttl: 60,
    };

    let claims = authorization_response_jwt_claims("https://issuer.example", &input, 1_000);

    assert_eq!(claims.get("code"), Some(&json!("code-123")));
    assert_eq!(claims.get("error"), Some(&json!("invalid_request")));
    assert_eq!(claims.get("state"), Some(&json!("state-abc")));
}

#[test]
fn authorization_response_jwt_with_all_optionals_absent() {
    let input = AuthorizationResponseClaimsInput {
        client_id: "client-1",
        code: None,
        error: None,
        state: None,
        ttl: 60,
    };

    let claims = authorization_response_jwt_claims("https://issuer.example", &input, 1_000);

    assert!(!claims.contains_key("code"));
    assert!(!claims.contains_key("error"));
    assert!(!claims.contains_key("state"));
}

#[test]
fn authorization_response_jwt_exp_floor_is_iat_plus_one() {
    for ttl in [0, -60] {
        let input = AuthorizationResponseClaimsInput {
            client_id: "client-1",
            code: Some("code-1"),
            error: None,
            state: None,
            ttl,
        };
        let claims = authorization_response_jwt_claims("https://issuer.example", &input, 1_000);

        assert_eq!(
            claims.get("exp"),
            Some(&json!(1_001)),
            "JARM response exp must be iat + 1 when ttl <= 0 (got ttl {ttl})"
        );
    }
}

#[test]
fn authorization_response_jwt_includes_standard_timestamp_and_identifier_claims() {
    let input = AuthorizationResponseClaimsInput {
        client_id: "client-1",
        code: Some("code-1"),
        error: None,
        state: None,
        ttl: 60,
    };

    let claims = authorization_response_jwt_claims("https://issuer.example", &input, 1_000);

    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    assert_eq!(claims.get("aud"), Some(&json!("client-1")));
    assert_eq!(claims.get("iat"), Some(&json!(1_000)));
    assert_eq!(claims.get("nbf"), Some(&json!(1_000)));
    assert!(claims.get("exp").is_some());
    let jti = claims.get("jti").and_then(Value::as_str);
    assert!(jti.is_some_and(|v| !v.is_empty()));
}
