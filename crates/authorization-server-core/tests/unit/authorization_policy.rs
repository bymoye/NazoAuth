use super::*;
use proptest::prelude::*;
use serde_json::json;

fn client_policy<'a>(
    scopes: &'a [String],
    audiences: &'a [String],
) -> AuthorizationClientPolicy<'a> {
    AuthorizationClientPolicy {
        client_type: "confidential",
        allowed_scopes: scopes,
        allowed_audiences: audiences,
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
    }
}

fn capabilities() -> AuthorizationCapabilityPolicy {
    AuthorizationCapabilityPolicy {
        authorization_details: true,
        jarm: true,
        native_sso: true,
        form_post: true,
    }
}

#[test]
fn authorization_policy_normalizes_oidc_claims_rar_and_jarm() {
    let scopes = vec!["openid".to_owned(), "profile".to_owned()];
    let audiences = vec!["https://api.example".to_owned()];
    let parameters = HashMap::from([
        ("response_type".to_owned(), "code".to_owned()),
        ("code_challenge".to_owned(), "A".repeat(43)),
        ("code_challenge_method".to_owned(), "S256".to_owned()),
        ("response_mode".to_owned(), "jwt".to_owned()),
        ("scope".to_owned(), "openid profile".to_owned()),
        ("resource".to_owned(), "https://api.example".to_owned()),
        ("prompt".to_owned(), "consent".to_owned()),
        ("max_age".to_owned(), "300".to_owned()),
        (
            "claims".to_owned(),
            json!({
                "userinfo": {"email": {"essential": true}},
                "id_token": {"acr": {"essential": true, "values": ["1"]}, "auth_time": null}
            })
            .to_string(),
        ),
        (
            "authorization_details".to_owned(),
            json!([{"type": "payment_initiation", "actions": ["initiate"]}]).to_string(),
        ),
    ]);
    let normalized = normalize_authorization_request(
        &parameters,
        client_policy(&scopes, &audiences),
        capabilities(),
        AuthorizationProfilePolicy {
            signed_authorization_response_required: false,
            pkce_required: false,
        },
        false,
    )
    .expect("valid request");
    assert_eq!(normalized.response_mode.as_deref(), Some("jwt"));
    assert!(normalized.prompt.consent);
    assert_eq!(normalized.acr.as_deref(), Some(BASELINE_ACR_VALUE));
    assert_eq!(normalized.requested_claims.userinfo[0].name, "email");
    assert!(normalized.requested_claims.auth_time);
    assert_eq!(
        normalized.authorization_details[0]["type"],
        "payment_initiation"
    );
}

#[test]
fn module_and_profile_failures_preserve_protocol_error_categories() {
    let scopes = vec!["openid".to_owned(), "device_sso".to_owned()];
    let audiences = Vec::new();
    let base = HashMap::from([
        ("response_type".to_owned(), "code".to_owned()),
        ("code_challenge".to_owned(), "A".repeat(43)),
        ("code_challenge_method".to_owned(), "S256".to_owned()),
        ("response_mode".to_owned(), "jwt".to_owned()),
        ("scope".to_owned(), "openid device_sso".to_owned()),
    ]);
    assert_eq!(
        normalize_authorization_request(
            &base,
            client_policy(&scopes, &audiences),
            AuthorizationCapabilityPolicy {
                jarm: false,
                ..capabilities()
            },
            AuthorizationProfilePolicy {
                signed_authorization_response_required: false,
                pkce_required: false,
            },
            false,
        ),
        Err(AuthorizationPolicyError::UnsupportedResponseMode)
    );
    let mut no_jarm = base;
    no_jarm.remove("response_mode");
    assert_eq!(
        normalize_authorization_request(
            &no_jarm,
            client_policy(&scopes, &audiences),
            AuthorizationCapabilityPolicy {
                native_sso: false,
                ..capabilities()
            },
            AuthorizationProfilePolicy {
                signed_authorization_response_required: false,
                pkce_required: false,
            },
            false,
        ),
        Err(AuthorizationPolicyError::InvalidScope)
    );
}

#[test]
fn session_policy_handles_prompt_none_and_reauthentication_without_transport_state() {
    let prompt_none = PromptDirectives {
        none: true,
        ..PromptDirectives::default()
    };
    assert_eq!(
        authorization_session_decision(None, prompt_none, None, None, 1_000),
        AuthorizationSessionDecision::LoginRequired
    );
    assert_eq!(
        authorization_session_decision(
            Some(AuthorizationSession { auth_time: 900 }),
            PromptDirectives::default(),
            Some(50),
            None,
            1_000,
        ),
        AuthorizationSessionDecision::Login {
            fresh_authentication: false
        }
    );
}

#[test]
fn response_plan_keeps_plain_and_jarm_outputs_distinct() {
    let plain = plan_authorization_response(AuthorizationResponsePolicyInput {
        issuer: "https://issuer.example",
        redirect_uri: "https://client.example/cb",
        client_id: "client",
        response_mode: None,
        code: Some("code"),
        error: None,
        state: Some("state"),
        ttl_seconds: 60,
        signed_response_required: false,
        jarm_available: true,
        session_management_available: true,
    })
    .expect("plain response");
    let AuthorizationResponsePlan::Plain(plain) = plain else {
        panic!("expected plain response");
    };
    assert!(plain.issue_session_state);
    assert!(
        plain
            .parameters
            .contains(&("iss".to_owned(), "https://issuer.example".to_owned()))
    );
    let plain_uri = plain_authorization_response_uri(&plain, Some("session-state"));
    let plain_uri = url::Url::parse(&plain_uri).unwrap();
    assert_eq!(
        plain_uri.query_pairs().collect::<Vec<_>>(),
        vec![
            ("code".into(), "code".into()),
            ("state".into(), "state".into()),
            ("session_state".into(), "session-state".into()),
            ("iss".into(), "https://issuer.example".into()),
        ]
    );

    let jarm = plan_authorization_response(AuthorizationResponsePolicyInput {
        response_mode: Some("jwt"),
        ..AuthorizationResponsePolicyInput {
            issuer: "https://issuer.example",
            redirect_uri: "https://client.example/cb",
            client_id: "client",
            response_mode: None,
            code: None,
            error: Some("access_denied"),
            state: Some("state"),
            ttl_seconds: 60,
            signed_response_required: false,
            jarm_available: true,
            session_management_available: true,
        }
    })
    .expect("JARM response");
    let AuthorizationResponsePlan::Jarm(jarm) = jarm else {
        panic!("expected JARM response");
    };
    assert_eq!(jarm.error.as_deref(), Some("access_denied"));
    assert_eq!(
        jarm.signing_input(Some("PS256")).signing_algorithm,
        Some("PS256")
    );
    let signed_uri = signed_jarm_authorization_response_uri(&SignedJarmAuthorizationResponse {
        redirect_uri: jarm.redirect_uri,
        response: "signed.response".to_owned(),
    });
    assert_eq!(
        url::Url::parse(&signed_uri)
            .unwrap()
            .query_pairs()
            .collect::<Vec<_>>(),
        vec![("response".into(), "signed.response".into())]
    );
}

#[test]
fn interaction_and_response_failures_are_typed_and_fail_closed() {
    assert_eq!(
        prompt_none_decision(Ok(true)),
        Ok(PromptNoneDecision::IssueAuthorizationCode)
    );
    assert_eq!(
        prompt_none_decision(Ok(false)),
        Ok(PromptNoneDecision::ConsentRequired)
    );
    assert_eq!(
        prompt_none_decision(Err(AuthorizationPortError::Unavailable)),
        Err(AuthorizationPortError::Unavailable)
    );
    assert_eq!(
        parse_user_authorization_decision("approve"),
        Some(UserAuthorizationDecision::Approve)
    );
    assert_eq!(parse_user_authorization_decision("other"), None);

    for (client_id, jarm_available, expected) in [
        (
            "client",
            false,
            AuthorizationResponsePolicyError::UnsupportedResponseMode,
        ),
        (" ", true, AuthorizationResponsePolicyError::MissingClientId),
    ] {
        assert_eq!(
            plan_authorization_response(AuthorizationResponsePolicyInput {
                issuer: "https://issuer.example",
                redirect_uri: "https://client.example/cb",
                client_id,
                response_mode: Some("jwt"),
                code: Some("code"),
                error: None,
                state: None,
                ttl_seconds: 60,
                signed_response_required: false,
                jarm_available,
                session_management_available: false,
            }),
            Err(expected)
        );
    }
}

proptest! {
    #[test]
    fn max_age_decision_matches_elapsed_session_age(
        auth_time in 0_i64..1_000_000,
        elapsed in 0_i64..100_000,
        max_age in 0_i64..100_000,
    ) {
        let now = auth_time.saturating_add(elapsed);
        let decision = authorization_session_decision(
            Some(AuthorizationSession { auth_time }),
            PromptDirectives::default(),
            Some(max_age),
            None,
            now,
        );
        let requires_login = max_age == 0 || elapsed > max_age;
        prop_assert_eq!(
            decision,
            if requires_login {
                AuthorizationSessionDecision::Login { fresh_authentication: false }
            } else {
                AuthorizationSessionDecision::Continue
            }
        );
    }
}
