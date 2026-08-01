use super::*;
use crate::ConfirmationClaims;

fn jwt_policy<'a>(scopes: &'a [String], audiences: &'a [String]) -> JwtBearerGrantPolicy<'a> {
    JwtBearerGrantPolicy {
        enabled: true,
        issuer: "https://issuer.example",
        client_id: "client",
        client_is_confidential: true,
        allowed_scopes: scopes,
        allowed_audiences: audiences,
        default_audience: "https://api.example",
        now: 1_700_000_000,
    }
}

fn exchange_policy<'a>(
    scopes: &'a [String],
    audiences: &'a [String],
    tenant_id: Uuid,
) -> TokenExchangePolicy<'a> {
    TokenExchangePolicy {
        enabled: true,
        client_id: "client",
        client_is_confidential: true,
        client_tenant_id: tenant_id,
        allowed_scopes: scopes,
        allowed_audiences: audiences,
        require_dpop_bound_tokens: true,
        require_mtls_bound_tokens: false,
        now: 1_700_000_000,
    }
}

fn access_claims(tenant_id: Uuid) -> Claims {
    Claims {
        iss: "https://issuer.example".to_owned(),
        sub: "subject".to_owned(),
        tenant_id: tenant_id.to_string(),
        user_id: Some(Uuid::nil().to_string()),
        subject_type: "public".to_owned(),
        aud: json!("https://api.example"),
        client_id: "client".to_owned(),
        scope: "openid read write".to_owned(),
        authorization_details: json!([]),
        token_use: "access".to_owned(),
        jti: "jti".to_owned(),
        iat: 1_699_999_900,
        nbf: 1_699_999_900,
        exp: 1_700_000_100,
        cnf: None,
        act: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
    }
}

#[test]
fn jwt_bearer_claims_require_exact_party_audience_time_and_replay_values() {
    let scopes = vec!["read".to_owned()];
    let audiences = vec!["https://api.example".to_owned()];
    let policy = jwt_policy(&scopes, &audiences);
    let assertion = validate_jwt_bearer_assertion_claims(
        JwtBearerAssertionClaims {
            iss: "client".to_owned(),
            sub: "client".to_owned(),
            aud: json!("https://issuer.example"),
            exp: policy.now + 120,
            nbf: Some(policy.now),
            iat: Some(policy.now),
            jti: "unique".to_owned(),
        },
        policy,
    )
    .expect("valid assertion");
    assert_eq!(assertion.replay_ttl_seconds, 120);
    assert_eq!(
        classify_jwt_bearer_replay(Ok(false)),
        Err(JwtBearerGrantError::ReplayDetected)
    );
    assert_eq!(
        classify_jwt_bearer_replay(Err(AuthorizationPortError::Unavailable)),
        Err(JwtBearerGrantError::Dependency(
            AuthorizationPortError::Unavailable
        ))
    );
}

#[test]
fn empty_but_present_grant_tokens_reach_crypto_validation() {
    let scopes = vec!["read".to_owned()];
    let audiences = vec!["https://api.example".to_owned()];
    let jwt = admit_jwt_bearer_grant(
        Some(""),
        Some("read"),
        &audiences,
        jwt_policy(&scopes, &audiences),
    )
    .expect("an empty assertion is present but will fail signature validation");
    assert!(jwt.assertion.is_empty());

    let tenant_id = Uuid::nil();
    let exchange = admit_token_exchange(
        &TokenExchangeRequestInput {
            subject_token: Some(String::new()),
            subject_token_type: Some(ACCESS_TOKEN_TYPE.to_owned()),
            audiences: audiences.clone(),
            ..TokenExchangeRequestInput::default()
        },
        exchange_policy(&scopes, &audiences, tenant_id),
    )
    .expect("an empty subject token is present but will fail token validation");
    assert!(exchange.subject_token.is_empty());
}

#[test]
fn token_exchange_type_scope_and_target_policy_is_explicit() {
    let scopes = vec!["read".to_owned(), "write".to_owned()];
    let audiences = vec!["https://api.example".to_owned()];
    let tenant_id = Uuid::now_v7();
    let request = TokenExchangeRequestInput {
        subject_token: Some("subject-token".to_owned()),
        subject_token_type: Some(ACCESS_TOKEN_TYPE.to_owned()),
        actor_token: None,
        actor_token_type: None,
        requested_token_type: Some(ACCESS_TOKEN_TYPE.to_owned()),
        scope: Some("read".to_owned()),
        audiences: audiences.clone(),
    };
    let admitted = admit_token_exchange(&request, exchange_policy(&scopes, &audiences, tenant_id))
        .expect("valid exchange request");
    assert_eq!(admitted.requested_scope.as_deref(), Some("read"));

    let mut unsupported = request;
    unsupported.requested_token_type = Some("urn:example:unknown".to_owned());
    assert_eq!(
        admit_token_exchange(
            &unsupported,
            exchange_policy(&scopes, &audiences, tenant_id)
        ),
        Err(TokenExchangeError::UnsupportedTokenType)
    );
}

#[test]
fn verified_subject_limits_scope_and_preserves_sender_binding() {
    let scopes = vec!["read".to_owned(), "write".to_owned()];
    let audiences = vec!["https://api.example".to_owned()];
    let tenant_id = Uuid::now_v7();
    let policy = exchange_policy(&scopes, &audiences, tenant_id);
    let mut claims = access_claims(tenant_id);
    claims.cnf = Some(ConfirmationClaims {
        jkt: Some("subject-jkt".to_owned()),
        x5t_s256: None,
    });
    let subject =
        validate_token_exchange_subject(&claims, Some("read"), policy).expect("valid subject");
    assert_eq!(subject.scopes, ["read"]);
    assert_eq!(
        token_exchange_issuance_binding(
            &subject.sender_binding,
            PresentedSenderConstraint {
                dpop_jkt: None,
                mtls_x5t_s256: None,
            },
            policy,
        ),
        Err(TokenExchangeError::InvalidGrant)
    );
    assert_eq!(
        token_exchange_issuance_binding(
            &subject.sender_binding,
            PresentedSenderConstraint {
                dpop_jkt: Some("subject-jkt"),
                mtls_x5t_s256: None,
            },
            policy,
        ),
        Ok(TokenExchangeSenderBinding::Dpop("subject-jkt".to_owned()))
    );
}

#[test]
fn dual_subject_binding_and_sender_binding_conversion_fail_closed() {
    let scopes = vec!["read".to_owned()];
    let audiences = vec!["https://api.example".to_owned()];
    let tenant_id = Uuid::now_v7();
    let dpop_policy = exchange_policy(&scopes, &audiences, tenant_id);
    let mut claims = access_claims(tenant_id);
    claims.cnf = Some(ConfirmationClaims {
        jkt: Some("dpop".to_owned()),
        x5t_s256: Some("mtls".to_owned()),
    });
    assert_eq!(
        validate_token_exchange_subject(&claims, Some("read"), dpop_policy),
        Err(TokenExchangeError::InvalidGrant)
    );
    assert_eq!(
        token_exchange_issuance_binding(
            &TokenExchangeSenderBinding::MutualTls("mtls".to_owned()),
            PresentedSenderConstraint {
                dpop_jkt: None,
                mtls_x5t_s256: None,
            },
            dpop_policy,
        ),
        Err(TokenExchangeError::InvalidGrant)
    );
}

#[test]
fn actor_claim_requires_same_client_and_rejects_sender_constraint() {
    let scopes = vec!["read".to_owned()];
    let audiences = vec!["https://api.example".to_owned()];
    let tenant_id = Uuid::now_v7();
    let policy = exchange_policy(&scopes, &audiences, tenant_id);
    let mut actor = access_claims(tenant_id);
    actor.act = Some(json!({"sub": "previous"}));
    let claim = token_exchange_actor_claim(&actor, policy).expect("valid actor");
    assert_eq!(claim["act"]["sub"], "previous");
    actor.cnf = Some(ConfirmationClaims {
        jkt: Some("jkt".to_owned()),
        x5t_s256: None,
    });
    assert_eq!(
        token_exchange_actor_claim(&actor, policy),
        Err(TokenExchangeError::InvalidGrant)
    );
}
