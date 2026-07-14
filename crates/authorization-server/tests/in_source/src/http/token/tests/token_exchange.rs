use super::*;

fn client() -> ClientRow {
    crate::client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "resource-server".to_owned(),
        client_name: "Resource Server".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!([]),
        scopes: json!(["accounts", "payments", "read"]),
        allowed_audiences: json!(["https://backend.example/api", "urn:example:target"]),
        grant_types: json!([TOKEN_EXCHANGE_GRANT_TYPE]),
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        allow_authorization_code_without_pkce: false,
        is_active: true,
        jwks: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}

fn claims(client_id: &str, audience: Value, scope: &str) -> Claims {
    Claims {
        iss: "https://issuer.example".to_owned(),
        sub: "subject-1".to_owned(),
        tenant_id: DEFAULT_TENANT_ID.to_string(),
        user_id: None,
        subject_type: "user".to_owned(),
        aud: audience,
        client_id: client_id.to_owned(),
        scope: scope.to_owned(),
        authorization_details: json!([]),
        token_use: "access".to_owned(),
        jti: Uuid::now_v7().to_string(),
        iat: 1_000,
        nbf: 1_000,
        exp: Utc::now().timestamp() + 300,
        cnf: None,
        act: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
    }
}

fn form() -> TokenForm {
    TokenForm {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE.to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: Some("resource-server".to_owned()),
        client_secret: Some("secret".to_owned()),
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: Some("subject-token".to_owned()),
        subject_token_type: Some(ACCESS_TOKEN_TYPE.to_owned()),
        actor_token: None,
        actor_token_type: None,
        audiences: vec!["https://backend.example/api".to_owned()],
        has_audience_param: false,
    }
}

fn policy(client: &ClientRow) -> TokenExchangePolicy<'_> {
    TokenExchangePolicy {
        enabled: true,
        client_id: &client.client_id,
        client_is_confidential: client.client_type == "confidential",
        client_tenant_id: client.tenant_id,
        allowed_scopes: &client.scopes,
        allowed_audiences: &client.allowed_audiences,
        require_dpop_bound_tokens: client.require_dpop_bound_tokens,
        require_mtls_bound_tokens: client.require_mtls_bound_tokens,
        now: Utc::now().timestamp(),
    }
}

#[test]
fn token_exchange_type_policy_requires_subject_token_and_matching_types() {
    let client = client();
    assert!(
        validate_token_exchange_grant_prerequisites(
            &token_exchange_request(&form()),
            policy(&client)
        )
        .is_ok()
    );

    let mut missing_subject = form();
    missing_subject.subject_token = None;
    assert_eq!(
        validate_token_exchange_grant_prerequisites(
            &token_exchange_request(&missing_subject),
            policy(&client)
        ),
        Err(TokenExchangeError::MissingParameter)
    );

    let mut actor_type_without_actor = form();
    actor_type_without_actor.actor_token_type = Some(ACCESS_TOKEN_TYPE.to_owned());
    assert_eq!(
        validate_token_exchange_grant_prerequisites(
            &token_exchange_request(&actor_type_without_actor),
            policy(&client)
        ),
        Err(TokenExchangeError::MissingParameter)
    );

    let mut actor_without_type = form();
    actor_without_type.actor_token = Some("actor-token".to_owned());
    assert_eq!(
        validate_token_exchange_grant_prerequisites(
            &token_exchange_request(&actor_without_type),
            policy(&client)
        ),
        Err(TokenExchangeError::MissingParameter)
    );

    let mut unsupported_requested = form();
    unsupported_requested.requested_token_type =
        Some("urn:ietf:params:oauth:token-type:refresh_token".to_owned());
    assert_eq!(
        validate_token_exchange_grant_prerequisites(
            &token_exchange_request(&unsupported_requested),
            policy(&client)
        ),
        Err(TokenExchangeError::UnsupportedTokenType)
    );
}

#[test]
fn token_exchange_scopes_are_limited_to_subject_and_client_scopes() {
    let client = client();
    let subject = claims(
        "resource-server",
        json!("https://backend.example/api"),
        "openid accounts payments",
    );

    let default_subject = validate_token_exchange_subject(&subject, None, policy(&client))
        .expect("default scopes should be the safe intersection");
    assert_eq!(default_subject.scopes, vec!["accounts", "payments"]);

    let requested = validate_token_exchange_subject(&subject, Some("payments"), policy(&client))
        .expect("requested scopes may be a subset");
    assert_eq!(requested.scopes, vec!["payments"]);

    assert_eq!(
        validate_token_exchange_subject(&subject, Some("admin"), policy(&client)),
        Err(TokenExchangeError::InvalidScope)
    );
}

#[test]
fn token_exchange_requires_explicit_allowed_target() {
    let client = client();

    let mut no_target = form();
    no_target.audiences.clear();
    assert_eq!(
        admit_token_exchange(&token_exchange_request(&no_target), policy(&client)),
        Err(TokenExchangeError::InvalidTarget)
    );

    let mut forbidden = form();
    forbidden.audiences = vec!["https://other.example/api".to_owned()];
    assert_eq!(
        admit_token_exchange(&token_exchange_request(&forbidden), policy(&client)),
        Err(TokenExchangeError::InvalidTarget)
    );

    assert_eq!(
        admit_token_exchange(&token_exchange_request(&form()), policy(&client))
            .expect("target is registered")
            .audiences,
        vec!["https://backend.example/api"]
    );
}

#[test]
fn token_exchange_client_must_match_subject_token_client_by_default() {
    let client = client();

    assert!(
        validate_token_exchange_subject(
            &claims(
                "resource-server",
                json!("https://other.example/api"),
                "accounts"
            ),
            None,
            policy(&client)
        )
        .is_ok()
    );
    assert!(
        validate_token_exchange_subject(
            &claims(
                "frontend-client",
                json!("https://backend.example/api"),
                "accounts"
            ),
            None,
            policy(&client)
        )
        .is_err()
    );
    assert!(
        validate_token_exchange_subject(
            &claims(
                "frontend-client",
                json!(["https://backend.example/api", "urn:example:target"]),
                "accounts"
            ),
            None,
            policy(&client)
        )
        .is_err()
    );
    assert!(
        validate_token_exchange_subject(
            &claims(
                "frontend-client",
                json!("https://other.example/api"),
                "accounts"
            ),
            None,
            policy(&client)
        )
        .is_err()
    );
}

#[test]
fn token_exchange_actor_claim_preserves_current_and_prior_actor_context() {
    let client = client();
    let mut actor = claims("resource-server", json!("resource-server"), "read");
    actor.sub = "service-16".to_owned();
    actor.act = Some(json!({"sub": "service-77"}));

    assert_eq!(
        token_exchange_actor_claim(&actor, policy(&client)).expect("actor should be valid"),
        json!({
            "sub": "service-16",
            "client_id": "resource-server",
            "act": {"sub": "service-77"}
        })
    );
}
