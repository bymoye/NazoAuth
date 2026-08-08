use super::*;
use crate::config::ConfigSource;
use crate::domain::tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
use crate::settings::Settings;
use crate::test_support::TestInfrastructure;
use actix_web::{body::to_bytes, http::StatusCode};
use nazo_auth::ACCESS_TOKEN_TYPE;
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_postgres::create_pool;
use std::sync::Arc;

fn token_exchange_state() -> TestInfrastructure {
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_token_exchange_invalid:nazo_token_exchange_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("Valkey client construction should not connect"),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager_with_algorithm(
            jsonwebtoken::Algorithm::PS256,
        ),
    }
}

fn client() -> ClientRow {
    client_row! {
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

#[test]
fn token_exchange_binding_claims_preserve_sender_constraint_type() {
    assert_eq!(
        token_exchange_binding_claims(TokenExchangeSenderBinding::Bearer),
        (None, None)
    );
    assert_eq!(
        token_exchange_binding_claims(TokenExchangeSenderBinding::Dpop("dpop-jkt".to_owned())),
        (Some("dpop-jkt".to_owned()), None)
    );
    assert_eq!(
        token_exchange_binding_claims(TokenExchangeSenderBinding::MutualTls(
            "mtls-thumbprint".to_owned(),
        )),
        (None, Some("mtls-thumbprint".to_owned()))
    );
}

#[actix_web::test]
async fn token_exchange_issue_binding_preserves_or_rejects_sender_constraints() {
    let presented =
        |dpop_jkt: Option<&str>, mtls_x5t_s256: Option<&str>| ValidatedSenderConstraints {
            dpop_jkt: dpop_jkt.map(str::to_owned),
            mtls_x5t_s256: mtls_x5t_s256.map(str::to_owned),
        };

    let bearer_client = client();
    assert_eq!(
        token_exchange_issue_binding(
            &bearer_client,
            &TokenExchangeSenderBinding::Bearer,
            &presented(None, None),
            policy(&bearer_client),
        )
        .expect("an unconstrained exchange may remain bearer"),
        TokenExchangeSenderBinding::Bearer
    );

    let dpop_subject = TokenExchangeSenderBinding::Dpop("dpop-jkt".to_owned());
    assert_eq!(
        token_exchange_issue_binding(
            &bearer_client,
            &dpop_subject,
            &presented(Some("dpop-jkt"), None),
            policy(&bearer_client),
        )
        .expect("matching DPoP proof must preserve the subject binding"),
        dpop_subject
    );

    let mut mtls_required = client();
    mtls_required.require_mtls_bound_tokens = true;
    let response = token_exchange_issue_binding(
        &mtls_required,
        &TokenExchangeSenderBinding::Dpop("dpop-jkt".to_owned()),
        &presented(Some("dpop-jkt"), None),
        policy(&mtls_required),
    )
    .expect_err("a DPoP subject binding must not be converted to mTLS");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_grant")
    );

    let mut dpop_required = client();
    dpop_required.require_dpop_bound_tokens = true;
    let response = token_exchange_issue_binding(
        &dpop_required,
        &TokenExchangeSenderBinding::MutualTls("mtls-thumbprint".to_owned()),
        &presented(None, Some("mtls-thumbprint")),
        policy(&dpop_required),
    )
    .expect_err("an mTLS subject binding must not be converted to DPoP");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_grant")
    );

    let response = token_exchange_issue_binding(
        &bearer_client,
        &TokenExchangeSenderBinding::Dpop("dpop-jkt".to_owned()),
        &presented(Some("different-jkt"), None),
        policy(&bearer_client),
    )
    .expect_err("a mismatched subject proof must fail closed");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_grant")
    );
}

#[actix_web::test]
async fn token_exchange_subject_binding_requires_the_presented_sender_proof() {
    let state = token_exchange_state();
    let config = crate::http::token::issue::TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = crate::http::token::issue::test_support::test_authorization_service(&state);
    let issuance = TokenIssuanceContext {
        config: &config,
        modules: &modules,
        authorization: &authorization,
    };
    let request = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let mut dpop_required = client();
    dpop_required.require_dpop_bound_tokens = true;
    let response = validate_subject_sender_binding(
        &issuance,
        &request,
        &dpop_required,
        "subject-token",
        &TokenExchangeSenderBinding::MutualTls("mtls-thumbprint".to_owned()),
    )
    .await
    .expect_err("an mTLS subject token cannot silently become DPoP-bound");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_grant")
    );

    let mut mtls_required = client();
    mtls_required.require_mtls_bound_tokens = true;
    let response = validate_subject_sender_binding(
        &issuance,
        &request,
        &mtls_required,
        "subject-token",
        &TokenExchangeSenderBinding::Bearer,
    )
    .await
    .expect_err("an mTLS-required exchange needs a verified certificate");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_grant")
    );

    let bearer_client = client();
    let response = validate_subject_sender_binding(
        &issuance,
        &request,
        &bearer_client,
        "subject-token",
        &TokenExchangeSenderBinding::Dpop("dpop-jkt".to_owned()),
    )
    .await
    .expect_err("a DPoP subject token requires its proof");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn token_exchange_error_responses_follow_rfc8693_error_classes() {
    enum ErrorCase {
        Policy(TokenExchangeError),
        TokenState(TokenExchangeTokenError),
    }

    let cases = [
        (
            "disabled",
            ErrorCase::Policy(TokenExchangeError::Disabled),
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
        ),
        (
            "unauthorized client",
            ErrorCase::Policy(TokenExchangeError::UnauthorizedClient),
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
        ),
        (
            "missing parameter",
            ErrorCase::Policy(TokenExchangeError::MissingParameter),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "unsupported token type",
            ErrorCase::Policy(TokenExchangeError::UnsupportedTokenType),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "invalid scope",
            ErrorCase::Policy(TokenExchangeError::InvalidScope),
            StatusCode::BAD_REQUEST,
            "invalid_scope",
        ),
        (
            "invalid target",
            ErrorCase::Policy(TokenExchangeError::InvalidTarget),
            StatusCode::BAD_REQUEST,
            "invalid_target",
        ),
        (
            "invalid grant",
            ErrorCase::Policy(TokenExchangeError::InvalidGrant),
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            "invalid subject token",
            ErrorCase::TokenState(TokenExchangeTokenError::Invalid),
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            "token state unavailable",
            ErrorCase::TokenState(TokenExchangeTokenError::StoreUnavailable),
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
        ),
    ];

    for (name, case, expected_status, expected_error) in cases {
        let response = match case {
            ErrorCase::Policy(error) => token_exchange_error_response(error),
            ErrorCase::TokenState(error) => exchange_token_error_response(error),
        };
        assert_eq!(response.status(), expected_status, "{name} status");
        assert_eq!(
            response
                .extensions()
                .get::<OAuthJsonErrorFields>()
                .map(|fields| fields.error.as_str()),
            Some(expected_error),
            "{name} extension error code",
        );
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body())
                .await
                .expect("OAuth error response should be readable"),
        )
        .expect("OAuth error response should be JSON");
        assert_eq!(
            body.get("error").and_then(Value::as_str),
            Some(expected_error),
            "{name} JSON error code",
        );
        assert!(
            body.get("error_description")
                .and_then(Value::as_str)
                .is_some_and(|description| !description.is_empty()),
            "{name} should include a safe error description",
        );
    }
}

#[actix_web::test]
async fn token_exchange_subject_boundaries_and_safe_default_scope_are_table_driven() {
    struct SubjectCase {
        name: &'static str,
        claims: Claims,
        requested_scope: Option<&'static str>,
        expected_scopes: &'static [&'static str],
        expected_error: Option<TokenExchangeError>,
        expected_description: &'static str,
    }

    let client = client();
    let policy = policy(&client);
    let mut wrong_client = claims(
        "resource-server",
        json!("https://backend.example/api"),
        "accounts",
    );
    wrong_client.client_id = "frontend-client".to_owned();
    let mut malformed_user = claims(
        "resource-server",
        json!("https://backend.example/api"),
        "accounts",
    );
    malformed_user.user_id = Some("not-a-uuid".to_owned());
    let mut wrong_tenant = claims(
        "resource-server",
        json!("https://backend.example/api"),
        "accounts",
    );
    wrong_tenant.tenant_id = Uuid::now_v7().to_string();
    let mut expired = claims(
        "resource-server",
        json!("https://backend.example/api"),
        "accounts",
    );
    expired.exp = policy.now;
    let mut dual_sender_binding = claims(
        "resource-server",
        json!("https://backend.example/api"),
        "accounts",
    );
    dual_sender_binding.cnf = Some(nazo_auth::ConfirmationClaims {
        jkt: Some("dpop-jkt".to_owned()),
        x5t_s256: Some("mtls-thumbprint".to_owned()),
    });

    let cases = [
        SubjectCase {
            name: "subject client boundary",
            claims: wrong_client,
            requested_scope: None,
            expected_scopes: &[],
            expected_error: Some(TokenExchangeError::InvalidGrant),
            expected_description: "client is not authorized to exchange this subject token.",
        },
        SubjectCase {
            name: "subject user boundary",
            claims: malformed_user,
            requested_scope: None,
            expected_scopes: &[],
            expected_error: Some(TokenExchangeError::InvalidGrant),
            expected_description: "subject token contains an invalid user boundary.",
        },
        SubjectCase {
            name: "subject tenant boundary",
            claims: wrong_tenant,
            requested_scope: None,
            expected_scopes: &[],
            expected_error: Some(TokenExchangeError::InvalidGrant),
            expected_description: "token exchange input token is invalid.",
        },
        SubjectCase {
            name: "subject expiry boundary",
            claims: expired,
            requested_scope: None,
            expected_scopes: &[],
            expected_error: Some(TokenExchangeError::InvalidGrant),
            expected_description: "token exchange input token is invalid.",
        },
        SubjectCase {
            name: "subject sender binding boundary",
            claims: dual_sender_binding,
            requested_scope: None,
            expected_scopes: &[],
            expected_error: Some(TokenExchangeError::InvalidGrant),
            expected_description: "token exchange input token is invalid.",
        },
        SubjectCase {
            name: "safe default scope intersection",
            claims: claims(
                "resource-server",
                json!("https://backend.example/api"),
                "openid accounts payments",
            ),
            requested_scope: None,
            expected_scopes: &["accounts", "payments"],
            expected_error: None,
            expected_description: "",
        },
        SubjectCase {
            name: "safe default rejects OIDC-only subject",
            claims: claims(
                "resource-server",
                json!("https://backend.example/api"),
                "openid",
            ),
            requested_scope: None,
            expected_scopes: &[],
            expected_error: Some(TokenExchangeError::InvalidScope),
            expected_description: "token exchange cannot issue an access token without non-OIDC scopes.",
        },
        SubjectCase {
            name: "requested openid scope",
            claims: claims(
                "resource-server",
                json!("https://backend.example/api"),
                "accounts",
            ),
            requested_scope: Some("openid"),
            expected_scopes: &[],
            expected_error: Some(TokenExchangeError::InvalidScope),
            expected_description: "token exchange scope must be a subset of the subject token and client scopes.",
        },
        SubjectCase {
            name: "requested out-of-bound scope",
            claims: claims(
                "resource-server",
                json!("https://backend.example/api"),
                "accounts",
            ),
            requested_scope: Some("admin"),
            expected_scopes: &[],
            expected_error: Some(TokenExchangeError::InvalidScope),
            expected_description: "token exchange scope must be a subset of the subject token and client scopes.",
        },
    ];

    for case in cases {
        let result = validate_token_exchange_subject(&case.claims, case.requested_scope, policy);
        match (result, case.expected_error) {
            (Ok(subject), None) => assert_eq!(
                subject.scopes, case.expected_scopes,
                "{} should retain only safe scopes",
                case.name
            ),
            (Err(error), Some(expected_error)) => {
                assert_eq!(error, expected_error, "{} error class", case.name);
                let response = token_exchange_subject_error_response(
                    error,
                    &client,
                    &TokenForm {
                        scope: case.requested_scope.map(str::to_owned),
                        ..form()
                    },
                    &case.claims,
                );
                assert_eq!(
                    response.status(),
                    StatusCode::BAD_REQUEST,
                    "{} status",
                    case.name
                );
                assert_eq!(
                    response
                        .extensions()
                        .get::<OAuthJsonErrorFields>()
                        .map(|fields| fields.error.as_str()),
                    Some(expected_error.oauth_error()),
                    "{} HTTP error class",
                    case.name,
                );
                let body: Value = serde_json::from_slice(
                    &to_bytes(response.into_body())
                        .await
                        .expect("subject error response should be readable"),
                )
                .expect("subject error response should be JSON");
                assert_eq!(
                    body.get("error_description").and_then(Value::as_str),
                    Some(case.expected_description),
                    "{} description",
                    case.name,
                );
            }
            (Ok(_), Some(expected_error)) => {
                panic!("{} should reject with {expected_error:?}", case.name)
            }
            (Err(error), None) => panic!("{} should be valid, got {error:?}", case.name),
        }
    }
}
