use crate::adapters::security::pkce_s256;

use crate::test_support::{DatabaseUserFixture, TestInfrastructure};

use nazo_valkey::test_support::authorization_code_storage_key as authorization_code_key;

use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;

use crate::domain::tenancy::DEFAULT_REALM_ID;

use crate::domain::tenancy::DEFAULT_TENANT_ID;

use crate::domain::{AuthorizationCodeState, PushedAuthorizationRequest};

use crate::http::sessions::SessionPayload;

use crate::settings::Settings;

use crate::test_support::valkey::valkey_get;

use crate::test_support::valkey::valkey_set_ex;

use actix_web::http::header;

use serde_json::json;

pub(crate) async fn consume_pushed_authorization_request(
    state: &TestInfrastructure,
    request_uri: &str,
) -> Result<(), PushedAuthorizationRequestConsumeError> {
    let dependencies =
        crate::http::authorization::test_support::TestAuthorizationDependencies::new(state);
    consume_pushed_authorization_request_with_context(&dependencies.context(), request_uri).await
}

async fn authorization_response_redirect_with_protection(
    state: &TestInfrastructure,
    input: AuthorizationResponseRedirect<'_>,
    protection: AuthorizationResponseProtection<'_>,
) -> HttpResponse {
    let dependencies =
        crate::http::authorization::test_support::TestAuthorizationDependencies::new(state);
    authorization_response_redirect_with_protection_context(
        &dependencies.context(),
        input,
        protection,
        60,
    )
    .await
}

async fn authorization_response_redirect(
    state: &TestInfrastructure,
    input: AuthorizationResponseRedirect<'_>,
) -> HttpResponse {
    let dependencies =
        crate::http::authorization::test_support::TestAuthorizationDependencies::new(state);
    authorization_response_redirect_with_context(&dependencies.context(), input).await
}

async fn consume_reauth_nonce(
    state: &TestInfrastructure,
    q: &mut HashMap<String, String>,
) -> Option<i64> {
    let dependencies =
        crate::http::authorization::test_support::TestAuthorizationDependencies::new(state);
    consume_reauth_nonce_with_context(&dependencies.context(), q).await
}

async fn authorization_login_url(
    state: &TestInfrastructure,
    q: &HashMap<String, String>,
    reauthentication_required: bool,
) -> Result<String, HttpResponse> {
    let dependencies =
        crate::http::authorization::test_support::TestAuthorizationDependencies::new(state);
    authorization_login_url_with_context(&dependencies.context(), q, reauthentication_required)
        .await
}

use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use nazo_auth::{
    AUTHORIZATION_NONCE_MAX_BYTES, AuthorizationPolicyError, NormalizedAuthorizationRequest,
    OidcClaimRequest, PlainAuthorizationResponse, PromptDirectives, RequestedClaims,
    authorization_session_decision, plain_authorization_response_uri,
};
use nazo_postgres::create_pool;

use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};

async fn authorize_get(state: Data<TestInfrastructure>, req: HttpRequest) -> HttpResponse {
    let query_parameters = authorization_duplicate_parameters();
    let mut q = match parse_authorization_query(req.query_string(), &query_parameters) {
        Ok(q) => q,
        Err(response) => return response,
    };
    authorize_request(state, req, &mut q).await
}

async fn authorize_post(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let query_parameters = authorization_duplicate_parameters();
    let mut q = match parse_authorization_post_form(&req, &body, &query_parameters) {
        Ok(q) => q,
        Err(response) => return response,
    };
    authorize_request(state, req, &mut q).await
}

async fn authorize_request(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    q: &mut HashMap<String, String>,
) -> HttpResponse {
    let dependencies =
        crate::http::authorization::test_support::TestAuthorizationDependencies::new(&state);
    authorize_request_with_context(&dependencies.context(), req, q).await
}

fn disconnected_valkey_client() -> fred::prelude::Client {
    let mut builder = ValkeyBuilder::default_centralized();
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = std::time::Duration::from_millis(50);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = std::time::Duration::from_millis(50);
        connection.internal_command_timeout = std::time::Duration::from_millis(50);
        connection.max_command_attempts = 1;
    });
    builder
        .build()
        .expect("valkey client construction should not connect")
}

fn response_oauth_error_code(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

#[path = "request/endpoint.rs"]
mod endpoint;
#[path = "request/prompt_none.rs"]
mod prompt_none;

fn query(values: &[(&str, &str)]) -> HashMap<String, String> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn normalize_for_test(
    supplied: &HashMap<String, String>,
) -> Result<NormalizedAuthorizationRequest, AuthorizationPolicyError> {
    let mut parameters = query(&[
        ("response_type", "code"),
        ("scope", "openid"),
        (
            "code_challenge",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("code_challenge_method", "S256"),
    ]);
    parameters.extend(supplied.clone());
    let scopes = ["openid".to_owned()];
    normalize_authorization_request(
        &parameters,
        AuthorizationClientPolicy {
            client_type: "confidential",
            allowed_scopes: &scopes,
            allowed_audiences: &[],
            require_dpop_bound_tokens: false,
            require_mtls_bound_tokens: false,
        },
        AuthorizationCapabilityPolicy {
            authorization_details: true,
            jarm: true,
            native_sso: true,
            form_post: true,
        },
        AuthorizationProfilePolicy {
            signed_authorization_response_required: false,
            pkce_required: false,
        },
        false,
    )
}

fn requested_claims(q: &HashMap<String, String>) -> Result<RequestedClaims, ()> {
    normalize_for_test(q)
        .map(|normalized| normalized.requested_claims)
        .map_err(|_| ())
}

fn requested_acr(
    q: &HashMap<String, String>,
    claim: Option<&OidcClaimRequest>,
) -> Result<Option<String>, ()> {
    let mut parameters = q.clone();
    if let Some(claim) = claim {
        let mut acr = serde_json::Map::new();
        acr.insert("essential".to_owned(), json!(claim.essential));
        if let Some(value) = claim.value.clone() {
            acr.insert("value".to_owned(), value);
        }
        if !claim.values.is_empty() {
            acr.insert("values".to_owned(), json!(claim.values));
        }
        parameters.insert(
            "claims".to_owned(),
            json!({"id_token": {"acr": acr}}).to_string(),
        );
    }
    normalize_for_test(&parameters)
        .map(|normalized| normalized.acr)
        .map_err(|_| ())
}

fn requested_prompt(q: &HashMap<String, String>) -> Result<PromptDirectives, ()> {
    normalize_for_test(q)
        .map(|normalized| normalized.prompt)
        .map_err(|_| ())
}

fn authorization_pkce(q: &HashMap<String, String>) -> Result<(Option<String>, Option<String>), ()> {
    normalize_pkce_case(q, false)
        .map(|normalized| (normalized.code_challenge, normalized.code_challenge_method))
        .map_err(|_| ())
}

fn normalize_pkce_case(
    supplied: &HashMap<String, String>,
    pkce_required: bool,
) -> Result<NormalizedAuthorizationRequest, AuthorizationPolicyError> {
    let mut parameters = query(&[("response_type", "code"), ("scope", "openid")]);
    parameters.extend(supplied.clone());
    let scopes = ["openid".to_owned()];
    normalize_authorization_request(
        &parameters,
        AuthorizationClientPolicy {
            client_type: "confidential",
            allowed_scopes: &scopes,
            allowed_audiences: &[],
            require_dpop_bound_tokens: false,
            require_mtls_bound_tokens: false,
        },
        AuthorizationCapabilityPolicy {
            authorization_details: true,
            jarm: true,
            native_sso: true,
            form_post: true,
        },
        AuthorizationProfilePolicy {
            signed_authorization_response_required: false,
            pkce_required,
        },
        false,
    )
}

fn session_requires_reauthentication(
    prompt: PromptDirectives,
    max_age: Option<i64>,
    auth_time: i64,
    reauth_started_at: Option<i64>,
    now: i64,
) -> bool {
    authorization_session_decision(
        Some(AuthorizationSession { auth_time }),
        prompt,
        max_age,
        reauth_started_at,
        now,
    ) != AuthorizationSessionDecision::Continue
}

fn append_authorization_response_query(
    redirect_uri: &str,
    issuer: &str,
    code: Option<&str>,
    error: Option<&str>,
    state: Option<&str>,
    session_state: Option<&str>,
) -> String {
    plain_authorization_response_uri(
        &PlainAuthorizationResponse {
            redirect_uri: redirect_uri.to_owned(),
            parameters: [
                code.map(|value| ("code".to_owned(), value.to_owned())),
                error.map(|value| ("error".to_owned(), value.to_owned())),
                state.map(|value| ("state".to_owned(), value.to_owned())),
                Some(("iss".to_owned(), issuer.to_owned())),
            ]
            .into_iter()
            .flatten()
            .collect(),
            issue_session_state: session_state.is_some(),
        },
        session_state,
    )
}

fn authorization_nonce_too_long(q: &HashMap<String, String>) -> bool {
    matches!(
        normalize_for_test(q),
        Err(AuthorizationPolicyError::InvalidRequest)
    )
}

fn reauth_nonce_state_with_valkey(valkey: fred::prelude::Client) -> TestInfrastructure {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.frontend_base_url = "https://auth.example".to_owned();

    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_reauth_nonce_test_invalid:nazo_reauth_nonce_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey,
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

#[test]
fn authorization_policy_enforces_runtime_modules_and_extracts_credential_ids() {
    let authorization_details = json!([
        {
            "type": "openid_credential",
            "credential_configuration_id": "university_degree"
        },
        {
            "type": "openid_credential"
        },
        {
            "type": "payment",
            "credential_configuration_id": "ignored_type"
        },
        {
            "type": "openid_credential",
            "credential_configuration_id": 42
        }
    ]);
    assert_eq!(
        credential_configuration_ids(&authorization_details),
        vec!["university_degree".to_owned()]
    );
    assert!(credential_configuration_ids(&json!({})).is_empty());

    let mut state = reauth_nonce_state_with_valkey(disconnected_valkey_client());
    {
        let settings = Arc::make_mut(&mut state.settings);
        settings.modules.enable_authorization_details = true;
        settings.modules.enable_native_sso = true;
    }
    let dependencies =
        crate::http::authorization::test_support::TestAuthorizationDependencies::new(&state);
    for (module, parameters, expected_error) in [
        (
            nazo_runtime_modules::ModuleId::RequestObjects,
            query(&[("request", "signed-request-object")]),
            "invalid_request",
        ),
        (
            nazo_runtime_modules::ModuleId::AuthorizationDetails,
            query(&[("authorization_details", "[]")]),
            "invalid_request",
        ),
        (
            nazo_runtime_modules::ModuleId::Jarm,
            query(&[("response_mode", "jwt")]),
            "unsupported_response_mode",
        ),
        (
            nazo_runtime_modules::ModuleId::NativeSso,
            query(&[("scope", "openid device_sso")]),
            "invalid_scope",
        ),
    ] {
        let mut context = dependencies.context();
        assert!(
            context.modules.accepting.remove(&module),
            "{module:?} must be enabled by the test fixture"
        );
        let response = runtime_authorization_capability_error(&context, &parameters)
            .expect("disabled module capability should fail closed");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_oauth_error_code(&response).as_deref(),
            Some(expected_error)
        );
    }

    assert!(
        runtime_authorization_capability_error(&dependencies.context(), &HashMap::new()).is_none()
    );
}

async fn live_reauth_nonce_state() -> Option<TestInfrastructure> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let mut builder =
        ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL"));
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = std::time::Duration::from_millis(1000);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = std::time::Duration::from_millis(1000);
        connection.internal_command_timeout = std::time::Duration::from_millis(1000);
        connection.max_command_attempts = 1;
    });
    let valkey = builder.build().expect("valkey client should build");
    valkey.init().await.expect("valkey should connect");
    Some(reauth_nonce_state_with_valkey(valkey))
}

#[test]
fn requested_acr_selects_supported_request_value() {
    assert_eq!(
        requested_acr(&query(&[("acr_values", "2 1")]), None),
        Ok(Some("1".to_owned()))
    );
}

#[test]
fn requested_acr_ignores_unsupported_request_values() {
    let claim = OidcClaimRequest {
        name: "acr".to_owned(),
        essential: false,
        value: Some(json!("urn:claims")),
        values: Vec::new(),
    };
    assert_eq!(
        requested_acr(&query(&[("acr_values", "urn:one urn:two")]), Some(&claim),),
        Ok(None)
    );
    assert_eq!(
        requested_acr(&query(&[("acr_values", "   ")]), Some(&claim)),
        Ok(None)
    );
}

#[test]
fn claims_parameter_extracts_supported_user_claim_names() {
    let requested = requested_claims(&query(&[(
        "claims",
        r#"{"userinfo":{"name":{"essential":true},"unknown":null},"id_token":{"email":{"essential":true},"acr":{"value":"urn:acr:1"},"auth_time":{"essential":true}}}"#,
    )]))
    .unwrap();

    assert_eq!(claim_request_names(&requested.userinfo), vec!["name"]);
    assert!(requested.userinfo[0].essential);
    assert_eq!(claim_request_names(&requested.id_token), vec!["email"]);
    assert!(requested.id_token[0].essential);
    assert_eq!(
        requested.acr.and_then(|request| request.value),
        Some(json!("urn:acr:1"))
    );
    assert!(requested.auth_time);
}

#[test]
fn claims_parameter_accepts_value_values_and_null_requests() {
    let requested = requested_claims(&query(&[(
        "claims",
        r#"{"userinfo":{"name":null,"email":{"value":"alice@example.com"},"phone_number":{"values":["+15555550000","+15555550001"]}},"id_token":{"email_verified":{"essential":false},"acr":{"values":["urn:acr:2"]}}}"#,
    )]))
    .unwrap();

    assert_eq!(
        claim_request_names(&requested.userinfo),
        vec!["email", "name", "phone_number"]
    );
    let email = requested
        .userinfo
        .iter()
        .find(|request| request.name == "email")
        .expect("email claim request");
    assert_eq!(email.value, Some(json!("alice@example.com")));
    let phone = requested
        .userinfo
        .iter()
        .find(|request| request.name == "phone_number")
        .expect("phone claim request");
    assert_eq!(
        phone.values,
        vec![json!("+15555550000"), json!("+15555550001")]
    );
    assert_eq!(
        claim_request_names(&requested.id_token),
        vec!["email_verified"]
    );
    assert!(!requested.id_token[0].essential);
    assert_eq!(
        requested
            .acr
            .expect("ACR request should be preserved")
            .values,
        vec![json!("urn:acr:2")]
    );
    assert!(!requested.auth_time);
}

#[test]
fn malformed_claims_parameter_is_invalid() {
    assert!(requested_claims(&query(&[("claims", "not-json")])).is_err());
    assert!(requested_claims(&query(&[("claims", r#"{"userinfo":[]}"#)])).is_err());
    assert!(requested_claims(&query(&[("claims", r#"{"id_token":{"acr":[]}}"#)])).is_err());
    assert!(
        requested_claims(&query(&[(
            "claims",
            r#"{"userinfo":{"email":{"essential":"yes"}}}"#
        )]))
        .is_err()
    );
    assert!(
        requested_claims(&query(&[(
            "claims",
            r#"{"userinfo":{"email":{"value":"a@example.com","values":["a@example.com"]}}}"#
        )]))
        .is_err()
    );
    assert!(
        requested_claims(&query(&[(
            "claims",
            r#"{"userinfo":{"email":{"values":"a@example.com"}}}"#
        )]))
        .is_err()
    );
    assert!(
        requested_claims(&query(&[(
            "claims",
            r#"{"userinfo":{"email":{"values":[]}}}"#
        )]))
        .is_err()
    );
    assert!(
        requested_claims(&query(&[(
            "claims",
            r#"{"id_token":{"acr":{"values":"one"}}}"#
        )]))
        .is_err()
    );
    assert!(
        requested_claims(&query(&[(
            "claims",
            r#"{"id_token":{"auth_time":{"essential":"yes"}}}"#
        )]))
        .is_err()
    );
}

#[test]
fn claims_parameter_preserves_requested_acr_values() {
    let requested = requested_claims(&query(&[(
        "claims",
        r#"{"id_token":{"acr":{"values":["","urn:acr:2","urn:acr:3"]}}}"#,
    )]))
    .unwrap();

    assert_eq!(
        requested
            .acr
            .expect("ACR request should be preserved")
            .values,
        vec![json!(""), json!("urn:acr:2"), json!("urn:acr:3")]
    );
}

#[test]
fn max_age_zero_and_prompt_directives_require_reauthentication() {
    let prompt = PromptDirectives::default();

    assert!(session_requires_reauthentication(
        prompt,
        Some(0),
        1_000,
        None,
        1_000
    ));
    assert!(!session_requires_reauthentication(
        prompt,
        Some(30),
        1_000,
        None,
        1_030
    ));
    assert!(session_requires_reauthentication(
        prompt,
        Some(30),
        1_000,
        None,
        1_031
    ));
    assert!(session_requires_reauthentication(
        PromptDirectives {
            login: true,
            ..PromptDirectives::default()
        },
        None,
        1_000,
        None,
        1_001,
    ));
    assert!(session_requires_reauthentication(
        PromptDirectives {
            login: true,
            ..PromptDirectives::default()
        },
        None,
        1_000,
        Some(1_001),
        1_001,
    ));
    assert!(!session_requires_reauthentication(
        PromptDirectives {
            login: true,
            ..PromptDirectives::default()
        },
        None,
        1_001,
        Some(1_001),
        1_006,
    ));
    assert!(session_requires_reauthentication(
        PromptDirectives {
            select_account: true,
            ..PromptDirectives::default()
        },
        None,
        1_000,
        None,
        1_001,
    ));
    assert!(session_requires_reauthentication(
        PromptDirectives {
            select_account: true,
            ..PromptDirectives::default()
        },
        None,
        1_000,
        Some(1_001),
        1_001,
    ));
    assert!(!session_requires_reauthentication(
        PromptDirectives {
            select_account: true,
            ..PromptDirectives::default()
        },
        None,
        1_001,
        Some(1_001),
        1_006,
    ));
}

#[test]
fn authorization_login_url_marks_reauthentication_start_once() {
    let q = query(&[("client_id", "client-1"), ("prompt", "login")]);

    let url =
        authorization_login_url_for_frontend("https://auth.example", &q, Some("server-nonce"));

    let url = url::Url::parse(&url).unwrap();
    assert!(url.as_str().starts_with("https://auth.example/auth?"));
    let next = url
        .query_pairs()
        .find_map(|(key, value)| (key == "next").then_some(value.into_owned()))
        .unwrap();
    assert!(next.contains("_nazo_reauth_nonce=server-nonce"));
}

#[actix_web::test]
async fn reauth_nonce_is_single_use_authorization_state() {
    let Some(state) = live_reauth_nonce_state().await else {
        return;
    };

    let location = authorization_login_url(
        &state,
        &query(&[("client_id", "client-1"), ("prompt", "login")]),
        true,
    )
    .await
    .expect("reauthentication nonce should be issued");
    let login_url = url::Url::parse(&location).expect("login URL should parse");
    let next = login_url
        .query_pairs()
        .find_map(|(key, value)| (key == "next").then_some(value.into_owned()))
        .expect("login URL should carry next authorization request");
    let next_url = url::Url::parse(&format!("https://issuer.example{next}"))
        .expect("next authorization request should parse as path and query");
    let nonce = next_url
        .query_pairs()
        .find_map(|(key, value)| (key == reauth_nonce_parameter()).then_some(value.into_owned()))
        .expect("reauthentication redirect should carry opaque nonce");

    let mut resumed = query(&[(reauth_nonce_parameter(), nonce.as_str())]);
    let first_started_at = consume_reauth_nonce(&state, &mut resumed).await;
    assert!(first_started_at.is_some());
    assert!(!resumed.contains_key(reauth_nonce_parameter()));

    let mut replayed = query(&[(reauth_nonce_parameter(), nonce.as_str())]);
    assert_eq!(consume_reauth_nonce(&state, &mut replayed).await, None);
    assert!(!replayed.contains_key(reauth_nonce_parameter()));
}

#[actix_web::test]
async fn reauth_nonce_store_failure_returns_server_error() {
    let state = reauth_nonce_state_with_valkey(disconnected_valkey_client());
    let response = authorization_login_url(&state, &query(&[("client_id", "client-1")]), true)
        .await
        .expect_err("reauthentication nonce storage failure should fail closed");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response_oauth_error_code(&response).as_deref(),
        Some("server_error")
    );
}

#[actix_web::test]
async fn reauth_nonce_consume_failure_removes_untrusted_nonce() {
    let state = reauth_nonce_state_with_valkey(disconnected_valkey_client());
    let mut resumed = query(&[(reauth_nonce_parameter(), "opaque-nonce")]);

    assert_eq!(consume_reauth_nonce(&state, &mut resumed).await, None);
    assert!(!resumed.contains_key(reauth_nonce_parameter()));
}

#[test]
fn request_uri_allows_outer_parameters_only_when_equal_to_pushed_values() {
    let pushed = query(&[
        ("client_id", "client-1"),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("scope", "openid profile"),
    ]);

    assert!(outer_request_uri_parameters_match_pushed(
        &query(&[
            ("client_id", "client-1"),
            ("request_uri", "urn:ietf:params:oauth:request_uri:abc"),
            ("redirect_uri", "https://client.example/callback"),
            ("response_type", "code"),
            ("scope", "openid profile"),
        ]),
        &pushed,
    ));
    assert!(!outer_request_uri_parameters_match_pushed(
        &query(&[
            ("client_id", "client-1"),
            ("request_uri", "urn:ietf:params:oauth:request_uri:abc"),
            ("redirect_uri", "https://attacker.example/callback"),
        ]),
        &pushed,
    ));
    assert!(!outer_request_uri_parameters_match_pushed(
        &query(&[
            ("client_id", "client-1"),
            ("request_uri", "urn:ietf:params:oauth:request_uri:abc"),
            ("state", "outer-state"),
        ]),
        &pushed,
    ));
}

#[test]
fn authorization_nonce_length_check_allows_long_state_but_rejects_long_nonce() {
    assert!(!authorization_nonce_too_long(&query(&[(
        "state",
        &"s".repeat(1000),
    )])));
    assert!(authorization_nonce_too_long(&query(&[(
        "nonce",
        &"n".repeat(AUTHORIZATION_NONCE_MAX_BYTES + 1),
    )])));
}

#[test]
fn authorization_response_query_preserves_explicit_empty_state() {
    let location = append_authorization_response_query(
        "https://client.example/callback",
        "https://issuer.example",
        Some("code-1"),
        None,
        Some(""),
        None,
    );

    let url = url::Url::parse(&location).unwrap();
    let pairs = url.query_pairs().collect::<Vec<_>>();
    assert_eq!(
        pairs,
        vec![
            ("code".into(), "code-1".into()),
            ("state".into(), "".into()),
            ("iss".into(), "https://issuer.example".into()),
        ]
    );
}

#[test]
fn authorization_response_query_omits_absent_state_and_inapplicable_result() {
    let location = append_authorization_response_query(
        "https://client.example/callback",
        "https://issuer.example",
        None,
        Some("invalid_request"),
        None,
        None,
    );

    let url = url::Url::parse(&location).unwrap();
    let pairs = url.query_pairs().collect::<Vec<_>>();
    assert_eq!(
        pairs,
        vec![
            ("error".into(), "invalid_request".into()),
            ("iss".into(), "https://issuer.example".into()),
        ]
    );
}

#[test]
fn authorization_response_jwt_redirect_uses_only_response_parameter() {
    let response = authorization_response_jwt_redirect(
        "https://client.example/callback?existing=1",
        "signed-jarm",
    );

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    let url = url::Url::parse(location).unwrap();
    let pairs = url.query_pairs().collect::<Vec<_>>();
    assert_eq!(
        pairs,
        vec![
            ("existing".into(), "1".into()),
            ("response".into(), "signed-jarm".into()),
        ]
    );
    assert!(
        !pairs
            .iter()
            .any(|(key, _)| matches!(key.as_ref(), "code" | "error" | "state" | "iss"))
    );
}

#[test]
fn authorization_response_jwt_signing_failure_does_not_fallback_to_query() {
    let response = authorization_response_jwt_result(
        "https://client.example/callback",
        Err(
            jsonwebtoken::errors::new_error(jsonwebtoken::errors::ErrorKind::Signing(
                "test signing failure".to_owned(),
            ))
            .into(),
        ),
    );

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(header::LOCATION).is_none());
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
}

#[test]
fn preserve_verified_dpop_binding_adds_missing_authorization_parameter() {
    let mut q = query(&[("client_id", "client-1")]);
    let dpop_jkt = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";

    preserve_verified_dpop_binding(&mut q, Some(dpop_jkt));

    assert_eq!(q.get("dpop_jkt").map(String::as_str), Some(dpop_jkt));
}

#[test]
fn preserve_verified_dpop_binding_keeps_explicit_authorization_parameter() {
    let mut q = query(&[
        ("client_id", "client-1"),
        ("dpop_jkt", "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ"),
    ]);

    preserve_verified_dpop_binding(&mut q, Some("Vx6mH6nGWV2DnuqEbuGX4Xw_Dc0p0AQxnKpEG7o5YS8"));

    assert_eq!(
        q.get("dpop_jkt").map(String::as_str),
        Some("w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ")
    );
}

#[test]
fn prompt_parsing_accepts_oidc_values_and_rejects_invalid_combinations() {
    let directives =
        requested_prompt(&query(&[("prompt", "login consent select_account")])).unwrap();
    assert!(directives.login);
    assert!(directives.consent);
    assert!(directives.select_account);
    assert!(!directives.none);

    assert_eq!(
        requested_prompt(&query(&[("prompt", "none")])).unwrap(),
        PromptDirectives {
            none: true,
            ..PromptDirectives::default()
        }
    );
    assert!(requested_prompt(&query(&[("prompt", "none consent")])).is_err());
    assert!(requested_prompt(&query(&[("prompt", "unsupported")])).is_err());
}

#[test]
fn authorization_pkce_compatibility_keeps_oidc_nonce_optional() {
    assert_eq!(authorization_pkce(&HashMap::new()).unwrap(), (None, None));
    assert_eq!(
        authorization_pkce(&query(&[("nonce", "fresh-nonce")])).unwrap(),
        (None, None)
    );
    let valid_challenge = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

    assert!(
        authorization_pkce(&query(&[
            ("code_challenge", valid_challenge),
            ("code_challenge_method", "plain"),
        ]))
        .is_err()
    );
    assert!(authorization_pkce(&query(&[("code_challenge", valid_challenge)])).is_err());
    assert!(
        authorization_pkce(&query(&[
            ("code_challenge", valid_challenge),
            ("code_challenge_method", "S256"),
        ]))
        .is_ok()
    );
}

#[test]
fn authorization_request_pkce_policy_preserves_effective_profile_boundary() {
    assert!(normalize_pkce_case(&HashMap::new(), false).is_ok());
    assert!(normalize_pkce_case(&query(&[("nonce", "fresh-nonce")]), false).is_ok());
    assert_eq!(
        normalize_pkce_case(&HashMap::new(), true),
        Err(AuthorizationPolicyError::InvalidRequest),
    );
}
