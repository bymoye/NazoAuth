use super::*;
use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore};
use crate::support::{generate_key_material, public_jwk_from_private_der};
use std::io::{self, Write};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tracing::Subscriber;
use tracing_subscriber::{Layer, layer::Context, prelude::*};

#[derive(Clone)]
struct AuditCounter(Arc<AtomicUsize>);

impl<S> Layer<S> for AuditCounter
where
    S: Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, S>) {
        if event.metadata().target() == "audit" {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct FailingAuditWriter;

impl Write for FailingAuditWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("deliberate audit writer failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("deliberate audit writer failure"))
    }
}

fn ciba_test_state_with(configure: impl FnOnce(&mut Settings)) -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    configure(&mut settings);
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_ciba_test_invalid:nazo_ciba_test_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

fn ciba_test_state() -> AppState {
    ciba_test_state_with(|_| {})
}

fn ciba_private_key_jwt_client_with_alg(
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    private_pkcs8_der: &[u8],
) -> ClientRow {
    let public_jwk =
        public_jwk_from_private_der(kid, alg, private_pkcs8_der).expect("public jwk should derive");
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "CIBA Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "profile", "email", "offline_access"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!([CIBA_GRANT_TYPE, "refresh_token"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
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
        jwks: Some(json!({"keys": [public_jwk]})),
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
        backchannel_logout_session_required: true,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: true,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}

fn ciba_private_key_jwt_client(kid: &str, private_pkcs8_der: &[u8]) -> ClientRow {
    ciba_private_key_jwt_client_with_alg(kid, jsonwebtoken::Algorithm::PS256, private_pkcs8_der)
}

fn signed_ciba_request_object_with_alg(
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    private_pkcs8_der: &[u8],
    extra_claims: Value,
) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": "client-1",
        "aud": "https://issuer.example",
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": format!("ciba-request-{}", Uuid::now_v7()),
        "scope": "openid profile email",
        "login_hint": "oidf-local@example.test",
        "binding_message": "1234"
    });
    let target = claims.as_object_mut().expect("claims should be object");
    for (key, value) in extra_claims
        .as_object()
        .expect("extra claims should be object")
    {
        if value.is_null() {
            target.remove(key);
        } else {
            target.insert(key.clone(), value.clone());
        }
    }
    let mut header = jsonwebtoken::Header::new(alg);
    header.kid = Some(kid.to_owned());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_der(private_pkcs8_der),
    )
    .expect("CIBA request object should sign")
}

fn signed_ciba_request_object(kid: &str, private_pkcs8_der: &[u8], extra_claims: Value) -> String {
    signed_ciba_request_object_with_alg(
        kid,
        jsonwebtoken::Algorithm::PS256,
        private_pkcs8_der,
        extra_claims,
    )
}

#[test]
fn ciba_request_key_hashes_auth_req_id() {
    let key = ciba_request_key("auth-req-id");

    assert!(key.starts_with("oauth:ciba:"));
    assert!(!key.contains("auth-req-id"));
    assert_eq!(key, ciba_request_key("auth-req-id"));
    assert_ne!(key, ciba_request_key("other"));
}

#[test]
fn ciba_status_serializes_as_protocol_state() {
    assert_eq!(
        serde_json::to_value(CibaStatus::Pending).unwrap(),
        json!("pending")
    );
}

#[test]
fn ciba_start_audit_fields_are_redacted() {
    let now = Utc::now().timestamp();
    let state = CibaRequestState {
        client_id: "client-1".to_owned(),
        user_id: Uuid::now_v7(),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        acr: None,
        binding_message: Some("sensitive binding text".to_owned()),
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: now + 60,
        retention_expires_at: now + 180,
        last_poll_at: None,
    };

    let fields = ciba_start_audit_fields(
        &state,
        "secret-auth-req-id",
        Some("source-ip-hash".to_owned()),
    );
    let serialized = serde_json::to_string(&fields).unwrap();

    assert!(serialized.contains(&blake3_hex("secret-auth-req-id")));
    assert!(!serialized.contains("secret-auth-req-id"));
    assert!(!serialized.contains("sensitive binding text"));
    assert!(!serialized.contains("binding_message"));
    assert!(!serialized.contains("client_assertion"));
    assert_eq!(fields.get("client_id"), Some(&json!("client-1")));
    assert_eq!(fields.get("source_ip_hash"), Some(&json!("source-ip-hash")));
}

fn committed_decision_fixture(decision: CibaDecision) -> CommittedCibaDecision {
    let now = Utc::now().timestamp();
    CommittedCibaDecision {
        auth_req_id_hash: blake3_hex("auth-req-id"),
        state: CibaRequestState {
            client_id: "client-1".to_owned(),
            user_id: Uuid::now_v7(),
            scopes: vec!["openid".to_owned()],
            audiences: vec!["resource://default".to_owned()],
            acr: None,
            binding_message: None,
            issued_at: now,
            status: match decision {
                CibaDecision::Approve => CibaStatus::Approved,
                CibaDecision::Deny => CibaStatus::Denied,
            },
            interval_seconds: 5,
            expires_at: now + 60,
            retention_expires_at: now + 180,
            last_poll_at: None,
        },
        decision,
    }
}

#[test]
fn ciba_decision_audit_is_emitted_only_for_committed_outcome() {
    let count = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(AuditCounter(Arc::clone(&count)));

    tracing::subscriber::with_default(subscriber, || {
        for failure in [
            CibaDecisionFailure::Missing,
            CibaDecisionFailure::UserMismatch,
            CibaDecisionFailure::AlreadyHandled,
            CibaDecisionFailure::Expired,
            CibaDecisionFailure::Contended,
            CibaDecisionFailure::Storage(CibaStateError::Malformed("bad state".to_owned())),
        ] {
            let _ = complete_ciba_decision(
                Err(failure),
                CibaDecisionSource::User,
                Some("source-ip-hash".to_owned()),
            );
        }
        assert_eq!(count.as_ref().load(Ordering::SeqCst), 0);

        let response = complete_ciba_decision(
            Ok(committed_decision_fixture(CibaDecision::Approve)),
            CibaDecisionSource::User,
            Some("source-ip-hash".to_owned()),
        );
        assert_eq!(response.status(), StatusCode::OK);
    });

    assert_eq!(count.as_ref().load(Ordering::SeqCst), 1);
}

#[test]
fn ciba_audit_writer_failure_does_not_change_committed_response() {
    let subscriber = tracing_subscriber::fmt()
        .with_writer(|| FailingAuditWriter)
        .finish();

    let response = tracing::subscriber::with_default(subscriber, || {
        complete_ciba_decision(
            Ok(committed_decision_fixture(CibaDecision::Deny)),
            CibaDecisionSource::Automation,
            None,
        )
    });

    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn ciba_decision_storage_failure_maps_to_non_cacheable_server_error() {
    let response = complete_ciba_decision(
        Err(CibaDecisionFailure::Storage(CibaStateError::Malformed(
            "bad state".to_owned(),
        ))),
        CibaDecisionSource::User,
        None,
    );

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}

#[test]
fn ciba_poll_storage_failure_returns_503_and_never_protocol_progress() {
    let response = ciba_poll_failure_response(CibaPollFailure::Storage(CibaStateError::Malformed(
        "bad state".to_owned(),
    )));

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}

#[actix_web::test]
async fn ciba_automated_decision_route_accepts_empty_post_without_json_content_type() {
    let state = ciba_test_state_with(|settings| {
        settings.enable_ciba = true;
        settings.ciba_automated_decision_token =
            Some("test-ciba-automated-decision-token-32".to_owned());
    });
    let settings = Arc::clone(&state.settings);
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(actix_web::web::Data::new(state))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = actix_web::test::TestRequest::post()
        .uri("/auth/ciba-automated-decision?token=fake&type=allow&decision_token=wrong-token")
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = actix_web::test::read_body(response).await;
    assert!(body.is_empty());
}

#[test]
fn ciba_signed_request_object_claims_apply_to_backchannel_form() {
    let state = ciba_test_state();
    let key = generate_key_material(jsonwebtoken::Algorithm::PS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let client = ciba_private_key_jwt_client("ciba-kid", &key);
    let request_object = signed_ciba_request_object(
        "ciba-kid",
        &key,
        json!({"requested_expiry": "30", "acr_values": "1"}),
    );
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        ..BackchannelAuthenticationForm::default()
    };

    validate_and_apply_ciba_request_object_claims(&state, &client, &mut form)
        .expect("valid signed CIBA request object should apply");

    assert_eq!(form.scope.as_deref(), Some("openid profile email"));
    assert_eq!(form.login_hint.as_deref(), Some("oidf-local@example.test"));
    assert_eq!(form.binding_message.as_deref(), Some("1234"));
    assert_eq!(form.acr_values.as_deref(), Some("1"));
    assert_eq!(form.requested_expiry_seconds, Some(30));
}

#[test]
fn ciba_request_object_presence_enforces_client_policy() {
    let key = generate_key_material(jsonwebtoken::Algorithm::PS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_par_request_object = true;

    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let missing_request_response = validate_ciba_request_object_presence(
        &settings,
        &client,
        &BackchannelAuthenticationForm::default(),
    )
    .expect_err("CIBA request object policy must reject unsigned form parameters");

    assert_eq!(missing_request_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        missing_request_response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_request")
    );

    let form_with_request = BackchannelAuthenticationForm {
        request: Some("request-object.jwt".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };
    validate_ciba_request_object_presence(&settings, &client, &form_with_request)
        .expect("present request object should satisfy the presence policy");
}

#[test]
fn fapi_ciba_compatibility_profile_preserves_client_request_object_policy() {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let key = generate_key_material(jsonwebtoken::Algorithm::PS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let client = ciba_private_key_jwt_client("ciba-kid", &key);

    validate_ciba_request_object_presence(
        &settings,
        &client,
        &BackchannelAuthenticationForm::default(),
    )
    .expect("OIDF FAPI-CIBA compatibility profile must preserve per-client request-object policy");
}

#[test]
fn ciba_profile_does_not_apply_authorization_code_only_controls() {
    let mut settings = ciba_test_state().settings.as_ref().clone();
    settings.authorization_server_profile =
        crate::settings::AuthorizationServerProfile::Fapi2Security;
    settings.require_pushed_authorization_requests = true;
    settings.enable_request_uri_parameter = false;
    settings.ciba_security_profile =
        crate::settings::CibaSecurityProfile::FapiCibaId1PlainPrivateKeyJwtPoll;
    let key = generate_key_material(jsonwebtoken::Algorithm::PS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_dpop_bound_tokens = true;
    let form = BackchannelAuthenticationForm {
        request: Some("signed-request-object".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };

    validate_token_request_profile(&settings, &client, "private_key_jwt")
        .expect("CIBA-compatible client authentication should pass the server profile");
    validate_ciba_security_profile_client(&settings, &client, "private_key_jwt")
        .expect("official FAPI-CIBA compatibility policy should remain separate");
    validate_ciba_request_object_presence(&settings, &client, &form)
        .expect("CIBA must not require PAR, PKCE, or authorization response_type fields");
}

#[test]
fn fapi2_ciba_profile_requires_signed_backchannel_authentication_request() {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.ciba_security_profile = crate::settings::CibaSecurityProfile::Fapi2Ciba;
    let key = generate_key_material(jsonwebtoken::Algorithm::PS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let client = ciba_private_key_jwt_client("ciba-kid", &key);

    let response = validate_ciba_request_object_presence(
        &settings,
        &client,
        &BackchannelAuthenticationForm::default(),
    )
    .expect_err("Fapi2Ciba must require a signed backchannel authentication request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_request")
    );
}

#[test]
fn fapi2_ciba_client_policy_rejects_public_weak_auth_and_bearer_tokens() {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.ciba_security_profile = crate::settings::CibaSecurityProfile::Fapi2Ciba;
    let key = generate_key_material(jsonwebtoken::Algorithm::PS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);

    let response = validate_ciba_security_profile_client(&settings, &client, "private_key_jwt")
        .expect_err("Fapi2Ciba must reject bearer access tokens");
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_request")
    );

    client.require_mtls_bound_tokens = true;
    validate_ciba_security_profile_client(&settings, &client, "private_key_jwt")
        .expect("Fapi2Ciba must allow private_key_jwt with sender-constrained tokens");

    client.require_mtls_bound_tokens = false;
    client.require_dpop_bound_tokens = true;
    validate_ciba_security_profile_client(&settings, &client, "private_key_jwt")
        .expect("Fapi2Ciba must allow DPoP sender-constrained tokens");

    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;
    let response = validate_ciba_security_profile_client(&settings, &client, "client_secret_basic")
        .expect_err("Fapi2Ciba must reject shared-secret client authentication");
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_client")
    );

    client.client_type = "public".to_owned();
    let response = validate_ciba_security_profile_client(&settings, &client, "none")
        .expect_err("Fapi2Ciba must reject public CIBA clients");
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("unauthorized_client")
    );
}

#[test]
fn fapi2_ciba_private_key_jwt_requires_issuer_audience_only() {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.ciba_security_profile = crate::settings::CibaSecurityProfile::Fapi2Ciba;
    let key = generate_key_material(jsonwebtoken::Algorithm::PS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_mtls_bound_tokens = true;
    client.allow_client_assertion_endpoint_audience = true;

    let response = validate_ciba_security_profile_client(&settings, &client, "private_key_jwt")
        .expect_err("Fapi2Ciba must reject endpoint-audience client assertions");
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_client")
    );

    settings.ciba_security_profile =
        crate::settings::CibaSecurityProfile::FapiCibaId1PlainPrivateKeyJwtPoll;
    validate_ciba_security_profile_client(&settings, &client, "private_key_jwt")
        .expect("OIDF FAPI-CIBA compatibility profile must preserve endpoint audience allowance");
}

#[test]
fn ciba_selected_acr_uses_supported_requested_value() {
    assert_eq!(ciba_selected_acr(Some("1")).as_deref(), Some("1"));
    assert_eq!(ciba_selected_acr(Some("0 1")).as_deref(), Some("1"));
    assert_eq!(ciba_selected_acr(Some("0")).as_deref(), None);
    assert_eq!(ciba_selected_acr(None), None);
}

#[test]
fn ciba_token_issue_allows_refresh_and_binds_refresh_sender_constraint() {
    let ciba = CibaRequestState {
        client_id: "client-1".to_owned(),
        user_id: Uuid::now_v7(),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        acr: Some("1".to_owned()),
        binding_message: None,
        issued_at: Utc::now().timestamp(),
        status: CibaStatus::Approved,
        interval_seconds: 5,
        expires_at: Utc::now().timestamp() + 600,
        retention_expires_at: Utc::now().timestamp() + 720,
        last_poll_at: None,
    };

    let issue = ciba_token_issue(
        ciba.user_id,
        "subject-1".to_owned(),
        ciba,
        Some("dpop-jkt".to_owned()),
        None,
    );

    assert!(issue.include_refresh);
    assert_eq!(issue.refresh_token_policy, RefreshTokenPolicy::IssueNew);
    assert_eq!(issue.dpop_jkt.as_deref(), Some("dpop-jkt"));
    assert_eq!(issue.refresh_token_dpop_jkt.as_deref(), Some("dpop-jkt"));
    assert_eq!(issue.scopes, vec!["openid", "offline_access"]);
}

#[test]
fn ciba_token_grant_state_rejects_other_client_auth_req_id_as_invalid_grant() {
    let key = generate_key_material(jsonwebtoken::Algorithm::PS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let mut ciba = CibaRequestState {
        client_id: "client-1".to_owned(),
        user_id: Uuid::now_v7(),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        acr: None,
        binding_message: None,
        issued_at: Utc::now().timestamp(),
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: Utc::now().timestamp() + 600,
        retention_expires_at: Utc::now().timestamp() + 720,
        last_poll_at: None,
    };
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.client_id = "client-2".to_owned();

    let response = ciba_auth_req_id_client_error(&ciba, &client)
        .expect("auth_req_id issued to another client must be rejected");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_grant")
    );

    ciba.client_id = client.client_id.clone();
    assert!(ciba_auth_req_id_client_error(&ciba, &client).is_none());
}

#[actix_web::test]
async fn ciba_token_request_validates_mtls_before_auth_req_id_state() {
    let state = ciba_test_state_with(|settings| {
        settings.enable_ciba = true;
    });
    let key = generate_key_material(jsonwebtoken::Algorithm::PS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_mtls_bound_tokens = true;
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let form = TokenForm {
        grant_type: CIBA_GRANT_TYPE.to_owned(),
        code: None,
        device_code: None,
        auth_req_id: Some("missing-auth-req-id".to_owned()),
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        audiences: Vec::new(),
        has_audience_param: false,
    };

    let response = token_ciba(&state, &req, &client, &form, None, "private_key_jwt").await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_grant")
    );
}

#[test]
fn ciba_signed_request_object_missing_audience_maps_to_invalid_request() {
    let state = ciba_test_state();
    let key = generate_key_material(jsonwebtoken::Algorithm::PS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let client = ciba_private_key_jwt_client("ciba-kid", &key);
    let request_object = signed_ciba_request_object("ciba-kid", &key, json!({"aud": null}));
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        ..BackchannelAuthenticationForm::default()
    };

    let response = validate_and_apply_ciba_request_object_claims(&state, &client, &mut form)
        .expect_err("missing CIBA request object audience must be invalid_request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_request")
    );
    assert!(form.scope.is_none());
}

#[test]
fn ciba_signed_request_object_missing_required_claim_maps_to_invalid_request() {
    for claim in ["iss", "aud", "iat", "nbf", "exp", "jti"] {
        let state = ciba_test_state();
        let key = generate_key_material(jsonwebtoken::Algorithm::PS256)
            .expect("client key should generate")
            .private_pkcs8_der;
        let client = ciba_private_key_jwt_client("ciba-kid", &key);
        let request_object = signed_ciba_request_object(
            "ciba-kid",
            &key,
            Value::Object(serde_json::Map::from_iter([(
                claim.to_owned(),
                Value::Null,
            )])),
        );
        let mut form = BackchannelAuthenticationForm {
            request: Some(request_object),
            ..BackchannelAuthenticationForm::default()
        };

        let response = validate_and_apply_ciba_request_object_claims(&state, &client, &mut form)
            .expect_err("missing CIBA request object claim must be invalid");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .extensions()
                .get::<OAuthJsonErrorFields>()
                .map(|fields| fields.error.as_str()),
            Some("invalid_request"),
            "unexpected OAuth error for missing {claim}"
        );
        assert!(
            form.scope.is_none(),
            "missing {claim} must not merge claims"
        );
    }
}

#[test]
fn ciba_rejects_rs256_request_object_signing_algorithm() {
    let state = ciba_test_state();
    let key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("client key should generate")
        .private_pkcs8_der;
    let client =
        ciba_private_key_jwt_client_with_alg("ciba-kid", jsonwebtoken::Algorithm::RS256, &key);
    let request_object = signed_ciba_request_object_with_alg(
        "ciba-kid",
        jsonwebtoken::Algorithm::RS256,
        &key,
        json!({}),
    );
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        ..BackchannelAuthenticationForm::default()
    };

    let response = validate_and_apply_ciba_request_object_claims(&state, &client, &mut form)
        .expect_err("FAPI-CIBA request objects must reject RS256");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_request")
    );
}

#[test]
fn ciba_rejects_rs256_client_assertion_algorithm() {
    assert!(!ciba_jwt_signing_algorithm_supported(
        jsonwebtoken::Algorithm::RS256
    ));
    assert!(ciba_jwt_signing_algorithm_supported(
        jsonwebtoken::Algorithm::PS256
    ));
}
