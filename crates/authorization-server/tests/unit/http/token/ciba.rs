use nazo_http_actix::OAuthJsonErrorFields;

use crate::test_support::TestInfrastructure;

use crate::domain::tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID};

use super::super::dispatch::validate_token_request_profile_with_profile;

fn validate_and_apply_ciba_request_object_claims(
    state: &TestInfrastructure,
    client: &ClientRow,
    form: &mut BackchannelAuthenticationForm,
) -> Result<Option<CibaRequestObjectReplay>, HttpResponse> {
    validate_and_apply_ciba_request_object_claims_with_config(
        &CibaHttpConfig::from(state.settings.as_ref()),
        client,
        form,
    )
}

fn validate_ciba_security_profile_client(
    settings: &Settings,
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    validate_ciba_security_profile_client_with_config(
        &CibaHttpConfig::from(settings),
        client,
        auth_method,
    )
}

fn validate_ciba_request_object_presence(
    settings: &Settings,
    client: &ClientRow,
    form: &BackchannelAuthenticationForm,
) -> Result<(), HttpResponse> {
    validate_ciba_request_object_presence_with_config(&CibaHttpConfig::from(settings), client, form)
}

use super::*;
use crate::config::ConfigSource;
use nazo_postgres::create_pool;

use crate::test_support::ClientSigningFixture;
use crate::test_support::client_signing_fixture;
use std::io::{self, Write};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration as StdDuration;
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

fn ciba_test_state_with(configure: impl FnOnce(&mut Settings)) -> TestInfrastructure {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    configure(&mut settings);
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_ciba_test_invalid:nazo_ciba_test_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn ciba_test_state() -> TestInfrastructure {
    ciba_test_state_with(|_| {})
}

async fn live_ciba_replay_state() -> Option<TestInfrastructure> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let valkey = live_test_valkey().await?;
    let mut settings = Settings::from_config(&ConfigSource::default())
        .expect("default CIBA test settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.modules.enable_ciba = true;
    Some(TestInfrastructure {
        diesel_db: create_pool(database_url, 2).expect("CIBA test database should build"),
        valkey,
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    })
}

async fn live_test_valkey() -> Option<nazo_valkey::test_support::Client> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    Some(
        nazo_valkey::test_support::connect(&valkey_url, StdDuration::from_secs(1))
            .await
            .expect("VALKEY_URL should point to a reachable test Valkey instance"),
    )
}

fn ciba_token_form(auth_req_id: String) -> TokenForm {
    TokenForm {
        grant_type: CIBA_GRANT_TYPE.to_owned(),
        code: None,
        device_code: None,
        auth_req_id: Some(auth_req_id),
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
    }
}

async fn store_ciba_state(
    state: &TestInfrastructure,
    client: &ClientRow,
    auth_req_id: &str,
    status: CibaStatus,
) {
    let now = Utc::now().timestamp();
    CibaStore::new(&state.valkey_connection())
        .create(
            auth_req_id,
            &CibaRequestState {
                client_id: client.client_id.clone(),
                user_id: Uuid::now_v7(),
                scopes: vec!["openid".to_owned()],
                audiences: vec!["resource://default".to_owned()],
                acr: None,
                authentication_context: None,
                binding_message: None,
                issued_at: now,
                status,
                interval_seconds: 5,
                expires_at: now + 600,
                retention_expires_at: now + 720,
                last_poll_at: None,
                ping_notification: None,
            },
        )
        .await
        .expect("CIBA state should be stored");
}

async fn call_ciba_token_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    auth_req_id: String,
) -> HttpResponse {
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let form = ciba_token_form(auth_req_id);
    let connection = state.valkey_connection();
    let ciba_service = ServerCibaService::new(CibaStore::new(&connection));
    let users = nazo_postgres::UserRepository::new(state.diesel_db.clone());
    let token_service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&connection),
        state.keyset.clone(),
    );
    let issuance_config = TokenIssuanceConfig::from(state.settings.as_ref());
    let ciba_config = CibaHttpConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = super::super::issue::test_support::test_authorization_service(state);
    let issuance = TokenIssuanceContext {
        config: &issuance_config,
        modules: &modules,
        authorization: &authorization,
    };
    let handles = CibaTokenHandles::new(
        Data::new(ciba_service),
        Data::new(users),
        Data::new(ciba_config),
    );
    token_ciba(
        CibaTokenContext {
            token_service: &token_service,
            issuance: &issuance,
            handles: &handles,
            request: &req,
        },
        client,
        &form,
        None,
        "private_key_jwt",
    )
    .await
}

#[actix_web::test]
async fn token_ciba_rejects_client_policy_before_state_access() {
    let state = ciba_test_state();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.security_policy = Some(nazo_auth::ClientSecurityPolicy {
        allow_cross_device_flows: false,
        ..nazo_auth::ClientSecurityPolicy::default()
    });

    let response = call_ciba_token_for_test(&state, &client, "not-stored".to_owned()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("unauthorized_client")
    );
}

fn ciba_private_key_jwt_client_with_alg(kid: &str, fixture: &ClientSigningFixture) -> ClientRow {
    let public_jwk = fixture.public_jwk(kid);
    client_row! {
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

fn ciba_private_key_jwt_client(kid: &str, fixture: &ClientSigningFixture) -> ClientRow {
    ciba_private_key_jwt_client_with_alg(kid, fixture)
}

fn signed_ciba_request_object_with_alg(
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    fixture: &ClientSigningFixture,
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
        "login_hint": "subject@example.test",
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
    fixture.encode_jwt(&header, &claims)
}

fn signed_ciba_request_object(
    kid: &str,
    fixture: &ClientSigningFixture,
    extra_claims: Value,
) -> String {
    signed_ciba_request_object_with_alg(kid, jsonwebtoken::Algorithm::PS256, fixture, extra_claims)
}

fn unsigned_ciba_request_object(client_id: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": client_id,
            "sub": client_id,
        }))
        .expect("payload should serialize"),
    );
    format!("{header}.{payload}.")
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
        authentication_context: None,
        binding_message: Some("sensitive binding text".to_owned()),
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: now + 60,
        retention_expires_at: now + 180,
        last_poll_at: None,
        ping_notification: None,
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

fn committed_decision_fixture(decision: CibaDecision) -> CibaCommittedDecision {
    let now = Utc::now().timestamp();
    CibaCommittedDecision {
        state: CibaRequestState {
            client_id: "client-1".to_owned(),
            user_id: Uuid::now_v7(),
            scopes: vec!["openid".to_owned()],
            audiences: vec!["resource://default".to_owned()],
            acr: None,
            authentication_context: None,
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
            ping_notification: None,
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
            CibaDecisionFailure::Storage(CibaStatePortError::CorruptData),
        ] {
            let _ = complete_ciba_decision(
                Err(failure),
                "auth-req-id",
                CibaDecisionSource::User,
                Some("source-ip-hash".to_owned()),
            );
        }
        assert_eq!(count.as_ref().load(Ordering::SeqCst), 0);

        let response = complete_ciba_decision(
            Ok(committed_decision_fixture(CibaDecision::Approve)),
            "auth-req-id",
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
            "auth-req-id",
            CibaDecisionSource::Automation,
            None,
        )
    });

    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn ciba_decision_storage_failure_maps_to_non_cacheable_server_error() {
    let response = complete_ciba_decision(
        Err(CibaDecisionFailure::Storage(
            CibaStatePortError::CorruptData,
        )),
        "auth-req-id",
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
    let response =
        ciba_poll_failure_response(CibaPollFailure::Storage(CibaStatePortError::CorruptData));

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
async fn ciba_automated_decision_oidf_query_mode_rejects_post() {
    let state = ciba_test_state_with(|settings| {
        settings.modules.enable_ciba = true;
        settings.ciba.ciba_automated_decision_token =
            Some("test-ciba-automated-decision-token-32".to_owned());
        settings.ciba.ciba_automated_decision_mode = CibaAutomatedDecisionMode::QueryParameter;
    });
    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let ciba_service =
        ServerCibaService::new(nazo_valkey::CibaStore::new(&state.valkey_connection()));
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(actix_web::web::Data::new(ciba_service))
            .app_data(actix_web::web::Data::new(CibaHttpConfig::from(
                settings.as_ref(),
            )))
            .app_data(actix_web::web::Data::from(runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = actix_web::test::TestRequest::post()
        .uri("/auth/ciba-automated-decision?token=fake&type=allow&decision_token=test-ciba-automated-decision-token-32")
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = actix_web::test::read_body(response).await;
    assert!(body.is_empty());
}

#[actix_web::test]
async fn ciba_automated_decision_header_mode_rejects_get_and_query_secret() {
    let state = ciba_test_state_with(|settings| {
        settings.modules.enable_ciba = true;
        settings.ciba.ciba_automated_decision_token =
            Some("test-ciba-automated-decision-token-32".to_owned());
        settings.ciba.ciba_automated_decision_mode = CibaAutomatedDecisionMode::Header;
    });
    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let ciba_service =
        ServerCibaService::new(nazo_valkey::CibaStore::new(&state.valkey_connection()));
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(actix_web::web::Data::new(ciba_service))
            .app_data(actix_web::web::Data::new(CibaHttpConfig::from(
                settings.as_ref(),
            )))
            .app_data(actix_web::web::Data::from(runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = actix_web::test::TestRequest::get()
        .uri("/auth/ciba-automated-decision?token=fake&type=allow&decision_token=test-ciba-automated-decision-token-32")
        .insert_header((header::AUTHORIZATION, "Bearer test-ciba-automated-decision-token-32"))
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(actix_web::test::read_body(response).await.is_empty());
}

#[actix_web::test]
async fn disabled_ciba_automated_decision_rejects_invalid_token_before_state_access() {
    let database_url =
        match std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL")) {
            Ok(database_url) => database_url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!("CI requires a database URL for leased CIBA decision coverage")
            }
            Err(_) => return,
        };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("leased CIBA decision migrations should apply");
    let pool = create_pool(database_url, 2).expect("test database pool should initialize");
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.modules.enable_ciba = true;
    settings.ciba.ciba_automated_decision_mode = CibaAutomatedDecisionMode::Disabled;
    settings.ciba.ciba_automated_decision_token = None;
    let settings = Arc::new(settings);
    let leases = nazo_postgres::ConformanceLeaseRepository::new(pool.clone());
    let valid_token_sha256 = sha256_hex(b"valid-per-run-ciba-decision-token");
    let lease = leases
        .create(
            DEFAULT_TENANT_ID,
            CIBA_AUTOMATED_DECISION_PROFILE,
            &format!("{:064x}", Uuid::now_v7().as_u128()),
            nazo_postgres::ConformanceLeaseTokenDigests {
                dynamic_registration_initial_access_token_sha256: None,
                ciba_automated_decision_token_sha256: Some(&valid_token_sha256),
            },
            None,
            60,
        )
        .await
        .expect("leased CIBA decision credential should be stored");
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        pool.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let disconnected_valkey = fred::prelude::Builder::default_centralized()
        .build()
        .expect("disconnected test Valkey client should construct");
    let disconnected_connection =
        nazo_valkey::ValkeyConnection::from_existing_client(disconnected_valkey);
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(actix_web::web::Data::new(ServerCibaService::new(
                CibaStore::new(&disconnected_connection),
            )))
            .app_data(actix_web::web::Data::new(leases.clone()))
            .app_data(actix_web::web::Data::new(CibaHttpConfig::from(
                settings.as_ref(),
            )))
            .app_data(actix_web::web::Data::from(runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    // A state lookup would hit the deliberately disconnected Valkey client and
    // produce a service error. NOT_FOUND therefore proves the invalid digest
    // was rejected at the lease lookup boundary before state access.
    let request = actix_web::test::TestRequest::post()
        .uri("/auth/ciba-automated-decision?token=not-stored&type=allow&decision_token=invalid-per-run-token")
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(actix_web::test::read_body(response).await.is_empty());

    leases
        .revoke(DEFAULT_TENANT_ID, lease.id)
        .await
        .expect("leased CIBA decision credential should be revocable");
}

#[actix_web::test]
async fn disabled_ciba_automated_decision_enforces_lease_client_binding_for_oidf_post() {
    let database_url =
        match std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL")) {
            Ok(database_url) => database_url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!("CI requires a database URL for leased CIBA decision coverage")
            }
            Err(_) => return,
        };
    let valkey = match live_test_valkey().await {
        Some(valkey) => valkey,
        None if std::env::var_os("CI").is_some() => {
            panic!("CI requires VALKEY_URL for leased CIBA decision coverage")
        }
        None => return,
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("leased CIBA decision migrations should apply");
    let pool = create_pool(database_url, 2).expect("test database pool should initialize");
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.modules.enable_ciba = true;
    settings.ciba.ciba_automated_decision_mode = CibaAutomatedDecisionMode::Disabled;
    settings.ciba.ciba_automated_decision_token = None;
    let settings = Arc::new(settings);
    let state = TestInfrastructure {
        diesel_db: pool.clone(),
        valkey,
        settings: Arc::clone(&settings),
        keyset: crate::test_support::test_key_manager(),
    };
    let leases = nazo_postgres::ConformanceLeaseRepository::new(pool.clone());
    let clients = nazo_postgres::OAuthClientRepository::new(pool.clone());
    let token_a = format!("lease-a-{}", Uuid::now_v7());
    let token_b = format!("lease-b-{}", Uuid::now_v7());
    let digest_a = sha256_hex(token_a.as_bytes());
    let digest_b = sha256_hex(token_b.as_bytes());
    let lease_a = leases
        .create(
            DEFAULT_TENANT_ID,
            CIBA_AUTOMATED_DECISION_PROFILE,
            &format!("{:064x}", Uuid::now_v7().as_u128()),
            nazo_postgres::ConformanceLeaseTokenDigests {
                dynamic_registration_initial_access_token_sha256: None,
                ciba_automated_decision_token_sha256: Some(&digest_a),
            },
            None,
            60,
        )
        .await
        .expect("lease A should be stored");
    let lease_b = leases
        .create(
            DEFAULT_TENANT_ID,
            CIBA_AUTOMATED_DECISION_PROFILE,
            &format!("{:064x}", Uuid::now_v7().as_u128()),
            nazo_postgres::ConformanceLeaseTokenDigests {
                dynamic_registration_initial_access_token_sha256: None,
                ciba_automated_decision_token_sha256: Some(&digest_b),
            },
            None,
            60,
        )
        .await
        .expect("lease B should be stored");
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client_a = ciba_private_key_jwt_client("lease-a-kid", &key);
    client_a.client_id = format!("lease-a-client-{}", Uuid::now_v7());
    let mut client_b = ciba_private_key_jwt_client("lease-b-kid", &key);
    client_b.client_id = format!("lease-b-client-{}", Uuid::now_v7());
    clients
        .insert(&client_a, None, None, Some(lease_a.id))
        .await
        .expect("lease A client should be stored");
    clients
        .insert(&client_b, None, None, Some(lease_b.id))
        .await
        .expect("lease B client should be stored");
    let auth_req_id = format!("cross-lease-{}", Uuid::now_v7());
    store_ciba_state(&state, &client_b, &auth_req_id, CibaStatus::Pending).await;
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        pool.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let ciba_service = actix_web::web::Data::new(ServerCibaService::new(CibaStore::new(
        &state.valkey_connection(),
    )));
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(ciba_service.clone())
            .app_data(actix_web::web::Data::new(leases.clone()))
            .app_data(actix_web::web::Data::new(CibaHttpConfig::from(
                settings.as_ref(),
            )))
            .app_data(actix_web::web::Data::from(runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = actix_web::test::TestRequest::post()
        .uri(&format!(
            "/auth/ciba-automated-decision?token={auth_req_id}&type=allow&decision_token={token_a}"
        ))
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(actix_web::test::read_body(response).await.is_empty());
    let state_after = match load_ciba_request_payload(&ciba_service, &auth_req_id).await {
        Ok(Some(state_after)) => state_after,
        Ok(None) => panic!("cross-lease rejection must retain the CIBA transaction"),
        Err(_) => panic!("cross-lease rejection must leave readable CIBA state"),
    };
    assert_eq!(state_after.status, CibaStatus::Pending);

    let request = actix_web::test::TestRequest::post()
        .uri(&format!(
            "/auth/ciba-automated-decision?token={auth_req_id}&type=allow&decision_token={token_b}"
        ))
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let state_after = match load_ciba_request_payload(&ciba_service, &auth_req_id).await {
        Ok(Some(state_after)) => state_after,
        Ok(None) => panic!("same-lease approval must retain the CIBA transaction until polling"),
        Err(_) => panic!("same-lease approval must leave readable CIBA state"),
    };
    assert_eq!(state_after.status, CibaStatus::Approved);

    leases
        .revoke(DEFAULT_TENANT_ID, lease_a.id)
        .await
        .expect("lease A should be revocable");
    leases
        .revoke(DEFAULT_TENANT_ID, lease_b.id)
        .await
        .expect("lease B should be revocable");

    // Revocation is checked on every request, not only when the lease is
    // created. The same credential must fail closed after its lease is
    // revoked, while the already committed CIBA decision remains intact.
    let request = actix_web::test::TestRequest::post()
        .uri(&format!(
            "/auth/ciba-automated-decision?token={auth_req_id}&type=allow&decision_token={token_b}"
        ))
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(actix_web::test::read_body(response).await.is_empty());
    let state_after = match load_ciba_request_payload(&ciba_service, &auth_req_id).await {
        Ok(Some(state_after)) => state_after,
        Ok(None) => panic!("revocation must retain the CIBA transaction"),
        Err(_) => panic!("revocation must leave readable CIBA state"),
    };
    assert_eq!(state_after.status, CibaStatus::Approved);
}

#[actix_web::test]
async fn disabled_ciba_automated_decision_rejects_expired_lease() {
    let database_url =
        match std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL")) {
            Ok(database_url) => database_url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!("CI requires a database URL for leased CIBA decision coverage")
            }
            Err(_) => return,
        };
    let valkey = match live_test_valkey().await {
        Some(valkey) => valkey,
        None if std::env::var_os("CI").is_some() => {
            panic!("CI requires VALKEY_URL for leased CIBA decision coverage")
        }
        None => return,
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("leased CIBA decision migrations should apply");
    let pool = create_pool(database_url, 2).expect("test database pool should initialize");
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.modules.enable_ciba = true;
    settings.ciba.ciba_automated_decision_mode = CibaAutomatedDecisionMode::Disabled;
    settings.ciba.ciba_automated_decision_token = None;
    let settings = Arc::new(settings);
    let state = TestInfrastructure {
        diesel_db: pool.clone(),
        valkey,
        settings: Arc::clone(&settings),
        keyset: crate::test_support::test_key_manager(),
    };
    let leases = nazo_postgres::ConformanceLeaseRepository::new(pool.clone());
    let clients = nazo_postgres::OAuthClientRepository::new(pool.clone());
    let token = format!("expired-lease-{}", Uuid::now_v7());
    let digest = sha256_hex(token.as_bytes());
    let lease = leases
        .create(
            DEFAULT_TENANT_ID,
            CIBA_AUTOMATED_DECISION_PROFILE,
            &format!("{:064x}", Uuid::now_v7().as_u128()),
            nazo_postgres::ConformanceLeaseTokenDigests {
                dynamic_registration_initial_access_token_sha256: None,
                ciba_automated_decision_token_sha256: Some(&digest),
            },
            None,
            60,
        )
        .await
        .expect("expired lease should be stored");
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("expired-lease-kid", &key);
    client.client_id = format!("expired-lease-client-{}", Uuid::now_v7());
    clients
        .insert(&client, None, None, Some(lease.id))
        .await
        .expect("expired lease client should be stored");
    let auth_req_id = format!("expired-lease-{}", Uuid::now_v7());
    store_ciba_state(&state, &client, &auth_req_id, CibaStatus::Pending).await;

    // Expire the lease in the database before the request. This exercises the
    // repository's `expires_at > CURRENT_TIMESTAMP` gate rather than relying
    // on a client-side clock or a cleanup task having run first.
    {
        use diesel_async::RunQueryDsl as _;
        let mut connection = nazo_postgres::get_conn(&pool)
            .await
            .expect("test database connection should be available");
        diesel::sql_query(
            "UPDATE conformance_leases SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 minute' WHERE id = $1",
        )
        .bind::<diesel::sql_types::Uuid, _>(lease.id)
        .execute(&mut connection)
        .await
        .expect("lease expiry should be writable");
    }

    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        pool.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let ciba_service = actix_web::web::Data::new(ServerCibaService::new(CibaStore::new(
        &state.valkey_connection(),
    )));
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(ciba_service.clone())
            .app_data(actix_web::web::Data::new(leases.clone()))
            .app_data(actix_web::web::Data::new(CibaHttpConfig::from(
                settings.as_ref(),
            )))
            .app_data(actix_web::web::Data::from(runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = actix_web::test::TestRequest::post()
        .uri(&format!(
            "/auth/ciba-automated-decision?token={auth_req_id}&type=allow&decision_token={token}"
        ))
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(actix_web::test::read_body(response).await.is_empty());
    let state_after = match load_ciba_request_payload(&ciba_service, &auth_req_id).await {
        Ok(Some(state_after)) => state_after,
        Ok(None) => panic!("expired lease must retain the CIBA transaction"),
        Err(_) => panic!("expired lease must leave readable CIBA state"),
    };
    assert_eq!(state_after.status, CibaStatus::Pending);

    leases
        .cleanup()
        .await
        .expect("expired CIBA lease should be cleanable");
}

#[test]
fn ciba_automated_decision_transport_keeps_header_and_oidf_query_separate() {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.ciba.ciba_automated_decision_mode = CibaAutomatedDecisionMode::Header;
    let mut config = CibaHttpConfig::from(&settings);
    let header_request = actix_web::test::TestRequest::post()
        .insert_header((header::AUTHORIZATION, "Bearer header-secret"))
        .to_http_request();
    let mut query = CibaAutomatedDecisionQuery {
        token: Some("request-id".to_owned()),
        auth_req_id: None,
        r#type: Some("allow".to_owned()),
        action: None,
        decision_token: None,
    };
    assert_eq!(
        ciba_automated_decision_request_token(&config, &header_request, &query).as_deref(),
        Some("header-secret")
    );

    query.decision_token = Some("query-secret".to_owned());
    assert!(ciba_automated_decision_request_token(&config, &header_request, &query).is_none());

    config.automated_decision_mode = CibaAutomatedDecisionMode::QueryParameter;
    let get_request = actix_web::test::TestRequest::get().to_http_request();
    assert_eq!(
        ciba_automated_decision_request_token(&config, &get_request, &query).as_deref(),
        Some("query-secret")
    );

    config.automated_decision_mode = CibaAutomatedDecisionMode::Disabled;
    let post_request = actix_web::test::TestRequest::post().to_http_request();
    assert_eq!(
        ciba_automated_decision_request_token(&config, &post_request, &query).as_deref(),
        Some("query-secret")
    );
    assert!(ciba_automated_decision_request_token(&config, &get_request, &query).is_none());
}

#[actix_web::test]
async fn ciba_verification_page_preserves_redirect_and_non_cacheable_headers() {
    let state = ciba_test_state_with(|settings| {
        settings.modules.enable_ciba = true;
        settings.endpoint.frontend_base_url = "https://frontend.example/".to_owned();
    });
    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(actix_web::web::Data::new(CibaHttpConfig::from(
                settings.as_ref(),
            )))
            .app_data(actix_web::web::Data::from(runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = actix_web::test::TestRequest::get()
        .uri("/ciba/auth-request-id")
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("https://frontend.example/ciba/auth-request-id")
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(header::PRAGMA)
            .and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
}

#[test]
fn ciba_signed_request_object_claims_apply_to_backchannel_form() {
    let state = ciba_test_state();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
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
    assert_eq!(form.login_hint.as_deref(), Some("subject@example.test"));
    assert_eq!(form.binding_message.as_deref(), Some("1234"));
    assert_eq!(form.acr_values.as_deref(), Some("1"));
    assert_eq!(form.requested_expiry_seconds, Some(30));
}

#[test]
fn ciba_request_object_presence_enforces_client_policy() {
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
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
fn fapi_ciba_id1_requires_a_signed_backchannel_authentication_request() {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("ciba-kid", &key);

    let response = validate_ciba_request_object_presence(
        &settings,
        &client,
        &BackchannelAuthenticationForm::default(),
    )
    .expect_err("FAPI-CIBA ID1 requires a signed request object");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn fapi_ciba_id1_accepts_both_private_key_jwt_and_mtls_client_authentication() {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_mtls_bound_tokens = true;

    validate_ciba_security_profile_client(&settings, &client, "private_key_jwt")
        .expect("FAPI-CIBA ID1 supports private_key_jwt");
    client.token_endpoint_auth_method = "tls_client_auth".to_owned();
    validate_ciba_security_profile_client(&settings, &client, "tls_client_auth")
        .expect("FAPI-CIBA ID1 supports mTLS client authentication");

    let response = validate_ciba_security_profile_client(&settings, &client, "client_secret_post")
        .expect_err("FAPI-CIBA ID1 must reject shared-secret client authentication");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn ciba_ping_requires_a_registered_endpoint_and_high_entropy_notification_token() {
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.backchannel_token_delivery_mode = "ping".to_owned();
    client.backchannel_client_notification_endpoint =
        Some("https://client.example/ciba-notification".to_owned());

    let missing =
        validate_ciba_delivery_request(&client, &BackchannelAuthenticationForm::default())
            .expect_err("ping requests require client_notification_token");
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

    let weak = BackchannelAuthenticationForm {
        client_notification_token: Some("too-short".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };
    assert!(validate_ciba_delivery_request(&client, &weak).is_err());

    let valid = BackchannelAuthenticationForm {
        client_notification_token: Some("notification-token-0123456789".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };
    validate_ciba_delivery_request(&client, &valid)
        .expect("registered ping clients may supply a bearer notification token");
}

#[test]
fn ciba_poll_rejects_ping_only_notification_credentials() {
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("ciba-kid", &key);
    let form = BackchannelAuthenticationForm {
        client_notification_token: Some("notification-token-0123456789".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };

    assert!(validate_ciba_delivery_request(&client, &form).is_err());
}

#[test]
fn ciba_profile_does_not_apply_authorization_code_only_controls() {
    let mut settings = ciba_test_state().settings.as_ref().clone();
    settings.protocol.authorization_server_profile =
        crate::settings::AuthorizationServerProfile::Fapi2Security;
    settings.protocol.require_pushed_authorization_requests = true;
    settings.protocol.ciba_security_profile = crate::settings::CibaSecurityProfile::FapiCibaId1;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_mtls_bound_tokens = true;
    let form = BackchannelAuthenticationForm {
        request: Some("signed-request-object".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };

    validate_token_request_profile_with_profile(
        settings.protocol.authorization_server_profile,
        &client,
        "private_key_jwt",
    )
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
    settings.protocol.ciba_security_profile = crate::settings::CibaSecurityProfile::Fapi2Ciba;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
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
    settings.protocol.ciba_security_profile = crate::settings::CibaSecurityProfile::Fapi2Ciba;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
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
    settings.protocol.ciba_security_profile = crate::settings::CibaSecurityProfile::Fapi2Ciba;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
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

    settings.protocol.ciba_security_profile = crate::settings::CibaSecurityProfile::FapiCibaId1;
    validate_ciba_security_profile_client(&settings, &client, "private_key_jwt")
        .expect("FAPI-CIBA ID1 permits the registered token endpoint as assertion audience");
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
        authentication_context: None,
        binding_message: None,
        issued_at: Utc::now().timestamp(),
        status: CibaStatus::Approved,
        interval_seconds: 5,
        expires_at: Utc::now().timestamp() + 600,
        retention_expires_at: Utc::now().timestamp() + 720,
        last_poll_at: None,
        ping_notification: None,
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
fn ciba_token_issue_transfers_approved_authentication_context() {
    let user_id = Uuid::now_v7();
    let ciba = CibaRequestState {
        client_id: "client-1".to_owned(),
        user_id,
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        acr: Some("1".to_owned()),
        authentication_context: Some(CibaAuthenticationContext {
            auth_time: 1_700_000_000,
            amr: vec!["pwd".to_owned(), "otp".to_owned()],
            oidc_sid: Some("sid-approved".to_owned()),
        }),
        binding_message: None,
        issued_at: 1_700_000_100,
        status: CibaStatus::Approved,
        interval_seconds: 5,
        expires_at: 1_700_000_600,
        retention_expires_at: 1_700_000_720,
        last_poll_at: None,
        ping_notification: None,
    };

    let issue = ciba_token_issue(user_id, "subject-1".to_owned(), ciba, None, None);

    assert_eq!(issue.auth_time, Some(1_700_000_000));
    assert_eq!(issue.amr, vec!["pwd", "otp"]);
    assert_eq!(issue.oidc_sid.as_deref(), Some("sid-approved"));
}

#[test]
fn ciba_token_grant_state_rejects_other_client_auth_req_id_as_invalid_grant() {
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut ciba = CibaRequestState {
        client_id: "client-1".to_owned(),
        user_id: Uuid::now_v7(),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        acr: None,
        authentication_context: None,
        binding_message: None,
        issued_at: Utc::now().timestamp(),
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: Utc::now().timestamp() + 600,
        retention_expires_at: Utc::now().timestamp() + 720,
        last_poll_at: None,
        ping_notification: None,
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
async fn ciba_token_request_requires_mtls_binding_before_pending_state() {
    let Some(valkey) = live_test_valkey().await else {
        return;
    };
    let mut state = ciba_test_state_with(|settings| {
        settings.modules.enable_ciba = true;
    });
    state.valkey = valkey;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_mtls_bound_tokens = true;
    let auth_req_id = format!("pending-mtls-{}", Uuid::now_v7());
    store_ciba_state(&state, &client, &auth_req_id, CibaStatus::Pending).await;

    let response = call_ciba_token_for_test(&state, &client, auth_req_id).await;

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
async fn ciba_token_request_validates_mtls_binding_before_issuing_approved_token() {
    let Some(valkey) = live_test_valkey().await else {
        return;
    };
    let mut state = ciba_test_state_with(|settings| {
        settings.modules.enable_ciba = true;
    });
    state.valkey = valkey;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_mtls_bound_tokens = true;
    let auth_req_id = format!("approved-mtls-{}", Uuid::now_v7());
    store_ciba_state(&state, &client, &auth_req_id, CibaStatus::Approved).await;

    let response = call_ciba_token_for_test(&state, &client, auth_req_id).await;

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
async fn ciba_replay_rejects_a_consumed_auth_req_id_even_with_a_persisted_response() {
    let Some(state) = live_ciba_replay_state().await else {
        return;
    };
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("ciba-replay-kid", &key);
    let auth_req_id = format!("ciba-replay-{}", Uuid::now_v7());
    let grant_key = ciba_grant_key(&auth_req_id, None, None);

    crate::http::token::issue::tests::persist_token_issuance_response_for_test(
        &state, &client, &grant_key,
    )
    .await;

    let response = call_ciba_token_for_test(&state, &client, auth_req_id).await;
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
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
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
fn ciba_mtls_lookup_may_use_signed_request_object_issuer_as_hint() {
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let request_object = signed_ciba_request_object(
        "ciba-kid",
        &key,
        json!({
            "nbf": null,
            "sub": "client-1"
        }),
    );
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        ..BackchannelAuthenticationForm::default()
    };

    apply_ciba_request_object_client_id_hint(&mut form, false, false);

    assert_eq!(form.client_id.as_deref(), Some("client-1"));
}

#[test]
fn ciba_lookup_hint_never_trusts_unsigned_request_object_or_mixed_auth() {
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let signed = signed_ciba_request_object("ciba-kid", &key, json!({"sub": "client-1"}));
    let mut unsigned = BackchannelAuthenticationForm {
        request: Some(unsigned_ciba_request_object("client-1")),
        ..BackchannelAuthenticationForm::default()
    };
    let mut basic = BackchannelAuthenticationForm {
        request: Some(signed),
        ..BackchannelAuthenticationForm::default()
    };

    apply_ciba_request_object_client_id_hint(&mut unsigned, false, false);
    apply_ciba_request_object_client_id_hint(&mut basic, true, false);

    assert!(unsigned.client_id.is_none());
    assert!(basic.client_id.is_none());
}

#[test]
fn ciba_signed_request_object_missing_required_claim_maps_to_invalid_request() {
    for claim in ["iss", "aud", "iat", "nbf", "exp", "jti"] {
        let state = ciba_test_state();
        let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
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
    let key = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let client = ciba_private_key_jwt_client_with_alg("ciba-kid", &key);
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
