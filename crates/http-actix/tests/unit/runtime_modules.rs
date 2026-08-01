use std::sync::Mutex;

use actix_web::{
    App,
    body::to_bytes,
    cookie::Cookie,
    http::{Method, header},
    middleware::from_fn,
    test::{self as actix_test, TestRequest},
    web::{Data, Json, Path, Query},
};
use nazo_identity::{
    AccountIdentity, OrganizationId, Principal, PublicAccount, RealmId, SessionId,
    SessionRotationOutcome, SessionSnapshot, SessionVersion, TenantContext, TenantId, UserId,
    UserProfile, UserRole,
    ports::{RepositoryFuture, SessionAccountPort, SessionStorePort},
    session::SessionRecord,
};
use nazo_runtime_modules::DesiredStateRecord;
use serde_json::Value;
use uuid::Uuid;

use super::*;

const NOW_SECONDS: u64 = 10_000;

fn fixed_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW_SECONDS)
}

#[derive(Clone)]
struct FixedSessionStore {
    snapshot: SessionSnapshot,
}

impl SessionStorePort for FixedSessionStore {
    fn load<'a>(
        &'a self,
        _session_id: &'a SessionId,
    ) -> RepositoryFuture<'a, Option<SessionSnapshot>> {
        let snapshot = self.snapshot.clone();
        Box::pin(async move { Ok(Some(snapshot)) })
    }

    fn delete<'a>(&'a self, _session_id: &'a SessionId) -> RepositoryFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn rotate<'a>(
        &'a self,
        _old_session_id: &'a SessionId,
        _expected: &'a SessionSnapshot,
        _new_session_id: &'a SessionId,
        _replacement: &'a SessionRecord,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, SessionRotationOutcome> {
        Box::pin(async { Ok(SessionRotationOutcome::Conflict) })
    }

    fn compare_and_set<'a>(
        &'a self,
        _session_id: &'a SessionId,
        _expected: &'a SessionSnapshot,
        _replacement: &'a SessionRecord,
    ) -> RepositoryFuture<'a, nazo_identity::SessionUpdateOutcome> {
        Box::pin(async { Ok(nazo_identity::SessionUpdateOutcome::Conflict) })
    }
}

#[derive(Clone)]
struct FixedAccount(PublicAccount);

impl SessionAccountPort for FixedAccount {
    fn public_account_by_id(
        &self,
        _tenant_id: TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        let account = self.0.clone();
        Box::pin(async move { Ok(Some(account)) })
    }
}

struct FakeAdministration {
    list: Mutex<Result<Vec<RuntimeModuleView>, RuntimeModuleAdminError>>,
    events: Mutex<Result<ModuleEventPage, RuntimeModuleAdminError>>,
    update: Mutex<Result<DesiredStateUpdateOutcome, RuntimeModuleAdminError>>,
    updates: Mutex<Vec<DesiredStateUpdate>>,
}

impl RuntimeModuleAdministration for FakeAdministration {
    fn list(&self) -> RuntimeModuleAdminFuture<'_, Vec<RuntimeModuleView>> {
        let result = self.list.lock().unwrap().clone();
        Box::pin(async move { result })
    }

    fn events(&self, _offset: i64, _limit: i64) -> RuntimeModuleAdminFuture<'_, ModuleEventPage> {
        let result = self.events.lock().unwrap().clone();
        Box::pin(async move { result })
    }

    fn update_desired(
        &self,
        update: DesiredStateUpdate,
    ) -> RuntimeModuleAdminFuture<'_, DesiredStateUpdateOutcome> {
        self.updates.lock().unwrap().push(update);
        let result = self.update.lock().unwrap().clone();
        Box::pin(async move { result })
    }
}

fn account(admin_level: u32) -> PublicAccount {
    let tenant = TenantContext {
        tenant_id: TenantId::new(Uuid::from_u128(1)).unwrap(),
        realm_id: RealmId::new(Uuid::from_u128(2)).unwrap(),
        organization_id: OrganizationId::new(Uuid::from_u128(3)).unwrap(),
    };
    PublicAccount {
        principal: Principal {
            user_id: UserId::new(Uuid::from_u128(4)).unwrap(),
            tenant,
            role: UserRole::Admin { level: admin_level },
            active: true,
        },
        account: AccountIdentity {
            username: "admin".to_owned(),
            email: "admin@example.com".to_owned(),
            email_verified: true,
            mfa_enabled: true,
        },
        profile: UserProfile::default(),
        created_at: DateTime::<Utc>::from(UNIX_EPOCH),
        updated_at: DateTime::<Utc>::from(UNIX_EPOCH),
    }
}

fn view() -> RuntimeModuleView {
    RuntimeModuleView {
        module_id: ModuleId::Ciba,
        desired_state: DesiredMode::Disabled,
        resolved_enabled: false,
        actual_state: ModuleState::Draining,
        revision: Some(ModuleRevision::new(7)),
        transition_revision: Some(ModuleRevision::new(7)),
        applied_revision: Some(ModuleRevision::new(6)),
        dependencies: vec![ModuleId::RequestObjects],
        dependents: vec![ModuleId::Jarm],
        allowed_actions: vec![DesiredMode::Inherit, DesiredMode::Enabled],
        disable_policy: DisablePolicy::DrainStoredTransactions {
            max_duration: Duration::from_secs(300),
        },
        drain_deadline: Some(UNIX_EPOCH + Duration::from_secs(20_000)),
        failure_code: None,
        updated_at: UNIX_EPOCH + Duration::from_secs(9_999),
    }
}

fn desired_outcome() -> DesiredStateUpdateOutcome {
    DesiredStateUpdateOutcome::Accepted {
        desired: DesiredStateRecord {
            module_id: ModuleId::Ciba,
            mode: DesiredMode::Disabled,
            revision: ModuleRevision::new(8),
            actor_id: Some(Uuid::from_u128(4).to_string()),
            reason: Some("maintenance".to_owned()),
            updated_at: fixed_now(),
        },
        actual_state: ModuleState::Enabled,
    }
}

fn administration() -> Arc<FakeAdministration> {
    Arc::new(FakeAdministration {
        list: Mutex::new(Ok(vec![view()])),
        events: Mutex::new(Ok(ModuleEventPage {
            total: 0,
            events: Vec::new(),
        })),
        update: Mutex::new(Ok(desired_outcome())),
        updates: Mutex::new(Vec::new()),
    })
}

fn endpoint(
    administration: Arc<FakeAdministration>,
    admin_level: u32,
    auth_time: i64,
    amr: Vec<String>,
) -> Data<RuntimeModuleAdminEndpoint> {
    let user = account(admin_level);
    let tenant_id = user.tenant().tenant_id;
    let user_id = user.user_id();
    let snapshot = SessionSnapshot::new(
        SessionRecord::new(user_id, auth_time, amr, false, Some("oidc-sid".to_owned())),
        SessionVersion::from_storage(vec![1]),
    );
    Data::new(RuntimeModuleAdminEndpoint::with_clock(
        SessionService::new(
            Arc::new(FixedSessionStore { snapshot }),
            Arc::new(FixedAccount(user)),
            tenant_id,
        ),
        SessionCookieConfig::new("session", "csrf", true),
        administration,
        fixed_now,
    ))
}

fn authenticated_request() -> HttpRequest {
    TestRequest::default()
        .cookie(Cookie::new("session", "session-id"))
        .to_http_request()
}

fn patch_request() -> HttpRequest {
    TestRequest::default()
        .cookie(Cookie::new("session", "session-id"))
        .cookie(Cookie::new("csrf", "csrf-token"))
        .insert_header(("x-csrf-token", "csrf-token"))
        .to_http_request()
}

async fn response_json(response: HttpResponse) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap()
}

fn assert_no_store(response: &HttpResponse) {
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
}

#[actix_web::test]
async fn list_preserves_the_existing_wire_contract_and_cache_policy() {
    let response = admin_runtime_modules(
        endpoint(
            administration(),
            2,
            i64::try_from(NOW_SECONDS).unwrap() - 600,
            vec!["pwd".to_owned()],
        ),
        authenticated_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_no_store(&response);
    let body = response_json(response).await;
    assert_eq!(body["items"][0]["module_id"], "ciba");
    assert_eq!(body["items"][0]["desired_state"], "disabled");
    assert_eq!(body["items"][0]["actual_state"], "draining");
    assert_eq!(body["items"][0]["revision"], 7);
    assert_eq!(
        body["items"][0]["allowed_actions"],
        json!(["inherit", "enable"])
    );
    assert_eq!(
        body["items"][0]["disable_policy"],
        "drain_stored_transactions:300s"
    );
}

#[actix_web::test]
async fn patch_changes_only_desired_state_and_returns_pending_revision() {
    let administration = administration();
    let response = admin_patch_runtime_module(
        endpoint(
            administration.clone(),
            2,
            i64::try_from(NOW_SECONDS).unwrap() - 300,
            vec!["pwd".to_owned(), "mfa".to_owned()],
        ),
        patch_request(),
        Path::from("ciba".to_owned()),
        Json(RuntimeModulePatch {
            desired_state: DesiredMode::Disabled,
            expected_revision: 7,
            reason: "  maintenance  ".to_owned(),
            cascade: false,
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_no_store(&response);
    let body = response_json(response).await;
    assert_eq!(body["revision"], 8);
    assert_eq!(body["actual_state"], "enabled");
    assert_eq!(body["status_url"], "/admin/runtime-modules");
    let updates = administration.updates.lock().unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].reason, "maintenance");
    assert_eq!(updates[0].expected_revision, Some(ModuleRevision::new(7)));
}

#[actix_web::test]
async fn patch_checks_csrf_before_session_and_recent_mfa_policy() {
    let administration = administration();
    let missing_csrf = TestRequest::default()
        .cookie(Cookie::new("session", "session-id"))
        .to_http_request();
    let response = admin_patch_runtime_module(
        endpoint(
            administration.clone(),
            2,
            i64::try_from(NOW_SECONDS).unwrap(),
            vec!["mfa".to_owned()],
        ),
        missing_csrf,
        Path::from("ciba".to_owned()),
        Json(RuntimeModulePatch {
            desired_state: DesiredMode::Disabled,
            expected_revision: 7,
            reason: "maintenance".to_owned(),
            cascade: false,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&response);
    assert!(administration.updates.lock().unwrap().is_empty());

    let response = admin_patch_runtime_module(
        endpoint(
            administration,
            2,
            i64::try_from(NOW_SECONDS).unwrap() - 301,
            vec!["mfa".to_owned()],
        ),
        patch_request(),
        Path::from("ciba".to_owned()),
        Json(RuntimeModulePatch {
            desired_state: DesiredMode::Disabled,
            expected_revision: 7,
            reason: "maintenance".to_owned(),
            cascade: false,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
    assert_no_store(&response);
    assert_eq!(
        response_json(response).await["error"],
        "mfa_step_up_required"
    );
}

#[actix_web::test]
async fn stale_revision_is_a_non_cacheable_conflict() {
    let administration = administration();
    *administration.update.lock().unwrap() = Ok(DesiredStateUpdateOutcome::Stale {
        current_revision: Some(ModuleRevision::new(11)),
    });
    let response = admin_patch_runtime_module(
        endpoint(
            administration,
            2,
            i64::try_from(NOW_SECONDS).unwrap(),
            vec!["mfa".to_owned()],
        ),
        patch_request(),
        Path::from("ciba".to_owned()),
        Json(RuntimeModulePatch {
            desired_state: DesiredMode::Disabled,
            expected_revision: 7,
            reason: "maintenance".to_owned(),
            cascade: false,
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_no_store(&response);
    let body = response_json(response).await;
    assert_eq!(body["error"], "revision_conflict");
    assert_eq!(body["current_revision"], 11);
}

#[actix_web::test]
async fn event_pagination_rejects_out_of_bounds_before_the_port() {
    let response = admin_runtime_module_events(
        endpoint(
            administration(),
            2,
            i64::try_from(NOW_SECONDS).unwrap(),
            vec!["pwd".to_owned()],
        ),
        authenticated_request(),
        Query(RuntimeModuleEventPageQuery {
            page: Some(0),
            page_size: Some(101),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&response);
    assert_eq!(response_json(response).await["error"], "invalid_request");
}

#[actix_web::test]
async fn static_routes_lock_cors_security_method_and_preflight_contracts() {
    let endpoint = endpoint(
        administration(),
        2,
        i64::try_from(NOW_SECONDS).unwrap(),
        vec!["mfa".to_owned()],
    );
    let allowed_origin = "https://admin.example";
    let app = actix_test::init_service(
        App::new()
            .wrap(from_fn(crate::security_headers))
            .app_data(endpoint)
            .service(
                actix_web::web::scope("/admin")
                    .wrap(crate::cors_admin(&[allowed_origin.to_owned()]))
                    .route(
                        "/runtime-modules",
                        actix_web::web::get().to(admin_runtime_modules),
                    )
                    .route(
                        "/runtime-modules/events",
                        actix_web::web::get().to(admin_runtime_module_events),
                    )
                    .route(
                        "/runtime-modules/{module_id}",
                        actix_web::web::patch().to(admin_patch_runtime_module),
                    ),
            ),
    )
    .await;

    let get = actix_test::call_service(
        &app,
        TestRequest::get()
            .uri("/admin/runtime-modules")
            .insert_header((header::ORIGIN, allowed_origin))
            .cookie(Cookie::new("session", "session-id"))
            .to_request(),
    )
    .await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        allowed_origin
    );
    assert_eq!(
        get.headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );
    assert_eq!(
        get.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        get.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(get.headers().get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(
        get.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert!(!actix_test::read_body(get).await.is_empty());

    let post = actix_test::call_service(
        &app,
        TestRequest::post()
            .uri("/admin/runtime-modules")
            .insert_header((header::ORIGIN, allowed_origin))
            .to_request(),
    )
    .await;
    assert_eq!(post.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        post.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert!(post.headers().get(header::CONTENT_TYPE).is_none());
    assert!(post.headers().get(header::CACHE_CONTROL).is_none());
    assert!(actix_test::read_body(post).await.is_empty());

    let options = actix_test::call_service(
        &app,
        TestRequest::default()
            .method(Method::OPTIONS)
            .uri("/admin/runtime-modules/ciba")
            .insert_header((header::ORIGIN, allowed_origin))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH"))
            .insert_header((
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "x-csrf-token,content-type",
            ))
            .to_request(),
    )
    .await;
    assert_eq!(options.status(), StatusCode::OK);
    assert_eq!(
        options
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        allowed_origin
    );
    assert_eq!(
        options
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );
    let mut allowed_methods = options
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_METHODS)
        .unwrap()
        .to_str()
        .unwrap()
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    allowed_methods.sort_unstable();
    assert_eq!(allowed_methods, ["DELETE", "GET", "PATCH", "POST"]);
    assert_eq!(
        options
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .unwrap(),
        "nosniff"
    );
    assert!(options.headers().get(header::CONTENT_TYPE).is_none());
    assert!(actix_test::read_body(options).await.is_empty());
}

#[test]
fn module_identifiers_and_event_names_are_exhaustive() {
    for module_id in ModuleId::ALL {
        assert_eq!(parse_module_id(module_id_name(module_id)), Some(module_id));
        assert!(!module_description(module_id).is_empty());
    }
    for event_type in ModuleEventType::ALL {
        assert!(!event_type_name(event_type).is_empty());
    }
    assert_eq!(parse_module_id("unknown"), None);
}
