use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use actix_web::{
    HttpRequest, HttpResponse,
    http::StatusCode,
    web::{Data, Json, Path, Query},
};
use chrono::{DateTime, Utc};
use nazo_identity::{CurrentSession, SessionResolution, SessionService};
use nazo_runtime_modules::{
    DesiredMode, DesiredStateUpdate, DesiredStateUpdateOutcome, DisablePolicy, ModuleEventPage,
    ModuleEventRecord, ModuleEventState, ModuleEventType, ModuleId, ModuleRevision, ModuleState,
    RuntimeModuleView,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    SessionCookieConfig, csrf_error, json_response_no_store, json_response_status_no_store,
    oauth_error,
};

const MFA_STEP_UP_MAX_AGE: Duration = Duration::from_secs(5 * 60);
const MFA_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_REASON_CHARS: usize = 500;

pub type RuntimeModuleAdminFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RuntimeModuleAdminError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeModuleAdminError {
    Unavailable,
    PolicyConflict,
    CatalogInconsistent,
}

/// Infrastructure-neutral administration port used by the Actix adapter.
pub trait RuntimeModuleAdministration: Send + Sync {
    fn list(&self) -> RuntimeModuleAdminFuture<'_, Vec<RuntimeModuleView>>;

    fn events(&self, offset: i64, limit: i64) -> RuntimeModuleAdminFuture<'_, ModuleEventPage>;

    fn update_desired(
        &self,
        update: DesiredStateUpdate,
    ) -> RuntimeModuleAdminFuture<'_, DesiredStateUpdateOutcome>;
}

/// Focused dependencies for runtime-module administration endpoints.
#[derive(Clone)]
pub struct RuntimeModuleAdminEndpoint {
    sessions: SessionService,
    cookies: SessionCookieConfig,
    administration: Arc<dyn RuntimeModuleAdministration>,
    now: fn() -> SystemTime,
}

impl RuntimeModuleAdminEndpoint {
    #[must_use]
    pub fn new(
        sessions: SessionService,
        cookies: SessionCookieConfig,
        administration: Arc<dyn RuntimeModuleAdministration>,
    ) -> Self {
        Self::with_clock(sessions, cookies, administration, SystemTime::now)
    }

    #[must_use]
    pub fn with_clock(
        sessions: SessionService,
        cookies: SessionCookieConfig,
        administration: Arc<dyn RuntimeModuleAdministration>,
        now: fn() -> SystemTime,
    ) -> Self {
        Self {
            sessions,
            cookies,
            administration,
            now,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeModulePatch {
    desired_state: DesiredMode,
    expected_revision: u64,
    reason: String,
    #[serde(default)]
    cascade: bool,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeModuleEventPageQuery {
    page: Option<i32>,
    page_size: Option<i32>,
}

pub async fn admin_runtime_modules(
    endpoint: Data<RuntimeModuleAdminEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    if let Err(response) = require_runtime_admin(&endpoint, &request, false).await {
        return response;
    }
    match endpoint.administration.list().await {
        Ok(items) => json_response_no_store(json!({
            "items": items.iter().map(runtime_module_json).collect::<Vec<_>>(),
        })),
        Err(error) => management_error(error),
    }
}

pub async fn admin_runtime_module_events(
    endpoint: Data<RuntimeModuleAdminEndpoint>,
    request: HttpRequest,
    Query(query): Query<RuntimeModuleEventPageQuery>,
) -> HttpResponse {
    if let Err(response) = require_runtime_admin(&endpoint, &request, false).await {
        return response;
    }
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(20);
    if page < 1 || !(1..=100).contains(&page_size) {
        return no_store(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "page and page_size are out of bounds.",
        ));
    }
    let offset = i64::from(page - 1) * i64::from(page_size);
    match endpoint
        .administration
        .events(offset, i64::from(page_size))
        .await
    {
        Ok(result) => json_response_no_store(json!({
            "total": result.total,
            "page": page,
            "page_size": page_size,
            "items": result.events.iter().map(runtime_event_json).collect::<Vec<_>>(),
        })),
        Err(error) => management_error(error),
    }
}

pub async fn admin_patch_runtime_module(
    endpoint: Data<RuntimeModuleAdminEndpoint>,
    request: HttpRequest,
    path: Path<String>,
    Json(payload): Json<RuntimeModulePatch>,
) -> HttpResponse {
    if !endpoint.cookies.has_valid_csrf_token(&request, None) {
        return no_store(csrf_error());
    }
    let admin = match require_runtime_admin(&endpoint, &request, true).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let Some(module_id) = parse_module_id(&path) else {
        return no_store(oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "Unknown runtime module.",
        ));
    };
    let reason = match validated_reason(&payload) {
        Ok(reason) => reason,
        Err(description) => {
            return no_store(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                description,
            ));
        }
    };
    let now = (endpoint.now)();
    let update = DesiredStateUpdate {
        module_id,
        desired_state: payload.desired_state,
        expected_revision: (payload.expected_revision != 0)
            .then(|| ModuleRevision::new(payload.expected_revision)),
        actor_id: admin.user().id().to_string(),
        reason,
        changed_at: now,
    };
    match endpoint.administration.update_desired(update).await {
        Ok(DesiredStateUpdateOutcome::Accepted {
            desired,
            actual_state,
        }) => json_response_status_no_store(
            StatusCode::ACCEPTED,
            json!({
                "module_id": module_id_name(module_id),
                "desired_state": desired_mode_name(desired.mode),
                "revision": desired.revision.get(),
                "actual_state": actual_state_name(actual_state),
                "status_url": "/admin/runtime-modules",
            }),
        ),
        Ok(DesiredStateUpdateOutcome::Stale { current_revision }) => json_response_status_no_store(
            StatusCode::CONFLICT,
            json!({
                "error": "revision_conflict",
                "error_description": "Runtime module desired state changed concurrently.",
                "current_revision": current_revision.map_or(0, ModuleRevision::get),
            }),
        ),
        Err(error) => management_error(error),
    }
}

async fn require_runtime_admin(
    endpoint: &RuntimeModuleAdminEndpoint,
    request: &HttpRequest,
    require_recent_mfa: bool,
) -> Result<Box<CurrentSession>, HttpResponse> {
    let Some(session_id) = endpoint.cookies.session_id(request) else {
        return Err(admin_required());
    };
    let now = (endpoint.now)();
    let now_seconds = unix_timestamp(now);
    let session = match endpoint.sessions.current(&session_id, now_seconds).await {
        Ok(SessionResolution::Present(session)) => session,
        Ok(SessionResolution::Missing | SessionResolution::Invalidated) => {
            return Err(admin_required());
        }
        Err(_) => {
            return Err(no_store(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Session lookup failed.",
            )));
        }
    };
    if session.user().admin_level() < 2 {
        return Err(no_store(oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "Administrator level 2 is required.",
        )));
    }
    if require_recent_mfa && !recent_mfa(&session, now_seconds) {
        return Err(no_store(oauth_error(
            StatusCode::PRECONDITION_REQUIRED,
            "mfa_step_up_required",
            "Recent MFA verification is required.",
        )));
    }
    Ok(session)
}

fn admin_required() -> HttpResponse {
    no_store(oauth_error(
        StatusCode::FORBIDDEN,
        "access_denied",
        "Administrator access is required.",
    ))
}

fn recent_mfa(session: &CurrentSession, now: i64) -> bool {
    let max_age = i64::try_from(MFA_STEP_UP_MAX_AGE.as_secs()).expect("MFA max age fits i64");
    session.amr().iter().any(|method| method == "mfa")
        && session.auth_time() <= now.saturating_add(MFA_CLOCK_SKEW_SECONDS)
        && now.saturating_sub(session.auth_time()) <= max_age
}

fn validated_reason(payload: &RuntimeModulePatch) -> Result<String, &'static str> {
    let reason = payload.reason.trim();
    if reason.is_empty() || reason.chars().count() > MAX_REASON_CHARS {
        return Err("reason must contain between 1 and 500 characters.");
    }
    if payload.cascade {
        return Err("cascade is not supported; change dependent modules explicitly.");
    }
    Ok(reason.to_owned())
}

fn management_error(error: RuntimeModuleAdminError) -> HttpResponse {
    match error {
        RuntimeModuleAdminError::Unavailable => no_store(oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Runtime module state is unavailable.",
        )),
        RuntimeModuleAdminError::PolicyConflict => no_store(oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "Runtime module dependencies or disable policy reject this change.",
        )),
        RuntimeModuleAdminError::CatalogInconsistent => no_store(oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Runtime module catalog is inconsistent.",
        )),
    }
}

fn runtime_module_json(module: &RuntimeModuleView) -> Value {
    json!({
        "module_id": module_id_name(module.module_id),
        "description": module_description(module.module_id),
        "desired_state": desired_mode_name(module.desired_state),
        "resolved_enabled": module.resolved_enabled,
        "actual_state": actual_state_name(module.actual_state),
        "revision": module.revision.map_or(0, ModuleRevision::get),
        "transition_revision": module.transition_revision.map(ModuleRevision::get),
        "applied_revision": module.applied_revision.map(ModuleRevision::get),
        "dependencies": module.dependencies.iter().copied().map(module_id_name).collect::<Vec<_>>(),
        "dependents": module.dependents.iter().copied().map(module_id_name).collect::<Vec<_>>(),
        "allowed_actions": module.allowed_actions.iter().copied().map(action_name).collect::<Vec<_>>(),
        "disable_policy": disable_policy_name(module.disable_policy),
        "drain_deadline": module.drain_deadline.map(timestamp),
        "failure_code": module.failure_code,
        "updated_at": timestamp(module.updated_at),
    })
}

fn runtime_event_json(event: &ModuleEventRecord) -> Value {
    json!({
        "event_id": event.event_id,
        "module_id": module_id_name(event.module_id),
        "event_type": event_type_name(event.event_type),
        "instance_id": event.instance_id,
        "actor_id": event.actor_id,
        "reason": event.reason,
        "before_state": event.before.map(event_state_name),
        "after_state": event.after.map(event_state_name),
        "revision": event.revision.get(),
        "outcome_code": event.outcome_code,
        "created_at": timestamp(event.occurred_at),
    })
}

fn no_store(mut response: HttpResponse) -> HttpResponse {
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        actix_web::http::header::PRAGMA,
        actix_web::http::header::HeaderValue::from_static("no-cache"),
    );
    response
}

fn parse_module_id(value: &str) -> Option<ModuleId> {
    match value {
        "device_authorization" => Some(ModuleId::DeviceAuthorization),
        "token_exchange" => Some(ModuleId::TokenExchange),
        "jwt_bearer_grant" => Some(ModuleId::JwtBearerGrant),
        "ciba" => Some(ModuleId::Ciba),
        "dynamic_client_registration" => Some(ModuleId::DynamicClientRegistration),
        "request_objects" => Some(ModuleId::RequestObjects),
        "jarm" => Some(ModuleId::Jarm),
        "authorization_details" => Some(ModuleId::AuthorizationDetails),
        "http_message_signatures" => Some(ModuleId::HttpMessageSignatures),
        "scim" => Some(ModuleId::Scim),
        "native_sso" => Some(ModuleId::NativeSso),
        "frontchannel_logout" => Some(ModuleId::FrontchannelLogout),
        "session_management" => Some(ModuleId::SessionManagement),
        _ => None,
    }
}

const fn module_id_name(value: ModuleId) -> &'static str {
    match value {
        ModuleId::DeviceAuthorization => "device_authorization",
        ModuleId::TokenExchange => "token_exchange",
        ModuleId::JwtBearerGrant => "jwt_bearer_grant",
        ModuleId::Ciba => "ciba",
        ModuleId::DynamicClientRegistration => "dynamic_client_registration",
        ModuleId::RequestObjects => "request_objects",
        ModuleId::Jarm => "jarm",
        ModuleId::AuthorizationDetails => "authorization_details",
        ModuleId::HttpMessageSignatures => "http_message_signatures",
        ModuleId::Scim => "scim",
        ModuleId::NativeSso => "native_sso",
        ModuleId::FrontchannelLogout => "frontchannel_logout",
        ModuleId::SessionManagement => "session_management",
    }
}

const fn module_description(value: ModuleId) -> &'static str {
    match value {
        ModuleId::DeviceAuthorization => "Device Authorization Grant",
        ModuleId::TokenExchange => "OAuth Token Exchange",
        ModuleId::JwtBearerGrant => "JWT Bearer Grant",
        ModuleId::Ciba => "Client-Initiated Backchannel Authentication",
        ModuleId::DynamicClientRegistration => "Dynamic Client Registration",
        ModuleId::RequestObjects => "OAuth Request Objects",
        ModuleId::Jarm => "JWT-Secured Authorization Response Mode",
        ModuleId::AuthorizationDetails => "Rich Authorization Requests",
        ModuleId::HttpMessageSignatures => "HTTP Message Signatures",
        ModuleId::Scim => "SCIM",
        ModuleId::NativeSso => "Native SSO",
        ModuleId::FrontchannelLogout => "Front-Channel Logout",
        ModuleId::SessionManagement => "OIDC Session Management",
    }
}

const fn desired_mode_name(value: DesiredMode) -> &'static str {
    match value {
        DesiredMode::Inherit => "inherit",
        DesiredMode::Enabled => "enabled",
        DesiredMode::Disabled => "disabled",
    }
}

const fn action_name(value: DesiredMode) -> &'static str {
    match value {
        DesiredMode::Inherit => "inherit",
        DesiredMode::Enabled => "enable",
        DesiredMode::Disabled => "disable",
    }
}

const fn actual_state_name(value: ModuleState) -> &'static str {
    match value {
        ModuleState::Disabled => "disabled",
        ModuleState::Starting => "starting",
        ModuleState::Enabled => "enabled",
        ModuleState::Draining => "draining",
        ModuleState::Failed => "failed",
    }
}

fn disable_policy_name(value: DisablePolicy) -> String {
    match value {
        DisablePolicy::Immediate => "immediate".to_owned(),
        DisablePolicy::FinishExecutingRequests => "finish_executing_requests".to_owned(),
        DisablePolicy::DrainStoredTransactions { max_duration } => {
            format!("drain_stored_transactions:{}s", max_duration.as_secs())
        }
        DisablePolicy::NotRuntimeDisableable => "not_runtime_disableable".to_owned(),
    }
}

const fn event_type_name(value: ModuleEventType) -> &'static str {
    match value {
        ModuleEventType::DesiredStateChanged => "desired_state_changed",
        ModuleEventType::TransitionStarted => "transition_started",
        ModuleEventType::TransitionCompleted => "transition_completed",
        ModuleEventType::TransitionFailed => "transition_failed",
        ModuleEventType::DrainStarted => "drain_started",
        ModuleEventType::DrainCompleted => "drain_completed",
        ModuleEventType::StaleTransitionDiscarded => "stale_transition_discarded",
    }
}

const fn event_state_name(value: ModuleEventState) -> &'static str {
    match value {
        ModuleEventState::Desired(value) => desired_mode_name(value),
        ModuleEventState::Actual(value) => actual_state_name(value),
    }
}

fn timestamp(value: SystemTime) -> String {
    DateTime::<Utc>::from(value).to_rfc3339()
}

fn unix_timestamp(value: SystemTime) -> i64 {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
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

        fn events(
            &self,
            _offset: i64,
            _limit: i64,
        ) -> RuntimeModuleAdminFuture<'_, ModuleEventPage> {
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
}
