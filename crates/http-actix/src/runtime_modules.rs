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
        "scim_security_events" => Some(ModuleId::ScimSecurityEvents),
        "native_sso" => Some(ModuleId::NativeSso),
        "frontchannel_logout" => Some(ModuleId::FrontchannelLogout),
        "session_management" => Some(ModuleId::SessionManagement),
        "openid4vci_issuer" => Some(ModuleId::Openid4vciIssuer),
        "openid4vp_verifier" => Some(ModuleId::Openid4vpVerifier),
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
        ModuleId::ScimSecurityEvents => "scim_security_events",
        ModuleId::NativeSso => "native_sso",
        ModuleId::FrontchannelLogout => "frontchannel_logout",
        ModuleId::SessionManagement => "session_management",
        ModuleId::Openid4vciIssuer => "openid4vci_issuer",
        ModuleId::Openid4vpVerifier => "openid4vp_verifier",
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
        ModuleId::ScimSecurityEvents => "SCIM Security Events",
        ModuleId::NativeSso => "Native SSO",
        ModuleId::FrontchannelLogout => "Front-Channel Logout",
        ModuleId::SessionManagement => "OIDC Session Management",
        ModuleId::Openid4vciIssuer => "OpenID4VCI Credential Issuer",
        ModuleId::Openid4vpVerifier => "OpenID4VP Verifier",
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
#[path = "../tests/unit/runtime_modules.rs"]
mod tests;
