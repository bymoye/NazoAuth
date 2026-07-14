//! 会话用户与权限解析。
#[cfg(test)]
use crate::domain::TestAppState;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
#[cfg(test)]
use crate::test_support::valkey::valkey_get;
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
use nazo_http_actix::oauth_error;
use nazo_identity::PublicAccount;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::{Value, json};
use uuid::Uuid;
// 只处理从请求 Cookie 到当前用户/管理员身份的解析。

#[cfg(test)]
use crate::adapters::security::random_urlsafe_token;
use crate::domain::tenancy::DEFAULT_TENANT_ID;
#[cfg(test)]
#[cfg(test)]
use crate::test_support::valkey::valkey_set_ex;
use nazo_http_actix::{
    clear_cookie, cookie_value, has_valid_csrf_token_for_cookies, with_cookie_headers,
};
#[cfg(test)]
use nazo_identity::session::add_amr;
use nazo_postgres::UserRepository;
use nazo_valkey::SessionStore;

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct SessionPayload {
    pub(crate) user_id: Uuid,
    pub(crate) auth_time: i64,
    pub(crate) amr: Vec<String>,
    #[serde(default)]
    pub(crate) pending_mfa: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) oidc_sid: Option<String>,
}

pub(crate) struct CurrentSession {
    pub(crate) user: PublicAccount,
    pub(crate) auth_time: i64,
    pub(crate) amr: Vec<String>,
    pub(crate) oidc_sid: String,
}

/// Runtime-admin authentication dependencies, assembled once at the composition root.
///
/// This deliberately owns concrete repository/store handles instead of exposing the
/// application database pool, Valkey connection, or complete server settings to HTTP handlers.
pub(crate) struct AdminSessionHandles {
    sessions: SessionStore,
    users: UserRepository,
    http: SessionHttpConfig,
}

/// Profile session endpoint dependencies assembled at the composition root.
///
/// The profile transport only receives the concrete session/user stores and the
/// small amount of HTTP/runtime configuration it consumes. It cannot reach the
/// application database pool, raw Valkey connection, keyset, or complete settings.
#[derive(Clone)]
pub(crate) struct SessionProfileHandles {
    sessions: SessionStore,
    users: UserRepository,
    http: SessionHttpConfig,
}

#[derive(Clone)]
pub(crate) struct SessionHttpConfig {
    session_cookie_name: Box<str>,
    csrf_cookie_name: Box<str>,
    cookie_secure: bool,
}

impl SessionHttpConfig {
    pub(crate) fn new(
        session_cookie_name: &str,
        csrf_cookie_name: &str,
        cookie_secure: bool,
    ) -> Self {
        Self {
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            cookie_secure,
        }
    }

    pub(crate) fn session_cookie_name(&self) -> &str {
        &self.session_cookie_name
    }

    pub(crate) fn csrf_cookie_name(&self) -> &str {
        &self.csrf_cookie_name
    }

    pub(crate) fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }
}

impl AdminSessionHandles {
    pub(crate) fn new(
        sessions: SessionStore,
        users: UserRepository,
        http: SessionHttpConfig,
    ) -> Self {
        Self {
            sessions,
            users,
            http,
        }
    }

    pub(crate) fn http_config(&self) -> &SessionHttpConfig {
        &self.http
    }

    pub(crate) async fn current_session(
        &self,
        req: &HttpRequest,
    ) -> anyhow::Result<Option<CurrentSession>> {
        current_session_from_handles(
            &self.sessions,
            &self.users,
            self.http.session_cookie_name(),
            req,
        )
        .await
    }

    pub(crate) async fn current_user_or_login_required(
        &self,
        req: &HttpRequest,
    ) -> Result<nazo_identity::PublicAccount, HttpResponse> {
        current_user_or_login_required_from_handles(
            &self.sessions,
            &self.users,
            self.http.session_cookie_name(),
            self.http.csrf_cookie_name(),
            self.http.cookie_secure(),
            req,
        )
        .await
    }
}

#[cfg(test)]
pub(crate) fn login_required_response(state: &TestAppState) -> HttpResponse {
    let session = &state.settings.session;
    with_cookie_headers(
        oauth_error(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "会话不存在或已过期,请重新登录.",
        ),
        &[
            clear_cookie(&session.session_cookie_name, session.cookie_secure),
            clear_cookie(&session.csrf_cookie_name, session.cookie_secure),
        ],
    )
}

impl SessionProfileHandles {
    pub(crate) fn new(
        sessions: SessionStore,
        users: UserRepository,
        http: SessionHttpConfig,
    ) -> Self {
        Self {
            sessions,
            users,
            http,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_state(state: &TestAppState) -> Self {
        let session = &state.settings.session;
        Self::new(
            SessionStore::new(&state.valkey_connection()),
            UserRepository::new(state.diesel_db.clone()),
            SessionHttpConfig::new(
                &session.session_cookie_name,
                &session.csrf_cookie_name,
                session.cookie_secure,
            ),
        )
    }

    pub(crate) fn http_config(&self) -> &SessionHttpConfig {
        &self.http
    }

    pub(crate) fn has_valid_csrf_token(
        &self,
        req: &HttpRequest,
        fallback_token: Option<&str>,
    ) -> bool {
        has_valid_csrf_token_for_cookies(
            req,
            fallback_token,
            self.http.session_cookie_name(),
            self.http.csrf_cookie_name(),
        )
    }

    pub(crate) fn login_required_response(&self) -> HttpResponse {
        with_cookie_headers(
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "会话不存在或已过期,请重新登录.",
            ),
            &[
                clear_cookie(self.http.session_cookie_name(), self.http.cookie_secure()),
                clear_cookie(self.http.csrf_cookie_name(), self.http.cookie_secure()),
            ],
        )
    }

    pub(crate) async fn current_user_or_login_required(
        &self,
        req: &HttpRequest,
    ) -> Result<PublicAccount, HttpResponse> {
        match self.current_session(req).await {
            Ok(Some(session)) => Ok(session.user),
            Ok(None) => Err(self.login_required_response()),
            Err(error) => Err(session_lookup_error_response(error)),
        }
    }

    pub(crate) async fn delete_session(&self, session_id: &str) -> Result<(), nazo_valkey::Error> {
        self.sessions.delete(session_id).await.map(|_| ())
    }

    pub(crate) async fn current_session_by_id(
        &self,
        session_id: &str,
    ) -> anyhow::Result<Option<CurrentSession>> {
        current_session_by_id_from_handles(&self.sessions, &self.users, session_id).await
    }

    pub(crate) async fn current_session(
        &self,
        req: &HttpRequest,
    ) -> anyhow::Result<Option<CurrentSession>> {
        let Some(session_id) = cookie_value(req, self.http.session_cookie_name()) else {
            return Ok(None);
        };
        self.current_session_by_id(&session_id).await
    }
}

#[cfg(test)]
pub(crate) struct SessionRotation {
    pub(crate) session_id: String,
    pub(crate) csrf_token: String,
}

impl SessionPayload {
    #[cfg(test)]
    fn to_record(&self) -> anyhow::Result<nazo_identity::session::SessionRecord> {
        Ok(nazo_identity::session::SessionRecord::new(
            nazo_identity::UserId::new(self.user_id)?,
            self.auth_time,
            self.amr.clone(),
            self.pending_mfa,
            self.oidc_sid.clone(),
        ))
    }

    fn from_record(record: &nazo_identity::session::SessionRecord) -> Self {
        Self {
            user_id: record.user_id().as_uuid(),
            auth_time: record.auth_time(),
            amr: record.amr().to_vec(),
            pending_mfa: record.pending_mfa(),
            oidc_sid: record.oidc_sid().map(str::to_owned),
        }
    }
}

#[cfg(test)]
pub(crate) async fn current_user(
    state: &TestAppState,
    req: &HttpRequest,
) -> anyhow::Result<Option<PublicAccount>> {
    Ok(current_session(state, req)
        .await?
        .map(|session| session.user))
}

#[cfg(test)]
pub(crate) async fn current_session(
    state: &TestAppState,
    req: &HttpRequest,
) -> anyhow::Result<Option<CurrentSession>> {
    let sessions = SessionStore::new(&state.valkey_connection());
    let users = UserRepository::new(state.diesel_db.clone());
    current_session_from_handles(
        &sessions,
        &users,
        &state.settings.session.session_cookie_name,
        req,
    )
    .await
}

pub(crate) async fn current_session_from_handles(
    sessions: &SessionStore,
    users: &UserRepository,
    session_cookie_name: &str,
    req: &HttpRequest,
) -> anyhow::Result<Option<CurrentSession>> {
    let Some(sid) = cookie_value(req, session_cookie_name) else {
        return Ok(None);
    };
    current_session_by_id_from_handles(sessions, users, &sid).await
}

async fn current_session_by_id_from_handles(
    sessions: &SessionStore,
    users: &UserRepository,
    session_id: &str,
) -> anyhow::Result<Option<CurrentSession>> {
    let stored = match sessions.load(session_id).await {
        Ok(stored) => stored,
        Err(error) if error.kind() == nazo_valkey::ErrorKind::CorruptData => {
            tracing::warn!(%error, "session payload is malformed");
            let _ = sessions.delete(session_id).await;
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let Some(stored) = stored else {
        return Ok(None);
    };
    let now = Utc::now().timestamp();
    let payload = SessionPayload::from_record(stored.value());
    let payload = if valid_session_payload(&payload, now) {
        payload
    } else {
        tracing::warn!("session payload contains invalid authentication metadata");
        let _ = sessions.delete(session_id).await;
        return Ok(None);
    };
    if payload.pending_mfa {
        return Ok(None);
    }
    session_from_payload(sessions, users, session_id, payload).await
}

#[cfg(test)]
pub(crate) async fn current_pending_mfa_session(
    state: &TestAppState,
    req: &HttpRequest,
) -> anyhow::Result<Option<CurrentSession>> {
    let store = SessionStore::new(&state.valkey_connection());
    let users = UserRepository::new(state.diesel_db.clone());
    current_pending_mfa_session_from_handles(
        &store,
        &users,
        &state.settings.session.session_cookie_name,
        req,
    )
    .await
}

#[cfg(test)]
async fn current_pending_mfa_session_from_handles(
    store: &SessionStore,
    users: &UserRepository,
    session_cookie_name: &str,
    req: &HttpRequest,
) -> anyhow::Result<Option<CurrentSession>> {
    let Some(sid) = cookie_value(req, session_cookie_name) else {
        return Ok(None);
    };
    let stored = match store.load(&sid).await {
        Ok(stored) => stored,
        Err(error) if error.kind() == nazo_valkey::ErrorKind::CorruptData => {
            tracing::warn!(%error, "pending MFA session payload is malformed");
            let _ = store.delete(&sid).await;
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let Some(stored) = stored else {
        return Ok(None);
    };
    let now = Utc::now().timestamp();
    let payload = SessionPayload::from_record(stored.value());
    let payload = if valid_session_payload(&payload, now) {
        payload
    } else {
        tracing::warn!("pending MFA session payload contains invalid authentication metadata");
        let _ = store.delete(&sid).await;
        return Ok(None);
    };
    if !payload.pending_mfa {
        return Ok(None);
    }
    session_from_payload(store, users, &sid, payload).await
}

#[cfg(test)]
pub(crate) async fn complete_mfa_session(
    state: &TestAppState,
    req: &HttpRequest,
    method: &str,
) -> anyhow::Result<Option<SessionRotation>> {
    record_mfa_step_up(state, req, method, true).await
}

#[cfg(test)]
pub(crate) async fn step_up_current_session(
    state: &TestAppState,
    req: &HttpRequest,
    method: &str,
) -> anyhow::Result<Option<SessionRotation>> {
    record_mfa_step_up(state, req, method, false).await
}

#[cfg(test)]
async fn record_mfa_step_up(
    state: &TestAppState,
    req: &HttpRequest,
    method: &str,
    require_pending_mfa: bool,
) -> anyhow::Result<Option<SessionRotation>> {
    let store = SessionStore::new(&state.valkey_connection());
    record_mfa_step_up_with_store(
        &store,
        &state.settings.session.session_cookie_name,
        state.settings.session.session_ttl_seconds,
        req,
        method,
        require_pending_mfa,
    )
    .await
}

#[cfg(test)]
async fn record_mfa_step_up_with_store(
    store: &SessionStore,
    session_cookie_name: &str,
    session_ttl_seconds: u64,
    req: &HttpRequest,
    method: &str,
    require_pending_mfa: bool,
) -> anyhow::Result<Option<SessionRotation>> {
    let Some(sid) = cookie_value(req, session_cookie_name) else {
        return Ok(None);
    };
    let stored = match store.load(&sid).await {
        Ok(stored) => stored,
        Err(error) if error.kind() == nazo_valkey::ErrorKind::CorruptData => {
            tracing::warn!(%error, "MFA session payload is malformed");
            let _ = store.delete(&sid).await;
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let Some(stored) = stored else {
        return Ok(None);
    };
    let now = Utc::now().timestamp();
    let mut payload = SessionPayload::from_record(stored.value());
    if !valid_session_payload(&payload, now) || (require_pending_mfa && !payload.pending_mfa) {
        return Ok(None);
    }
    payload.pending_mfa = false;
    payload.auth_time = now;
    add_amr(&mut payload.amr, method);
    add_amr(&mut payload.amr, "mfa");
    let new_session_id = random_urlsafe_token();
    let result = store
        .rotate(
            &sid,
            &stored,
            &new_session_id,
            &payload.to_record()?,
            session_ttl_seconds,
        )
        .await?;
    match result {
        nazo_valkey::SessionRotationResult::Applied => Ok(Some(SessionRotation {
            session_id: new_session_id,
            csrf_token: random_urlsafe_token(),
        })),
        nazo_valkey::SessionRotationResult::Conflict => Ok(None),
        nazo_valkey::SessionRotationResult::Collision => {
            anyhow::bail!("generated MFA session identifier already exists")
        }
    }
}

async fn session_from_payload(
    sessions: &SessionStore,
    users: &UserRepository,
    session_id: &str,
    payload: SessionPayload,
) -> anyhow::Result<Option<CurrentSession>> {
    let tenant_id = nazo_identity::TenantId::new(DEFAULT_TENANT_ID)?;
    let user_id = nazo_identity::UserId::new(payload.user_id)?;
    let Some(user) = users
        .public_account_by_id(tenant_id, user_id)
        .await?
        .filter(|u| u.principal.active)
    else {
        let _ = sessions.delete(session_id).await;
        return Ok(None);
    };
    Ok(Some(CurrentSession {
        user,
        auth_time: payload.auth_time,
        amr: payload.amr,
        oidc_sid: payload.oidc_sid.expect("valid session payload has sid"),
    }))
}

fn valid_session_payload(payload: &SessionPayload, now: i64) -> bool {
    nazo_identity::session::valid_authentication_metadata(
        payload.auth_time,
        &payload.amr,
        payload.oidc_sid.as_deref(),
        now,
    )
}

#[cfg(test)]
pub(crate) async fn require_admin(
    state: &TestAppState,
    req: &HttpRequest,
) -> anyhow::Result<Option<PublicAccount>> {
    Ok(current_user(state, req)
        .await?
        .filter(|u| u.admin_level() > 0))
}

#[cfg(test)]
pub(crate) async fn current_user_or_login_required(
    state: &TestAppState,
    req: &HttpRequest,
) -> Result<PublicAccount, HttpResponse> {
    match current_user(state, req).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(login_required_response(state)),
        Err(error) => Err(session_lookup_error_response(error)),
    }
}

pub(crate) async fn current_user_or_login_required_from_handles(
    sessions: &SessionStore,
    users: &UserRepository,
    session_cookie_name: &str,
    csrf_cookie_name: &str,
    cookie_secure: bool,
    req: &HttpRequest,
) -> Result<PublicAccount, HttpResponse> {
    match current_session_from_handles(sessions, users, session_cookie_name, req).await {
        Ok(Some(session)) => Ok(session.user),
        Ok(None) => Err(login_required_response_for_cookies(
            session_cookie_name,
            csrf_cookie_name,
            cookie_secure,
        )),
        Err(error) => Err(session_lookup_error_response(error)),
    }
}

fn login_required_response_for_cookies(
    session_cookie_name: &str,
    csrf_cookie_name: &str,
    cookie_secure: bool,
) -> HttpResponse {
    with_cookie_headers(
        oauth_error(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "会话不存在或已过期,请重新登录.",
        ),
        &[
            clear_cookie(session_cookie_name, cookie_secure),
            clear_cookie(csrf_cookie_name, cookie_secure),
        ],
    )
}

#[cfg(test)]
pub(crate) async fn require_admin_or_forbidden(
    state: &TestAppState,
    req: &HttpRequest,
) -> Result<PublicAccount, HttpResponse> {
    match require_admin(state, req).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前账号无管理权限.",
        )),
        Err(error) => Err(session_lookup_error_response(error)),
    }
}

pub(crate) async fn require_admin_or_forbidden_with_handles(
    handles: &AdminSessionHandles,
    req: &HttpRequest,
) -> Result<PublicAccount, HttpResponse> {
    match handles.current_session(req).await {
        Ok(Some(session)) if session.user.admin_level() > 0 => Ok(session.user),
        Ok(Some(_)) | Ok(None) => Err(oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前账号无管理权限.",
        )),
        Err(error) => Err(session_lookup_error_response(error)),
    }
}

fn session_lookup_error_response(error: anyhow::Error) -> HttpResponse {
    tracing::warn!(%error, "failed to resolve current session user");
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "会话查询失败.",
    )
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/sessions.rs"]
mod tests;
