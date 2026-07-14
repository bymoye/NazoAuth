use std::{future::Future, pin::Pin, sync::Arc};

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::{
    IdTokenHintClaims, LogoutClient, LogoutPolicyError, frontchannel_logout_url,
    id_token_hint_matches_session, resolve_logout_client_id, unique_logout_subject_for_client,
    validate_post_logout_redirect,
};

pub const BACKCHANNEL_LOGOUT_TOKEN_TTL_SECONDS: i64 = 120;

pub type LogoutFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, LogoutDependencyError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogoutDependencyError {
    Unavailable,
    Consistency,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpLogoutRequest {
    pub id_token_hint_present: bool,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogoutSession {
    pub user_id: Uuid,
    pub oidc_sid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredLogoutClient {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub active: bool,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub backchannel_logout_uri: Option<String>,
    pub frontchannel_logout_uri: Option<String>,
    pub frontchannel_logout_session_required: bool,
    pub subject_type: String,
    pub sector_identifier_host: Option<String>,
}

impl RegisteredLogoutClient {
    fn policy(&self) -> LogoutClient {
        LogoutClient {
            redirect_uris: self.redirect_uris.clone(),
            subject_type: self.subject_type.clone(),
            sector_identifier_host: self.sector_identifier_host.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotentBackchannelLogoutDelivery {
    pub operation_key: String,
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub client_public_id: String,
    pub logout_uri: String,
    pub logout_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogoutExecution {
    pub redirect_uri: Option<String>,
    pub frontchannel_logout_urls: Vec<String>,
    pub operation_key: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LogoutInput {
    pub tenant_id: Uuid,
    pub request: RpLogoutRequest,
    pub id_token_hint: Option<IdTokenHintClaims>,
    pub id_token_hint_expired: bool,
    pub session: Option<LogoutSession>,
    pub csrf_authorized: bool,
    pub frontchannel_enabled: bool,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogoutServiceError {
    Policy(LogoutPolicyError),
    InvalidIdTokenHint,
    UnauthorizedSession,
    ClientNotFound,
    ClientUnavailable,
    SigningUnavailable,
    OutboxUnavailable,
}

pub trait LogoutClientRepositoryPort: Send + Sync {
    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> LogoutFuture<'a, Option<RegisteredLogoutClient>>;

    fn active_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> LogoutFuture<'_, Vec<RegisteredLogoutClient>>;
}

pub trait BackchannelLogoutOutboxPort: Send + Sync {
    fn enqueue_idempotent_batch<'a>(
        &'a self,
        deliveries: &'a [IdempotentBackchannelLogoutDelivery],
    ) -> LogoutFuture<'a, ()>;
}

pub trait LogoutTokenSignerPort: Send + Sync {
    fn sign_logout_token<'a>(
        &'a self,
        client_id: &'a str,
        subject: Option<&'a str>,
        sid: &'a str,
        issued_at: DateTime<Utc>,
        ttl_seconds: i64,
    ) -> LogoutFuture<'a, String>;
}

#[derive(Clone)]
pub struct LogoutService {
    clients: Arc<dyn LogoutClientRepositoryPort>,
    outbox: Arc<dyn BackchannelLogoutOutboxPort>,
    signer: Arc<dyn LogoutTokenSignerPort>,
    issuer: Box<str>,
    pairwise_subject_secret: Option<Box<str>>,
}

impl LogoutService {
    #[must_use]
    pub fn new(
        clients: Arc<dyn LogoutClientRepositoryPort>,
        outbox: Arc<dyn BackchannelLogoutOutboxPort>,
        signer: Arc<dyn LogoutTokenSignerPort>,
        issuer: impl Into<Box<str>>,
        pairwise_subject_secret: Option<impl Into<Box<str>>>,
    ) -> Self {
        Self {
            clients,
            outbox,
            signer,
            issuer: issuer.into(),
            pairwise_subject_secret: pairwise_subject_secret.map(Into::into),
        }
    }

    pub async fn execute(&self, input: LogoutInput) -> Result<LogoutExecution, LogoutServiceError> {
        if input.request.id_token_hint_present && input.id_token_hint.is_none() {
            return Err(LogoutServiceError::InvalidIdTokenHint);
        }
        let client_id = resolve_logout_client_id(
            input.request.client_id.as_deref(),
            input.request.post_logout_redirect_uri.is_some(),
            input.id_token_hint.as_ref(),
        )
        .map_err(LogoutServiceError::Policy)?;
        let hinted_client = match client_id.as_deref() {
            Some(client_id) => Some(self.lookup_client(input.tenant_id, client_id).await?),
            None => None,
        };
        let redirect_uri = validate_post_logout_redirect(
            input.request.post_logout_redirect_uri.as_deref(),
            input.request.state.as_deref(),
            hinted_client
                .as_ref()
                .map(|client| client.post_logout_redirect_uris.as_slice()),
        )
        .map_err(LogoutServiceError::Policy)?;

        let hint_matches_current_session = input.session.as_ref().is_some_and(|session| {
            input.id_token_hint.as_ref().is_some_and(|hint| {
                self.hint_matches_session(hinted_client.as_ref(), session, hint)
            })
        });

        if input.id_token_hint_expired && !hint_matches_current_session {
            return Err(LogoutServiceError::InvalidIdTokenHint);
        }

        if input.session.is_some() && !input.csrf_authorized && !hint_matches_current_session {
            return Err(LogoutServiceError::UnauthorizedSession);
        }

        let mut active_clients = match input.session.as_ref() {
            Some(session) => self
                .clients
                .active_for_user(input.tenant_id, session.user_id)
                .await
                .map_err(|_| LogoutServiceError::ClientUnavailable)?,
            None => Vec::new(),
        };
        let hinted_client_is_bound = hinted_client.as_ref().is_some_and(|client| {
            hint_matches_current_session
                || active_clients
                    .iter()
                    .any(|candidate| candidate.client_id == client.client_id)
        });
        if hinted_client_is_bound
            && let Some(client) = hinted_client.as_ref()
            && !active_clients
                .iter()
                .any(|candidate| candidate.client_id == client.client_id)
        {
            active_clients.push(client.clone());
        }
        let frontchannel_logout_urls = self.frontchannel_urls(
            hinted_client.as_ref(),
            hinted_client_is_bound,
            &active_clients,
            input.session.as_ref(),
            input.frontchannel_enabled,
        );
        let operation_key = input.session.as_ref().map(logout_operation_key);
        if let (Some(session), Some(operation_key)) =
            (input.session.as_ref(), operation_key.as_deref())
        {
            self.enqueue_backchannel(
                session,
                input.id_token_hint.as_ref(),
                hinted_client.as_ref(),
                &active_clients,
                operation_key,
                input.now,
            )
            .await?;
        }
        Ok(LogoutExecution {
            redirect_uri,
            frontchannel_logout_urls,
            operation_key,
        })
    }

    async fn lookup_client(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> Result<RegisteredLogoutClient, LogoutServiceError> {
        self.clients
            .by_client_id(tenant_id, client_id)
            .await
            .map_err(|_| LogoutServiceError::ClientUnavailable)?
            .filter(|client| client.active)
            .ok_or(LogoutServiceError::ClientNotFound)
    }

    fn hint_matches_session(
        &self,
        client: Option<&RegisteredLogoutClient>,
        session: &LogoutSession,
        hint: &IdTokenHintClaims,
    ) -> bool {
        let policy = client.map(RegisteredLogoutClient::policy);
        id_token_hint_matches_session(
            &self.issuer,
            self.pairwise_subject_secret.as_deref(),
            policy.as_ref(),
            session.user_id,
            &session.oidc_sid,
            hint,
        )
    }

    fn frontchannel_urls(
        &self,
        hinted_client: Option<&RegisteredLogoutClient>,
        hinted_client_is_bound: bool,
        active_clients: &[RegisteredLogoutClient],
        session: Option<&LogoutSession>,
        enabled: bool,
    ) -> Vec<String> {
        if !enabled {
            return Vec::new();
        }
        let Some(session) = session else {
            return Vec::new();
        };
        let clients = match hinted_client {
            Some(client) if hinted_client_is_bound => std::slice::from_ref(client),
            Some(_) => return Vec::new(),
            None => active_clients,
        };
        clients
            .iter()
            .filter_map(|client| {
                let uri = client.frontchannel_logout_uri.as_deref()?;
                frontchannel_logout_url(
                    uri,
                    client.frontchannel_logout_session_required,
                    &self.issuer,
                    &session.oidc_sid,
                )
                .ok()
            })
            .collect()
    }

    async fn enqueue_backchannel(
        &self,
        session: &LogoutSession,
        hint: Option<&IdTokenHintClaims>,
        hinted_client: Option<&RegisteredLogoutClient>,
        active_clients: &[RegisteredLogoutClient],
        operation_key: &str,
        now: DateTime<Utc>,
    ) -> Result<(), LogoutServiceError> {
        if hint.is_some_and(|hint| !self.hint_matches_session(hinted_client, session, hint)) {
            return Ok(());
        }
        let mut deliveries = Vec::new();
        for client in active_clients {
            let Some(logout_uri) = client.backchannel_logout_uri.clone() else {
                continue;
            };
            let Ok(subject) = unique_logout_subject_for_client(
                &self.issuer,
                self.pairwise_subject_secret.as_deref(),
                session.user_id,
                &client.policy(),
            ) else {
                continue;
            };
            let logout_token = self
                .signer
                .sign_logout_token(
                    &client.client_id,
                    subject.as_deref(),
                    &session.oidc_sid,
                    now,
                    BACKCHANNEL_LOGOUT_TOKEN_TTL_SECONDS,
                )
                .await
                .map_err(|_| LogoutServiceError::SigningUnavailable)?;
            deliveries.push(IdempotentBackchannelLogoutDelivery {
                operation_key: operation_key.to_owned(),
                tenant_id: client.tenant_id,
                client_id: client.id,
                client_public_id: client.client_id.clone(),
                logout_uri,
                logout_token,
                expires_at: now + Duration::seconds(BACKCHANNEL_LOGOUT_TOKEN_TTL_SECONDS),
            });
        }
        self.outbox
            .enqueue_idempotent_batch(&deliveries)
            .await
            .map_err(|_| LogoutServiceError::OutboxUnavailable)
    }
}

#[must_use]
pub fn logout_operation_key(session: &LogoutSession) -> String {
    let mut input = Vec::with_capacity(32 + session.oidc_sid.len());
    input.extend_from_slice(b"oidc-logout:v1\0");
    input.extend_from_slice(session.user_id.as_bytes());
    input.extend_from_slice(session.oidc_sid.as_bytes());
    blake3::hash(&input).to_hex().to_string()
}
