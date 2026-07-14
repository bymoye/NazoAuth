use std::{future::Future, sync::Arc};

use chrono::{DateTime, Utc};
use nazo_auth::{
    BackchannelLogoutClaimsInput, LogoutDependencyError, LogoutInput, LogoutService,
    LogoutServiceError, LogoutSession, LogoutTokenSignerPort, RpLogoutRequest,
};
use nazo_http_actix::{
    OidcLogoutCommand, OidcLogoutError, OidcLogoutFuture, OidcLogoutOperations, OidcLogoutSuccess,
};
use nazo_key_management::KeyManager;
use nazo_postgres::{AuditRepository, OAuthClientRepository};
use serde::Deserialize;
use serde_json::Value;

use crate::adapters::security::jwt_decoding_key_from_jwk;
use crate::http::sessions::SessionProfileHandles;
#[cfg(not(test))]
use crate::runtime_modules::ServerRuntimeModuleRegistry;
use crate::settings::Settings;
use nazo_key_management::signing_algorithm_name;

#[derive(Clone)]
pub(crate) struct OidcLogoutConfig {
    issuer: Box<str>,
    pairwise_subject_secret: Option<Box<str>>,
}

impl From<&Settings> for OidcLogoutConfig {
    fn from(settings: &Settings) -> Self {
        Self {
            issuer: settings.endpoint.issuer.as_str().into(),
            pairwise_subject_secret: settings
                .protocol
                .pairwise_subject_secret
                .as_deref()
                .map(Into::into),
        }
    }
}

/// OIDC logout dependencies assembled once at the composition root.
///
/// Transport code can resolve the current session and invoke logout operations,
/// but cannot obtain the database pool, Valkey connection, or complete settings.
#[derive(Clone)]
pub(crate) struct OidcLogoutHandles {
    sessions: SessionProfileHandles,
    service: LogoutService,
    keys: KeyManager,
    config: OidcLogoutConfig,
    #[cfg(not(test))]
    runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    #[cfg(test)]
    frontchannel_logout_enabled: bool,
}

impl OidcLogoutHandles {
    #[cfg(not(test))]
    pub(crate) fn new(
        sessions: SessionProfileHandles,
        clients: OAuthClientRepository,
        deliveries: AuditRepository,
        keys: KeyManager,
        config: OidcLogoutConfig,
        runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    ) -> Self {
        let service = LogoutService::new(
            Arc::new(clients.clone()),
            Arc::new(deliveries.clone()),
            Arc::new(ServerLogoutTokenSigner {
                keys: keys.clone(),
                issuer: config.issuer.clone(),
            }),
            config.issuer.clone(),
            config.pairwise_subject_secret.clone(),
        );
        Self {
            sessions,
            service,
            keys,
            config,
            runtime_modules,
        }
    }

    #[cfg(test)]
    pub(crate) fn new(
        sessions: SessionProfileHandles,
        clients: OAuthClientRepository,
        deliveries: AuditRepository,
        keys: KeyManager,
        config: OidcLogoutConfig,
        frontchannel_logout_enabled: bool,
    ) -> Self {
        let service = LogoutService::new(
            Arc::new(clients.clone()),
            Arc::new(deliveries.clone()),
            Arc::new(ServerLogoutTokenSigner {
                keys: keys.clone(),
                issuer: config.issuer.clone(),
            }),
            config.issuer.clone(),
            config.pairwise_subject_secret.clone(),
        );
        Self {
            sessions,
            service,
            keys,
            config,
            frontchannel_logout_enabled,
        }
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.config.issuer
    }

    #[cfg(not(test))]
    pub(crate) fn permits_existing_frontchannel_transaction(&self) -> bool {
        nazo_auth::module_admissible(
            &self.runtime_modules.snapshot(),
            nazo_runtime_modules::ModuleId::FrontchannelLogout,
            nazo_auth::CapabilityAdmission::ExistingTransaction,
        )
    }

    #[cfg(test)]
    pub(crate) fn permits_existing_frontchannel_transaction(&self) -> bool {
        self.frontchannel_logout_enabled
    }

    fn decode_id_token_hint_with_expiry(
        &self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Option<DecodedIdTokenHint> {
        let header = jsonwebtoken::decode_header(token).ok()?;
        if header.typ.as_deref().is_some_and(|typ| typ != "JWT")
            || signing_algorithm_name(header.alg).is_none()
        {
            return None;
        }
        let keyset = self.keys.snapshot();
        let verification_key = keyset.verification_key(header.kid.as_deref()?)?;
        let decoding_key = jwt_decoding_key_from_jwk(&verification_key.public_jwk, header.alg)?;
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.validate_aud = false;
        // RP-Initiated Logout 1.0 §2 recommends accepting an expired ID Token
        // when it remains bound to the current or a recent OP session. The auth
        // service below enforces that session binding before accepting it.
        validation.validate_exp = false;
        validation.set_issuer(&[self.issuer()]);
        jsonwebtoken::decode::<DecodedIdTokenHintClaims>(token, &decoding_key, &validation)
            .ok()
            .map(|data| DecodedIdTokenHint {
                expired: id_token_hint_expired(data.claims.exp, now),
                claims: nazo_auth::IdTokenHintClaims {
                    sub: data.claims.sub,
                    aud: data.claims.aud,
                    sid: data.claims.sid,
                },
            })
    }
}

struct DecodedIdTokenHint {
    claims: nazo_auth::IdTokenHintClaims,
    expired: bool,
}

#[derive(Deserialize)]
struct DecodedIdTokenHintClaims {
    sub: String,
    aud: Value,
    #[serde(default)]
    sid: Option<String>,
    exp: i64,
}

#[derive(Clone)]
struct ServerLogoutTokenSigner {
    keys: KeyManager,
    issuer: Box<str>,
}

impl LogoutTokenSignerPort for ServerLogoutTokenSigner {
    fn sign_logout_token<'a>(
        &'a self,
        client_id: &'a str,
        subject: Option<&'a str>,
        sid: &'a str,
        issued_at: DateTime<Utc>,
        ttl_seconds: i64,
    ) -> nazo_auth::LogoutFuture<'a, String> {
        Box::pin(async move {
            let claims = nazo_auth::backchannel_logout_token_claims(
                &self.issuer,
                &BackchannelLogoutClaimsInput {
                    client_id,
                    subject,
                    sid: Some(sid),
                    ttl: ttl_seconds,
                },
                issued_at.timestamp(),
            );
            let snapshot = self.keys.snapshot();
            let mut header = jsonwebtoken::Header::new(snapshot.active_alg);
            header.typ = Some("logout+jwt".to_owned());
            header.kid = Some(snapshot.active_kid.clone());
            self.keys
                .encode_jwt(
                    nazo_auth::SigningPurpose::LogoutToken,
                    &header,
                    &serde_json::Value::Object(claims),
                )
                .await
                .map_err(|_| LogoutDependencyError::Unavailable)
        })
    }
}

impl OidcLogoutOperations for OidcLogoutHandles {
    fn logout(&self, command: OidcLogoutCommand) -> OidcLogoutFuture<'_> {
        Box::pin(async move {
            let now = Utc::now();
            let current_session = match command.session_id.as_deref() {
                Some(session_id) => self
                    .sessions
                    .current_session_by_id(session_id)
                    .await
                    .map_err(|error| {
                        tracing::warn!(%error, "failed to resolve session for oidc logout");
                        OidcLogoutError::SessionLookupUnavailable
                    })?,
                None => None,
            };
            let decoded_id_token_hint = command
                .request
                .id_token_hint
                .as_deref()
                .and_then(|token| self.decode_id_token_hint_with_expiry(token, now));
            let subject_hash = current_session.as_ref().map(|session| {
                blake3::hash(session.user.id().as_bytes())
                    .to_hex()
                    .to_string()
            });
            let execution = self
                .service
                .execute(LogoutInput {
                    tenant_id: crate::domain::tenancy::DEFAULT_TENANT_ID,
                    request: RpLogoutRequest {
                        id_token_hint_present: command.request.id_token_hint.is_some(),
                        client_id: command.request.client_id,
                        post_logout_redirect_uri: command.request.post_logout_redirect_uri,
                        state: command.request.state,
                    },
                    id_token_hint: decoded_id_token_hint
                        .as_ref()
                        .map(|decoded| decoded.claims.clone()),
                    id_token_hint_expired: decoded_id_token_hint
                        .as_ref()
                        .is_some_and(|decoded| decoded.expired),
                    session: current_session.as_ref().map(|session| LogoutSession {
                        user_id: session.user.id(),
                        oidc_sid: session.oidc_sid.clone(),
                    }),
                    csrf_authorized: command.csrf_authorized,
                    frontchannel_enabled: self.permits_existing_frontchannel_transaction(),
                    now,
                })
                .await;

            let operation_key = execution
                .as_ref()
                .ok()
                .and_then(|execution| execution.operation_key.clone());
            let success = finalize_logout_execution(execution, command.session_id, |session_id| {
                let sessions = self.sessions.clone();
                async move {
                    sessions.delete_session(&session_id).await.map_err(|error| {
                        tracing::warn!(%error, "failed to delete session after oidc logout");
                    })
                }
            })
            .await?;

            tracing::info!(
                event = "oidc_logout",
                subject_hash = ?subject_hash,
                operation_key = ?operation_key,
                "oidc logout completed"
            );
            Ok(success)
        })
    }
}

fn id_token_hint_expired(exp: i64, now: DateTime<Utc>) -> bool {
    exp <= now.timestamp()
}

async fn finalize_logout_execution<F, Fut>(
    execution: Result<nazo_auth::LogoutExecution, LogoutServiceError>,
    session_id: Option<String>,
    delete_session: F,
) -> Result<OidcLogoutSuccess, OidcLogoutError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<(), ()>>,
{
    let execution = execution.map_err(map_logout_service_error)?;
    if let Some(session_id) = session_id {
        delete_session(session_id)
            .await
            .map_err(|()| OidcLogoutError::SessionDeleteUnavailable)?;
    }
    Ok(OidcLogoutSuccess {
        redirect_uri: execution.redirect_uri,
        frontchannel_logout_urls: execution.frontchannel_logout_urls,
    })
}

fn map_logout_service_error(error: LogoutServiceError) -> OidcLogoutError {
    match error {
        LogoutServiceError::Policy(policy) => match policy {
            nazo_auth::LogoutPolicyError::ClientAudienceMismatch => {
                OidcLogoutError::ClientAudienceMismatch
            }
            nazo_auth::LogoutPolicyError::AmbiguousAudience => OidcLogoutError::AmbiguousAudience,
            nazo_auth::LogoutPolicyError::ClientRequiredForRedirect => {
                OidcLogoutError::ClientRequiredForRedirect
            }
            nazo_auth::LogoutPolicyError::RegisteredClientRequired => {
                OidcLogoutError::RegisteredClientRequired
            }
            nazo_auth::LogoutPolicyError::UnregisteredRedirect => {
                OidcLogoutError::UnregisteredRedirect
            }
            nazo_auth::LogoutPolicyError::InvalidRedirect
            | nazo_auth::LogoutPolicyError::PairwiseSecretMissing
            | nazo_auth::LogoutPolicyError::UnsupportedSubjectType => {
                OidcLogoutError::InvalidRedirect
            }
        },
        LogoutServiceError::InvalidIdTokenHint => OidcLogoutError::InvalidIdTokenHint,
        LogoutServiceError::UnauthorizedSession => OidcLogoutError::UnauthorizedSession,
        LogoutServiceError::ClientNotFound => OidcLogoutError::ClientNotFound,
        LogoutServiceError::ClientUnavailable => OidcLogoutError::ClientLookupUnavailable,
        LogoutServiceError::SigningUnavailable => OidcLogoutError::SigningUnavailable,
        LogoutServiceError::OutboxUnavailable => OidcLogoutError::OutboxUnavailable,
    }
}

#[cfg(test)]
mod orchestration_tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use chrono::TimeZone as _;

    use super::*;

    fn committed_execution(operation_key: &str) -> nazo_auth::LogoutExecution {
        nazo_auth::LogoutExecution {
            redirect_uri: None,
            frontchannel_logout_urls: Vec::new(),
            operation_key: Some(operation_key.to_owned()),
        }
    }

    #[test]
    fn id_token_hint_expires_at_the_exact_exp_boundary() {
        let now = Utc.timestamp_opt(2_000_000_000, 0).unwrap();
        assert!(!id_token_hint_expired(2_000_000_001, now));
        assert!(id_token_hint_expired(2_000_000_000, now));
        assert!(id_token_hint_expired(1_999_999_999, now));
    }

    #[tokio::test]
    async fn postgres_outbox_failure_never_deletes_the_valkey_session() {
        let delete_calls = Arc::new(AtomicUsize::new(0));
        let observed = delete_calls.clone();
        let result = finalize_logout_execution(
            Err(LogoutServiceError::OutboxUnavailable),
            Some("session-cookie".to_owned()),
            move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                async { Ok(()) }
            },
        )
        .await;
        assert_eq!(result, Err(OidcLogoutError::OutboxUnavailable));
        assert_eq!(delete_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn valkey_failure_keeps_the_committed_operation_retryable() {
        let operation_key = "same-user-and-oidc-session";
        let first = finalize_logout_execution(
            Ok(committed_execution(operation_key)),
            Some("session-cookie".to_owned()),
            |_| async { Err(()) },
        )
        .await;
        assert_eq!(first, Err(OidcLogoutError::SessionDeleteUnavailable));

        let second = finalize_logout_execution(
            Ok(committed_execution(operation_key)),
            Some("session-cookie".to_owned()),
            |_| async { Ok(()) },
        )
        .await;
        assert_eq!(
            second,
            Ok(OidcLogoutSuccess {
                redirect_uri: None,
                frontchannel_logout_urls: Vec::new(),
            })
        );
    }
}
