use nazo_http_actix::{
    PasskeyEndpointError, PasskeyFuture, PasskeyLoginFinishCommand, PasskeyLoginOperations,
    PasskeyProfileContext, PasskeyProfileOperations, PasskeyRegistrationFinishCommand,
};
use nazo_identity::{
    LoginSuccess, PasskeyError, PasskeyLoginBegin, PasskeyRegistrationBegin, PublicAccount,
    SessionId, SessionResolution, SessionService, ports::PasskeyCredential,
};
use uuid::Uuid;

use crate::bootstrap::LocalPasskeyService;

#[derive(Clone)]
pub(crate) struct PasskeyOperationsProvider {
    passkeys: LocalPasskeyService,
    sessions: SessionService,
}

impl PasskeyOperationsProvider {
    pub(crate) fn new(passkeys: LocalPasskeyService, sessions: SessionService) -> Self {
        Self { passkeys, sessions }
    }

    async fn current_account(
        &self,
        context: &PasskeyProfileContext,
    ) -> Result<PublicAccount, PasskeyEndpointError> {
        match self
            .sessions
            .current(&SessionId::new(context.session_id.as_str()), context.now)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "failed to resolve current session user for passkey operation");
                PasskeyEndpointError::SessionUnavailable
            })?
        {
            SessionResolution::Present(session) => Ok(session.into_user()),
            SessionResolution::Missing | SessionResolution::Invalidated => {
                Err(PasskeyEndpointError::SessionMissing)
            }
        }
    }

    fn login_error(error: PasskeyError) -> PasskeyEndpointError {
        match &error {
            PasskeyError::Account(cause) => {
                tracing::warn!(%cause, "failed to query user for passkey login");
            }
            PasskeyError::State(cause) | PasskeyError::CeremonyState(cause) => {
                tracing::warn!(%cause, "passkey login state unavailable");
            }
            PasskeyError::Mfa(cause) => {
                tracing::warn!(%cause, "failed to check remembered MFA device for passkey login");
            }
            PasskeyError::Session(cause) => {
                tracing::warn!(%cause, "failed to store passkey login session");
            }
            _ => {}
        }
        error.into()
    }

    fn profile_error(error: PasskeyError) -> PasskeyEndpointError {
        tracing::warn!(?error, "passkey operation failed");
        error.into()
    }
}

impl PasskeyLoginOperations for PasskeyOperationsProvider {
    fn login_begin(&self, email: String) -> PasskeyFuture<'_, PasskeyLoginBegin> {
        Box::pin(async move {
            self.passkeys
                .login_begin(email)
                .await
                .map_err(Self::login_error)
        })
    }

    fn login_finish(&self, command: PasskeyLoginFinishCommand) -> PasskeyFuture<'_, LoginSuccess> {
        Box::pin(async move {
            self.passkeys
                .login_finish(
                    &command.ceremony_id,
                    command.response,
                    command.source_ip,
                    command.remembered_mfa,
                    command.previous_session_id,
                    command.now,
                )
                .await
                .map_err(Self::login_error)
        })
    }
}

impl PasskeyProfileOperations for PasskeyOperationsProvider {
    fn registration_begin(
        &self,
        context: PasskeyProfileContext,
        label: Option<String>,
    ) -> PasskeyFuture<'_, PasskeyRegistrationBegin> {
        Box::pin(async move {
            let account = self.current_account(&context).await?;
            self.passkeys
                .registration_begin(&account, label)
                .await
                .map_err(Self::profile_error)
        })
    }

    fn registration_finish(
        &self,
        command: PasskeyRegistrationFinishCommand,
    ) -> PasskeyFuture<'_, PasskeyCredential> {
        Box::pin(async move {
            let account = self.current_account(&command.context).await?;
            self.passkeys
                .registration_finish(&account, &command.ceremony_id, command.response)
                .await
                .map_err(Self::profile_error)
        })
    }

    fn list(&self, context: PasskeyProfileContext) -> PasskeyFuture<'_, Vec<PasskeyCredential>> {
        Box::pin(async move {
            let account = self.current_account(&context).await?;
            self.passkeys
                .list(&account)
                .await
                .map_err(Self::profile_error)
        })
    }

    fn delete(&self, context: PasskeyProfileContext, passkey_id: Uuid) -> PasskeyFuture<'_, ()> {
        Box::pin(async move {
            let account = self.current_account(&context).await?;
            self.passkeys
                .delete(&account, passkey_id)
                .await
                .map_err(Self::profile_error)
        })
    }
}

#[cfg(test)]
fn test_operations(
    state: &crate::domain::TestAppState,
) -> std::sync::Arc<PasskeyOperationsProvider> {
    std::sync::Arc::new(PasskeyOperationsProvider::new(
        crate::test_support::passkey_service(state)
            .get_ref()
            .clone(),
        SessionService::new(
            std::sync::Arc::new(nazo_valkey::SessionStore::new(&state.valkey_connection())),
            std::sync::Arc::new(nazo_postgres::UserRepository::new(state.diesel_db.clone())),
            nazo_identity::TenantId::new(crate::domain::tenancy::DEFAULT_TENANT_ID)
                .expect("default tenant ID is valid"),
        ),
    ))
}

#[cfg(test)]
fn test_login_endpoint(
    state: &crate::domain::TestAppState,
) -> actix_web::web::Data<nazo_http_actix::PasskeyLoginEndpoint> {
    let identity = &state.settings.identity;
    let session = &state.settings.session;
    let endpoint = &state.settings.endpoint;
    actix_web::web::Data::new(nazo_http_actix::PasskeyLoginEndpoint::new(
        test_operations(state),
        std::sync::Arc::new(crate::domain::ServerAuthenticationRateLimit::new(
            nazo_valkey::RateLimitStore::new(&state.valkey_connection()),
            identity.rate_limit.window_seconds,
            identity.rate_limit.auth_max_requests,
        )),
        nazo_http_actix::ClientIpConfig::new(
            &endpoint.trusted_proxy_cidrs,
            endpoint.client_ip_header_mode,
        ),
        nazo_http_actix::PasskeyLoginConfig::new(
            &session.session_cookie_name,
            &session.csrf_cookie_name,
            crate::domain::MFA_REMEMBERED_COOKIE_NAME,
            session.session_ttl_seconds,
            session.cookie_secure,
        ),
    ))
}

#[cfg(test)]
fn test_profile_endpoint(
    state: &crate::domain::TestAppState,
) -> actix_web::web::Data<nazo_http_actix::PasskeyProfileEndpoint> {
    let session = &state.settings.session;
    actix_web::web::Data::new(nazo_http_actix::PasskeyProfileEndpoint::new(
        test_operations(state),
        nazo_http_actix::PasskeyProfileConfig::new(
            &session.session_cookie_name,
            &session.csrf_cookie_name,
            session.cookie_secure,
        ),
    ))
}

#[cfg(test)]
#[path = "../../tests/in_source/src/http/auth/tests/passkey.rs"]
mod login_tests;

#[cfg(test)]
#[path = "../../tests/in_source/src/http/profile/tests/passkeys.rs"]
mod profile_tests;
