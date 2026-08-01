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
#[path = "../../tests/support/domain/passkey.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "../../tests/unit/domain/passkey/login.rs"]
mod login_tests;

#[cfg(test)]
#[path = "../../tests/unit/domain/passkey/profile.rs"]
mod profile_tests;
