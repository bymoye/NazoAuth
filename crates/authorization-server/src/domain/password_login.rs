use nazo_http_actix::{PasswordLoginFuture, PasswordLoginOperations};
use nazo_identity::{
    AuthenticatePasswordError, AuthenticatePasswordInput, AuthenticationService,
    authentication::PasswordLoginResult,
    ports::{
        AuthenticationAuditPort, LoginAccountRepositoryPort, LoginSessionPort, LoginThrottlePort,
        RememberedMfaDevicePort, SecretVerifyPort,
    },
};

#[derive(Clone)]
pub(crate) struct ServerPasswordLoginOperations<A, T, V, M, S, U> {
    service: AuthenticationService<A, T, V, M, S, U>,
}

impl<A, T, V, M, S, U> ServerPasswordLoginOperations<A, T, V, M, S, U> {
    pub(crate) fn new(service: AuthenticationService<A, T, V, M, S, U>) -> Self {
        Self { service }
    }
}

impl<A, T, V, M, S, U> PasswordLoginOperations for ServerPasswordLoginOperations<A, T, V, M, S, U>
where
    A: LoginAccountRepositoryPort + 'static,
    T: LoginThrottlePort + 'static,
    V: SecretVerifyPort + 'static,
    M: RememberedMfaDevicePort + 'static,
    S: LoginSessionPort + 'static,
    U: AuthenticationAuditPort + 'static,
{
    fn authenticate_password(&self, input: AuthenticatePasswordInput) -> PasswordLoginFuture<'_> {
        Box::pin(async move {
            let result = self.service.authenticate_password(input).await;
            match &result {
                Err(AuthenticatePasswordError::ThrottleUnavailable(error)) => {
                    tracing::warn!(%error, "login failure throttle lookup failed");
                }
                Err(AuthenticatePasswordError::AccountLookup(error)) => {
                    tracing::warn!(%error, "failed to query user for login");
                }
                Err(AuthenticatePasswordError::SecretUnavailable) => {
                    tracing::warn!("password verification worker failed");
                }
                Err(AuthenticatePasswordError::FailureRecord(error)) => {
                    tracing::warn!(%error, "login failure throttle increment failed");
                }
                Err(AuthenticatePasswordError::RememberedMfa(error)) => {
                    tracing::warn!(%error, "failed to check remembered MFA device");
                }
                Err(AuthenticatePasswordError::Session(error)) => {
                    tracing::warn!(%error, "failed to store login session");
                }
                Err(AuthenticatePasswordError::SessionCollision) => {
                    tracing::warn!("generated login session identifier collided");
                }
                _ => {}
            }
            result.map(PasswordLoginResult::from)
        })
    }
}
