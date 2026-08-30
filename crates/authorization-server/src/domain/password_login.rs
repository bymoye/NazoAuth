use nazo_http_actix::{PasswordLoginFuture, PasswordLoginOperations};
use nazo_identity::{
    AuthenticatePasswordError, AuthenticatePasswordInput, AuthenticationService,
    authentication::PasswordLoginResult,
    ports::{AuthenticationAuditPort, LoginSessionPort, LoginThrottlePort, SecretVerifyPort},
};

#[derive(Clone)]
pub(crate) struct ServerPasswordLoginOperations<T, V, S, U> {
    service: AuthenticationService<T, V, S, U>,
}

impl<T, V, S, U> ServerPasswordLoginOperations<T, V, S, U> {
    pub(crate) fn new(service: AuthenticationService<T, V, S, U>) -> Self {
        Self { service }
    }
}

impl<T, V, S, U> PasswordLoginOperations for ServerPasswordLoginOperations<T, V, S, U>
where
    T: LoginThrottlePort + 'static,
    V: SecretVerifyPort + 'static,
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
