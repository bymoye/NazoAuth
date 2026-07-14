use nazo_http_actix::{
    AuthenticationRateLimit, AuthenticationRateLimitError, LocalRegistrationFuture,
    LocalRegistrationOperations,
};
use nazo_identity::{
    RegisterLocalAccountError, RegisterLocalAccountInput, RegistrationService,
    SendVerificationCodeError, SendVerificationCodeOutcome,
    ports::{
        EmailVerificationStorePort, RegistrationAccountRepositoryPort, SecretHashPort,
        VerificationEmailDeliveryPort,
    },
    registration::RegisteredAccount,
};

#[derive(Clone)]
pub(crate) struct ServerLocalRegistrationOperations<A, V, H, E> {
    service: RegistrationService<A, V, H, E>,
}

impl<A, V, H, E> ServerLocalRegistrationOperations<A, V, H, E> {
    pub(crate) fn new(service: RegistrationService<A, V, H, E>) -> Self {
        Self { service }
    }
}

impl<A, V, H, E> LocalRegistrationOperations for ServerLocalRegistrationOperations<A, V, H, E>
where
    A: RegistrationAccountRepositoryPort + 'static,
    V: EmailVerificationStorePort + 'static,
    H: SecretHashPort + 'static,
    E: VerificationEmailDeliveryPort + 'static,
{
    fn send_verification_code<'a>(
        &'a self,
        normalized_email: &'a str,
        peer_subject: &'a str,
    ) -> LocalRegistrationFuture<'a, Result<SendVerificationCodeOutcome, SendVerificationCodeError>>
    {
        Box::pin(async move {
            let result = self
                .service
                .send_verification_code(normalized_email, peer_subject)
                .await;
            if let Err(SendVerificationCodeError::Delivery(error)) = &result {
                tracing::warn!(%error, "failed to send verification email");
            }
            result
        })
    }

    fn register_local_account(
        &self,
        input: RegisterLocalAccountInput,
    ) -> LocalRegistrationFuture<'_, Result<RegisteredAccount, RegisterLocalAccountError>> {
        Box::pin(async move {
            let result = self.service.register_local_account(input).await;
            match &result {
                Err(RegisterLocalAccountError::Create(error)) => {
                    tracing::warn!(%error, "failed to create user");
                }
                Err(RegisterLocalAccountError::Consistency) => {
                    tracing::warn!("created user returned outside the default tenant context");
                }
                _ => {}
            }
            result.map(RegisteredAccount::from)
        })
    }
}

/// Infrastructure adapter for the authentication fixed-window limiter.
///
/// Business-independent Valkey failures and counters are converted to a small
/// typed boundary; HTTP rendering remains in `nazo-http-actix`.
#[derive(Clone)]
pub(crate) struct ServerAuthenticationRateLimit {
    store: nazo_valkey::RateLimitStore,
    window_seconds: u64,
    max_requests: u64,
}

impl ServerAuthenticationRateLimit {
    pub(crate) fn new(
        store: nazo_valkey::RateLimitStore,
        window_seconds: u64,
        max_requests: u64,
    ) -> Self {
        Self {
            store,
            window_seconds,
            max_requests,
        }
    }
}

impl AuthenticationRateLimit for ServerAuthenticationRateLimit {
    fn enforce<'a>(
        &'a self,
        subject: &'a str,
    ) -> LocalRegistrationFuture<'a, Result<(), AuthenticationRateLimitError>> {
        Box::pin(async move {
            let count = self
                .store
                .increment(
                    nazo_valkey::RateDimension::Auth,
                    subject,
                    self.window_seconds,
                )
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "authentication rate limit increment failed");
                    AuthenticationRateLimitError::Unavailable
                })?;
            if count > self.max_requests {
                return Err(AuthenticationRateLimitError::Limited {
                    retry_after_seconds: self.window_seconds,
                });
            }
            Ok(())
        })
    }
}

#[cfg(test)]
#[path = "../../tests/in_source/src/domain/tests/local_registration.rs"]
mod tests;
