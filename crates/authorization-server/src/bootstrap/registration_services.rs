use crate::adapters::email::SmtpVerificationEmailDelivery;
use crate::adapters::security::PasswordHashingError;
use crate::adapters::security::PasswordVerificationError;
use crate::adapters::security::hash_password_blocking_limited;
use crate::adapters::security::verify_password_blocking_limited;

#[derive(Clone, Copy)]
pub(crate) struct RegistrationSecretHasher;

impl nazo_identity::ports::SecretHashPort for RegistrationSecretHasher {
    fn hash_secret(
        &self,
        secret: String,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::ports::PasswordHashInput> {
        Box::pin(async move {
            let hash =
                hash_password_blocking_limited(secret)
                    .await
                    .map_err(|error| match error {
                        PasswordHashingError::Saturated | PasswordHashingError::WorkerFailed => {
                            nazo_identity::ports::RepositoryError::Unavailable
                        }
                        PasswordHashingError::HashFailed => {
                            nazo_identity::ports::RepositoryError::Unexpected(
                                "Argon2 password hashing failed".to_owned(),
                            )
                        }
                    })?;
            nazo_identity::ports::PasswordHashInput::new(hash).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(error.to_string())
            })
        })
    }

    fn verify_secret(
        &self,
        secret: String,
        password_hash: nazo_identity::PasswordHash,
    ) -> nazo_identity::ports::RepositoryFuture<'_, bool> {
        Box::pin(async move {
            verify_password_blocking_limited(secret, password_hash)
                .await
                .map_err(|error| match error {
                    PasswordVerificationError::Saturated
                    | PasswordVerificationError::WorkerFailed => {
                        nazo_identity::ports::RepositoryError::Unavailable
                    }
                })
        })
    }
}

pub(crate) type LocalRegistrationService = nazo_identity::RegistrationService<
    nazo_postgres::UserRepository,
    nazo_valkey::AuthenticationStore,
    RegistrationSecretHasher,
    SmtpVerificationEmailDelivery,
>;
