use uuid::Uuid;

use crate::{
    PublicAccount, TenantContext,
    ports::{
        EmailVerificationConsume, EmailVerificationStorePort, NewUser,
        RegistrationAccountRepositoryPort, RepositoryError, SecretHashPort,
        VerificationEmailDeliveryPort,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationServiceConfig {
    pub delivery_enabled: bool,
    pub send_peer_cooldown_seconds: u64,
    pub send_cooldown_seconds: u64,
    pub code_ttl_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendVerificationCodeOutcome {
    Suppressed,
    Sent { code: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendVerificationCodeError {
    DeliveryNotConfigured,
    AccountLookup(RepositoryError),
    Reservation(RepositoryError),
    CodeHash(RepositoryError),
    CodeStore(RepositoryError),
    Delivery(RepositoryError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterLocalAccountInput {
    pub email: String,
    pub verification_code: String,
    pub password: String,
}

/// Minimal identity projection returned to the public registration transport.
///
/// The transport must not receive the full account, tenant, role, or profile
/// merely to render the stable `id` and `email` response fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredAccount {
    pub id: Uuid,
    pub email: String,
}

impl From<PublicAccount> for RegisteredAccount {
    fn from(account: PublicAccount) -> Self {
        Self {
            id: account.id(),
            email: account.account.email,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisterLocalAccountError {
    VerificationUnavailable(RepositoryError),
    InvalidVerificationCode,
    AccountLookup(RepositoryError),
    Conflict,
    PasswordHash(RepositoryError),
    Create(RepositoryError),
    Consistency,
}

#[derive(Clone)]
pub struct RegistrationService<A, V, H, E> {
    accounts: A,
    verification: V,
    secret_hashes: H,
    email_delivery: E,
    tenant: TenantContext,
    config: RegistrationServiceConfig,
}

impl<A, V, H, E> RegistrationService<A, V, H, E>
where
    A: RegistrationAccountRepositoryPort,
    V: EmailVerificationStorePort,
    H: SecretHashPort,
    E: VerificationEmailDeliveryPort,
{
    pub fn new(
        accounts: A,
        verification: V,
        secret_hashes: H,
        email_delivery: E,
        tenant: TenantContext,
        config: RegistrationServiceConfig,
    ) -> Self {
        Self {
            accounts,
            verification,
            secret_hashes,
            email_delivery,
            tenant,
            config,
        }
    }

    pub async fn send_verification_code(
        &self,
        normalized_email: &str,
        peer_subject: &str,
    ) -> Result<SendVerificationCodeOutcome, SendVerificationCodeError> {
        if !self.config.delivery_enabled {
            return Err(SendVerificationCodeError::DeliveryNotConfigured);
        }
        if self
            .accounts
            .account_by_email(self.tenant.tenant_id, normalized_email)
            .await
            .map_err(SendVerificationCodeError::AccountLookup)?
            .is_some()
        {
            return Ok(SendVerificationCodeOutcome::Suppressed);
        }
        if !self
            .verification
            .reserve_peer_send(peer_subject, self.config.send_peer_cooldown_seconds)
            .await
            .map_err(SendVerificationCodeError::Reservation)?
        {
            return Ok(SendVerificationCodeOutcome::Suppressed);
        }
        if !self
            .verification
            .reserve_email_send(normalized_email, self.config.send_cooldown_seconds)
            .await
            .map_err(SendVerificationCodeError::Reservation)?
        {
            return Ok(SendVerificationCodeOutcome::Suppressed);
        }

        let code = random_numeric_code();
        let password_hash = match self.secret_hashes.hash_secret(code.clone()).await {
            Ok(password_hash) => password_hash,
            Err(error) => {
                self.release_send_reservations(normalized_email, peer_subject)
                    .await;
                return Err(SendVerificationCodeError::CodeHash(error));
            }
        };
        if let Err(error) = self
            .verification
            .store_code(
                normalized_email,
                password_hash,
                self.config.code_ttl_seconds,
            )
            .await
        {
            self.release_send_reservations(normalized_email, peer_subject)
                .await;
            return Err(SendVerificationCodeError::CodeStore(error));
        }
        if let Err(error) = self
            .email_delivery
            .deliver(normalized_email, &code, self.config.code_ttl_seconds)
            .await
        {
            let _ = self.verification.delete_code(normalized_email).await;
            self.release_send_reservations(normalized_email, peer_subject)
                .await;
            return Err(SendVerificationCodeError::Delivery(error));
        }
        Ok(SendVerificationCodeOutcome::Sent { code })
    }

    pub async fn register_local_account(
        &self,
        input: RegisterLocalAccountInput,
    ) -> Result<PublicAccount, RegisterLocalAccountError> {
        let record = self
            .verification
            .load_code(&input.email)
            .await
            .map_err(RegisterLocalAccountError::VerificationUnavailable)?
            .ok_or(RegisterLocalAccountError::InvalidVerificationCode)?;
        let verified = self
            .secret_hashes
            .verify_secret(input.verification_code, record.password_hash.clone())
            .await
            .map_err(RegisterLocalAccountError::VerificationUnavailable)?;
        if !verified {
            return Err(RegisterLocalAccountError::InvalidVerificationCode);
        }

        // Preserve enumeration resistance without destroying a valid code for an
        // address that is already registered. A concurrent create is still
        // handled below after the one-time code has been atomically consumed.
        if self
            .accounts
            .account_by_email(self.tenant.tenant_id, &input.email)
            .await
            .map_err(RegisterLocalAccountError::AccountLookup)?
            .is_some()
        {
            return Err(RegisterLocalAccountError::Conflict);
        }
        match self
            .verification
            .consume_code(&input.email, &record)
            .await
            .map_err(RegisterLocalAccountError::VerificationUnavailable)?
        {
            EmailVerificationConsume::Consumed => {}
            EmailVerificationConsume::MissingOrChanged => {
                return Err(RegisterLocalAccountError::InvalidVerificationCode);
            }
        }
        let password_hash = self
            .secret_hashes
            .hash_secret(input.password)
            .await
            .map_err(RegisterLocalAccountError::PasswordHash)?;
        let account = self
            .accounts
            .create_user(NewUser {
                tenant: self.tenant,
                username: format!("user_{}", Uuid::now_v7()),
                email: input.email,
                password_hash,
                email_verified: true,
            })
            .await
            .map_err(|error| match error {
                RepositoryError::Conflict => RegisterLocalAccountError::Conflict,
                error => RegisterLocalAccountError::Create(error),
            })?;
        if account.tenant() != self.tenant {
            return Err(RegisterLocalAccountError::Consistency);
        }
        Ok(account)
    }

    async fn release_send_reservations(&self, email: &str, peer_subject: &str) {
        let _ = self.verification.release_peer_send(peer_subject).await;
        let _ = self.verification.release_email_send(email).await;
    }
}

fn random_numeric_code() -> String {
    const RANGE: u32 = 1_000_000;
    const LIMIT: u32 = u32::MAX - (u32::MAX % RANGE);

    loop {
        let value = u32::from_be_bytes(rand::random::<[u8; 4]>());
        if value < LIMIT {
            return format!("{:06}", value % RANGE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::random_numeric_code;

    #[test]
    fn verification_codes_are_fixed_width_decimal_values() {
        for _ in 0..64 {
            let code = random_numeric_code();
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
        }
    }
}
