use crate::{PasswordHash, PublicAccount};

use super::NewUser;

use super::common::{PasswordHashInput, RepositoryFuture};

pub trait RegistrationAccountRepositoryPort: Send + Sync {
    fn account_by_email<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<PublicAccount>>;

    fn create_user(&self, user: NewUser) -> RepositoryFuture<'_, PublicAccount>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailVerificationRecord {
    pub password_hash: PasswordHash,
    pub opaque_version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmailVerificationConsume {
    Consumed,
    MissingOrChanged,
}

pub trait EmailVerificationStorePort: Send + Sync {
    fn reserve_peer_send<'a>(
        &'a self,
        subject: &'a str,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool>;

    fn reserve_email_send<'a>(
        &'a self,
        email: &'a str,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool>;

    fn store_code<'a>(
        &'a self,
        email: &'a str,
        password_hash: PasswordHashInput,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn load_code<'a>(
        &'a self,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<EmailVerificationRecord>>;

    fn consume_code<'a>(
        &'a self,
        email: &'a str,
        expected: &'a EmailVerificationRecord,
    ) -> RepositoryFuture<'a, EmailVerificationConsume>;

    fn delete_code<'a>(&'a self, email: &'a str) -> RepositoryFuture<'a, ()>;
    fn release_email_send<'a>(&'a self, email: &'a str) -> RepositoryFuture<'a, ()>;
    fn release_peer_send<'a>(&'a self, subject: &'a str) -> RepositoryFuture<'a, ()>;
}

pub trait SecretHashPort: Send + Sync {
    fn hash_secret(&self, secret: String) -> RepositoryFuture<'_, PasswordHashInput>;

    fn verify_secret(
        &self,
        secret: String,
        password_hash: PasswordHash,
    ) -> RepositoryFuture<'_, bool>;
}

pub trait VerificationEmailDeliveryPort: Send + Sync {
    fn deliver<'a>(
        &'a self,
        normalized_email: &'a str,
        code: &'a str,
        code_ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;
}
