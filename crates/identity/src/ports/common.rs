use std::{future::Future, pin::Pin};

use crate::{IdentityModelError, PasswordHash};

pub type RepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RepositoryError>> + Send + 'a>>;
pub type AvatarStorageFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, super::avatar::AvatarStorageError>> + Send + 'a>>;
pub type SecretVerifyFuture<'a> = Pin<
    Box<dyn Future<Output = Result<bool, super::authentication::SecretVerifyError>> + Send + 'a>,
>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    Unavailable,
    Conflict,
    AlreadyProcessed,
    NotFound,
    Consistency(String),
    Unexpected(String),
}

impl std::fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("repository unavailable"),
            Self::Conflict => formatter.write_str("repository conflict"),
            Self::AlreadyProcessed => formatter.write_str("repository value already processed"),
            Self::NotFound => formatter.write_str("repository value not found"),
            Self::Consistency(message) => {
                write!(formatter, "repository consistency error: {message}")
            }
            Self::Unexpected(message) => {
                write!(formatter, "unexpected repository error: {message}")
            }
        }
    }
}

impl std::error::Error for RepositoryError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedSecretHash(String);

impl EncodedSecretHash {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityModelError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(IdentityModelError::EmptyPasswordHash);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Write-side password verifier material.
///
/// This capability is accepted only by new-identity commands. Authentication
/// projections return PasswordHash, which deliberately has no extraction API.
#[derive(Clone, Eq, PartialEq)]
pub struct PasswordHashInput(String);

impl std::fmt::Debug for PasswordHashInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PasswordHashInput([REDACTED])")
    }
}

impl PasswordHashInput {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityModelError> {
        let value = value.into();
        PasswordHash::new(value.clone())?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn into_persistence_value(self) -> String {
        self.0
    }
}
