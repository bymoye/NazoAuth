use std::{future::Future, pin::Pin};

use serde_json::Value;
use uuid::Uuid;

use crate::OAuthClient;

pub type AdminClientFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AdminClientPortError>> + Send + 'a>>;
pub type SectorIdentifierFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminClientPortError {
    Unavailable,
    Conflict,
    CorruptData,
    Unexpected,
}

impl std::fmt::Display for AdminClientPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "admin client repository unavailable",
            Self::Conflict => "admin client repository conflict",
            Self::CorruptData => "admin client repository returned corrupt data",
            Self::Unexpected => "unexpected admin client repository failure",
        })
    }
}

impl std::error::Error for AdminClientPortError {}

/// Persistence boundary used by administrative client use cases.
pub trait AdminClientRepositoryPort: Send + Sync {
    fn page(&self, offset: i64, limit: i64) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)>;

    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>>;

    fn insert<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_blake3: Option<&'a str>,
        conformance_lease_id: Option<Uuid>,
    ) -> AdminClientFuture<'a, OAuthClient>;

    fn update<'a>(&'a self, client: &'a OAuthClient) -> AdminClientFuture<'a, OAuthClient>;
}

/// External sector identifier document lookup boundary.
pub trait SectorIdentifierResolverPort: Send + Sync {
    fn resolve<'a>(&'a self, uri: &'a str) -> SectorIdentifierFuture<'a>;
}

/// Cryptographic operations are isolated from protocol validation and use-case policy.
pub trait AdminClientCryptoPort: Send + Sync {
    fn response_signing_algorithms(&self) -> Vec<String>;
    fn id_token_signing_algorithms(&self) -> Vec<String> {
        self.response_signing_algorithms()
    }
    fn issue_client_secret(&self, pepper: &str) -> (String, String);
    fn validate_jwks(&self, jwks: &Value) -> Result<(), String>;
    fn validate_rfc4514_dn(&self, value: &str) -> Result<(), String>;
    fn matching_encryption_key_count(&self, jwks: &Value, algorithm: &str) -> usize;
    fn contains_signing_key(&self, jwks: &Value) -> bool;
    fn contains_signing_key_for_algorithm(&self, jwks: &Value, algorithm: &str) -> bool {
        let _ = algorithm;
        self.contains_signing_key(jwks)
    }
    fn valid_self_signed_mtls_jwks(&self, jwks: &Value) -> bool;
}
