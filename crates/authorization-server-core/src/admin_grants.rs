use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::authorization_service::AuthorizationPortError;

pub type AdminGrantFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AuthorizationPortError>> + Send + 'a>>;
pub type AdminGrantRevokeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AdminGrantRevocation, AdminGrantRevokeError>> + Send + 'a>>;

#[derive(Clone, Debug, PartialEq)]
pub struct AdminGrantView {
    pub user_id: Uuid,
    pub email: String,
    pub client_id: String,
    pub client_name: String,
    pub last_authorized_at: DateTime<Utc>,
    pub authorization_count: i32,
    pub last_scopes: Vec<String>,
    pub last_authorization_details: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AdminGrantPage {
    pub total: i64,
    pub grants: Vec<AdminGrantView>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminGrantRevocation {
    pub revoked_refresh_tokens: usize,
    pub removed_grants: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminGrantRevokeError {
    ClientNotFound,
    ClientLookup(AuthorizationPortError),
    Revoke(AuthorizationPortError),
}

impl std::fmt::Display for AdminGrantRevokeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientNotFound => formatter.write_str("OAuth client not found"),
            Self::ClientLookup(error) => write!(formatter, "OAuth client lookup failed: {error}"),
            Self::Revoke(error) => write!(formatter, "grant revocation failed: {error}"),
        }
    }
}

impl std::error::Error for AdminGrantRevokeError {}

/// Administrative grant persistence boundary.
///
/// Implementations must resolve the logical client id and revoke its grants and
/// refresh tokens in one atomic storage transaction.
pub trait AdminGrantRepositoryPort: Send + Sync {
    fn page(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> AdminGrantFuture<'_, AdminGrantPage>;

    fn revoke_by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        client_id: &'a str,
    ) -> AdminGrantRevokeFuture<'a>;
}
