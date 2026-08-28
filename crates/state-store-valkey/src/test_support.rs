//! Raw Valkey harness for application contract tests.
//!
//! Production code must use focused stores rather than these raw inspection
//! primitives.

pub use fred::interfaces::{ClientLike, KeysInterface};
pub use fred::prelude::{
    Builder, Client, Config, ConnectionConfig, Error, Expiration, LuaInterface, PerformanceConfig,
};

use std::time::Duration;
use uuid::Uuid;

const TEST_DEPLOYMENT_ID: &str = "test";
const TEST_STATE_EPOCH: Uuid = Uuid::from_u128(0x019c_8ca2_30a6_7000_8000_0000_0000_0001);

/// Prefix an inspected business key with the fixed explicit test namespace.
/// Raw test clients never receive an unscoped business key.
#[must_use]
pub fn state_storage_key(key: impl AsRef<str>) -> String {
    storage_key(TEST_DEPLOYMENT_ID, TEST_STATE_EPOCH, key)
        .expect("fixed test state namespace is valid")
}

/// Derive a physical key for a raw inspector from the same namespace boundary
/// production construction uses. This is test-only evidence, not a second
/// key-building API for application code.
pub fn storage_key(
    deployment_id: &str,
    state_epoch: Uuid,
    key: impl AsRef<str>,
) -> Result<String, crate::Error> {
    Ok(format!(
        "{}{}",
        crate::connection::state_namespace(deployment_id, state_epoch)?,
        key.as_ref()
    ))
}

/// Returns the actual storage key used for a PAR request URI.
///
/// This is intentionally exposed only through the raw test harness so
/// corruption and atomic-consumption contract tests do not duplicate key
/// derivation logic.
#[must_use]
pub fn par_storage_key(request_uri: &str) -> String {
    state_storage_key(crate::keys::par(request_uri))
}

/// Returns the actual storage key used for an OIDC federation state token.
///
/// Raw cross-crate tests use this to inject malformed or legacy state without
/// copying production key derivation.
#[must_use]
pub fn oidc_federation_storage_key(state: &str) -> String {
    state_storage_key(crate::keys::oidc_federation(state))
}

/// Returns the actual storage key used for a CIBA authentication request.
///
/// Raw cross-crate tests use this to inspect or inject state without copying
/// the production hashing and namespace contract.
#[must_use]
pub fn ciba_request_storage_key(auth_req_id: &str) -> String {
    state_storage_key(crate::keys::ciba(auth_req_id))
}

/// Returns the actual storage key used for an authorization code.
///
/// Raw cross-crate tests use this to inspect state transitions without
/// duplicating the production hashing and namespace contract.
#[must_use]
pub fn authorization_code_storage_key(code: &str) -> String {
    state_storage_key(crate::keys::authorization_code(code))
}

pub async fn connect(url: &str, timeout: Duration) -> Result<Client, Error> {
    let mut builder = Builder::from_config(Config::from_url(url)?);
    builder.with_performance_config(|config: &mut PerformanceConfig| {
        config.default_command_timeout = timeout;
    });
    builder.with_connection_config(|config: &mut ConnectionConfig| {
        config.connection_timeout = timeout;
        config.internal_command_timeout = timeout;
        config.max_command_attempts = 1;
    });
    let client = builder.build()?;
    client.init().await?;
    Ok(client)
}

/// Construct a scoped store connection for tests. Production construction has
/// no test fallback and always receives the deployment epoch from startup.
pub fn scoped_connection(client: Client) -> crate::ValkeyConnection {
    crate::ValkeyConnection::from_existing_client(client, TEST_DEPLOYMENT_ID, TEST_STATE_EPOCH)
        .expect("fixed test state namespace is valid")
}

pub async fn scoped_connect(
    url: &str,
    timeout: Duration,
) -> Result<crate::ValkeyConnection, crate::Error> {
    let client = connect(url, timeout)
        .await
        .map_err(crate::Error::from_fred)?;
    Ok(scoped_connection(client))
}
