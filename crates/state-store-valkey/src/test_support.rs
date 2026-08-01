//! Raw Valkey harness for application contract tests.
//!
//! Production code must use focused stores rather than these raw inspection
//! primitives.

pub use fred::interfaces::{ClientLike, KeysInterface};
pub use fred::prelude::{
    Builder, Client, Config, ConnectionConfig, Error, Expiration, LuaInterface, PerformanceConfig,
};

use std::time::Duration;

/// Returns the actual storage key used for a PAR request URI.
///
/// This is intentionally exposed only through the raw test harness so
/// corruption and atomic-consumption contract tests do not duplicate key
/// derivation logic.
#[must_use]
pub fn par_storage_key(request_uri: &str) -> String {
    crate::keys::par(request_uri)
}

/// Returns the actual storage key used for an OIDC federation state token.
///
/// Raw cross-crate tests use this to inject malformed or legacy state without
/// copying production key derivation.
#[must_use]
pub fn oidc_federation_storage_key(state: &str) -> String {
    crate::keys::oidc_federation(state)
}

/// Returns the actual storage key used for a CIBA authentication request.
///
/// Raw cross-crate tests use this to inspect or inject state without copying
/// the production hashing and namespace contract.
#[must_use]
pub fn ciba_request_storage_key(auth_req_id: &str) -> String {
    crate::keys::ciba(auth_req_id)
}

/// Returns the actual storage key used for an authorization code.
///
/// Raw cross-crate tests use this to inspect state transitions without
/// duplicating the production hashing and namespace contract.
#[must_use]
pub fn authorization_code_storage_key(code: &str) -> String {
    crate::keys::authorization_code(code)
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
