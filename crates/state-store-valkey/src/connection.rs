use std::time::Duration;

use fred::{
    interfaces::ClientLike,
    prelude::{Builder, Config, ConnectionConfig, LuaInterface, PerformanceConfig},
    types::config::ServerConfig,
};
use nazo_identity::{DEFAULT_TENANT_ID, TenantId};

use crate::Error;

const TENANT_OWNER_KEY: &str = "nazo:runtime:tenant-owner:v1";
const CLAIM_TENANT_OWNER_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if current then
  if current == ARGV[1] then
    return 'owned'
  end
  return 'conflict'
end
if redis.call('DBSIZE') == 0 or ARGV[1] == ARGV[2] then
  redis.call('SET', KEYS[1], ARGV[1])
  return 'claimed'
end
return 'legacy_state'
"#;

/// Cloneable connection handle used only to construct focused stores.
#[derive(Clone)]
pub struct ValkeyConnection {
    pub(crate) client: fred::prelude::Client,
}

impl ValkeyConnection {
    /// Wrap an already initialized Fred client during the server cutover.
    #[doc(hidden)]
    pub fn from_existing_client(client: fred::prelude::Client) -> Self {
        Self { client }
    }

    pub async fn connect(url: &str, command_timeout: Duration) -> Result<Self, Error> {
        let config = Config::from_url(url).map_err(Error::from_fred)?;
        if !matches!(config.server, ServerConfig::Centralized { .. }) {
            return Err(Error::unexpected(
                "only standalone Valkey topology is supported by reviewed multi-key scripts",
            ));
        }
        let mut builder = Builder::from_config(config);
        builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = command_timeout;
        });
        builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = command_timeout;
            connection.internal_command_timeout = command_timeout;
            connection.max_command_attempts = 1;
        });
        let client = builder.build().map_err(Error::from_fred)?;
        client.init().await.map_err(Error::from_fred)?;
        Ok(Self { client })
    }

    /// Performs a real round trip used by readiness probes.
    pub async fn health_check(&self) -> Result<(), Error> {
        let response: String = self.client.ping(None).await.map_err(Error::from_fred)?;
        if response == "PONG" {
            Ok(())
        } else {
            Err(Error::unexpected(
                "Valkey PING returned an unexpected response",
            ))
        }
    }

    /// Permanently binds this Valkey logical database to one active tenant.
    ///
    /// Existing unmarked state can only be adopted by the legacy default
    /// tenant. A non-default tenant must start from an empty logical database,
    /// preventing tenant-blind transient keys from crossing deployment
    /// boundaries while request-level namespacing is still incomplete.
    pub async fn bind_tenant_owner(&self, tenant_id: TenantId) -> Result<(), Error> {
        let tenant_id = tenant_id.as_uuid().to_string();
        let default_tenant_id = DEFAULT_TENANT_ID.to_string();
        let result: String = self
            .client
            .eval(
                CLAIM_TENANT_OWNER_SCRIPT,
                vec![TENANT_OWNER_KEY.to_owned()],
                vec![tenant_id, default_tenant_id],
            )
            .await
            .map_err(Error::from_fred)?;
        match result.as_str() {
            "owned" | "claimed" => Ok(()),
            "conflict" => Err(Error::unexpected(
                "Valkey logical database is already bound to another active tenant",
            )),
            "legacy_state" => Err(Error::unexpected(
                "non-default active tenant requires an empty Valkey logical database before its ownership marker can be established",
            )),
            other => Err(Error::unexpected(format!(
                "unexpected tenant owner preflight reply {other:?}"
            ))),
        }
    }
}

impl std::fmt::Debug for ValkeyConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValkeyConnection { .. }")
    }
}
