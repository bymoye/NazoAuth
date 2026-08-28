use std::time::Duration;

use fred::{
    interfaces::ClientLike,
    prelude::{Builder, Config, ConnectionConfig, LuaInterface, PerformanceConfig},
    types::config::ServerConfig,
};
use nazo_identity::TenantId;
use uuid::Uuid;

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
if redis.call('DBSIZE') == 0 then
  redis.call('SET', KEYS[1], ARGV[1])
  return 'claimed'
end
return 'legacy_state'
"#;

/// Cloneable connection handle used only to construct focused stores.
#[derive(Clone)]
pub struct ValkeyConnection {
    pub(crate) client: fred::prelude::Client,
    namespace: String,
}

impl ValkeyConnection {
    /// Wrap an already initialized Fred client in an explicit physical state
    /// namespace. Callers must provide the same deployment and epoch contract
    /// as normal startup; this constructor has no fallback namespace.
    pub fn from_existing_client(
        client: fred::prelude::Client,
        deployment_id: &str,
        state_epoch: Uuid,
    ) -> Result<Self, Error> {
        Ok(Self {
            client,
            namespace: state_namespace(deployment_id, state_epoch)?,
        })
    }

    pub async fn connect(
        url: &str,
        command_timeout: Duration,
        deployment_id: &str,
        state_epoch: Uuid,
    ) -> Result<Self, Error> {
        let namespace = state_namespace(deployment_id, state_epoch)?;
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
        Ok(Self { client, namespace })
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
    /// The marker deliberately stays outside the state namespace. A database
    /// with unmarked keys is rejected rather than adopted: only an empty
    /// database may acquire this deployment's first owner marker.
    pub async fn bind_tenant_owner(&self, tenant_id: TenantId) -> Result<(), Error> {
        let tenant_id = tenant_id.as_uuid().to_string();
        let result: String = self
            .client
            .eval(
                CLAIM_TENANT_OWNER_SCRIPT,
                vec![TENANT_OWNER_KEY.to_owned()],
                vec![tenant_id],
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

    pub(crate) fn state_key(&self, key: String) -> String {
        format!("{}{key}", self.namespace)
    }

    pub(crate) fn state_keys(&self, keys: Vec<String>) -> Vec<String> {
        keys.into_iter().map(|key| self.state_key(key)).collect()
    }

    pub(crate) fn state_prefix(&self) -> &str {
        &self.namespace
    }
}

pub(crate) fn state_namespace(deployment_id: &str, state_epoch: Uuid) -> Result<String, Error> {
    let deployment_id = deployment_id.trim();
    if deployment_id.is_empty()
        || deployment_id.len() > 255
        || !deployment_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(Error::unexpected(
            "Valkey deployment identifier must be 1..=255 ASCII letters, digits, dots, dashes, or underscores",
        ));
    }
    if state_epoch.is_nil() {
        return Err(Error::unexpected("VALKEY_STATE_EPOCH must not be nil"));
    }
    Ok(format!("nazo:state:v1:{deployment_id}:{state_epoch}:"))
}

impl std::fmt::Debug for ValkeyConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValkeyConnection { .. }")
    }
}
