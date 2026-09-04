use std::time::Duration;

use fred::{
    interfaces::ClientLike,
    prelude::{Builder, Config, ConnectionConfig, PerformanceConfig},
    types::config::ServerConfig,
};
use nazo_identity::TenantId;
use uuid::Uuid;

use crate::Error;

/// One initialized physical Valkey client shared by every tenant in a
/// deployment.
#[derive(Clone)]
pub struct ValkeyClient {
    pub(crate) client: fred::prelude::Client,
    namespace: String,
}

/// Cloneable connection handle used only to construct focused stores.
#[derive(Clone)]
pub struct ValkeyConnection {
    pub(crate) client: fred::prelude::Client,
    namespace: String,
}

impl ValkeyClient {
    /// Wrap an initialized Fred client in one deployment namespace.
    pub fn from_existing_client(
        client: fred::prelude::Client,
        deployment_id: &str,
        state_epoch: Uuid,
    ) -> Result<Self, Error> {
        Ok(Self {
            client,
            namespace: deployment_namespace(deployment_id, state_epoch)?,
        })
    }

    pub async fn connect(
        url: &str,
        command_timeout: Duration,
        deployment_id: &str,
        state_epoch: Uuid,
    ) -> Result<Self, Error> {
        let namespace = deployment_namespace(deployment_id, state_epoch)?;
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

    pub fn for_tenant(&self, tenant_id: TenantId) -> ValkeyConnection {
        ValkeyConnection {
            client: self.client.clone(),
            namespace: format!("{}tenant:{}:", self.namespace, tenant_id.as_uuid()),
        }
    }

    pub async fn health_check(&self) -> Result<(), Error> {
        health_check(&self.client).await
    }

    pub(crate) fn deployment_key(&self, key: &str) -> String {
        format!("{}{key}", self.namespace)
    }
}

impl ValkeyConnection {
    /// Wrap an already initialized Fred client in an explicit physical state
    /// namespace. Callers must provide the same deployment and epoch contract
    /// as normal startup; this constructor has no fallback namespace.
    pub fn from_existing_client(
        client: fred::prelude::Client,
        deployment_id: &str,
        state_epoch: Uuid,
        tenant_id: TenantId,
    ) -> Result<Self, Error> {
        Ok(Self {
            client,
            namespace: state_namespace(deployment_id, state_epoch, tenant_id)?,
        })
    }

    pub async fn connect(
        url: &str,
        command_timeout: Duration,
        deployment_id: &str,
        state_epoch: Uuid,
        tenant_id: TenantId,
    ) -> Result<Self, Error> {
        Ok(
            ValkeyClient::connect(url, command_timeout, deployment_id, state_epoch)
                .await?
                .for_tenant(tenant_id),
        )
    }

    /// Performs a real round trip used by readiness probes.
    pub async fn health_check(&self) -> Result<(), Error> {
        health_check(&self.client).await
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

pub(crate) fn deployment_namespace(
    deployment_id: &str,
    state_epoch: Uuid,
) -> Result<String, Error> {
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

pub(crate) fn state_namespace(
    deployment_id: &str,
    state_epoch: Uuid,
    tenant_id: TenantId,
) -> Result<String, Error> {
    Ok(format!(
        "{}tenant:{}:",
        deployment_namespace(deployment_id, state_epoch)?,
        tenant_id.as_uuid()
    ))
}

async fn health_check(client: &fred::prelude::Client) -> Result<(), Error> {
    let response: String = client.ping(None).await.map_err(Error::from_fred)?;
    if response == "PONG" {
        Ok(())
    } else {
        Err(Error::unexpected(
            "Valkey PING returned an unexpected response",
        ))
    }
}

impl std::fmt::Debug for ValkeyClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValkeyClient { .. }")
    }
}

impl std::fmt::Debug for ValkeyConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValkeyConnection { .. }")
    }
}
