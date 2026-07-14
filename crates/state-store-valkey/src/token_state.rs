use crate::{Error, ValkeyConnection, command, keys};
use serde_json::Value;
use uuid::Uuid;
#[derive(Clone, Debug)]
pub struct TokenStateStore {
    connection: ValkeyConnection,
}
impl TokenStateStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }
    pub async fn store_access_token_subject(
        &self,
        tenant: Uuid,
        jti: &str,
        user: Uuid,
        ttl: u64,
    ) -> Result<(), Error> {
        command::set_ex_string(
            &self.connection,
            keys::access_token_subject(tenant, jti),
            user.to_string(),
            ttl,
        )
        .await
    }
    pub async fn load_access_token_subject(
        &self,
        tenant: Uuid,
        jti: &str,
    ) -> Result<Option<Uuid>, Error> {
        command::get(&self.connection, keys::access_token_subject(tenant, jti))
            .await?
            .map(|raw| {
                Uuid::parse_str(&raw)
                    .map_err(|e| Error::protocol(format!("invalid access-token subject: {e}")))
            })
            .transpose()
    }
    pub async fn store_native_sso(
        &self,
        secret: &str,
        value: &Value,
        ttl: u64,
    ) -> Result<(), Error> {
        let raw = serde_json::to_string(value)
            .map_err(|e| Error::protocol(format!("failed to serialize native SSO state: {e}")))?;
        command::set_ex_string(&self.connection, keys::native_sso(secret), raw, ttl).await
    }
    pub async fn load_native_sso(&self, secret: &str) -> Result<Option<Value>, Error> {
        command::get(&self.connection, keys::native_sso(secret))
            .await?
            .map(|raw| {
                serde_json::from_str(&raw)
                    .map_err(|e| Error::protocol(format!("malformed native SSO state: {e}")))
            })
            .transpose()
    }
}
