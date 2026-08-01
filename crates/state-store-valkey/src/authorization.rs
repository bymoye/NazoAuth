use chrono::{DateTime, SecondsFormat, Utc};
use nazo_auth::{AuthorizationCodeState, CodePayload, ConsentPayload, PushedAuthorizationRequest};

use crate::{Error, ValkeyConnection, command, keys};

const BEGIN_AUTHORIZATION_CODE_CONSUMPTION_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 'missing'
end
local ok, state = pcall(cjson.decode, raw)
if not ok or type(state) ~= 'table' or type(state.status) ~= 'string' then
  return 'malformed'
end
if state.status == 'pending' then
  if type(state.payload) ~= 'table' then
    return 'malformed'
  end
  state.status = 'consuming'
  state.consuming_at = ARGV[1]
  redis.call('SET', KEYS[1], cjson.encode(state), 'KEEPTTL')
  return 'consuming|' .. cjson.encode(state.payload)
end
if state.status == 'consuming' then
  return 'busy'
end
if state.status == 'consumed' then
  return 'consumed|' .. raw
end
if state.status == 'failed' then
  return 'failed'
end
return 'malformed'
"#;

const MARK_AUTHORIZATION_CODE_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 'missing'
end
local ok, state = pcall(cjson.decode, raw)
if not ok or type(state) ~= 'table' or type(state.status) ~= 'string' then
  return 'malformed'
end
if state.status ~= 'consuming' then
  return state.status
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 'ok'
"#;

#[derive(Debug)]
pub enum AuthorizationCodeBegin {
    Consuming(CodePayload),
    Busy,
    Consumed(AuthorizationCodeState),
    Failed,
    Missing,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationTransition {
    Applied,
    Missing,
    Malformed,
    Pending,
    Consuming,
    Consumed,
    Failed,
}

#[derive(Clone, Debug)]
pub struct AuthorizationStore {
    connection: ValkeyConnection,
}

impl AuthorizationStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }

    pub async fn store_consent(
        &self,
        request_id: &str,
        payload: &ConsentPayload,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        self.store_json(keys::consent(request_id), payload, ttl_seconds)
            .await
    }

    pub async fn load_consent(&self, request_id: &str) -> Result<Option<ConsentPayload>, Error> {
        self.load_json(keys::consent(request_id)).await
    }

    pub async fn take_consent(&self, request_id: &str) -> Result<Option<ConsentPayload>, Error> {
        self.take_json(keys::consent(request_id)).await
    }

    pub async fn compare_and_delete_consent(
        &self,
        request_id: &str,
        expected: &ConsentPayload,
    ) -> Result<bool, Error> {
        self.compare_delete_json(keys::consent(request_id), expected)
            .await
    }

    pub async fn delete_consent(&self, request_id: &str) -> Result<i64, Error> {
        command::delete(&self.connection, keys::consent(request_id)).await
    }

    pub async fn store_par(
        &self,
        request_uri: &str,
        payload: &PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        self.store_json(keys::par(request_uri), payload, ttl_seconds)
            .await
    }

    pub async fn load_par(
        &self,
        request_uri: &str,
    ) -> Result<Option<PushedAuthorizationRequest>, Error> {
        self.load_json(keys::par(request_uri)).await
    }

    pub async fn take_par(
        &self,
        request_uri: &str,
    ) -> Result<Option<PushedAuthorizationRequest>, Error> {
        self.take_json(keys::par(request_uri)).await
    }

    pub async fn compare_and_delete_par(
        &self,
        request_uri: &str,
        expected: &PushedAuthorizationRequest,
    ) -> Result<bool, Error> {
        self.compare_delete_json(keys::par(request_uri), expected)
            .await
    }

    pub async fn store_authorization_code_hash(
        &self,
        code_hash: &str,
        state: &AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        self.store_json(keys::authorization_code_hash(code_hash), state, ttl_seconds)
            .await
    }

    pub async fn load_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeState>, Error> {
        self.load_json(keys::authorization_code(code)).await
    }

    pub async fn load_authorization_code_hash(
        &self,
        code_hash: &str,
    ) -> Result<Option<AuthorizationCodeState>, Error> {
        self.load_json(keys::authorization_code_hash(code_hash))
            .await
    }

    pub async fn delete_authorization_code_hash(&self, code_hash: &str) -> Result<i64, Error> {
        command::delete(&self.connection, keys::authorization_code_hash(code_hash)).await
    }

    pub async fn begin_authorization_code(
        &self,
        code_hash: &str,
        consuming_at: DateTime<Utc>,
    ) -> Result<AuthorizationCodeBegin, Error> {
        let reply = command::eval_string(
            &self.connection,
            BEGIN_AUTHORIZATION_CODE_CONSUMPTION_SCRIPT,
            vec![keys::authorization_code_hash(code_hash)],
            vec![consuming_at.to_rfc3339_opts(SecondsFormat::Millis, true)],
        )
        .await?;
        parse_authorization_code_begin_reply(&reply)
    }

    pub async fn mark_authorization_code(
        &self,
        code_hash: &str,
        replacement: &AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> Result<AuthorizationTransition, Error> {
        let raw = serde_json::to_string(replacement).map_err(|error| {
            Error::protocol(format!("failed to serialize authorization code: {error}"))
        })?;
        let reply = command::eval_string(
            &self.connection,
            MARK_AUTHORIZATION_CODE_SCRIPT,
            vec![keys::authorization_code_hash(code_hash)],
            vec![raw, ttl_seconds.to_string()],
        )
        .await?;
        match reply.as_str() {
            "ok" => Ok(AuthorizationTransition::Applied),
            "missing" => Ok(AuthorizationTransition::Missing),
            "malformed" => Ok(AuthorizationTransition::Malformed),
            "pending" => Ok(AuthorizationTransition::Pending),
            "consuming" => Ok(AuthorizationTransition::Consuming),
            "consumed" => Ok(AuthorizationTransition::Consumed),
            "failed" => Ok(AuthorizationTransition::Failed),
            other => Err(Error::unexpected(format!(
                "unexpected authorization-code transition {other:?}"
            ))),
        }
    }

    pub async fn store_reauth_nonce(
        &self,
        nonce: &str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        command::set_ex_string(
            &self.connection,
            keys::reauth_nonce(nonce),
            started_at.to_string(),
            ttl_seconds,
        )
        .await
    }

    pub async fn take_reauth_nonce(&self, nonce: &str) -> Result<Option<i64>, Error> {
        command::take(&self.connection, keys::reauth_nonce(nonce))
            .await?
            .map(|raw| {
                raw.parse().map_err(|error| {
                    Error::corrupt_data(format!("malformed reauth timestamp: {error}"))
                })
            })
            .transpose()
    }

    async fn store_json<T: serde::Serialize + ?Sized>(
        &self,
        key: String,
        value: &T,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        let raw = serde_json::to_string(value).map_err(|error| {
            Error::protocol(format!("failed to serialize authorization state: {error}"))
        })?;
        command::set_ex_string(&self.connection, key, raw, ttl_seconds).await
    }

    async fn load_json<T: serde::de::DeserializeOwned>(
        &self,
        key: String,
    ) -> Result<Option<T>, Error> {
        command::get(&self.connection, key)
            .await?
            .map(|raw| {
                serde_json::from_str(&raw).map_err(|error| {
                    Error::corrupt_data(format!("malformed authorization state: {error}"))
                })
            })
            .transpose()
    }

    async fn take_json<T: serde::de::DeserializeOwned>(
        &self,
        key: String,
    ) -> Result<Option<T>, Error> {
        command::take(&self.connection, key)
            .await?
            .map(|raw| {
                serde_json::from_str(&raw).map_err(|error| {
                    Error::corrupt_data(format!("malformed consumed authorization state: {error}"))
                })
            })
            .transpose()
    }

    async fn compare_delete_json<T: serde::Serialize + ?Sized>(
        &self,
        key: String,
        expected: &T,
    ) -> Result<bool, Error> {
        let expected = serde_json::to_string(expected).map_err(|error| {
            Error::protocol(format!(
                "failed to serialize expected authorization state: {error}"
            ))
        })?;
        command::compare_delete_json(&self.connection, key, &expected)
            .await
            .map(|outcome| matches!(outcome, command::CompareDelete::Deleted))
    }
}

fn parse_authorization_code_begin_reply(reply: &str) -> Result<AuthorizationCodeBegin, Error> {
    if let Some(raw) = reply.strip_prefix("consuming|") {
        return serde_json::from_str(raw)
            .map(AuthorizationCodeBegin::Consuming)
            .map_err(|error| {
                Error::corrupt_data(format!("malformed consuming authorization code: {error}"))
            });
    }
    if let Some(raw) = reply.strip_prefix("consumed|") {
        return serde_json::from_str(raw)
            .map(AuthorizationCodeBegin::Consumed)
            .map_err(|error| {
                Error::corrupt_data(format!("malformed consumed authorization code: {error}"))
            });
    }
    match reply {
        "busy" => Ok(AuthorizationCodeBegin::Busy),
        "failed" => Ok(AuthorizationCodeBegin::Failed),
        "missing" => Ok(AuthorizationCodeBegin::Missing),
        "malformed" => Ok(AuthorizationCodeBegin::Malformed),
        other => Err(Error::unexpected(format!(
            "unexpected authorization-code begin reply {other:?}"
        ))),
    }
}

#[cfg(test)]
#[path = "../tests/unit/authorization.rs"]
mod tests;
