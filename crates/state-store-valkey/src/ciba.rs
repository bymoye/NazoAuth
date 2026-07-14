use nazo_auth::{
    CibaAtomicResult, CibaRequestState, CibaStatePortError, CibaStateStorePort, CibaStoredRequest,
};
use serde_json::{Number, Value};

use crate::{Error, ValkeyConnection, command, keys};

const SNAPSHOT_SCRIPT: &str = r#"
local value = redis.call('GET', KEYS[1])
if not value then
  return cjson.encode({found = false})
end
return cjson.encode({found = true, value = value, expire_at = redis.call('EXPIRETIME', KEYS[1])})
"#;
const SET_NX_DEADLINE_SCRIPT: &str = r#"
local deadline = tonumber(ARGV[2])
local now = tonumber(redis.call('TIME')[1])
if now >= deadline then return 'deadline_elapsed' end
if redis.call('SETNX', KEYS[1], ARGV[1]) == 0 then return 'conflict' end
redis.call('EXPIREAT', KEYS[1], deadline)
if redis.call('EXISTS', KEYS[1]) == 0 then return 'deadline_elapsed' end
return 'applied'
"#;
const COMPARE_SET_DEADLINE_SCRIPT: &str = r#"
local deadline = tonumber(ARGV[3])
local now = tonumber(redis.call('TIME')[1])
if now >= deadline then
  local expired = redis.call('GET', KEYS[1])
  if expired and expired == ARGV[1] then redis.call('DEL', KEYS[1]) end
  return 'deadline_elapsed'
end
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 'conflict' end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('EXPIREAT', KEYS[1], deadline)
if redis.call('EXISTS', KEYS[1]) == 0 then return 'deadline_elapsed' end
return 'applied'
"#;
const COMPARE_DELETE_DEADLINE_SCRIPT: &str = r#"
local deadline = tonumber(ARGV[2])
local now = tonumber(redis.call('TIME')[1])
if now >= deadline then
  local expired = redis.call('GET', KEYS[1])
  if expired and expired == ARGV[1] then redis.call('DEL', KEYS[1]) end
  return 'deadline_elapsed'
end
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 'conflict' end
redis.call('DEL', KEYS[1])
return 'applied'
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicResult {
    Applied,
    Conflict,
    DeadlineElapsed,
}

#[derive(Clone, Debug)]
pub struct StoredCibaRequest {
    value: CibaRequestState,
    raw: String,
    deadline: i64,
}
impl StoredCibaRequest {
    pub fn value(&self) -> &CibaRequestState {
        &self.value
    }
}

#[derive(Clone, Debug)]
pub struct CibaStore {
    connection: ValkeyConnection,
}
impl CibaStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }

    pub async fn create(
        &self,
        auth_req_id: &str,
        state: &CibaRequestState,
    ) -> Result<AtomicResult, Error> {
        let raw = serde_json::to_string(state).map_err(serialization_error)?;
        let reply = command::eval_string(
            &self.connection,
            SET_NX_DEADLINE_SCRIPT,
            vec![keys::ciba(auth_req_id)],
            vec![raw, state.retention_expires_at.to_string()],
        )
        .await?;
        parse_atomic(&reply)
    }

    pub async fn load(&self, auth_req_id: &str) -> Result<Option<StoredCibaRequest>, Error> {
        let reply = command::eval_string(
            &self.connection,
            SNAPSHOT_SCRIPT,
            vec![keys::ciba(auth_req_id)],
            vec![],
        )
        .await?;
        let snapshot: Value = serde_json::from_str(&reply).map_err(serialization_error)?;
        if snapshot.get("found").and_then(Value::as_bool) != Some(true) {
            return Ok(None);
        }
        let raw = snapshot
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::protocol("missing CIBA snapshot value"))?
            .to_owned();
        let deadline = snapshot
            .get("expire_at")
            .and_then(Value::as_i64)
            .ok_or_else(|| Error::protocol("missing CIBA snapshot deadline"))?;
        let mut object: Value = serde_json::from_str(&raw).map_err(serialization_error)?;
        if object.get("retention_expires_at").is_none() {
            object["retention_expires_at"] = Value::Number(Number::from(deadline));
        }
        let value: CibaRequestState =
            serde_json::from_value(object).map_err(serialization_error)?;
        if value.retention_expires_at != deadline {
            return Err(Error::protocol(
                "CIBA retention deadline disagrees with EXPIRETIME",
            ));
        }
        Ok(Some(StoredCibaRequest {
            value,
            raw,
            deadline,
        }))
    }

    pub async fn replace(
        &self,
        auth_req_id: &str,
        expected: &StoredCibaRequest,
        replacement: &CibaRequestState,
    ) -> Result<AtomicResult, Error> {
        if replacement.retention_expires_at != expected.deadline {
            return Err(Error::protocol(
                "CIBA replacement changed retention deadline",
            ));
        }
        let raw = serde_json::to_string(replacement).map_err(serialization_error)?;
        let reply = command::eval_string(
            &self.connection,
            COMPARE_SET_DEADLINE_SCRIPT,
            vec![keys::ciba(auth_req_id)],
            vec![expected.raw.clone(), raw, expected.deadline.to_string()],
        )
        .await?;
        parse_atomic(&reply)
    }

    pub async fn delete(
        &self,
        auth_req_id: &str,
        expected: &StoredCibaRequest,
    ) -> Result<AtomicResult, Error> {
        let reply = command::eval_string(
            &self.connection,
            COMPARE_DELETE_DEADLINE_SCRIPT,
            vec![keys::ciba(auth_req_id)],
            vec![expected.raw.clone(), expected.deadline.to_string()],
        )
        .await?;
        parse_atomic(&reply)
    }
}

impl CibaStateStorePort for CibaStore {
    type Version = StoredCibaRequest;

    fn load<'a>(
        &'a self,
        auth_req_id: &'a str,
    ) -> nazo_auth::CibaStateFuture<'a, Option<CibaStoredRequest<Self::Version>>> {
        Box::pin(async move {
            CibaStore::load(self, auth_req_id)
                .await
                .map_err(port_error)
                .map(|stored| {
                    stored.map(|version| CibaStoredRequest::new(version.value().clone(), version))
                })
        })
    }

    fn create<'a>(
        &'a self,
        auth_req_id: &'a str,
        state: &'a CibaRequestState,
    ) -> nazo_auth::CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async move {
            CibaStore::create(self, auth_req_id, state)
                .await
                .map(Into::into)
                .map_err(port_error)
        })
    }

    fn replace<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        state: &'a CibaRequestState,
    ) -> nazo_auth::CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async move {
            CibaStore::replace(self, auth_req_id, version, state)
                .await
                .map(Into::into)
                .map_err(port_error)
        })
    }

    fn delete<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
    ) -> nazo_auth::CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async move {
            CibaStore::delete(self, auth_req_id, version)
                .await
                .map(Into::into)
                .map_err(port_error)
        })
    }
}

impl From<AtomicResult> for CibaAtomicResult {
    fn from(result: AtomicResult) -> Self {
        match result {
            AtomicResult::Applied => Self::Applied,
            AtomicResult::Conflict => Self::Conflict,
            AtomicResult::DeadlineElapsed => Self::DeadlineElapsed,
        }
    }
}

fn serialization_error(error: serde_json::Error) -> Error {
    Error::protocol(format!("invalid CIBA state: {error}"))
}

fn port_error(error: Error) -> CibaStatePortError {
    match error.kind() {
        crate::ErrorKind::Timeout | crate::ErrorKind::Unavailable => {
            CibaStatePortError::Unavailable
        }
        crate::ErrorKind::Protocol | crate::ErrorKind::CorruptData => {
            CibaStatePortError::CorruptData
        }
        crate::ErrorKind::UnexpectedResult => CibaStatePortError::Unexpected,
    }
}
fn parse_atomic(reply: &str) -> Result<AtomicResult, Error> {
    match reply {
        "applied" => Ok(AtomicResult::Applied),
        "conflict" => Ok(AtomicResult::Conflict),
        "deadline_elapsed" => Ok(AtomicResult::DeadlineElapsed),
        other => Err(Error::unexpected(format!(
            "unexpected atomic result {other:?}"
        ))),
    }
}
