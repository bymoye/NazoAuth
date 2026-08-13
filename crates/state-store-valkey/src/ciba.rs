use nazo_auth::{
    CibaAtomicResult, CibaPingNotificationStatus, CibaRequestState, CibaStatePortError,
    CibaStateStorePort, CibaStoredRequest,
};
use serde::Deserialize;
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
local lease_deadline = tonumber(ARGV[3]) or 0
local now = tonumber(redis.call('TIME')[1])
if lease_deadline > 0 and now >= lease_deadline then return 'deadline_elapsed' end
local deadline = tonumber(ARGV[2])
if now >= deadline then return 'deadline_elapsed' end
if redis.call('SETNX', KEYS[1], ARGV[1]) == 0 then return 'conflict' end
redis.call('EXPIREAT', KEYS[1], deadline)
if redis.call('EXISTS', KEYS[1]) == 0 then return 'deadline_elapsed' end
return 'applied'
"#;
const COMPARE_SET_DEADLINE_SCRIPT: &str = r#"
local deadline = tonumber(ARGV[3])
local now = tonumber(redis.call('TIME')[1])
local lease_deadline = tonumber(ARGV[6]) or 0
if lease_deadline > 0 and now >= lease_deadline then
  return 'deadline_elapsed'
end
if now >= deadline then
  local expired = redis.call('GET', KEYS[1])
  if expired and expired == ARGV[1] then
    redis.call('DEL', KEYS[1])
    redis.call('ZREM', KEYS[2], ARGV[4])
  end
  return 'deadline_elapsed'
end
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 'conflict' end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('EXPIREAT', KEYS[1], deadline)
if redis.call('EXISTS', KEYS[1]) == 0 then return 'deadline_elapsed' end
if ARGV[5] == '' then
  redis.call('ZREM', KEYS[2], ARGV[4])
else
  redis.call('ZADD', KEYS[2], tonumber(ARGV[5]), ARGV[4])
end
return 'applied'
"#;
const COMPARE_DELETE_DEADLINE_SCRIPT: &str = r#"
local deadline = tonumber(ARGV[2])
local now = tonumber(redis.call('TIME')[1])
local lease_deadline = tonumber(ARGV[4]) or 0
if lease_deadline > 0 and now >= lease_deadline then
  return 'deadline_elapsed'
end
if now >= deadline then
  local expired = redis.call('GET', KEYS[1])
  if expired and expired == ARGV[1] then
    redis.call('DEL', KEYS[1])
    redis.call('ZREM', KEYS[2], ARGV[3])
  end
  return 'deadline_elapsed'
end
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 'conflict' end
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], ARGV[3])
return 'applied'
"#;

const CLAIM_DUE_PING_SCRIPT: &str = r#"
local now = tonumber(ARGV[1])
local lock_until = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local prefix = ARGV[4]
local members = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now, 'LIMIT', 0, limit)
local deliveries = {}
for _, member in ipairs(members) do
  local state_key = prefix .. member
  local raw = redis.call('GET', state_key)
  if not raw then
    redis.call('ZREM', KEYS[1], member)
  else
    local ok, state = pcall(cjson.decode, raw)
    local notification = ok and state['ping_notification'] or nil
    if ok and tonumber(state['expires_at'] or 0) <= now then
      if notification then
        notification['status'] = 'failed'
        notification['next_attempt_at'] = nil
        notification['client_notification_token'] = nil
        state['ping_notification'] = notification
        redis.call('SET', state_key, cjson.encode(state), 'KEEPTTL')
      end
      redis.call('ZREM', KEYS[1], member)
    elseif notification
      and notification['status'] == 'pending'
      and notification['auth_req_id']
      and notification['client_notification_token']
      and tonumber(notification['next_attempt_at'] or 0) <= now then
      notification['attempts'] = tonumber(notification['attempts'] or 0) + 1
      notification['next_attempt_at'] = lock_until
      state['ping_notification'] = notification
      redis.call('SET', state_key, cjson.encode(state), 'KEEPTTL')
      redis.call('ZADD', KEYS[1], lock_until, member)
      table.insert(deliveries, {
        auth_req_id_hash = member,
        auth_req_id = notification['auth_req_id'],
        endpoint = notification['endpoint'],
        client_notification_token = notification['client_notification_token'],
        attempts = notification['attempts'],
        expires_at = state['expires_at']
      })
    elseif notification
      and notification['status'] == 'pending'
      and tonumber(notification['next_attempt_at'] or 0) > now then
      redis.call('ZADD', KEYS[1], tonumber(notification['next_attempt_at']), member)
    else
      redis.call('ZREM', KEYS[1], member)
    end
  end
end
if #deliveries == 0 then return '[]' end
return cjson.encode(deliveries)
"#;

const FINISH_PING_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then
  redis.call('ZREM', KEYS[2], ARGV[1])
  return 'missing'
end
local ok, state = pcall(cjson.decode, raw)
if not ok or not state['ping_notification'] then
  redis.call('ZREM', KEYS[2], ARGV[1])
  return 'corrupt'
end
local notification = state['ping_notification']
if notification['status'] ~= 'pending'
  or tonumber(notification['attempts'] or 0) ~= tonumber(ARGV[2]) then
  return 'conflict'
end
if ARGV[3] == 'retry' then
  notification['next_attempt_at'] = tonumber(ARGV[4])
  redis.call('ZADD', KEYS[2], tonumber(ARGV[4]), ARGV[1])
else
  notification['status'] = ARGV[3]
  notification['next_attempt_at'] = nil
  notification['client_notification_token'] = nil
  redis.call('ZREM', KEYS[2], ARGV[1])
end
state['ping_notification'] = notification
redis.call('SET', KEYS[1], cjson.encode(state), 'KEEPTTL')
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CibaPingDelivery {
    pub auth_req_id_hash: String,
    pub auth_req_id: String,
    pub endpoint: String,
    pub client_notification_token: String,
    pub attempts: u32,
    pub expires_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaPingFinishResult {
    Applied,
    Missing,
    Conflict,
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
        self.create_with_lease_deadline(auth_req_id, state, None)
            .await
    }

    pub async fn create_with_lease_deadline(
        &self,
        auth_req_id: &str,
        state: &CibaRequestState,
        lease_expires_at: Option<i64>,
    ) -> Result<AtomicResult, Error> {
        let mut state = state.clone();
        if let Some(notification) = state.ping_notification.as_mut() {
            notification.auth_req_id = Some(auth_req_id.to_owned());
        }
        let raw = serde_json::to_string(&state).map_err(serialization_error)?;
        let reply = command::eval_string(
            &self.connection,
            SET_NX_DEADLINE_SCRIPT,
            vec![keys::ciba(auth_req_id)],
            vec![
                raw,
                state.retention_expires_at.to_string(),
                lease_expires_at.map_or_else(String::new, |value| value.to_string()),
            ],
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
        self.replace_with_lease_deadline(auth_req_id, expected, replacement, None)
            .await
    }

    pub async fn replace_with_lease_deadline(
        &self,
        auth_req_id: &str,
        expected: &StoredCibaRequest,
        replacement: &CibaRequestState,
        lease_expires_at: Option<i64>,
    ) -> Result<AtomicResult, Error> {
        if replacement.retention_expires_at != expected.deadline {
            return Err(Error::protocol(
                "CIBA replacement changed retention deadline",
            ));
        }
        let raw = serde_json::to_string(replacement).map_err(serialization_error)?;
        let auth_req_id_hash = keys::ciba_hash(auth_req_id);
        let due_at = replacement
            .ping_notification
            .as_ref()
            .filter(|notification| notification.status == CibaPingNotificationStatus::Pending)
            .and_then(|notification| notification.next_attempt_at)
            .map_or_else(String::new, |value| value.to_string());
        let reply = command::eval_string(
            &self.connection,
            COMPARE_SET_DEADLINE_SCRIPT,
            vec![keys::ciba(auth_req_id), keys::ciba_ping_queue()],
            vec![
                expected.raw.clone(),
                raw,
                expected.deadline.to_string(),
                auth_req_id_hash,
                due_at,
                lease_expires_at.map_or_else(String::new, |value| value.to_string()),
            ],
        )
        .await?;
        parse_atomic(&reply)
    }

    pub async fn delete(
        &self,
        auth_req_id: &str,
        expected: &StoredCibaRequest,
    ) -> Result<AtomicResult, Error> {
        self.delete_with_lease_deadline(auth_req_id, expected, None)
            .await
    }

    pub async fn delete_with_lease_deadline(
        &self,
        auth_req_id: &str,
        expected: &StoredCibaRequest,
        lease_expires_at: Option<i64>,
    ) -> Result<AtomicResult, Error> {
        let reply = command::eval_string(
            &self.connection,
            COMPARE_DELETE_DEADLINE_SCRIPT,
            vec![keys::ciba(auth_req_id), keys::ciba_ping_queue()],
            vec![
                expected.raw.clone(),
                expected.deadline.to_string(),
                keys::ciba_hash(auth_req_id),
                lease_expires_at.map_or_else(String::new, |value| value.to_string()),
            ],
        )
        .await?;
        parse_atomic(&reply)
    }

    pub async fn claim_due_ping(
        &self,
        now: i64,
        lock_until: i64,
        limit: usize,
    ) -> Result<Vec<CibaPingDelivery>, Error> {
        let raw = command::eval_string(
            &self.connection,
            CLAIM_DUE_PING_SCRIPT,
            vec![keys::ciba_ping_queue()],
            vec![
                now.to_string(),
                lock_until.to_string(),
                limit.to_string(),
                "oauth:ciba:".to_owned(),
            ],
        )
        .await?;
        serde_json::from_str(&raw).map_err(serialization_error)
    }

    pub async fn finish_ping(
        &self,
        delivery: &CibaPingDelivery,
        outcome: CibaPingFinishOutcome,
    ) -> Result<CibaPingFinishResult, Error> {
        let (status, next_attempt_at) = match outcome {
            CibaPingFinishOutcome::Delivered => ("delivered", String::new()),
            CibaPingFinishOutcome::Failed => ("failed", String::new()),
            CibaPingFinishOutcome::RetryAt(next_attempt_at) => {
                ("retry", next_attempt_at.to_string())
            }
        };
        let reply = command::eval_string(
            &self.connection,
            FINISH_PING_SCRIPT,
            vec![
                keys::ciba_from_hash(&delivery.auth_req_id_hash),
                keys::ciba_ping_queue(),
            ],
            vec![
                delivery.auth_req_id_hash.clone(),
                delivery.attempts.to_string(),
                status.to_owned(),
                next_attempt_at,
            ],
        )
        .await?;
        match reply.as_str() {
            "applied" => Ok(CibaPingFinishResult::Applied),
            "missing" => Ok(CibaPingFinishResult::Missing),
            "conflict" => Ok(CibaPingFinishResult::Conflict),
            "corrupt" => Err(Error::protocol("corrupt CIBA ping notification state")),
            other => Err(Error::unexpected(format!(
                "unexpected CIBA ping finish result {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaPingFinishOutcome {
    Delivered,
    RetryAt(i64),
    Failed,
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

    fn create_with_lease_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        state: &'a CibaRequestState,
        lease_expires_at: Option<i64>,
    ) -> nazo_auth::CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async move {
            CibaStore::create_with_lease_deadline(self, auth_req_id, state, lease_expires_at)
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

    fn replace_with_lease_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        state: &'a CibaRequestState,
        lease_expires_at: Option<i64>,
    ) -> nazo_auth::CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async move {
            CibaStore::replace_with_lease_deadline(
                self,
                auth_req_id,
                version,
                state,
                lease_expires_at,
            )
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

    fn delete_with_lease_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        lease_expires_at: Option<i64>,
    ) -> nazo_auth::CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async move {
            CibaStore::delete_with_lease_deadline(self, auth_req_id, version, lease_expires_at)
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
