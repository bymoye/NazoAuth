//! Valkey 缓存命令封装。
// 这里保留最小 Redis 协议操作，业务 key 仍由调用方决定。

use super::prelude::*;
use fred::prelude::LuaInterface;
use std::fmt;

const VALKEY_SNAPSHOT_SCRIPT: &str = r#"
local value = redis.call('GET', KEYS[1])
if not value then
  return cjson.encode({found = false})
end
return cjson.encode({
  found = true,
  value = value,
  expire_at = redis.call('EXPIRETIME', KEYS[1])
})
"#;

const VALKEY_SET_NX_AT_DEADLINE_SCRIPT: &str = r#"
local deadline = tonumber(ARGV[2])
local now = tonumber(redis.call('TIME')[1])
if now >= deadline then
  return 'deadline_elapsed'
end
if redis.call('SETNX', KEYS[1], ARGV[1]) == 0 then
  return 'conflict'
end
redis.call('EXPIREAT', KEYS[1], deadline)
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 'deadline_elapsed'
end
return 'applied'
"#;

const VALKEY_COMPARE_SET_AT_DEADLINE_SCRIPT: &str = r#"
local deadline = tonumber(ARGV[3])
local now = tonumber(redis.call('TIME')[1])
if now >= deadline then
  local expired = redis.call('GET', KEYS[1])
  if expired and expired == ARGV[1] then
    redis.call('DEL', KEYS[1])
  end
  return 'deadline_elapsed'
end
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then
  return 'conflict'
end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('EXPIREAT', KEYS[1], deadline)
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 'deadline_elapsed'
end
return 'applied'
"#;

const VALKEY_COMPARE_DELETE_AT_DEADLINE_SCRIPT: &str = r#"
local deadline = tonumber(ARGV[2])
local now = tonumber(redis.call('TIME')[1])
if now >= deadline then
  local expired = redis.call('GET', KEYS[1])
  if expired and expired == ARGV[1] then
    redis.call('DEL', KEYS[1])
  end
  return 'deadline_elapsed'
end
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then
  return 'conflict'
end
redis.call('DEL', KEYS[1])
return 'applied'
"#;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValkeySnapshot {
    pub(crate) raw: String,
    pub(crate) expire_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValkeyAtomicResult {
    Applied,
    Conflict,
    DeadlineElapsed,
}

#[derive(Debug)]
pub(crate) enum ValkeyAtomicError {
    Command(ValkeyError),
    InvalidReply(String),
}

impl fmt::Display for ValkeyAtomicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(error) => write!(formatter, "Valkey command failed: {error}"),
            Self::InvalidReply(reason) => {
                write!(formatter, "Valkey script reply is invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for ValkeyAtomicError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Command(error) => Some(error),
            Self::InvalidReply(_) => None,
        }
    }
}

impl From<ValkeyError> for ValkeyAtomicError {
    fn from(error: ValkeyError) -> Self {
        Self::Command(error)
    }
}

#[derive(Deserialize)]
struct ValkeySnapshotReply {
    found: bool,
    value: Option<String>,
    expire_at: Option<i64>,
}

pub(crate) async fn valkey_set_ex(
    valkey: &ValkeyClient,
    key: impl Into<String>,
    value: impl Into<String>,
    ttl_seconds: u64,
) -> Result<(), ValkeyError> {
    valkey
        .set::<(), _, _>(
            key.into(),
            value.into(),
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            None,
            false,
        )
        .await
}

pub(crate) async fn valkey_set_ex_nx(
    valkey: &ValkeyClient,
    key: impl Into<String>,
    value: impl Into<String>,
    ttl_seconds: u64,
) -> Result<bool, ValkeyError> {
    let response = valkey
        .set::<Option<String>, _, _>(
            key.into(),
            value.into(),
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            Some(SetOptions::NX),
            false,
        )
        .await?;
    Ok(response.is_some())
}

pub(crate) async fn valkey_get(
    valkey: &ValkeyClient,
    key: impl Into<String>,
) -> Result<Option<String>, ValkeyError> {
    valkey.get::<Option<String>, _>(key.into()).await
}

pub(crate) async fn valkey_getdel(
    valkey: &ValkeyClient,
    key: impl Into<String>,
) -> Result<Option<String>, ValkeyError> {
    valkey.getdel::<Option<String>, _>(key.into()).await
}

pub(crate) async fn valkey_del(
    valkey: &ValkeyClient,
    key: impl Into<String>,
) -> Result<i64, ValkeyError> {
    valkey.del::<i64, _>(key.into()).await
}

pub(crate) async fn valkey_eval_string(
    valkey: &ValkeyClient,
    script: &'static str,
    keys: Vec<String>,
    args: Vec<String>,
) -> Result<String, ValkeyError> {
    valkey.eval::<String, _, _, _>(script, keys, args).await
}

pub(crate) async fn valkey_atomic_snapshot(
    valkey: &ValkeyClient,
    key: &str,
) -> Result<Option<ValkeySnapshot>, ValkeyAtomicError> {
    let reply = valkey_eval_string(
        valkey,
        VALKEY_SNAPSHOT_SCRIPT,
        vec![key.to_owned()],
        Vec::new(),
    )
    .await?;
    let parsed: ValkeySnapshotReply = serde_json::from_str(&reply)
        .map_err(|error| ValkeyAtomicError::InvalidReply(error.to_string()))?;
    if !parsed.found {
        return Ok(None);
    }
    let raw = parsed
        .value
        .ok_or_else(|| ValkeyAtomicError::InvalidReply("missing snapshot value".to_owned()))?;
    let expire_at = parsed
        .expire_at
        .ok_or_else(|| ValkeyAtomicError::InvalidReply("missing snapshot expiry".to_owned()))?;
    Ok(Some(ValkeySnapshot { raw, expire_at }))
}

pub(crate) async fn valkey_set_nx_at_deadline(
    valkey: &ValkeyClient,
    key: &str,
    value: &str,
    deadline: i64,
) -> Result<ValkeyAtomicResult, ValkeyAtomicError> {
    let reply = valkey_eval_string(
        valkey,
        VALKEY_SET_NX_AT_DEADLINE_SCRIPT,
        vec![key.to_owned()],
        vec![value.to_owned(), deadline.to_string()],
    )
    .await?;
    parse_valkey_atomic_result(&reply)
}

pub(crate) async fn valkey_compare_set_at_deadline(
    valkey: &ValkeyClient,
    key: &str,
    expected: &str,
    replacement: &str,
    deadline: i64,
) -> Result<ValkeyAtomicResult, ValkeyAtomicError> {
    let reply = valkey_eval_string(
        valkey,
        VALKEY_COMPARE_SET_AT_DEADLINE_SCRIPT,
        vec![key.to_owned()],
        vec![
            expected.to_owned(),
            replacement.to_owned(),
            deadline.to_string(),
        ],
    )
    .await?;
    parse_valkey_atomic_result(&reply)
}

pub(crate) async fn valkey_compare_delete_at_deadline(
    valkey: &ValkeyClient,
    key: &str,
    expected: &str,
    deadline: i64,
) -> Result<ValkeyAtomicResult, ValkeyAtomicError> {
    let reply = valkey_eval_string(
        valkey,
        VALKEY_COMPARE_DELETE_AT_DEADLINE_SCRIPT,
        vec![key.to_owned()],
        vec![expected.to_owned(), deadline.to_string()],
    )
    .await?;
    parse_valkey_atomic_result(&reply)
}

fn parse_valkey_atomic_result(reply: &str) -> Result<ValkeyAtomicResult, ValkeyAtomicError> {
    match reply {
        "applied" => Ok(ValkeyAtomicResult::Applied),
        "conflict" => Ok(ValkeyAtomicResult::Conflict),
        "deadline_elapsed" => Ok(ValkeyAtomicResult::DeadlineElapsed),
        other => Err(ValkeyAtomicError::InvalidReply(format!(
            "unexpected transition result {other:?}"
        ))),
    }
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/valkey.rs"]
mod tests;
