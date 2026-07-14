use nazo_auth::DeviceAuthorizationState;
use nazo_auth::{
    DeviceAtomicResult, DeviceCreateResult as AuthDeviceCreateResult, DeviceStatePortError,
    DeviceStateStorePort, StoredDeviceAuthorization,
};

use crate::{Error, ValkeyConnection, command, keys};

const CREATE_DEVICE_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 then return 'device_collision' end
if redis.call('EXISTS', KEYS[2]) == 1 then return 'user_collision' end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
return 'applied'
"#;
const SNAPSHOT_DEVICE_SCRIPT: &str = r#"
local value = redis.call('GET', KEYS[1])
if not value then return cjson.encode({found = false}) end
return cjson.encode({found = true, value = value, expire_at = redis.call('PEXPIRETIME', KEYS[1])})
"#;
const COMPARE_SET_DEVICE_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 'conflict' end
local deadline = redis.call('PEXPIRETIME', KEYS[1])
if deadline == -2 then return 'deadline_elapsed' end
if deadline == -1 then return 'invalid_deadline' end
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
if now >= deadline then redis.call('DEL', KEYS[1]); return 'deadline_elapsed' end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('PEXPIREAT', KEYS[1], deadline)
return 'applied'
"#;
const COMPLETE_DEVICE_DECISION_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 'conflict' end
if redis.call('GET', KEYS[2]) ~= ARGV[3] then return 'conflict' end
local deadline = redis.call('PEXPIRETIME', KEYS[1])
if deadline == -2 then redis.call('DEL', KEYS[2]); return 'deadline_elapsed' end
if deadline == -1 then return 'invalid_deadline' end
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
if now >= deadline then
  redis.call('DEL', KEYS[1])
  redis.call('DEL', KEYS[2])
  return 'deadline_elapsed'
end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('PEXPIREAT', KEYS[1], deadline)
redis.call('DEL', KEYS[2])
return 'applied'
"#;
const COMPARE_DELETE_DEVICE_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 'conflict' end
local deadline = redis.call('PEXPIRETIME', KEYS[1])
if deadline == -2 then return 'deadline_elapsed' end
if deadline == -1 then return 'invalid_deadline' end
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
redis.call('DEL', KEYS[1])
if now >= deadline then return 'deadline_elapsed' end
return 'applied'
"#;
const DELETE_USER_CODE_IF_MATCHES_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 'conflict' end
redis.call('DEL', KEYS[1])
return 'applied'
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceCreateResult {
    Applied,
    DeviceCodeCollision,
    UserCodeCollision,
}

#[derive(Clone, Debug)]
pub struct StoredDeviceState {
    value: DeviceAuthorizationState,
    raw: String,
}

impl StoredDeviceState {
    #[must_use]
    pub const fn value(&self) -> &DeviceAuthorizationState {
        &self.value
    }
}

#[derive(Clone, Debug)]
pub struct DeviceStore {
    connection: ValkeyConnection,
}
impl DeviceStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }

    pub async fn create(
        &self,
        device_code: &str,
        user_code: &str,
        state: &DeviceAuthorizationState,
        ttl_seconds: u64,
    ) -> Result<DeviceCreateResult, Error> {
        let raw = serde_json::to_string(state).map_err(|error| {
            Error::protocol(format!("failed to serialize device state: {error}"))
        })?;
        let device_hash = blake3::hash(device_code.as_bytes()).to_hex().to_string();
        let reply = command::eval_string(
            &self.connection,
            CREATE_DEVICE_SCRIPT,
            vec![
                keys::device_code_hash(&device_hash),
                keys::device_user_code(user_code),
            ],
            vec![raw, device_hash, ttl_seconds.to_string()],
        )
        .await?;
        match reply.as_str() {
            "applied" => Ok(DeviceCreateResult::Applied),
            "device_collision" => Ok(DeviceCreateResult::DeviceCodeCollision),
            "user_collision" => Ok(DeviceCreateResult::UserCodeCollision),
            other => Err(Error::unexpected(format!(
                "unexpected device create result {other:?}"
            ))),
        }
    }

    pub async fn load_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceAuthorizationState>, Error> {
        self.load_snapshot(keys::device_code(device_code))
            .await
            .map(|stored| stored.map(|stored| stored.value))
    }
    pub async fn load_by_device_hash(
        &self,
        device_hash: &str,
    ) -> Result<Option<DeviceAuthorizationState>, Error> {
        self.load_snapshot(keys::device_code_hash(device_hash))
            .await
            .map(|stored| stored.map(|stored| stored.value))
    }
    pub async fn resolve_user_code(&self, user_code: &str) -> Result<Option<String>, Error> {
        command::get(&self.connection, keys::device_user_code(user_code)).await
    }
    async fn load_snapshot(&self, key: String) -> Result<Option<StoredDeviceState>, Error> {
        let reply =
            command::eval_string(&self.connection, SNAPSHOT_DEVICE_SCRIPT, vec![key], vec![])
                .await?;
        let snapshot: serde_json::Value = serde_json::from_str(&reply)
            .map_err(|error| Error::protocol(format!("malformed device snapshot: {error}")))?;
        if snapshot.get("found").and_then(serde_json::Value::as_bool) != Some(true) {
            return Ok(None);
        }
        let raw = snapshot
            .get("value")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::protocol("missing device snapshot value"))?
            .to_owned();
        let deadline = snapshot
            .get("expire_at")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| Error::protocol("missing device snapshot deadline"))?;
        if deadline == -2 {
            return Ok(None);
        }
        if deadline == -1 {
            return Err(Error::protocol("device state has no absolute expiry"));
        }
        let value = serde_json::from_str(&raw)
            .map_err(|error| Error::protocol(format!("malformed device state: {error}")))?;
        Ok(Some(StoredDeviceState { value, raw }))
    }
    async fn replace_snapshot(
        &self,
        key: String,
        expected: &StoredDeviceState,
        replacement: &DeviceAuthorizationState,
    ) -> Result<DeviceAtomicResult, Error> {
        let replacement = serde_json::to_string(replacement).map_err(|error| {
            Error::protocol(format!("failed to serialize device state: {error}"))
        })?;
        let reply = command::eval_string(
            &self.connection,
            COMPARE_SET_DEVICE_SCRIPT,
            vec![key],
            vec![expected.raw.clone(), replacement],
        )
        .await?;
        parse_atomic_result(&reply)
    }

    async fn complete_decision_snapshot(
        &self,
        device_hash: &str,
        user_code: &str,
        expected: &StoredDeviceState,
        replacement: &DeviceAuthorizationState,
    ) -> Result<DeviceAtomicResult, Error> {
        let replacement = serde_json::to_string(replacement).map_err(|error| {
            Error::protocol(format!("failed to serialize device state: {error}"))
        })?;
        let reply = command::eval_string(
            &self.connection,
            COMPLETE_DEVICE_DECISION_SCRIPT,
            vec![
                keys::device_code_hash(device_hash),
                keys::device_user_code(user_code),
            ],
            vec![expected.raw.clone(), replacement, device_hash.to_owned()],
        )
        .await?;
        parse_atomic_result(&reply)
    }

    async fn consume_snapshot(
        &self,
        device_code: &str,
        expected: &StoredDeviceState,
    ) -> Result<DeviceAtomicResult, Error> {
        let reply = command::eval_string(
            &self.connection,
            COMPARE_DELETE_DEVICE_SCRIPT,
            vec![keys::device_code(device_code)],
            vec![expected.raw.clone()],
        )
        .await?;
        parse_atomic_result(&reply)
    }
}

impl DeviceStateStorePort for DeviceStore {
    type Version = StoredDeviceState;

    fn create<'a>(
        &'a self,
        device_code: &'a str,
        user_code: &'a str,
        state: &'a DeviceAuthorizationState,
        ttl_seconds: u64,
    ) -> nazo_auth::DeviceStateFuture<'a, AuthDeviceCreateResult> {
        Box::pin(async move {
            DeviceStore::create(self, device_code, user_code, state, ttl_seconds)
                .await
                .map(|result| match result {
                    DeviceCreateResult::Applied => AuthDeviceCreateResult::Applied,
                    DeviceCreateResult::DeviceCodeCollision => {
                        AuthDeviceCreateResult::DeviceCodeCollision
                    }
                    DeviceCreateResult::UserCodeCollision => {
                        AuthDeviceCreateResult::UserCodeCollision
                    }
                })
                .map_err(port_error)
        })
    }

    fn load_by_device_code<'a>(
        &'a self,
        device_code: &'a str,
    ) -> nazo_auth::DeviceStateFuture<'a, Option<StoredDeviceAuthorization<Self::Version>>> {
        Box::pin(async move {
            self.load_snapshot(keys::device_code(device_code))
                .await
                .map(|stored| {
                    stored.map(|version| {
                        StoredDeviceAuthorization::new(version.value().clone(), version)
                    })
                })
                .map_err(port_error)
        })
    }

    fn load_by_device_hash<'a>(
        &'a self,
        device_hash: &'a str,
    ) -> nazo_auth::DeviceStateFuture<'a, Option<StoredDeviceAuthorization<Self::Version>>> {
        Box::pin(async move {
            self.load_snapshot(keys::device_code_hash(device_hash))
                .await
                .map(|stored| {
                    stored.map(|version| {
                        StoredDeviceAuthorization::new(version.value().clone(), version)
                    })
                })
                .map_err(port_error)
        })
    }

    fn resolve_user_code<'a>(
        &'a self,
        user_code: &'a str,
    ) -> nazo_auth::DeviceStateFuture<'a, Option<String>> {
        Box::pin(async move {
            DeviceStore::resolve_user_code(self, user_code)
                .await
                .map_err(port_error)
        })
    }

    fn replace_by_device_code<'a>(
        &'a self,
        device_code: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> nazo_auth::DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            self.replace_snapshot(keys::device_code(device_code), version, replacement)
                .await
                .map_err(port_error)
        })
    }

    fn replace_by_device_hash<'a>(
        &'a self,
        device_hash: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> nazo_auth::DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            self.replace_snapshot(keys::device_code_hash(device_hash), version, replacement)
                .await
                .map_err(port_error)
        })
    }

    fn complete_decision<'a>(
        &'a self,
        device_hash: &'a str,
        user_code: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> nazo_auth::DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            self.complete_decision_snapshot(device_hash, user_code, version, replacement)
                .await
                .map_err(port_error)
        })
    }

    fn consume_by_device_code<'a>(
        &'a self,
        device_code: &'a str,
        version: &'a Self::Version,
    ) -> nazo_auth::DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            self.consume_snapshot(device_code, version)
                .await
                .map_err(port_error)
        })
    }

    fn delete_user_code_if_matches<'a>(
        &'a self,
        user_code: &'a str,
        device_hash: &'a str,
    ) -> nazo_auth::DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            command::eval_string(
                &self.connection,
                DELETE_USER_CODE_IF_MATCHES_SCRIPT,
                vec![keys::device_user_code(user_code)],
                vec![device_hash.to_owned()],
            )
            .await
            .map_err(port_error)
            .and_then(|reply| parse_atomic_result(&reply).map_err(port_error))
        })
    }
}

fn parse_atomic_result(reply: &str) -> Result<DeviceAtomicResult, Error> {
    match reply {
        "applied" => Ok(DeviceAtomicResult::Applied),
        "conflict" => Ok(DeviceAtomicResult::Conflict),
        "deadline_elapsed" => Ok(DeviceAtomicResult::DeadlineElapsed),
        "invalid_deadline" => Err(Error::protocol("device state has no absolute expiry")),
        other => Err(Error::unexpected(format!(
            "unexpected device atomic result {other:?}"
        ))),
    }
}

fn port_error(error: Error) -> DeviceStatePortError {
    match error.kind() {
        crate::ErrorKind::Timeout | crate::ErrorKind::Unavailable => {
            DeviceStatePortError::Unavailable
        }
        crate::ErrorKind::Protocol | crate::ErrorKind::CorruptData => {
            DeviceStatePortError::CorruptData
        }
        crate::ErrorKind::UnexpectedResult => DeviceStatePortError::Unexpected,
    }
}
