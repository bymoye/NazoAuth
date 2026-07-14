use nazo_identity::{UserId, session::SessionRecord};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Error, ValkeyConnection, command, keys};

const ROTATE_SESSION_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if current ~= ARGV[1] then
  return 'conflict'
end
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 'collision'
end
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
redis.call('DEL', KEYS[1])
return 'ok'
"#;

const CREATE_REPLACING_SESSION_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 'collision'
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
if #KEYS == 2 and KEYS[1] ~= KEYS[2] then
  redis.call('DEL', KEYS[2])
end
return 'created'
"#;

#[derive(Deserialize, Serialize)]
struct SessionWireRecord {
    user_id: Uuid,
    auth_time: i64,
    amr: Vec<String>,
    #[serde(default)]
    pending_mfa: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oidc_sid: Option<String>,
}

impl From<&SessionRecord> for SessionWireRecord {
    fn from(value: &SessionRecord) -> Self {
        Self {
            user_id: value.user_id().as_uuid(),
            auth_time: value.auth_time(),
            amr: value.amr().to_vec(),
            pending_mfa: value.pending_mfa(),
            oidc_sid: value.oidc_sid().map(str::to_owned),
        }
    }
}

impl TryFrom<SessionWireRecord> for SessionRecord {
    type Error = Error;

    fn try_from(value: SessionWireRecord) -> Result<Self, Self::Error> {
        let user_id = UserId::new(value.user_id).map_err(|error| {
            Error::corrupt_data(format!("invalid stored session user: {error}"))
        })?;
        Ok(Self::new(
            user_id,
            value.auth_time,
            value.amr,
            value.pending_mfa,
            value.oidc_sid,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRotationResult {
    Applied,
    Conflict,
    Collision,
}

#[derive(Clone, Debug)]
pub struct StoredSession {
    value: SessionRecord,
    raw: String,
}

impl StoredSession {
    pub fn value(&self) -> &SessionRecord {
        &self.value
    }

    pub fn into_value(self) -> SessionRecord {
        self.value
    }
}

#[derive(Clone, Debug)]
pub struct SessionStore {
    connection: ValkeyConnection,
}

impl SessionStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }

    pub async fn store(
        &self,
        session_id: &str,
        record: &SessionRecord,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        let raw = serde_json::to_string(&SessionWireRecord::from(record)).map_err(|error| {
            Error::protocol(format!("failed to serialize session record: {error}"))
        })?;
        command::set_ex_string(
            &self.connection,
            keys::session(session_id),
            raw,
            ttl_seconds,
        )
        .await
    }

    pub async fn load(&self, session_id: &str) -> Result<Option<StoredSession>, Error> {
        command::get(&self.connection, keys::session(session_id))
            .await?
            .map(|raw| {
                let wire: SessionWireRecord = serde_json::from_str(&raw).map_err(|error| {
                    Error::corrupt_data(format!("malformed stored session payload: {error}"))
                })?;
                Ok(StoredSession {
                    value: wire.try_into()?,
                    raw,
                })
            })
            .transpose()
    }

    pub async fn delete(&self, session_id: &str) -> Result<i64, Error> {
        command::delete(&self.connection, keys::session(session_id)).await
    }

    pub async fn rotate(
        &self,
        old_session_id: &str,
        expected: &StoredSession,
        new_session_id: &str,
        replacement: &SessionRecord,
        ttl_seconds: u64,
    ) -> Result<SessionRotationResult, Error> {
        let replacement =
            serde_json::to_string(&SessionWireRecord::from(replacement)).map_err(|error| {
                Error::protocol(format!("failed to serialize replacement session: {error}"))
            })?;
        let reply = command::eval_string(
            &self.connection,
            ROTATE_SESSION_SCRIPT,
            vec![keys::session(old_session_id), keys::session(new_session_id)],
            vec![expected.raw.clone(), replacement, ttl_seconds.to_string()],
        )
        .await?;
        match reply.as_str() {
            "ok" => Ok(SessionRotationResult::Applied),
            "conflict" => Ok(SessionRotationResult::Conflict),
            "collision" => Ok(SessionRotationResult::Collision),
            other => Err(Error::unexpected(format!(
                "unexpected session rotation reply {other:?}"
            ))),
        }
    }
}

impl nazo_identity::ports::LoginSessionPort for SessionStore {
    fn create<'a>(
        &'a self,
        session_id: &'a str,
        record: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::LoginSessionCreate> {
        Box::pin(async move {
            let raw = serde_json::to_string(&SessionWireRecord::from(record)).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(format!(
                    "failed to serialize session record: {error}"
                ))
            })?;
            command::set_ex_nx_string(
                &self.connection,
                keys::session(session_id),
                raw,
                ttl_seconds,
            )
            .await
            .map(|created| {
                if created {
                    nazo_identity::ports::LoginSessionCreate::Created
                } else {
                    nazo_identity::ports::LoginSessionCreate::Collision
                }
            })
            .map_err(crate::identity_repository_error)
        })
    }

    fn create_replacing<'a>(
        &'a self,
        previous_session_id: Option<&'a str>,
        session_id: &'a str,
        record: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::LoginSessionCreate> {
        Box::pin(async move {
            let raw = serde_json::to_string(&SessionWireRecord::from(record)).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(format!(
                    "failed to serialize session record: {error}"
                ))
            })?;
            let mut keys = vec![keys::session(session_id)];
            if let Some(previous_session_id) = previous_session_id {
                keys.push(keys::session(previous_session_id));
            }
            let reply = command::eval_string(
                &self.connection,
                CREATE_REPLACING_SESSION_SCRIPT,
                keys,
                vec![raw, ttl_seconds.to_string()],
            )
            .await
            .map_err(crate::identity_repository_error)?;
            match reply.as_str() {
                "created" => Ok(nazo_identity::ports::LoginSessionCreate::Created),
                "collision" => Ok(nazo_identity::ports::LoginSessionCreate::Collision),
                other => Err(nazo_identity::ports::RepositoryError::Unexpected(format!(
                    "unexpected login session create reply {other:?}"
                ))),
            }
        })
    }
}

impl nazo_identity::ports::SessionStorePort for SessionStore {
    fn load<'a>(
        &'a self,
        session_id: &'a nazo_identity::SessionId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::SessionSnapshot>> {
        Box::pin(async move {
            SessionStore::load(self, session_id.as_str())
                .await
                .map(|stored| {
                    stored.map(|stored| {
                        nazo_identity::SessionSnapshot::new(
                            stored.value,
                            nazo_identity::SessionVersion::from_storage(
                                stored.raw.into_bytes().into_boxed_slice(),
                            ),
                        )
                    })
                })
                .map_err(crate::identity_repository_error)
        })
    }

    fn delete<'a>(
        &'a self,
        session_id: &'a nazo_identity::SessionId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async move {
            SessionStore::delete(self, session_id.as_str())
                .await
                .map(|deleted| deleted > 0)
                .map_err(crate::identity_repository_error)
        })
    }

    fn rotate<'a>(
        &'a self,
        old_session_id: &'a nazo_identity::SessionId,
        expected: &'a nazo_identity::SessionSnapshot,
        new_session_id: &'a nazo_identity::SessionId,
        replacement: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::SessionRotationOutcome> {
        Box::pin(async move {
            let replacement = serde_json::to_string(&SessionWireRecord::from(replacement))
                .map_err(|error| {
                    nazo_identity::ports::RepositoryError::Unexpected(format!(
                        "failed to serialize replacement session: {error}"
                    ))
                })?;
            let expected =
                std::str::from_utf8(expected.version().storage_bytes()).map_err(|error| {
                    nazo_identity::ports::RepositoryError::Unexpected(format!(
                        "session storage revision is not valid UTF-8: {error}"
                    ))
                })?;
            let reply = command::eval_string(
                &self.connection,
                ROTATE_SESSION_SCRIPT,
                vec![
                    keys::session(old_session_id.as_str()),
                    keys::session(new_session_id.as_str()),
                ],
                vec![expected.to_owned(), replacement, ttl_seconds.to_string()],
            )
            .await
            .map_err(crate::identity_repository_error)?;
            match reply.as_str() {
                "ok" => Ok(nazo_identity::SessionRotationOutcome::Applied),
                "conflict" => Ok(nazo_identity::SessionRotationOutcome::Conflict),
                "collision" => Ok(nazo_identity::SessionRotationOutcome::Collision),
                other => Err(nazo_identity::ports::RepositoryError::Unexpected(format!(
                    "unexpected session rotation reply {other:?}"
                ))),
            }
        })
    }
}
