use chrono::{DateTime, Utc};
use nazo_identity::{
    AvatarUploadAuthorization, AvatarUploadClaim, TenantId, UserId,
    ports::{AvatarUploadStatePort, RepositoryError, RepositoryFuture},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Error, ValkeyConnection, command, keys};

const CLAIM_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then return 'missing' end
local ok, state = pcall(cjson.decode, raw)
if not ok then return 'corrupt' end
local now = tonumber(redis.call('TIME')[1])
if tonumber(state['expires_at'] or 0) <= now then
  redis.call('DEL', KEYS[1])
  return 'missing'
end
if state['user_id'] ~= ARGV[1] then return 'missing' end
if state['status'] == 'completed' then
  if type(state['final_object_id']) ~= 'string' then return 'corrupt' end
  return cjson.encode({outcome = 'completed', final_object_id = state['final_object_id']})
end
if state['status'] ~= 'pending' and state['status'] ~= 'publishing' then return 'corrupt' end
if (tonumber(state['lease_until']) or 0) > now then return 'busy' end
local generation = tonumber(state['claim_generation'])
if not generation or generation < 0 then return 'corrupt' end
generation = generation + 1
local ownership_token = tostring(generation)
state['claim_generation'] = generation
state['ownership_token'] = ownership_token
state['lease_until'] = tonumber(ARGV[2])
redis.call('SET', KEYS[1], cjson.encode(state), 'KEEPTTL')
if state['status'] == 'pending' then
  return cjson.encode({outcome = 'pending', authorization = state, ownership_token = ownership_token})
end
if type(state['staged_version']) ~= 'string' or type(state['final_object_id']) ~= 'string' then
  return 'corrupt'
end
return cjson.encode({
  outcome = 'publishing',
  authorization = state,
  ownership_token = ownership_token,
  staged_version = state['staged_version'],
  final_object_id = state['final_object_id']
})
"#;

const RECORD_CANDIDATE_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then return 'rejected' end
local ok, state = pcall(cjson.decode, raw)
if not ok then return 'corrupt' end
local now = tonumber(redis.call('TIME')[1])
if tonumber(state['expires_at'] or 0) <= now then
  redis.call('DEL', KEYS[1])
  return 'rejected'
end
if state['user_id'] ~= ARGV[1]
  or state['ownership_token'] ~= ARGV[2]
  or (tonumber(state['lease_until']) or 0) <= now then
  return 'rejected'
end
if state['status'] == 'publishing' then
  if state['staged_version'] == ARGV[3] and state['final_object_id'] == ARGV[4] then
    return 'applied'
  end
  return 'rejected'
end
if state['status'] ~= 'pending' then return 'rejected' end
state['status'] = 'publishing'
state['staged_version'] = ARGV[3]
state['final_object_id'] = ARGV[4]
redis.call('SET', KEYS[1], cjson.encode(state), 'KEEPTTL')
return 'applied'
"#;

const COMPLETE_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then return 'rejected' end
local ok, state = pcall(cjson.decode, raw)
if not ok then return 'corrupt' end
local now = tonumber(redis.call('TIME')[1])
if tonumber(state['expires_at'] or 0) <= now then
  redis.call('DEL', KEYS[1])
  return 'rejected'
end
if state['user_id'] ~= ARGV[1] then return 'rejected' end
if state['status'] == 'completed' then
  if type(state['final_object_id']) ~= 'string' then return 'corrupt' end
  if state['final_object_id'] == ARGV[3] then return 'applied' end
  return 'rejected'
end
if state['status'] ~= 'publishing'
  or state['ownership_token'] ~= ARGV[2]
  or (tonumber(state['lease_until']) or 0) <= now then
  return 'rejected'
end
state['status'] = 'completed'
state['final_object_id'] = ARGV[3]
state['staged_version'] = nil
state['ownership_token'] = nil
state['lease_until'] = nil
redis.call('SET', KEYS[1], cjson.encode(state), 'KEEPTTL')
return 'applied'
"#;

const RELEASE_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then return 'rejected' end
local ok, state = pcall(cjson.decode, raw)
if not ok then return 'corrupt' end
local now = tonumber(redis.call('TIME')[1])
if tonumber(state['expires_at'] or 0) <= now then
  redis.call('DEL', KEYS[1])
  return 'rejected'
end
if state['user_id'] ~= ARGV[1]
  or (state['status'] ~= 'pending' and state['status'] ~= 'publishing')
  or state['ownership_token'] ~= ARGV[2]
  or (tonumber(state['lease_until']) or 0) <= now then
  return 'rejected'
end
state['ownership_token'] = nil
state['lease_until'] = nil
redis.call('SET', KEYS[1], cjson.encode(state), 'KEEPTTL')
return 'applied'
"#;

#[derive(Clone, Debug, Serialize)]
struct AvatarUploadWireState {
    status: &'static str,
    upload_id: String,
    tenant_id: Uuid,
    user_id: Uuid,
    expected_avatar_url: Option<String>,
    staging_object_id: String,
    expires_at: i64,
    claim_generation: u64,
    ownership_token: Option<String>,
    lease_until: Option<i64>,
    staged_version: Option<String>,
    final_object_id: Option<String>,
}

impl From<&AvatarUploadAuthorization> for AvatarUploadWireState {
    fn from(value: &AvatarUploadAuthorization) -> Self {
        Self {
            status: "pending",
            upload_id: value.upload_id.clone(),
            tenant_id: value.tenant_id.as_uuid(),
            user_id: value.user_id.as_uuid(),
            expected_avatar_url: value.expected_avatar_url.clone(),
            staging_object_id: value.staging_object_id.clone(),
            expires_at: value.expires_at.timestamp(),
            claim_generation: 0,
            ownership_token: None,
            lease_until: None,
            staged_version: None,
            final_object_id: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct AvatarUploadClaimWire {
    outcome: String,
    authorization: Option<AvatarUploadAuthorizationWire>,
    ownership_token: Option<String>,
    staged_version: Option<String>,
    final_object_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AvatarUploadAuthorizationWire {
    upload_id: String,
    tenant_id: Uuid,
    user_id: Uuid,
    expected_avatar_url: Option<String>,
    staging_object_id: String,
    expires_at: i64,
}

impl TryFrom<AvatarUploadAuthorizationWire> for AvatarUploadAuthorization {
    type Error = Error;

    fn try_from(value: AvatarUploadAuthorizationWire) -> Result<Self, Self::Error> {
        Ok(Self {
            upload_id: value.upload_id,
            tenant_id: TenantId::new(value.tenant_id).map_err(|error| {
                Error::corrupt_data(format!("invalid avatar upload tenant: {error}"))
            })?,
            user_id: UserId::new(value.user_id).map_err(|error| {
                Error::corrupt_data(format!("invalid avatar upload user: {error}"))
            })?,
            expected_avatar_url: value.expected_avatar_url,
            staging_object_id: value.staging_object_id,
            expires_at: DateTime::from_timestamp(value.expires_at, 0)
                .ok_or_else(|| Error::corrupt_data("invalid avatar upload expiry"))?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AvatarUploadStateStore {
    connection: ValkeyConnection,
}

impl AvatarUploadStateStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }

    fn key(upload_id: &str) -> String {
        keys::avatar_upload(upload_id)
    }

    async fn claim(
        &self,
        user_id: UserId,
        upload_id: &str,
        lease_until: DateTime<Utc>,
    ) -> Result<AvatarUploadClaim, Error> {
        let reply = command::eval_string(
            &self.connection,
            CLAIM_SCRIPT,
            vec![Self::key(upload_id)],
            vec![
                user_id.as_uuid().to_string(),
                lease_until.timestamp().to_string(),
            ],
        )
        .await?;
        match reply.as_str() {
            "missing" => Ok(AvatarUploadClaim::Missing),
            "busy" => Ok(AvatarUploadClaim::Busy),
            "corrupt" => Err(Error::corrupt_data("malformed avatar upload state")),
            raw => {
                let result: AvatarUploadClaimWire = serde_json::from_str(raw).map_err(|error| {
                    Error::corrupt_data(format!("malformed avatar upload claim: {error}"))
                })?;
                match result.outcome.as_str() {
                    "pending" => Ok(AvatarUploadClaim::Pending {
                        authorization: result
                            .authorization
                            .ok_or_else(|| {
                                Error::corrupt_data("missing avatar upload authorization")
                            })?
                            .try_into()?,
                        ownership_token: result.ownership_token.ok_or_else(|| {
                            Error::corrupt_data("missing avatar upload ownership token")
                        })?,
                    }),
                    "publishing" => Ok(AvatarUploadClaim::Publishing {
                        authorization: result
                            .authorization
                            .ok_or_else(|| {
                                Error::corrupt_data("missing avatar upload authorization")
                            })?
                            .try_into()?,
                        ownership_token: result.ownership_token.ok_or_else(|| {
                            Error::corrupt_data("missing avatar upload ownership token")
                        })?,
                        staged_version: result.staged_version.ok_or_else(|| {
                            Error::corrupt_data("missing staged avatar object version")
                        })?,
                        final_object_id: result.final_object_id.ok_or_else(|| {
                            Error::corrupt_data("missing avatar final object identifier")
                        })?,
                    }),
                    "completed" => Ok(AvatarUploadClaim::Completed {
                        final_object_id: result.final_object_id.ok_or_else(|| {
                            Error::corrupt_data("missing completed avatar object identifier")
                        })?,
                    }),
                    _ => Err(Error::unexpected("unexpected avatar upload claim outcome")),
                }
            }
        }
    }

    async fn transition(
        &self,
        script: &'static str,
        user_id: UserId,
        upload_id: &str,
        ownership_token: &str,
        final_object_id: Option<&str>,
    ) -> Result<bool, Error> {
        let mut args = vec![user_id.as_uuid().to_string(), ownership_token.to_owned()];
        if let Some(final_object_id) = final_object_id {
            args.push(final_object_id.to_owned());
        }
        match command::eval_string(&self.connection, script, vec![Self::key(upload_id)], args)
            .await?
            .as_str()
        {
            "applied" => Ok(true),
            "rejected" => Ok(false),
            "corrupt" => Err(Error::corrupt_data("malformed avatar upload state")),
            reply => Err(Error::unexpected(format!(
                "unexpected avatar upload transition result {reply:?}"
            ))),
        }
    }

    async fn record_candidate(
        &self,
        user_id: UserId,
        upload_id: &str,
        ownership_token: &str,
        staged_version: &str,
        final_object_id: &str,
    ) -> Result<bool, Error> {
        match command::eval_string(
            &self.connection,
            RECORD_CANDIDATE_SCRIPT,
            vec![Self::key(upload_id)],
            vec![
                user_id.as_uuid().to_string(),
                ownership_token.to_owned(),
                staged_version.to_owned(),
                final_object_id.to_owned(),
            ],
        )
        .await?
        .as_str()
        {
            "applied" => Ok(true),
            "rejected" => Ok(false),
            "corrupt" => Err(Error::corrupt_data("malformed avatar upload state")),
            reply => Err(Error::unexpected(format!(
                "unexpected avatar upload candidate result {reply:?}"
            ))),
        }
    }
}

impl AvatarUploadStatePort for AvatarUploadStateStore {
    fn create<'a>(
        &'a self,
        authorization: &'a AvatarUploadAuthorization,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let raw = serde_json::to_string(&AvatarUploadWireState::from(authorization)).map_err(
                |error| {
                    RepositoryError::Unexpected(format!("serialize avatar upload state: {error}"))
                },
            )?;
            command::set_ex_nx_string(
                &self.connection,
                Self::key(&authorization.upload_id),
                raw,
                ttl_seconds,
            )
            .await
            .map_err(crate::identity_repository_error)?
            .then_some(())
            .ok_or(RepositoryError::Conflict)
        })
    }

    fn claim<'a>(
        &'a self,
        user_id: UserId,
        upload_id: &'a str,
        lease_until: DateTime<Utc>,
    ) -> RepositoryFuture<'a, AvatarUploadClaim> {
        Box::pin(async move {
            AvatarUploadStateStore::claim(self, user_id, upload_id, lease_until)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn complete<'a>(
        &'a self,
        user_id: UserId,
        upload_id: &'a str,
        ownership_token: &'a str,
        final_object_id: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.transition(
                COMPLETE_SCRIPT,
                user_id,
                upload_id,
                ownership_token,
                Some(final_object_id),
            )
            .await
            .map_err(crate::identity_repository_error)
        })
    }

    fn record_candidate<'a>(
        &'a self,
        user_id: UserId,
        upload_id: &'a str,
        ownership_token: &'a str,
        staged_version: &'a str,
        final_object_id: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            AvatarUploadStateStore::record_candidate(
                self,
                user_id,
                upload_id,
                ownership_token,
                staged_version,
                final_object_id,
            )
            .await
            .map_err(crate::identity_repository_error)
        })
    }

    fn release<'a>(
        &'a self,
        user_id: UserId,
        upload_id: &'a str,
        ownership_token: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.transition(RELEASE_SCRIPT, user_id, upload_id, ownership_token, None)
                .await
                .map_err(crate::identity_repository_error)
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/avatar_upload_state.rs"]
mod tests;
