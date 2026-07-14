use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{OAuthClient, deserialize_authorization_details, empty_authorization_details};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DeviceAuthorizationPayload {
    pub client_id: String,
    pub client_name: String,
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_indicators: Vec<String>,
    #[serde(
        default = "empty_authorization_details",
        deserialize_with = "deserialize_authorization_details"
    )]
    pub authorization_details: Value,
    pub interval_seconds: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DeviceAuthorizationApproval {
    pub user_id: Uuid,
    pub subject: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_sid: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DeviceAuthorizationState {
    Pending {
        payload: DeviceAuthorizationPayload,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_poll_at: Option<DateTime<Utc>>,
        #[serde(default)]
        slow_down_count: u32,
    },
    Approving {
        payload: DeviceAuthorizationPayload,
        approval: DeviceAuthorizationApproval,
        claim_id: Uuid,
        grant_recorded: bool,
        started_at: DateTime<Utc>,
    },
    Approved {
        payload: DeviceAuthorizationPayload,
        approval: DeviceAuthorizationApproval,
        approved_at: DateTime<Utc>,
    },
    Denied {
        payload: DeviceAuthorizationPayload,
        denied_at: DateTime<Utc>,
    },
    Consumed {
        consumed_at: DateTime<Utc>,
    },
}

pub struct DeviceAuthorizationRequestPolicy<'a> {
    pub enabled: bool,
    pub client_active: bool,
    pub client_supports_grant: bool,
    pub client_id: &'a str,
    pub client_name: &'a str,
    pub requested_scopes: Vec<String>,
    pub allowed_scopes: &'a [String],
    pub requested_resources: Vec<String>,
    pub allowed_resources: &'a [String],
    pub default_resource: &'a str,
    pub interval_seconds: u64,
    pub ttl_seconds: u64,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAuthorizationRequestError {
    Disabled,
    UnauthorizedClient,
    InvalidScope,
    InvalidTarget,
}

pub fn device_authorization_request_payload(
    input: DeviceAuthorizationRequestPolicy<'_>,
) -> Result<DeviceAuthorizationPayload, DeviceAuthorizationRequestError> {
    if !input.enabled {
        return Err(DeviceAuthorizationRequestError::Disabled);
    }
    if !input.client_active || !input.client_supports_grant {
        return Err(DeviceAuthorizationRequestError::UnauthorizedClient);
    }
    if !input
        .requested_scopes
        .iter()
        .all(|scope| input.allowed_scopes.contains(scope))
    {
        return Err(DeviceAuthorizationRequestError::InvalidScope);
    }
    let resource_indicators = if input.requested_resources.is_empty() {
        vec![input.default_resource.to_owned()]
    } else {
        input.requested_resources
    };
    if resource_indicators.is_empty()
        || !resource_indicators
            .iter()
            .all(|resource| input.allowed_resources.contains(resource))
    {
        return Err(DeviceAuthorizationRequestError::InvalidTarget);
    }
    let ttl = i64::try_from(input.ttl_seconds).unwrap_or(i64::MAX / 1_000);
    let expires_at = input
        .now
        .checked_add_signed(chrono::Duration::seconds(ttl))
        .unwrap_or(DateTime::<Utc>::MAX_UTC);
    Ok(DeviceAuthorizationPayload {
        client_id: input.client_id.to_owned(),
        client_name: input.client_name.to_owned(),
        scopes: input.requested_scopes,
        resource_indicators,
        authorization_details: serde_json::json!([]),
        interval_seconds: input.interval_seconds,
        issued_at: input.now,
        expires_at,
    })
}

const DEVICE_TRANSITION_MAX_ATTEMPTS: usize = 5;
const DEVICE_SLOW_DOWN_INCREMENT_SECONDS: u64 = 5;

pub type DeviceStateFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DeviceStatePortError>> + Send + 'a>>;
pub type DeviceGrantFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DeviceGrantPortError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAtomicResult {
    Applied,
    Conflict,
    DeadlineElapsed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceCreateResult {
    Applied,
    DeviceCodeCollision,
    UserCodeCollision,
    DeadlineElapsed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStatePortError {
    Unavailable,
    CorruptData,
    Unexpected,
}

impl std::fmt::Display for DeviceStatePortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "device authorization state store unavailable",
            Self::CorruptData => "device authorization state store contains corrupt data",
            Self::Unexpected => "unexpected device authorization state store failure",
        })
    }
}

impl std::error::Error for DeviceStatePortError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceGrantPortError {
    Unavailable,
    Conflict,
    CorruptData,
    Unexpected,
}

impl std::fmt::Display for DeviceGrantPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "device authorization repository unavailable",
            Self::Conflict => "device authorization grant conflict",
            Self::CorruptData => "device authorization repository contains corrupt data",
            Self::Unexpected => "unexpected device authorization repository failure",
        })
    }
}

impl std::error::Error for DeviceGrantPortError {}

pub struct DeviceGrantWrite<'a> {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub scopes: &'a [String],
    pub resource_indicators: &'a [String],
    pub authorization_details: &'a Value,
}

pub trait DeviceGrantRepositoryPort: Send + Sync {
    fn client_by_id<'a>(&'a self, client_id: &'a str)
    -> DeviceGrantFuture<'a, Option<OAuthClient>>;

    fn upsert_grant<'a>(&'a self, write: DeviceGrantWrite<'a>) -> DeviceGrantFuture<'a, ()>;
}

#[derive(Debug)]
pub struct StoredDeviceAuthorization<V> {
    state: DeviceAuthorizationState,
    version: V,
}

impl<V> StoredDeviceAuthorization<V> {
    #[must_use]
    pub const fn new(state: DeviceAuthorizationState, version: V) -> Self {
        Self { state, version }
    }

    #[must_use]
    pub const fn state(&self) -> &DeviceAuthorizationState {
        &self.state
    }
}

pub trait DeviceStateStorePort: Send + Sync {
    type Version: Send + Sync;

    fn create<'a>(
        &'a self,
        device_code: &'a str,
        user_code: &'a str,
        state: &'a DeviceAuthorizationState,
        ttl_seconds: u64,
    ) -> DeviceStateFuture<'a, DeviceCreateResult>;

    fn load_by_device_code<'a>(
        &'a self,
        device_code: &'a str,
    ) -> DeviceStateFuture<'a, Option<StoredDeviceAuthorization<Self::Version>>>;

    fn load_by_device_hash<'a>(
        &'a self,
        device_hash: &'a str,
    ) -> DeviceStateFuture<'a, Option<StoredDeviceAuthorization<Self::Version>>>;

    fn resolve_user_code<'a>(&'a self, user_code: &'a str)
    -> DeviceStateFuture<'a, Option<String>>;

    fn replace_by_device_code<'a>(
        &'a self,
        device_code: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult>;

    fn replace_by_device_hash<'a>(
        &'a self,
        device_hash: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult>;

    fn complete_decision<'a>(
        &'a self,
        device_hash: &'a str,
        user_code: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult>;

    fn consume_by_device_code<'a>(
        &'a self,
        device_code: &'a str,
        version: &'a Self::Version,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult>;

    fn delete_user_code_if_matches<'a>(
        &'a self,
        user_code: &'a str,
        device_hash: &'a str,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceCreateFailure {
    DeadlineElapsed,
    Storage(DeviceStatePortError),
    CollisionLimit,
}

impl std::fmt::Display for DeviceCreateFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeadlineElapsed => formatter.write_str("device authorization deadline elapsed"),
            Self::Storage(error) => {
                write!(formatter, "device authorization creation failed: {error}")
            }
            Self::CollisionLimit => formatter.write_str("device code collision limit reached"),
        }
    }
}

impl std::error::Error for DeviceCreateFailure {}

#[derive(Clone, Debug, PartialEq)]
pub enum DevicePollTransition {
    AuthorizationPending(DeviceAuthorizationState),
    AuthorizationPendingUnchanged,
    SlowDown(DeviceAuthorizationState),
    Approved {
        payload: DeviceAuthorizationPayload,
        approval: DeviceAuthorizationApproval,
    },
    AccessDenied,
    Expired,
    Consumed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ApprovedDeviceAuthorization {
    pub payload: DeviceAuthorizationPayload,
    pub approval: DeviceAuthorizationApproval,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DevicePollCommit {
    AuthorizationPending,
    SlowDown,
    Approved(Box<ApprovedDeviceAuthorization>),
    AccessDenied,
    Expired,
    Consumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevicePollFailure {
    Missing,
    ClientMismatch,
    Storage(DeviceStatePortError),
    Contended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceDecisionFailure {
    Missing,
    AlreadyHandled,
    Expired,
    Storage(DeviceStatePortError),
    Repository(DeviceGrantPortError),
    Contended,
}

pub struct DeviceGrantService<S> {
    store: S,
}

impl<S> DeviceGrantService<S>
where
    S: DeviceStateStorePort,
{
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    pub async fn create_unique<FD, FU>(
        &self,
        payload: &DeviceAuthorizationPayload,
        ttl_seconds: u64,
        mut generate_device_code: FD,
        mut generate_user_code: FU,
    ) -> Result<(String, String), DeviceCreateFailure>
    where
        FD: FnMut() -> String,
        FU: FnMut() -> String,
    {
        if ttl_seconds == 0 || payload.expires_at <= payload.issued_at {
            return Err(DeviceCreateFailure::DeadlineElapsed);
        }
        let pending = DeviceAuthorizationState::Pending {
            payload: payload.clone(),
            last_poll_at: None,
            slow_down_count: 0,
        };
        for _ in 0..DEVICE_TRANSITION_MAX_ATTEMPTS {
            let device_code = generate_device_code();
            let user_code = generate_user_code();
            match self
                .store
                .create(&device_code, &user_code, &pending, ttl_seconds)
                .await
            {
                Ok(DeviceCreateResult::Applied) => return Ok((device_code, user_code)),
                Ok(
                    DeviceCreateResult::DeviceCodeCollision | DeviceCreateResult::UserCodeCollision,
                ) => continue,
                Ok(DeviceCreateResult::DeadlineElapsed) => {
                    return Err(DeviceCreateFailure::DeadlineElapsed);
                }
                Err(error) => return Err(DeviceCreateFailure::Storage(error)),
            }
        }
        Err(DeviceCreateFailure::CollisionLimit)
    }

    pub async fn poll<F>(
        &self,
        device_code: &str,
        expected_client_id: &str,
        mut current_time: F,
    ) -> Result<DevicePollCommit, DevicePollFailure>
    where
        F: FnMut() -> DateTime<Utc>,
    {
        for _ in 0..DEVICE_TRANSITION_MAX_ATTEMPTS {
            let stored = self
                .store
                .load_by_device_code(device_code)
                .await
                .map_err(DevicePollFailure::Storage)?
                .ok_or(DevicePollFailure::Missing)?;
            if device_authorization_payload(&stored.state)
                .is_some_and(|payload| payload.client_id != expected_client_id)
            {
                return Err(DevicePollFailure::ClientMismatch);
            }
            match evaluate_device_poll(&stored.state, current_time()) {
                DevicePollTransition::AuthorizationPending(next) => {
                    match self
                        .store
                        .replace_by_device_code(device_code, &stored.version, &next)
                        .await
                        .map_err(DevicePollFailure::Storage)?
                    {
                        DeviceAtomicResult::Applied => {
                            return Ok(DevicePollCommit::AuthorizationPending);
                        }
                        DeviceAtomicResult::Conflict => continue,
                        DeviceAtomicResult::DeadlineElapsed => {
                            return Ok(DevicePollCommit::Expired);
                        }
                    }
                }
                DevicePollTransition::AuthorizationPendingUnchanged => {
                    return Ok(DevicePollCommit::AuthorizationPending);
                }
                DevicePollTransition::SlowDown(next) => {
                    match self
                        .store
                        .replace_by_device_code(device_code, &stored.version, &next)
                        .await
                        .map_err(DevicePollFailure::Storage)?
                    {
                        DeviceAtomicResult::Applied => return Ok(DevicePollCommit::SlowDown),
                        DeviceAtomicResult::Conflict => continue,
                        DeviceAtomicResult::DeadlineElapsed => {
                            return Ok(DevicePollCommit::Expired);
                        }
                    }
                }
                DevicePollTransition::Approved { payload, approval } => {
                    match self
                        .store
                        .consume_by_device_code(device_code, &stored.version)
                        .await
                        .map_err(DevicePollFailure::Storage)?
                    {
                        DeviceAtomicResult::Applied => {
                            return Ok(DevicePollCommit::Approved(Box::new(
                                ApprovedDeviceAuthorization { payload, approval },
                            )));
                        }
                        DeviceAtomicResult::Conflict => continue,
                        DeviceAtomicResult::DeadlineElapsed => {
                            return Ok(DevicePollCommit::Expired);
                        }
                    }
                }
                DevicePollTransition::AccessDenied => return Ok(DevicePollCommit::AccessDenied),
                DevicePollTransition::Expired => return Ok(DevicePollCommit::Expired),
                DevicePollTransition::Consumed => return Ok(DevicePollCommit::Consumed),
            }
        }
        Err(DevicePollFailure::Contended)
    }

    pub async fn pending_request_for_user_code<F>(
        &self,
        user_code: &str,
        mut current_time: F,
    ) -> Result<Option<DeviceAuthorizationPayload>, DeviceStatePortError>
    where
        F: FnMut() -> DateTime<Utc>,
    {
        let Some(device_hash) = self.store.resolve_user_code(user_code).await? else {
            return Ok(None);
        };
        let Some(stored) = self.store.load_by_device_hash(&device_hash).await? else {
            let _ = self
                .store
                .delete_user_code_if_matches(user_code, &device_hash)
                .await?;
            return Ok(None);
        };
        let payload = match stored.state {
            DeviceAuthorizationState::Pending { payload, .. }
            | DeviceAuthorizationState::Approving { payload, .. } => payload,
            DeviceAuthorizationState::Approved { .. }
            | DeviceAuthorizationState::Denied { .. }
            | DeviceAuthorizationState::Consumed { .. } => return Ok(None),
        };
        if current_time() >= payload.expires_at {
            let _ = self
                .store
                .delete_user_code_if_matches(user_code, &device_hash)
                .await?;
            return Ok(None);
        }
        Ok(Some(payload))
    }

    pub async fn deny<F>(
        &self,
        user_code: &str,
        mut current_time: F,
    ) -> Result<(), DeviceDecisionFailure>
    where
        F: FnMut() -> DateTime<Utc>,
    {
        let device_hash = self
            .store
            .resolve_user_code(user_code)
            .await
            .map_err(DeviceDecisionFailure::Storage)?
            .ok_or(DeviceDecisionFailure::Missing)?;
        for _ in 0..DEVICE_TRANSITION_MAX_ATTEMPTS {
            let stored = self
                .store
                .load_by_device_hash(&device_hash)
                .await
                .map_err(DeviceDecisionFailure::Storage)?
                .ok_or(DeviceDecisionFailure::Missing)?;
            let now = current_time();
            let DeviceAuthorizationState::Pending { payload, .. } = &stored.state else {
                return Err(DeviceDecisionFailure::AlreadyHandled);
            };
            if now >= payload.expires_at {
                let _ = self
                    .store
                    .delete_user_code_if_matches(user_code, &device_hash)
                    .await
                    .map_err(DeviceDecisionFailure::Storage)?;
                return Err(DeviceDecisionFailure::Expired);
            }
            let next = DeviceAuthorizationState::Denied {
                payload: payload.clone(),
                denied_at: now,
            };
            match self
                .store
                .complete_decision(&device_hash, user_code, &stored.version, &next)
                .await
                .map_err(DeviceDecisionFailure::Storage)?
            {
                DeviceAtomicResult::Applied => return Ok(()),
                DeviceAtomicResult::Conflict => continue,
                DeviceAtomicResult::DeadlineElapsed => {
                    return Err(DeviceDecisionFailure::Expired);
                }
            }
        }
        Err(DeviceDecisionFailure::Contended)
    }

    pub async fn approve<R, F>(
        &self,
        user_code: &str,
        approval: DeviceAuthorizationApproval,
        client: &OAuthClient,
        repository: &R,
        mut current_time: F,
    ) -> Result<(), DeviceDecisionFailure>
    where
        R: DeviceGrantRepositoryPort,
        F: FnMut() -> DateTime<Utc>,
    {
        let claim_id = Uuid::now_v7();
        let device_hash = self
            .store
            .resolve_user_code(user_code)
            .await
            .map_err(DeviceDecisionFailure::Storage)?
            .ok_or(DeviceDecisionFailure::Missing)?;
        for _ in 0..DEVICE_TRANSITION_MAX_ATTEMPTS {
            let stored = self
                .store
                .load_by_device_hash(&device_hash)
                .await
                .map_err(DeviceDecisionFailure::Storage)?
                .ok_or(DeviceDecisionFailure::Missing)?;
            let now = current_time();
            match &stored.state {
                DeviceAuthorizationState::Pending { payload, .. } => {
                    if now >= payload.expires_at {
                        let _ = self
                            .store
                            .delete_user_code_if_matches(user_code, &device_hash)
                            .await
                            .map_err(DeviceDecisionFailure::Storage)?;
                        return Err(DeviceDecisionFailure::Expired);
                    }
                    if !client.is_active || client.client_id != payload.client_id {
                        return Err(DeviceDecisionFailure::Repository(
                            DeviceGrantPortError::CorruptData,
                        ));
                    }
                    let claimed = DeviceAuthorizationState::Approving {
                        payload: payload.clone(),
                        approval: approval.clone(),
                        claim_id,
                        grant_recorded: false,
                        started_at: now,
                    };
                    match self
                        .store
                        .replace_by_device_hash(&device_hash, &stored.version, &claimed)
                        .await
                        .map_err(DeviceDecisionFailure::Storage)?
                    {
                        DeviceAtomicResult::Applied | DeviceAtomicResult::Conflict => continue,
                        DeviceAtomicResult::DeadlineElapsed => {
                            return Err(DeviceDecisionFailure::Expired);
                        }
                    }
                }
                DeviceAuthorizationState::Approving {
                    payload,
                    approval: claimed_approval,
                    claim_id: active_claim_id,
                    grant_recorded,
                    started_at,
                    ..
                } => {
                    if claimed_approval.user_id != approval.user_id {
                        return Err(DeviceDecisionFailure::AlreadyHandled);
                    }
                    if !client.is_active || client.client_id != payload.client_id {
                        return Err(DeviceDecisionFailure::Repository(
                            DeviceGrantPortError::CorruptData,
                        ));
                    }
                    if now >= payload.expires_at {
                        let _ = self
                            .store
                            .delete_user_code_if_matches(user_code, &device_hash)
                            .await
                            .map_err(DeviceDecisionFailure::Storage)?;
                        return Err(DeviceDecisionFailure::Expired);
                    }
                    if !*grant_recorded {
                        if *active_claim_id != claim_id {
                            return Err(DeviceDecisionFailure::AlreadyHandled);
                        }
                        repository
                            .upsert_grant(DeviceGrantWrite {
                                tenant_id: client.tenant_id,
                                user_id: claimed_approval.user_id,
                                client_id: client.id,
                                scopes: &payload.scopes,
                                resource_indicators: &payload.resource_indicators,
                                authorization_details: &payload.authorization_details,
                            })
                            .await
                            .map_err(DeviceDecisionFailure::Repository)?;
                        let recorded = DeviceAuthorizationState::Approving {
                            payload: payload.clone(),
                            approval: claimed_approval.clone(),
                            claim_id: *active_claim_id,
                            grant_recorded: true,
                            started_at: *started_at,
                        };
                        match self
                            .store
                            .replace_by_device_hash(&device_hash, &stored.version, &recorded)
                            .await
                            .map_err(DeviceDecisionFailure::Storage)?
                        {
                            DeviceAtomicResult::Applied | DeviceAtomicResult::Conflict => continue,
                            DeviceAtomicResult::DeadlineElapsed => {
                                return Err(DeviceDecisionFailure::Expired);
                            }
                        }
                    }
                    let approved = DeviceAuthorizationState::Approved {
                        payload: payload.clone(),
                        approval: claimed_approval.clone(),
                        approved_at: current_time(),
                    };
                    match self
                        .store
                        .complete_decision(&device_hash, user_code, &stored.version, &approved)
                        .await
                        .map_err(DeviceDecisionFailure::Storage)?
                    {
                        DeviceAtomicResult::Applied => return Ok(()),
                        DeviceAtomicResult::Conflict => continue,
                        DeviceAtomicResult::DeadlineElapsed => {
                            return Err(DeviceDecisionFailure::Expired);
                        }
                    }
                }
                DeviceAuthorizationState::Approved { .. }
                | DeviceAuthorizationState::Denied { .. }
                | DeviceAuthorizationState::Consumed { .. } => {
                    return Err(DeviceDecisionFailure::AlreadyHandled);
                }
            }
        }
        Err(DeviceDecisionFailure::Contended)
    }
}

#[must_use]
pub fn evaluate_device_poll(
    state: &DeviceAuthorizationState,
    now: DateTime<Utc>,
) -> DevicePollTransition {
    if device_authorization_payload(state).is_some_and(|payload| now >= payload.expires_at) {
        return DevicePollTransition::Expired;
    }
    match state {
        DeviceAuthorizationState::Pending {
            payload,
            last_poll_at,
            slow_down_count,
        } => {
            let required_wait = payload.interval_seconds.saturating_add(
                u64::from(*slow_down_count).saturating_mul(DEVICE_SLOW_DOWN_INCREMENT_SECONDS),
            );
            let too_early = last_poll_at.is_some_and(|last| {
                let elapsed = now.signed_duration_since(last).num_seconds();
                elapsed < 0 || u64::try_from(elapsed).is_ok_and(|elapsed| elapsed < required_wait)
            });
            let next = DeviceAuthorizationState::Pending {
                payload: payload.clone(),
                last_poll_at: Some(now),
                slow_down_count: if too_early {
                    slow_down_count.saturating_add(1)
                } else {
                    *slow_down_count
                },
            };
            if too_early {
                DevicePollTransition::SlowDown(next)
            } else {
                DevicePollTransition::AuthorizationPending(next)
            }
        }
        DeviceAuthorizationState::Approved {
            payload, approval, ..
        } => DevicePollTransition::Approved {
            payload: payload.clone(),
            approval: approval.clone(),
        },
        DeviceAuthorizationState::Approving { .. } => {
            DevicePollTransition::AuthorizationPendingUnchanged
        }
        DeviceAuthorizationState::Denied { .. } => DevicePollTransition::AccessDenied,
        DeviceAuthorizationState::Consumed { .. } => DevicePollTransition::Consumed,
    }
}

#[must_use]
pub fn device_authorization_payload(
    state: &DeviceAuthorizationState,
) -> Option<&DeviceAuthorizationPayload> {
    match state {
        DeviceAuthorizationState::Pending { payload, .. }
        | DeviceAuthorizationState::Approving { payload, .. }
        | DeviceAuthorizationState::Approved { payload, .. }
        | DeviceAuthorizationState::Denied { payload, .. } => Some(payload),
        DeviceAuthorizationState::Consumed { .. } => None,
    }
}
