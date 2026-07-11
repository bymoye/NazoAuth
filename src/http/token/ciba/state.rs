//! CIBA request persistence model and deterministic state transitions.

use crate::support::{
    ValkeyAtomicError, ValkeyAtomicResult, valkey_atomic_snapshot,
    valkey_compare_delete_at_deadline, valkey_compare_set_at_deadline, valkey_set_nx_at_deadline,
};
use fred::prelude::Client as ValkeyClient;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use std::fmt;
use uuid::Uuid;

pub(super) const CIBA_TRANSITION_MAX_ATTEMPTS: usize = 4;
const CIBA_EXPIRED_STATE_RETENTION_SECONDS: i64 = 120;
const CIBA_SLOW_DOWN_INCREMENT_SECONDS: u64 = 5;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct CibaRequestState {
    pub(super) client_id: String,
    pub(super) user_id: Uuid,
    pub(super) scopes: Vec<String>,
    pub(super) audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) acr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) binding_message: Option<String>,
    #[serde(default)]
    pub(super) issued_at: i64,
    pub(super) status: CibaStatus,
    pub(super) interval_seconds: u64,
    pub(super) expires_at: i64,
    pub(super) retention_expires_at: i64,
    pub(super) last_poll_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum CibaStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StoredCibaRequest {
    pub(super) raw: String,
    pub(super) state: CibaRequestState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CibaPollTransition {
    AuthorizationPending(CibaRequestState),
    SlowDown(CibaRequestState),
    Approved,
    Denied,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CibaDecision {
    Approve,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CibaDecisionEvaluation {
    Commit(CibaRequestState),
    UserMismatch,
    AlreadyHandled,
    Expired,
}

#[derive(Debug)]
pub(super) enum CibaStateError {
    Atomic(ValkeyAtomicError),
    Malformed(String),
    Serialization(serde_json::Error),
}

#[derive(Debug)]
pub(super) enum CibaCreateFailure {
    DeadlineElapsed,
    Storage(CibaStateError),
    CollisionLimit,
}

impl fmt::Display for CibaCreateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlineElapsed => formatter.write_str("CIBA creation deadline elapsed"),
            Self::Storage(error) => write!(formatter, "CIBA creation storage failed: {error}"),
            Self::CollisionLimit => formatter.write_str("CIBA auth_req_id collision limit reached"),
        }
    }
}

impl std::error::Error for CibaCreateFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::DeadlineElapsed | Self::CollisionLimit => None,
        }
    }
}

impl fmt::Display for CibaStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Atomic(error) => write!(formatter, "CIBA state command failed: {error}"),
            Self::Malformed(reason) => write!(formatter, "CIBA state is malformed: {reason}"),
            Self::Serialization(error) => {
                write!(formatter, "CIBA state serialization failed: {error}")
            }
        }
    }
}

impl std::error::Error for CibaStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Atomic(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::Malformed(_) => None,
        }
    }
}

impl From<ValkeyAtomicError> for CibaStateError {
    fn from(error: ValkeyAtomicError) -> Self {
        Self::Atomic(error)
    }
}

impl From<serde_json::Error> for CibaStateError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

pub(super) fn ciba_retention_deadline(expires_at: i64) -> i64 {
    expires_at.saturating_add(CIBA_EXPIRED_STATE_RETENTION_SECONDS)
}

pub(super) fn ciba_request_key(auth_req_id: &str) -> String {
    format!("oauth:ciba:{}", crate::support::blake3_hex(auth_req_id))
}

pub(super) fn evaluate_ciba_poll(state: &CibaRequestState, now: i64) -> CibaPollTransition {
    if now >= state.expires_at {
        return CibaPollTransition::Expired;
    }
    match state.status {
        CibaStatus::Approved => CibaPollTransition::Approved,
        CibaStatus::Denied => CibaPollTransition::Denied,
        CibaStatus::Pending => {
            let too_early = state.last_poll_at.is_some_and(|last_poll_at| {
                let interval = i64::try_from(state.interval_seconds).unwrap_or(i64::MAX);
                now.saturating_sub(last_poll_at) < interval
            });
            let mut next = state.clone();
            next.last_poll_at = Some(now);
            if too_early {
                next.interval_seconds = next
                    .interval_seconds
                    .saturating_add(CIBA_SLOW_DOWN_INCREMENT_SECONDS);
                CibaPollTransition::SlowDown(next)
            } else {
                CibaPollTransition::AuthorizationPending(next)
            }
        }
    }
}

pub(super) fn evaluate_ciba_decision(
    state: &CibaRequestState,
    expected_user_id: Option<Uuid>,
    decision: CibaDecision,
    now: i64,
) -> CibaDecisionEvaluation {
    if expected_user_id.is_some_and(|user_id| user_id != state.user_id) {
        return CibaDecisionEvaluation::UserMismatch;
    }
    if state.status != CibaStatus::Pending {
        return CibaDecisionEvaluation::AlreadyHandled;
    }
    if now >= state.expires_at {
        return CibaDecisionEvaluation::Expired;
    }
    let mut next = state.clone();
    next.status = match decision {
        CibaDecision::Approve => CibaStatus::Approved,
        CibaDecision::Deny => CibaStatus::Denied,
    };
    CibaDecisionEvaluation::Commit(next)
}

pub(super) async fn load_ciba_request_state(
    valkey: &ValkeyClient,
    auth_req_id: &str,
) -> Result<Option<StoredCibaRequest>, CibaStateError> {
    let Some(snapshot) = valkey_atomic_snapshot(valkey, &ciba_request_key(auth_req_id)).await?
    else {
        return Ok(None);
    };
    if snapshot.expire_at <= 0 {
        return Err(CibaStateError::Malformed(
            "state key has no finite absolute expiry".to_owned(),
        ));
    }

    let mut value: Value = serde_json::from_str(&snapshot.raw).map_err(|error| {
        CibaStateError::Malformed(format!("state JSON cannot be decoded: {error}"))
    })?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| CibaStateError::Malformed("state JSON must be an object".to_owned()))?;
    match object.get("retention_expires_at") {
        Some(deadline) => {
            let stored_deadline = deadline.as_i64().ok_or_else(|| {
                CibaStateError::Malformed("retention_expires_at must be an integer".to_owned())
            })?;
            if stored_deadline != snapshot.expire_at {
                return Err(CibaStateError::Malformed(
                    "retention_expires_at disagrees with Valkey EXPIRETIME".to_owned(),
                ));
            }
        }
        None => {
            object.insert(
                "retention_expires_at".to_owned(),
                Value::Number(Number::from(snapshot.expire_at)),
            );
        }
    }

    let state: CibaRequestState = serde_json::from_value(value).map_err(|error| {
        CibaStateError::Malformed(format!("state fields cannot be decoded: {error}"))
    })?;
    if state.expires_at <= 0 {
        return Err(CibaStateError::Malformed(
            "expires_at must be a positive Unix timestamp".to_owned(),
        ));
    }
    if state.retention_expires_at < state.expires_at {
        return Err(CibaStateError::Malformed(
            "retention deadline precedes protocol expiry".to_owned(),
        ));
    }

    Ok(Some(StoredCibaRequest {
        raw: snapshot.raw,
        state,
    }))
}

pub(super) async fn create_ciba_request_state(
    valkey: &ValkeyClient,
    auth_req_id: &str,
    state: &CibaRequestState,
) -> Result<ValkeyAtomicResult, CibaStateError> {
    let body = serde_json::to_string(state)?;
    Ok(valkey_set_nx_at_deadline(
        valkey,
        &ciba_request_key(auth_req_id),
        &body,
        state.retention_expires_at,
    )
    .await?)
}

pub(super) async fn create_unique_ciba_request<F>(
    valkey: &ValkeyClient,
    state: &CibaRequestState,
    mut generate_id: F,
) -> Result<String, CibaCreateFailure>
where
    F: FnMut() -> String,
{
    for _ in 0..CIBA_TRANSITION_MAX_ATTEMPTS {
        let auth_req_id = generate_id();
        match create_ciba_request_state(valkey, &auth_req_id, state).await {
            Ok(ValkeyAtomicResult::Applied) => return Ok(auth_req_id),
            Ok(ValkeyAtomicResult::Conflict) => continue,
            Ok(ValkeyAtomicResult::DeadlineElapsed) => {
                return Err(CibaCreateFailure::DeadlineElapsed);
            }
            Err(error) => return Err(CibaCreateFailure::Storage(error)),
        }
    }
    Err(CibaCreateFailure::CollisionLimit)
}

pub(super) async fn replace_ciba_request_state(
    valkey: &ValkeyClient,
    auth_req_id: &str,
    expected_raw: &str,
    state: &CibaRequestState,
) -> Result<ValkeyAtomicResult, CibaStateError> {
    let body = serde_json::to_string(state)?;
    Ok(valkey_compare_set_at_deadline(
        valkey,
        &ciba_request_key(auth_req_id),
        expected_raw,
        &body,
        state.retention_expires_at,
    )
    .await?)
}

pub(super) async fn delete_ciba_request_state(
    valkey: &ValkeyClient,
    auth_req_id: &str,
    expected_raw: &str,
    retention_expires_at: i64,
) -> Result<ValkeyAtomicResult, CibaStateError> {
    Ok(valkey_compare_delete_at_deadline(
        valkey,
        &ciba_request_key(auth_req_id),
        expected_raw,
        retention_expires_at,
    )
    .await?)
}
