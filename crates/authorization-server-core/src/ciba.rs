use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

const CIBA_TRANSITION_MAX_ATTEMPTS: usize = 4;
const CIBA_EXPIRED_STATE_RETENTION_SECONDS: i64 = 120;
const CIBA_SLOW_DOWN_INCREMENT_SECONDS: u64 = 5;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CibaRequestState {
    pub client_id: String,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_message: Option<String>,
    #[serde(default)]
    pub issued_at: i64,
    pub status: CibaStatus,
    pub interval_seconds: u64,
    pub expires_at: i64,
    pub retention_expires_at: i64,
    pub last_poll_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CibaStatus {
    Pending,
    Approved,
    Denied,
}

pub type CibaStateFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, CibaStatePortError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaAtomicResult {
    Applied,
    Conflict,
    DeadlineElapsed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaStatePortError {
    Unavailable,
    CorruptData,
    Unexpected,
}

impl std::fmt::Display for CibaStatePortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "CIBA state store unavailable",
            Self::CorruptData => "CIBA state store contains corrupt data",
            Self::Unexpected => "unexpected CIBA state store failure",
        })
    }
}

impl std::error::Error for CibaStatePortError {}

#[derive(Debug)]
pub struct CibaStoredRequest<V> {
    state: CibaRequestState,
    version: V,
}

impl<V> CibaStoredRequest<V> {
    #[must_use]
    pub const fn new(state: CibaRequestState, version: V) -> Self {
        Self { state, version }
    }

    #[must_use]
    pub const fn state(&self) -> &CibaRequestState {
        &self.state
    }

    #[must_use]
    pub fn into_state(self) -> CibaRequestState {
        self.state
    }
}

pub trait CibaStateStorePort: Send + Sync {
    type Version: Send + Sync;

    fn load<'a>(
        &'a self,
        auth_req_id: &'a str,
    ) -> CibaStateFuture<'a, Option<CibaStoredRequest<Self::Version>>>;

    fn create<'a>(
        &'a self,
        auth_req_id: &'a str,
        state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult>;

    fn replace<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult>;

    fn delete<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
    ) -> CibaStateFuture<'a, CibaAtomicResult>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaDecision {
    Approve,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CibaDecisionEvaluation {
    Commit(CibaRequestState),
    UserMismatch,
    AlreadyHandled,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CibaPollTransition {
    AuthorizationPending(CibaRequestState),
    SlowDown(CibaRequestState),
    Approved,
    Denied,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CibaCommittedDecision {
    pub state: CibaRequestState,
    pub decision: CibaDecision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CibaPollCommit {
    AuthorizationPending,
    SlowDown,
    Approved(CibaRequestState),
    Denied,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaCreateFailure {
    DeadlineElapsed,
    Storage(CibaStatePortError),
    CollisionLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaDecisionFailure {
    Missing,
    UserMismatch,
    AlreadyHandled,
    Expired,
    Storage(CibaStatePortError),
    Contended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaPollFailure {
    Missing,
    ClientMismatch,
    Storage(CibaStatePortError),
    Contended,
}

impl std::fmt::Display for CibaCreateFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

pub struct CibaService<S> {
    store: S,
}

impl<S> CibaService<S>
where
    S: CibaStateStorePort,
{
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    pub async fn load(
        &self,
        auth_req_id: &str,
    ) -> Result<Option<CibaStoredRequest<S::Version>>, CibaStatePortError> {
        let stored = self.store.load(auth_req_id).await?;
        stored.map(validate_stored_request).transpose()
    }

    pub async fn create_unique<F>(
        &self,
        state: &CibaRequestState,
        mut generate_id: F,
    ) -> Result<String, CibaCreateFailure>
    where
        F: FnMut() -> String,
    {
        validate_state(state).map_err(CibaCreateFailure::Storage)?;
        for _ in 0..CIBA_TRANSITION_MAX_ATTEMPTS {
            let auth_req_id = generate_id();
            match self.store.create(&auth_req_id, state).await {
                Ok(CibaAtomicResult::Applied) => return Ok(auth_req_id),
                Ok(CibaAtomicResult::Conflict) => continue,
                Ok(CibaAtomicResult::DeadlineElapsed) => {
                    return Err(CibaCreateFailure::DeadlineElapsed);
                }
                Err(error) => return Err(CibaCreateFailure::Storage(error)),
            }
        }
        Err(CibaCreateFailure::CollisionLimit)
    }

    pub async fn decide<F>(
        &self,
        auth_req_id: &str,
        decision: CibaDecision,
        expected_user_id: Option<Uuid>,
        mut current_time: F,
    ) -> Result<CibaCommittedDecision, CibaDecisionFailure>
    where
        F: FnMut() -> i64,
    {
        for _ in 0..CIBA_TRANSITION_MAX_ATTEMPTS {
            let stored = self
                .load(auth_req_id)
                .await
                .map_err(CibaDecisionFailure::Storage)?
                .ok_or(CibaDecisionFailure::Missing)?;
            match evaluate_ciba_decision(&stored.state, expected_user_id, decision, current_time())
            {
                CibaDecisionEvaluation::UserMismatch => {
                    return Err(CibaDecisionFailure::UserMismatch);
                }
                CibaDecisionEvaluation::AlreadyHandled => {
                    return Err(CibaDecisionFailure::AlreadyHandled);
                }
                CibaDecisionEvaluation::Expired => {
                    match self.store.delete(auth_req_id, &stored.version).await {
                        Ok(CibaAtomicResult::Applied | CibaAtomicResult::DeadlineElapsed) => {
                            return Err(CibaDecisionFailure::Expired);
                        }
                        Ok(CibaAtomicResult::Conflict) => continue,
                        Err(error) => return Err(CibaDecisionFailure::Storage(error)),
                    }
                }
                CibaDecisionEvaluation::Commit(next) => {
                    match self
                        .store
                        .replace(auth_req_id, &stored.version, &next)
                        .await
                    {
                        Ok(CibaAtomicResult::Applied) => {
                            return Ok(CibaCommittedDecision {
                                state: next,
                                decision,
                            });
                        }
                        Ok(CibaAtomicResult::Conflict) => continue,
                        Ok(CibaAtomicResult::DeadlineElapsed) => {
                            return Err(CibaDecisionFailure::Expired);
                        }
                        Err(error) => return Err(CibaDecisionFailure::Storage(error)),
                    }
                }
            }
        }
        Err(CibaDecisionFailure::Contended)
    }

    pub async fn poll<F>(
        &self,
        auth_req_id: &str,
        expected_client_id: &str,
        mut stored: CibaStoredRequest<S::Version>,
        mut current_time: F,
    ) -> Result<CibaPollCommit, CibaPollFailure>
    where
        F: FnMut() -> i64,
    {
        for _ in 0..CIBA_TRANSITION_MAX_ATTEMPTS {
            if stored.state.client_id != expected_client_id {
                return Err(CibaPollFailure::ClientMismatch);
            }
            let atomic = match evaluate_ciba_poll(&stored.state, current_time()) {
                CibaPollTransition::AuthorizationPending(next) => {
                    match self
                        .store
                        .replace(auth_req_id, &stored.version, &next)
                        .await
                        .map_err(CibaPollFailure::Storage)?
                    {
                        CibaAtomicResult::Applied => {
                            return Ok(CibaPollCommit::AuthorizationPending);
                        }
                        result => result,
                    }
                }
                CibaPollTransition::SlowDown(next) => {
                    match self
                        .store
                        .replace(auth_req_id, &stored.version, &next)
                        .await
                        .map_err(CibaPollFailure::Storage)?
                    {
                        CibaAtomicResult::Applied => return Ok(CibaPollCommit::SlowDown),
                        result => result,
                    }
                }
                CibaPollTransition::Approved => {
                    match self
                        .store
                        .delete(auth_req_id, &stored.version)
                        .await
                        .map_err(CibaPollFailure::Storage)?
                    {
                        CibaAtomicResult::Applied => {
                            return Ok(CibaPollCommit::Approved(stored.state));
                        }
                        result => result,
                    }
                }
                CibaPollTransition::Denied => {
                    match self
                        .store
                        .delete(auth_req_id, &stored.version)
                        .await
                        .map_err(CibaPollFailure::Storage)?
                    {
                        CibaAtomicResult::Applied => return Ok(CibaPollCommit::Denied),
                        result => result,
                    }
                }
                CibaPollTransition::Expired => {
                    match self
                        .store
                        .delete(auth_req_id, &stored.version)
                        .await
                        .map_err(CibaPollFailure::Storage)?
                    {
                        CibaAtomicResult::Applied => return Ok(CibaPollCommit::Expired),
                        result => result,
                    }
                }
            };
            match atomic {
                CibaAtomicResult::Conflict => {
                    stored = self
                        .load(auth_req_id)
                        .await
                        .map_err(CibaPollFailure::Storage)?
                        .ok_or(CibaPollFailure::Missing)?;
                }
                CibaAtomicResult::DeadlineElapsed => return Ok(CibaPollCommit::Expired),
                CibaAtomicResult::Applied => unreachable!("applied transitions return immediately"),
            }
        }
        Err(CibaPollFailure::Contended)
    }
}

#[must_use]
pub const fn ciba_retention_deadline(expires_at: i64) -> i64 {
    expires_at.saturating_add(CIBA_EXPIRED_STATE_RETENTION_SECONDS)
}

#[must_use]
pub fn evaluate_ciba_poll(state: &CibaRequestState, now: i64) -> CibaPollTransition {
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

#[must_use]
pub fn evaluate_ciba_decision(
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

fn validate_stored_request<V>(
    stored: CibaStoredRequest<V>,
) -> Result<CibaStoredRequest<V>, CibaStatePortError> {
    validate_state(&stored.state)?;
    Ok(stored)
}

fn validate_state(state: &CibaRequestState) -> Result<(), CibaStatePortError> {
    if state.expires_at <= 0 || state.retention_expires_at < state.expires_at {
        return Err(CibaStatePortError::CorruptData);
    }
    Ok(())
}
