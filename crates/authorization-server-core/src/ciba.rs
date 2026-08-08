use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

const CIBA_TRANSITION_MAX_ATTEMPTS: usize = 4;
const CIBA_EXPIRED_STATE_RETENTION_SECONDS: i64 = 120;
const CIBA_SLOW_DOWN_INCREMENT_SECONDS: u64 = 5;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CibaAuthenticationContext {
    pub auth_time: i64,
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_sid: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CibaRequestState {
    pub client_id: String,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_context: Option<CibaAuthenticationContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_message: Option<String>,
    #[serde(default)]
    pub issued_at: i64,
    pub status: CibaStatus,
    pub interval_seconds: u64,
    pub expires_at: i64,
    pub retention_expires_at: i64,
    pub last_poll_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_notification: Option<CibaPingNotification>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CibaPingNotification {
    /// Populated atomically by the state-store adapter when the auth_req_id is
    /// persisted. It is the only value emitted in the ping JSON body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_req_id: Option<String>,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_notification_token: Option<String>,
    pub status: CibaPingNotificationStatus,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CibaPingNotificationStatus {
    AwaitingDecision,
    Pending,
    Delivered,
    Failed,
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

    /// Creates a request while optionally enforcing an external capability
    /// deadline in the state-store atomic operation itself.
    fn create_with_lease_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        state: &'a CibaRequestState,
        _lease_expires_at: Option<i64>,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.create(auth_req_id, state)
    }

    fn replace<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult>;

    /// Replaces a request while optionally enforcing an external capability
    /// deadline in the state-store CAS itself. Implementations that do not
    /// have an external deadline-aware CAS can safely fall back to the normal
    /// state transition; the PostgreSQL lease guard still serializes explicit
    /// revocation with the transition.
    fn replace_with_lease_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        state: &'a CibaRequestState,
        _lease_expires_at: Option<i64>,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.replace(auth_req_id, version, state)
    }

    fn delete<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
    ) -> CibaStateFuture<'a, CibaAtomicResult>;

    /// Deletes a request while optionally enforcing an external capability
    /// deadline in the state-store CAS itself.
    fn delete_with_lease_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        _lease_expires_at: Option<i64>,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.delete(auth_req_id, version)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaDecision {
    Approve,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CibaDecisionEvaluation {
    Commit(Box<CibaRequestState>),
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
    Approved(Box<CibaRequestState>),
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
        generate_id: F,
    ) -> Result<String, CibaCreateFailure>
    where
        F: FnMut() -> String,
    {
        self.create_unique_with_lease_deadline(state, None, generate_id)
            .await
    }

    pub async fn create_unique_with_lease_deadline<F>(
        &self,
        state: &CibaRequestState,
        lease_expires_at: Option<i64>,
        mut generate_id: F,
    ) -> Result<String, CibaCreateFailure>
    where
        F: FnMut() -> String,
    {
        validate_new_state(state).map_err(CibaCreateFailure::Storage)?;
        for _ in 0..CIBA_TRANSITION_MAX_ATTEMPTS {
            let auth_req_id = generate_id();
            match self
                .store
                .create_with_lease_deadline(&auth_req_id, state, lease_expires_at)
                .await
            {
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
        current_time: F,
    ) -> Result<CibaCommittedDecision, CibaDecisionFailure>
    where
        F: FnMut() -> i64,
    {
        self.decide_with_authentication_context(
            auth_req_id,
            decision,
            expected_user_id,
            None,
            current_time,
        )
        .await
    }

    pub async fn decide_with_authentication_context<F>(
        &self,
        auth_req_id: &str,
        decision: CibaDecision,
        expected_user_id: Option<Uuid>,
        authentication_context: Option<CibaAuthenticationContext>,
        current_time: F,
    ) -> Result<CibaCommittedDecision, CibaDecisionFailure>
    where
        F: FnMut() -> i64,
    {
        self.decide_with_authentication_context_and_lease_deadline(
            auth_req_id,
            decision,
            expected_user_id,
            authentication_context,
            None,
            current_time,
        )
        .await
    }

    pub async fn decide_with_authentication_context_and_lease_deadline<F>(
        &self,
        auth_req_id: &str,
        decision: CibaDecision,
        expected_user_id: Option<Uuid>,
        authentication_context: Option<CibaAuthenticationContext>,
        lease_expires_at: Option<i64>,
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
            match evaluate_ciba_decision_with_authentication_context(
                &stored.state,
                expected_user_id,
                decision,
                authentication_context.clone(),
                current_time(),
            ) {
                CibaDecisionEvaluation::UserMismatch => {
                    return Err(CibaDecisionFailure::UserMismatch);
                }
                CibaDecisionEvaluation::AlreadyHandled => {
                    return Err(CibaDecisionFailure::AlreadyHandled);
                }
                CibaDecisionEvaluation::Expired => {
                    match self
                        .store
                        .delete_with_lease_deadline(auth_req_id, &stored.version, lease_expires_at)
                        .await
                    {
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
                        .replace_with_lease_deadline(
                            auth_req_id,
                            &stored.version,
                            &next,
                            lease_expires_at,
                        )
                        .await
                    {
                        Ok(CibaAtomicResult::Applied) => {
                            return Ok(CibaCommittedDecision {
                                state: *next,
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
        stored: CibaStoredRequest<S::Version>,
        current_time: F,
    ) -> Result<CibaPollCommit, CibaPollFailure>
    where
        F: FnMut() -> i64,
    {
        self.poll_with_lease_deadline(auth_req_id, expected_client_id, stored, None, current_time)
            .await
    }

    pub async fn poll_with_lease_deadline<F>(
        &self,
        auth_req_id: &str,
        expected_client_id: &str,
        mut stored: CibaStoredRequest<S::Version>,
        lease_expires_at: Option<i64>,
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
                        .replace_with_lease_deadline(
                            auth_req_id,
                            &stored.version,
                            &next,
                            lease_expires_at,
                        )
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
                        .replace_with_lease_deadline(
                            auth_req_id,
                            &stored.version,
                            &next,
                            lease_expires_at,
                        )
                        .await
                        .map_err(CibaPollFailure::Storage)?
                    {
                        CibaAtomicResult::Applied => return Ok(CibaPollCommit::SlowDown),
                        result => result,
                    }
                }
                CibaPollTransition::Approved => {
                    // Keep the approved request available until its bounded
                    // retention TTL. Polling is only the read/decision step;
                    // downstream token issuance may fail after this method
                    // returns and must be able to retry the same grant. The
                    // issuance owner claim provides the idempotency boundary
                    // for concurrent duplicate polls.
                    return Ok(CibaPollCommit::Approved(Box::new(stored.state)));
                }
                CibaPollTransition::Denied => {
                    match self
                        .store
                        .delete_with_lease_deadline(auth_req_id, &stored.version, lease_expires_at)
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
                        .delete_with_lease_deadline(auth_req_id, &stored.version, lease_expires_at)
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
    evaluate_ciba_decision_with_authentication_context(state, expected_user_id, decision, None, now)
}

#[must_use]
pub fn evaluate_ciba_decision_with_authentication_context(
    state: &CibaRequestState,
    expected_user_id: Option<Uuid>,
    decision: CibaDecision,
    authentication_context: Option<CibaAuthenticationContext>,
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
    if decision == CibaDecision::Approve {
        next.authentication_context = authentication_context;
    }
    if let Some(notification) = next.ping_notification.as_mut() {
        notification.status = CibaPingNotificationStatus::Pending;
        notification.next_attempt_at = Some(now);
    }
    CibaDecisionEvaluation::Commit(Box::new(next))
}

fn validate_stored_request<V>(
    stored: CibaStoredRequest<V>,
) -> Result<CibaStoredRequest<V>, CibaStatePortError> {
    validate_stored_state(&stored.state)?;
    Ok(stored)
}

fn validate_new_state(state: &CibaRequestState) -> Result<(), CibaStatePortError> {
    validate_state_shape(state, false)?;
    if let Some(notification) = &state.ping_notification
        && (notification.status != CibaPingNotificationStatus::AwaitingDecision
            || notification.auth_req_id.is_some())
    {
        return Err(CibaStatePortError::CorruptData);
    }
    Ok(())
}

fn validate_stored_state(state: &CibaRequestState) -> Result<(), CibaStatePortError> {
    validate_state_shape(state, true)
}

fn validate_state_shape(
    state: &CibaRequestState,
    require_persisted_auth_req_id: bool,
) -> Result<(), CibaStatePortError> {
    if state.expires_at <= 0 || state.retention_expires_at < state.expires_at {
        return Err(CibaStatePortError::CorruptData);
    }
    if state
        .authentication_context
        .as_ref()
        .is_some_and(|context| {
            context.auth_time <= 0
                || context.amr.is_empty()
                || context.amr.iter().any(|method| method.trim().is_empty())
                || context.oidc_sid.as_deref().is_some_and(str::is_empty)
        })
    {
        return Err(CibaStatePortError::CorruptData);
    }
    if let Some(notification) = &state.ping_notification
        && (notification.endpoint.is_empty()
            || (require_persisted_auth_req_id
                && notification
                    .auth_req_id
                    .as_deref()
                    .is_none_or(str::is_empty))
            || notification
                .client_notification_token
                .as_deref()
                .is_some_and(str::is_empty)
            || (matches!(
                notification.status,
                CibaPingNotificationStatus::AwaitingDecision | CibaPingNotificationStatus::Pending
            ) && notification.client_notification_token.is_none())
            || (notification.status == CibaPingNotificationStatus::AwaitingDecision
                && notification.next_attempt_at.is_some())
            || (notification.status == CibaPingNotificationStatus::Pending
                && notification.next_attempt_at.is_none())
            || (matches!(
                notification.status,
                CibaPingNotificationStatus::Delivered | CibaPingNotificationStatus::Failed
            ) && (notification.client_notification_token.is_some()
                || notification.next_attempt_at.is_some())))
    {
        return Err(CibaStatePortError::CorruptData);
    }
    Ok(())
}
