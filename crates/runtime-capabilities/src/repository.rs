use std::future::Future;
use std::time::SystemTime;

use crate::{DesiredMode, ModuleEventType, ModuleId, ModuleRevision, ModuleState};

/// Durable desired state, independent of any database row representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredStateRecord {
    pub module_id: ModuleId,
    pub mode: DesiredMode,
    pub revision: ModuleRevision,
    pub actor_id: Option<String>,
    pub reason: Option<String>,
    pub updated_at: SystemTime,
}

/// Input to an atomic desired-state compare-and-set operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredStateChange {
    /// `None` means that no durable desired-state record is expected to exist.
    pub expected_revision: Option<ModuleRevision>,
    pub next: DesiredStateRecord,
}

/// A related desired-state revision that must still match when a change commits.
///
/// Repositories use these guards only as a transaction mechanism. The registry
/// remains responsible for deciding which dependency or dependent revisions
/// protect a policy decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DesiredRevisionGuard {
    pub module_id: ModuleId,
    pub expected_revision: Option<ModuleRevision>,
}

/// Durable actual state for one module on one process instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceStateRecord {
    pub instance_id: String,
    pub module_id: ModuleId,
    pub state: ModuleState,
    pub transition_revision: ModuleRevision,
    pub applied_revision: Option<ModuleRevision>,
    pub drain_deadline: Option<SystemTime>,
    pub error_code: Option<String>,
    pub updated_at: SystemTime,
}

/// Input to an actual-state compare-and-set operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceStateChange {
    /// `None` means that no durable instance-state record is expected to exist.
    pub expected_revision: Option<ModuleRevision>,
    pub next: InstanceStateRecord,
}

/// Revision-bound actual-state mutation and its mutually exclusive audit records.
///
/// Repositories must commit the state write and `applied_event` atomically. If the
/// revision is stale, they must leave state unchanged and append only `stale_event`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceStateMutation {
    pub change: InstanceStateChange,
    pub applied_event: ModuleEventRecord,
    pub stale_event: ModuleEventRecord,
}

/// Typed before/after value for module audit events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleEventState {
    Desired(DesiredMode),
    Actual(ModuleState),
}

/// Infrastructure-neutral append-only module audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleEventRecord {
    pub event_id: String,
    pub module_id: ModuleId,
    pub event_type: ModuleEventType,
    pub revision: ModuleRevision,
    pub instance_id: Option<String>,
    pub actor_id: Option<String>,
    pub reason: Option<String>,
    pub before: Option<ModuleEventState>,
    pub after: Option<ModuleEventState>,
    pub outcome_code: Option<String>,
    pub occurred_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleEventPage {
    pub total: i64,
    pub events: Vec<ModuleEventRecord>,
}

/// Result of a durable compare-and-set, including the state that won a race.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CasOutcome<T> {
    Applied(T),
    Stale { current: Option<T> },
}

/// Persistence inversion port for desired state, actual state, and audit events.
///
/// The returned futures require no particular executor. Implementations may use
/// an async runtime internally, but this core crate does not depend on one.
pub trait ModuleStateRepository: Send + Sync {
    type Error: Send;

    fn read_desired(
        &self,
        module_id: ModuleId,
    ) -> impl Future<Output = Result<Option<DesiredStateRecord>, Self::Error>> + Send;

    fn read_all_desired(
        &self,
    ) -> impl Future<Output = Result<Vec<DesiredStateRecord>, Self::Error>> + Send;

    /// Compares and sets desired state and appends the matching
    /// [`ModuleEventType::DesiredStateChanged`] event in one atomic commit.
    /// A stale outcome must mutate neither desired state nor the event stream.
    fn compare_and_set_desired(
        &self,
        change: DesiredStateChange,
    ) -> impl Future<Output = Result<CasOutcome<DesiredStateRecord>, Self::Error>> + Send;

    /// Atomically validates related desired-state revisions and applies the
    /// target compare-and-set. A guard mismatch returns [`CasOutcome::Stale`]
    /// with the current target record and must not mutate state or audit events.
    fn compare_and_set_desired_guarded(
        &self,
        change: DesiredStateChange,
        required_revisions: Vec<DesiredRevisionGuard>,
    ) -> impl Future<Output = Result<CasOutcome<DesiredStateRecord>, Self::Error>> + Send;

    fn read_instance(
        &self,
        instance_id: &str,
        module_id: ModuleId,
    ) -> impl Future<Output = Result<Option<InstanceStateRecord>, Self::Error>> + Send;

    fn read_all_instances(
        &self,
        instance_id: &str,
    ) -> impl Future<Output = Result<Vec<InstanceStateRecord>, Self::Error>> + Send;

    fn page_events(
        &self,
        offset: i64,
        limit: i64,
    ) -> impl Future<Output = Result<ModuleEventPage, Self::Error>> + Send;

    fn compare_and_set_instance(
        &self,
        required_desired_revision: ModuleRevision,
        mutation: InstanceStateMutation,
    ) -> impl Future<Output = Result<CasOutcome<InstanceStateRecord>, Self::Error>> + Send;

    /// Validates the bound revision against durable desired state.
    fn validate_revision(
        &self,
        module_id: ModuleId,
        expected: ModuleRevision,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;
}
