use std::collections::BTreeSet;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_runtime_modules::{
    CasOutcome, DesiredMode, DesiredRevisionGuard, DesiredStateChange, DesiredStateRecord,
    InstanceStateMutation, InstanceStateRecord, ModuleEventPage, ModuleEventRecord,
    ModuleEventState, ModuleEventType, ModuleId, ModuleRevision, ModuleState,
    ModuleStateRepository,
};
use uuid::Uuid;

use crate::{
    DbPool,
    repositories::audit::{
        actual_state, append_runtime_event, desired_mode, map_error, module_id, revision,
    },
    rows::runtime::{DesiredStateRow, InstanceStateRow, ModuleEventRow},
    schema::{
        runtime_module_desired_states, runtime_module_instance_states, runtime_module_state_events,
    },
};

pub type RuntimeModuleEventPage = ModuleEventPage;

const COMPOSABLE_DEFAULT_POLICY_VERSION: i32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDefaultPolicyMigration {
    pub previous_version: i32,
    pub current_version: i32,
    pub materialized_inherited_rows: usize,
    pub initialized_empty_state: bool,
}

#[derive(diesel::QueryableByName)]
struct RuntimeDefaultPolicyVersionRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    version: i32,
}

#[derive(Clone)]
pub struct RuntimeModuleRepository {
    pool: DbPool,
}

impl RuntimeModuleRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }

    pub async fn page_events(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<RuntimeModuleEventPage, RepositoryError> {
        self.page_events_inner(offset, limit).await
    }

    async fn page_events_inner(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<ModuleEventPage, RepositoryError> {
        if offset < 0 || !(1..=100).contains(&limit) {
            return Err(RepositoryError::Consistency(
                "runtime event pagination is out of bounds".to_owned(),
            ));
        }
        let mut connection = self.connection().await?;
        let total = runtime_module_state_events::table
            .count()
            .get_result::<i64>(&mut connection)
            .await
            .map_err(map_error)?;
        let rows = runtime_module_state_events::table
            .order((
                runtime_module_state_events::occurred_at.desc(),
                runtime_module_state_events::event_id.desc(),
            ))
            .offset(offset)
            .limit(limit)
            .select(ModuleEventRow::as_select())
            .load::<ModuleEventRow>(&mut connection)
            .await
            .map_err(map_error)?;
        let events = rows
            .into_iter()
            .map(event_from_row)
            .collect::<Result<_, _>>()?;
        Ok(ModuleEventPage { total, events })
    }

    pub async fn migrate_composable_default_policy(
        &self,
        legacy_inherited_enabled: &BTreeSet<ModuleId>,
    ) -> Result<RuntimeDefaultPolicyMigration, RepositoryError> {
        let mut connection = self.connection().await?;
        connection
            .transaction::<RuntimeDefaultPolicyMigration, RuntimeTransactionError, _>(
                async |connection| {
                    let policy = diesel::sql_query(
                        "SELECT version
                         FROM runtime_module_default_policy
                         WHERE singleton = TRUE
                         FOR UPDATE",
                    )
                    .get_result::<RuntimeDefaultPolicyVersionRow>(connection)
                    .await?;
                    if policy.version == COMPOSABLE_DEFAULT_POLICY_VERSION {
                        return Ok(RuntimeDefaultPolicyMigration {
                            previous_version: policy.version,
                            current_version: policy.version,
                            materialized_inherited_rows: 0,
                            initialized_empty_state: false,
                        });
                    }
                    if policy.version != 1 {
                        return Err(RuntimeTransactionError::Repository(
                            RepositoryError::Consistency(format!(
                                "unsupported runtime module default policy version: {}",
                                policy.version
                            )),
                        ));
                    }

                    let current_rows = runtime_module_desired_states::table
                        .select(DesiredStateRow::as_select())
                        .for_update()
                        .load::<DesiredStateRow>(connection)
                        .await?;
                    let initialized_empty_state = current_rows.is_empty();
                    let mut materialized_inherited_rows = 0;
                    let mut existing_modules = BTreeSet::new();
                    for row in current_rows {
                        let current =
                            desired_from_row(row).map_err(RuntimeTransactionError::Repository)?;
                        existing_modules.insert(current.module_id);
                        if current.mode != DesiredMode::Inherit {
                            continue;
                        }
                        let next_revision = next_desired_revision(Some(current.revision))
                            .map_err(RuntimeTransactionError::Repository)?;
                        let next = DesiredStateRecord {
                            module_id: current.module_id,
                            mode: if legacy_inherited_enabled.contains(&current.module_id) {
                                DesiredMode::Enabled
                            } else {
                                DesiredMode::Disabled
                            },
                            revision: ModuleRevision::new(next_revision),
                            actor_id: None,
                            reason: Some(
                                "materialized legacy inherited default before policy v2".to_owned(),
                            ),
                            updated_at: SystemTime::now(),
                        };
                        diesel::update(
                            runtime_module_desired_states::table.find(module_id(current.module_id)),
                        )
                        .set((
                            runtime_module_desired_states::desired_mode.eq(desired_mode(next.mode)),
                            runtime_module_desired_states::revision.eq(revision(next.revision)
                                .map_err(RuntimeTransactionError::Repository)?),
                            runtime_module_desired_states::actor_id.eq(Option::<Uuid>::None),
                            runtime_module_desired_states::reason.eq(next.reason.as_deref()),
                            runtime_module_desired_states::updated_at
                                .eq(DateTime::<Utc>::from(next.updated_at)),
                        ))
                        .execute(connection)
                        .await?;
                        let event = desired_event(&next, DesiredMode::Inherit, next.revision, None);
                        append_runtime_event(connection, &event)
                            .await
                            .map_err(RuntimeTransactionError::Repository)?;
                        materialized_inherited_rows += 1;
                    }
                    if !initialized_empty_state {
                        for module_id_value in ModuleId::ALL {
                            if existing_modules.contains(&module_id_value) {
                                continue;
                            }
                            let next = DesiredStateRecord {
                                module_id: module_id_value,
                                mode: if legacy_inherited_enabled.contains(&module_id_value) {
                                    DesiredMode::Enabled
                                } else {
                                    DesiredMode::Disabled
                                },
                                revision: ModuleRevision::new(1),
                                actor_id: None,
                                reason: Some(
                                    "materialized missing legacy default before policy v2"
                                        .to_owned(),
                                ),
                                updated_at: SystemTime::now(),
                            };
                            diesel::insert_into(runtime_module_desired_states::table)
                                .values((
                                    runtime_module_desired_states::module_id
                                        .eq(module_id(next.module_id)),
                                    runtime_module_desired_states::desired_mode
                                        .eq(desired_mode(next.mode)),
                                    runtime_module_desired_states::revision
                                        .eq(revision(next.revision)
                                            .map_err(RuntimeTransactionError::Repository)?),
                                    runtime_module_desired_states::actor_id
                                        .eq(Option::<Uuid>::None),
                                    runtime_module_desired_states::reason
                                        .eq(next.reason.as_deref()),
                                    runtime_module_desired_states::updated_at
                                        .eq(DateTime::<Utc>::from(next.updated_at)),
                                ))
                                .execute(connection)
                                .await?;
                            let event =
                                desired_event(&next, DesiredMode::Inherit, next.revision, None);
                            append_runtime_event(connection, &event)
                                .await
                                .map_err(RuntimeTransactionError::Repository)?;
                            materialized_inherited_rows += 1;
                        }
                    }

                    diesel::sql_query(
                        "UPDATE runtime_module_default_policy
                         SET version = $1, updated_at = now()
                         WHERE singleton = TRUE",
                    )
                    .bind::<diesel::sql_types::Integer, _>(COMPOSABLE_DEFAULT_POLICY_VERSION)
                    .execute(connection)
                    .await?;

                    Ok(RuntimeDefaultPolicyMigration {
                        previous_version: policy.version,
                        current_version: COMPOSABLE_DEFAULT_POLICY_VERSION,
                        materialized_inherited_rows,
                        initialized_empty_state,
                    })
                },
            )
            .await
            .map_err(RuntimeTransactionError::into_repository)
    }
}

impl ModuleStateRepository for RuntimeModuleRepository {
    type Error = RepositoryError;

    async fn read_desired(
        &self,
        requested_module_id: ModuleId,
    ) -> Result<Option<DesiredStateRecord>, Self::Error> {
        let mut connection = self.connection().await?;
        runtime_module_desired_states::table
            .find(module_id(requested_module_id))
            .select(DesiredStateRow::as_select())
            .first::<DesiredStateRow>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(desired_from_row)
            .transpose()
    }

    async fn read_all_desired(&self) -> Result<Vec<DesiredStateRecord>, Self::Error> {
        let mut connection = self.connection().await?;
        runtime_module_desired_states::table
            .select(DesiredStateRow::as_select())
            .load::<DesiredStateRow>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(desired_from_row)
            .collect()
    }

    async fn compare_and_set_desired(
        &self,
        change: DesiredStateChange,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        self.compare_and_set_desired_guarded(change, Vec::new())
            .await
    }

    async fn compare_and_set_desired_guarded(
        &self,
        change: DesiredStateChange,
        required_revisions: Vec<DesiredRevisionGuard>,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        let expected_next = next_desired_revision(change.expected_revision)?;
        let mut locked_modules = required_revisions
            .iter()
            .map(|guard| guard.module_id)
            .collect::<Vec<_>>();
        locked_modules.push(change.next.module_id);
        locked_modules.sort_unstable();
        locked_modules.dedup();
        let mut connection = self.connection().await?;
        connection
            .transaction::<CasOutcome<DesiredStateRecord>, RuntimeTransactionError, _>(
                async |connection| {
                    for locked_module in &locked_modules {
                        lock_key(connection, module_id(*locked_module)).await?;
                    }
                    let current = runtime_module_desired_states::table
                        .find(module_id(change.next.module_id))
                        .select(DesiredStateRow::as_select())
                        .for_update()
                        .first::<DesiredStateRow>(connection)
                        .await
                        .optional()?
                        .map(desired_from_row)
                        .transpose()
                        .map_err(RuntimeTransactionError::Repository)?;
                    if current.as_ref().map(|record| record.revision) != change.expected_revision {
                        return Ok(CasOutcome::Stale { current });
                    }
                    for guard in &required_revisions {
                        let guarded_revision = runtime_module_desired_states::table
                            .find(module_id(guard.module_id))
                            .select(runtime_module_desired_states::revision)
                            .first::<i64>(connection)
                            .await
                            .optional()?
                            .map(parse_revision)
                            .transpose()
                            .map_err(RuntimeTransactionError::Repository)?;
                        if guarded_revision != guard.expected_revision {
                            return Ok(CasOutcome::Stale { current });
                        }
                    }

                    if let Some(current) = current.as_ref()
                        && current.mode == change.next.mode
                    {
                        let event = desired_event(
                            &change.next,
                            current.mode,
                            current.revision,
                            Some("noop".to_owned()),
                        );
                        append_runtime_event(connection, &event)
                            .await
                            .map_err(RuntimeTransactionError::Repository)?;
                        return Ok(CasOutcome::Applied(current.clone()));
                    }

                    if change.next.revision.get() != expected_next {
                        return Err(RuntimeTransactionError::Repository(
                            RepositoryError::Consistency(format!(
                                "desired revision must advance to {expected_next}"
                            )),
                        ));
                    }
                    let actor_id = parse_optional_uuid(change.next.actor_id.as_deref(), "actor")?;
                    let updated_at = DateTime::<Utc>::from(change.next.updated_at);
                    if current.is_some() {
                        diesel::update(
                            runtime_module_desired_states::table
                                .find(module_id(change.next.module_id)),
                        )
                        .set((
                            runtime_module_desired_states::desired_mode
                                .eq(desired_mode(change.next.mode)),
                            runtime_module_desired_states::revision
                                .eq(revision(change.next.revision)
                                    .map_err(RuntimeTransactionError::Repository)?),
                            runtime_module_desired_states::actor_id.eq(actor_id),
                            runtime_module_desired_states::reason.eq(change.next.reason.as_deref()),
                            runtime_module_desired_states::updated_at.eq(updated_at),
                        ))
                        .execute(connection)
                        .await?;
                    } else {
                        diesel::insert_into(runtime_module_desired_states::table)
                            .values((
                                runtime_module_desired_states::module_id
                                    .eq(module_id(change.next.module_id)),
                                runtime_module_desired_states::desired_mode
                                    .eq(desired_mode(change.next.mode)),
                                runtime_module_desired_states::revision
                                    .eq(revision(change.next.revision)
                                        .map_err(RuntimeTransactionError::Repository)?),
                                runtime_module_desired_states::actor_id.eq(actor_id),
                                runtime_module_desired_states::reason
                                    .eq(change.next.reason.as_deref()),
                                runtime_module_desired_states::updated_at.eq(updated_at),
                            ))
                            .execute(connection)
                            .await?;
                    }
                    let event = desired_event(
                        &change.next,
                        current
                            .as_ref()
                            .map_or(DesiredMode::Inherit, |record| record.mode),
                        change.next.revision,
                        None,
                    );
                    append_runtime_event(connection, &event)
                        .await
                        .map_err(RuntimeTransactionError::Repository)?;
                    Ok(CasOutcome::Applied(change.next))
                },
            )
            .await
            .map_err(RuntimeTransactionError::into_repository)
    }

    async fn read_instance(
        &self,
        requested_instance_id: &str,
        requested_module_id: ModuleId,
    ) -> Result<Option<InstanceStateRecord>, Self::Error> {
        let mut connection = self.connection().await?;
        runtime_module_instance_states::table
            .find((requested_instance_id, module_id(requested_module_id)))
            .select(InstanceStateRow::as_select())
            .first::<InstanceStateRow>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(instance_from_row)
            .transpose()
    }

    async fn read_all_instances(
        &self,
        requested_instance_id: &str,
    ) -> Result<Vec<InstanceStateRecord>, Self::Error> {
        let mut connection = self.connection().await?;
        runtime_module_instance_states::table
            .filter(runtime_module_instance_states::instance_id.eq(requested_instance_id))
            .select(InstanceStateRow::as_select())
            .load::<InstanceStateRow>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(instance_from_row)
            .collect()
    }

    async fn page_events(&self, offset: i64, limit: i64) -> Result<ModuleEventPage, Self::Error> {
        self.page_events_inner(offset, limit).await
    }

    async fn compare_and_set_instance(
        &self,
        required_desired_revision: ModuleRevision,
        mutation: InstanceStateMutation,
    ) -> Result<CasOutcome<InstanceStateRecord>, Self::Error> {
        validate_instance_mutation(required_desired_revision, &mutation)?;
        let mut connection = self.connection().await?;
        connection
            .transaction::<CasOutcome<InstanceStateRecord>, RuntimeTransactionError, _>(
                async |connection| {
                    let change = mutation.change;
                    let key = format!(
                        "{}:{}",
                        change.next.instance_id,
                        module_id(change.next.module_id)
                    );
                    lock_key(connection, &key).await?;
                    let durable_desired_revision = runtime_module_desired_states::table
                        .find(module_id(change.next.module_id))
                        .select(runtime_module_desired_states::revision)
                        .for_update()
                        .first::<i64>(connection)
                        .await
                        .optional()?;
                    if durable_desired_revision
                        != Some(
                            revision(required_desired_revision)
                                .map_err(RuntimeTransactionError::Repository)?,
                        )
                    {
                        let current = load_instance(connection, &change.next).await?;
                        append_runtime_event(connection, &mutation.stale_event)
                            .await
                            .map_err(RuntimeTransactionError::Repository)?;
                        return Ok(CasOutcome::Stale { current });
                    }
                    let current = runtime_module_instance_states::table
                        .find((
                            change.next.instance_id.as_str(),
                            module_id(change.next.module_id),
                        ))
                        .select(InstanceStateRow::as_select())
                        .for_update()
                        .first::<InstanceStateRow>(connection)
                        .await
                        .optional()?
                        .map(instance_from_row)
                        .transpose()
                        .map_err(RuntimeTransactionError::Repository)?;
                    if current.as_ref().map(|record| record.transition_revision)
                        != change.expected_revision
                    {
                        append_runtime_event(connection, &mutation.stale_event)
                            .await
                            .map_err(RuntimeTransactionError::Repository)?;
                        return Ok(CasOutcome::Stale { current });
                    }
                    if change
                        .expected_revision
                        .is_some_and(|expected| change.next.transition_revision < expected)
                    {
                        return Err(RuntimeTransactionError::Repository(
                            RepositoryError::Consistency(
                                "instance transition revision cannot move backwards".to_owned(),
                            ),
                        ));
                    }
                    let transition_revision = revision(change.next.transition_revision)
                        .map_err(RuntimeTransactionError::Repository)?;
                    let applied_revision = change
                        .next
                        .applied_revision
                        .map(revision)
                        .transpose()
                        .map_err(RuntimeTransactionError::Repository)?;
                    let updated_at = DateTime::<Utc>::from(change.next.updated_at);
                    let drain_deadline = change.next.drain_deadline.map(DateTime::<Utc>::from);
                    if let Some(expected) = change.expected_revision {
                        let updated = diesel::update(
                            runtime_module_instance_states::table
                                .find((
                                    change.next.instance_id.as_str(),
                                    module_id(change.next.module_id),
                                ))
                                .filter(
                                    runtime_module_instance_states::transition_revision
                                        .eq(revision(expected)
                                            .map_err(RuntimeTransactionError::Repository)?),
                                ),
                        )
                        .set((
                            runtime_module_instance_states::actual_state
                                .eq(actual_state(change.next.state)),
                            runtime_module_instance_states::transition_revision
                                .eq(transition_revision),
                            runtime_module_instance_states::applied_revision.eq(applied_revision),
                            runtime_module_instance_states::drain_deadline.eq(drain_deadline),
                            runtime_module_instance_states::error_code
                                .eq(change.next.error_code.as_deref()),
                            runtime_module_instance_states::updated_at.eq(updated_at),
                        ))
                        .execute(connection)
                        .await?;
                        if updated != 1 {
                            let current = load_instance(connection, &change.next).await?;
                            append_runtime_event(connection, &mutation.stale_event)
                                .await
                                .map_err(RuntimeTransactionError::Repository)?;
                            return Ok(CasOutcome::Stale { current });
                        }
                    } else {
                        diesel::insert_into(runtime_module_instance_states::table)
                            .values((
                                runtime_module_instance_states::instance_id
                                    .eq(change.next.instance_id.as_str()),
                                runtime_module_instance_states::module_id
                                    .eq(module_id(change.next.module_id)),
                                runtime_module_instance_states::actual_state
                                    .eq(actual_state(change.next.state)),
                                runtime_module_instance_states::transition_revision
                                    .eq(transition_revision),
                                runtime_module_instance_states::applied_revision
                                    .eq(applied_revision),
                                runtime_module_instance_states::drain_deadline.eq(drain_deadline),
                                runtime_module_instance_states::error_code
                                    .eq(change.next.error_code.as_deref()),
                                runtime_module_instance_states::updated_at.eq(updated_at),
                            ))
                            .execute(connection)
                            .await?;
                    }
                    append_runtime_event(connection, &mutation.applied_event)
                        .await
                        .map_err(RuntimeTransactionError::Repository)?;
                    Ok(CasOutcome::Applied(change.next))
                },
            )
            .await
            .map_err(RuntimeTransactionError::into_repository)
    }

    async fn validate_revision(
        &self,
        requested_module_id: ModuleId,
        expected: ModuleRevision,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .read_desired(requested_module_id)
            .await?
            .is_some_and(|record| record.revision == expected))
    }
}

fn validate_instance_mutation(
    required_desired_revision: ModuleRevision,
    mutation: &InstanceStateMutation,
) -> Result<(), RepositoryError> {
    let next = &mutation.change.next;
    if next.transition_revision != required_desired_revision {
        return Err(RepositoryError::Consistency(
            "instance transition must be bound to the required desired revision".to_owned(),
        ));
    }
    let applied = &mutation.applied_event;
    let stale = &mutation.stale_event;
    if !matches!(
        applied.event_type,
        ModuleEventType::TransitionStarted
            | ModuleEventType::TransitionCompleted
            | ModuleEventType::TransitionFailed
            | ModuleEventType::DrainStarted
            | ModuleEventType::DrainCompleted
    ) {
        return Err(RepositoryError::Consistency(
            "actual-state mutation requires a transition or drain event".to_owned(),
        ));
    }
    if stale.event_type != ModuleEventType::StaleTransitionDiscarded {
        return Err(RepositoryError::Consistency(
            "actual-state mutation requires a stale-transition event".to_owned(),
        ));
    }
    for event in [applied, stale] {
        if event.module_id != next.module_id
            || event.instance_id.as_deref() != Some(next.instance_id.as_str())
            || event.revision != next.transition_revision
        {
            return Err(RepositoryError::Consistency(
                "actual-state event does not match its revision-bound mutation".to_owned(),
            ));
        }
    }
    if applied.after != Some(ModuleEventState::Actual(next.state)) {
        return Err(RepositoryError::Consistency(
            "applied actual-state event must describe the committed state".to_owned(),
        ));
    }
    Ok(())
}

async fn load_instance(
    connection: &mut AsyncPgConnection,
    next: &InstanceStateRecord,
) -> Result<Option<InstanceStateRecord>, RuntimeTransactionError> {
    runtime_module_instance_states::table
        .find((next.instance_id.as_str(), module_id(next.module_id)))
        .select(InstanceStateRow::as_select())
        .first::<InstanceStateRow>(connection)
        .await
        .optional()?
        .map(instance_from_row)
        .transpose()
        .map_err(RuntimeTransactionError::Repository)
}

async fn lock_key(
    connection: &mut AsyncPgConnection,
    key: &str,
) -> Result<(), diesel::result::Error> {
    diesel::sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<diesel::sql_types::Text, _>(key)
        .execute(connection)
        .await?;
    Ok(())
}

fn desired_event(
    next: &DesiredStateRecord,
    before: DesiredMode,
    revision: ModuleRevision,
    outcome_code: Option<String>,
) -> ModuleEventRecord {
    ModuleEventRecord {
        event_id: Uuid::now_v7().to_string(),
        module_id: next.module_id,
        event_type: ModuleEventType::DesiredStateChanged,
        revision,
        instance_id: None,
        actor_id: next.actor_id.clone(),
        reason: next.reason.clone(),
        before: Some(ModuleEventState::Desired(before)),
        after: Some(ModuleEventState::Desired(next.mode)),
        outcome_code,
        occurred_at: next.updated_at,
    }
}

fn desired_from_row(row: DesiredStateRow) -> Result<DesiredStateRecord, RepositoryError> {
    Ok(DesiredStateRecord {
        module_id: parse_module_id(&row.module_id)?,
        mode: parse_desired_mode(&row.desired_mode)?,
        revision: parse_revision(row.revision)?,
        actor_id: row.actor_id.map(|value| value.to_string()),
        reason: row.reason,
        updated_at: row.updated_at.into(),
    })
}

fn instance_from_row(row: InstanceStateRow) -> Result<InstanceStateRecord, RepositoryError> {
    Ok(InstanceStateRecord {
        instance_id: row.instance_id,
        module_id: parse_module_id(&row.module_id)?,
        state: parse_actual_state(&row.actual_state)?,
        transition_revision: parse_revision(row.transition_revision)?,
        applied_revision: row.applied_revision.map(parse_revision).transpose()?,
        drain_deadline: row.drain_deadline.map(Into::into),
        error_code: row.error_code,
        updated_at: row.updated_at.into(),
    })
}

fn event_from_row(row: ModuleEventRow) -> Result<ModuleEventRecord, RepositoryError> {
    let event_type = parse_event_type(&row.event_type)?;
    Ok(ModuleEventRecord {
        event_id: row.event_id.to_string(),
        module_id: parse_module_id(&row.module_id)?,
        event_type,
        revision: parse_revision(row.revision)?,
        instance_id: row.instance_id,
        actor_id: row.actor_id.map(|value| value.to_string()),
        reason: row.reason,
        before: row
            .before_state
            .as_deref()
            .map(|value| parse_event_state(event_type, value))
            .transpose()?,
        after: row
            .after_state
            .as_deref()
            .map(|value| parse_event_state(event_type, value))
            .transpose()?,
        outcome_code: row.outcome_code,
        occurred_at: row.occurred_at.into(),
    })
}

fn parse_event_type(value: &str) -> Result<ModuleEventType, RepositoryError> {
    match value {
        "desired_state_changed" => Ok(ModuleEventType::DesiredStateChanged),
        "transition_started" => Ok(ModuleEventType::TransitionStarted),
        "transition_completed" => Ok(ModuleEventType::TransitionCompleted),
        "transition_failed" => Ok(ModuleEventType::TransitionFailed),
        "drain_started" => Ok(ModuleEventType::DrainStarted),
        "drain_completed" => Ok(ModuleEventType::DrainCompleted),
        "stale_transition_discarded" => Ok(ModuleEventType::StaleTransitionDiscarded),
        _ => Err(RepositoryError::Consistency(format!(
            "unknown runtime event type: {value}"
        ))),
    }
}

fn parse_event_state(
    event_type: ModuleEventType,
    value: &str,
) -> Result<ModuleEventState, RepositoryError> {
    if event_type == ModuleEventType::DesiredStateChanged {
        parse_desired_mode(value).map(ModuleEventState::Desired)
    } else {
        parse_actual_state(value).map(ModuleEventState::Actual)
    }
}

fn parse_optional_uuid(
    value: Option<&str>,
    field: &str,
) -> Result<Option<Uuid>, RuntimeTransactionError> {
    value.map(Uuid::parse_str).transpose().map_err(|error| {
        RuntimeTransactionError::Repository(RepositoryError::Consistency(format!(
            "invalid runtime {field} id: {error}"
        )))
    })
}

fn parse_revision(value: i64) -> Result<ModuleRevision, RepositoryError> {
    u64::try_from(value)
        .map(ModuleRevision::new)
        .map_err(|_| RepositoryError::Consistency("negative runtime revision".to_owned()))
}

fn next_desired_revision(
    expected_revision: Option<ModuleRevision>,
) -> Result<u64, RepositoryError> {
    match expected_revision {
        None => Ok(1),
        Some(revision) => revision.get().checked_add(1).ok_or_else(|| {
            RepositoryError::Consistency("desired revision space is exhausted".to_owned())
        }),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/repositories/runtime_modules.rs"]
mod tests;

fn parse_desired_mode(value: &str) -> Result<DesiredMode, RepositoryError> {
    match value {
        "inherit" => Ok(DesiredMode::Inherit),
        "enabled" => Ok(DesiredMode::Enabled),
        "disabled" => Ok(DesiredMode::Disabled),
        _ => Err(RepositoryError::Consistency(format!(
            "unknown runtime desired mode: {value}"
        ))),
    }
}

fn parse_actual_state(value: &str) -> Result<ModuleState, RepositoryError> {
    match value {
        "disabled" => Ok(ModuleState::Disabled),
        "starting" => Ok(ModuleState::Starting),
        "enabled" => Ok(ModuleState::Enabled),
        "draining" => Ok(ModuleState::Draining),
        "failed" => Ok(ModuleState::Failed),
        _ => Err(RepositoryError::Consistency(format!(
            "unknown runtime actual state: {value}"
        ))),
    }
}

fn parse_module_id(value: &str) -> Result<ModuleId, RepositoryError> {
    match value {
        "device_authorization" => Ok(ModuleId::DeviceAuthorization),
        "token_exchange" => Ok(ModuleId::TokenExchange),
        "jwt_bearer_grant" => Ok(ModuleId::JwtBearerGrant),
        "ciba" => Ok(ModuleId::Ciba),
        "dynamic_client_registration" => Ok(ModuleId::DynamicClientRegistration),
        "request_objects" => Ok(ModuleId::RequestObjects),
        "jarm" => Ok(ModuleId::Jarm),
        "authorization_details" => Ok(ModuleId::AuthorizationDetails),
        "http_message_signatures" => Ok(ModuleId::HttpMessageSignatures),
        "scim" => Ok(ModuleId::Scim),
        "scim_security_events" => Ok(ModuleId::ScimSecurityEvents),
        "native_sso" => Ok(ModuleId::NativeSso),
        "frontchannel_logout" => Ok(ModuleId::FrontchannelLogout),
        "session_management" => Ok(ModuleId::SessionManagement),
        "openid4vci_issuer" => Ok(ModuleId::Openid4vciIssuer),
        "openid4vp_verifier" => Ok(ModuleId::Openid4vpVerifier),
        _ => Err(RepositoryError::Consistency(format!(
            "unknown runtime module id: {value}"
        ))),
    }
}

#[derive(Debug)]
enum RuntimeTransactionError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
}

impl RuntimeTransactionError {
    fn into_repository(self) -> RepositoryError {
        match self {
            Self::Diesel(error) => map_error(error),
            Self::Repository(error) => error,
        }
    }
}

impl From<diesel::result::Error> for RuntimeTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}
