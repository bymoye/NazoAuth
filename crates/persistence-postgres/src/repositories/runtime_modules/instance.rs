use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_runtime_modules::{
    CasOutcome, InstanceStateMutation, InstanceStateRecord, ModuleEventState, ModuleEventType,
    ModuleRevision,
};

use crate::{
    repositories::audit::{actual_state, append_runtime_event, map_error, module_id, revision},
    rows::runtime::InstanceStateRow,
    schema::{runtime_module_desired_states, runtime_module_instance_states},
};

use super::{
    RuntimeModuleRepository, mapping,
    transaction::{RuntimeTransactionError, lock_key},
};

pub(super) async fn read_instance(
    repository: &RuntimeModuleRepository,
    requested_instance_id: &str,
    requested_module_id: nazo_runtime_modules::ModuleId,
) -> Result<Option<InstanceStateRecord>, RepositoryError> {
    let mut connection = repository.connection().await?;
    runtime_module_instance_states::table
        .find((requested_instance_id, module_id(requested_module_id)))
        .select(InstanceStateRow::as_select())
        .first::<InstanceStateRow>(&mut connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(mapping::instance_from_row)
        .transpose()
}

pub(super) async fn read_all_instances(
    repository: &RuntimeModuleRepository,
    requested_instance_id: &str,
) -> Result<Vec<InstanceStateRecord>, RepositoryError> {
    let mut connection = repository.connection().await?;
    runtime_module_instance_states::table
        .filter(runtime_module_instance_states::instance_id.eq(requested_instance_id))
        .select(InstanceStateRow::as_select())
        .load::<InstanceStateRow>(&mut connection)
        .await
        .map_err(map_error)?
        .into_iter()
        .map(mapping::instance_from_row)
        .collect()
}

pub(super) async fn compare_and_set_instance(
    repository: &RuntimeModuleRepository,
    required_desired_revision: ModuleRevision,
    mutation: InstanceStateMutation,
) -> Result<CasOutcome<InstanceStateRecord>, RepositoryError> {
    validate_instance_mutation(required_desired_revision, &mutation)?;
    let mut connection = repository.connection().await?;
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
                    .map(mapping::instance_from_row)
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
                            .filter(runtime_module_instance_states::transition_revision.eq(
                                revision(expected).map_err(RuntimeTransactionError::Repository)?,
                            )),
                    )
                    .set((
                        runtime_module_instance_states::actual_state
                            .eq(actual_state(change.next.state)),
                        runtime_module_instance_states::transition_revision.eq(transition_revision),
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
                            runtime_module_instance_states::applied_revision.eq(applied_revision),
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
        .map(mapping::instance_from_row)
        .transpose()
        .map_err(RuntimeTransactionError::Repository)
}
