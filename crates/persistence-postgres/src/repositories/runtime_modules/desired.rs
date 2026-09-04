use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_runtime_modules::{
    CasOutcome, DesiredMode, DesiredRevisionGuard, DesiredStateChange, DesiredStateRecord,
    HistoricalDesiredMode, ModuleId, ModuleRevision,
};

use crate::{
    repositories::audit::{append_runtime_event, desired_mode, map_error, module_id, revision},
    rows::runtime::DesiredStateRow,
    schema::runtime_module_desired_states,
};

use super::{
    RuntimeModuleRepository, events,
    mapping::{self, parse_optional_uuid},
    transaction::{RuntimeTransactionError, lock_key},
};

pub(super) async fn read_desired(
    repository: &RuntimeModuleRepository,
    requested_module_id: ModuleId,
) -> Result<Option<DesiredStateRecord>, RepositoryError> {
    let mut connection = repository.connection().await?;
    runtime_module_desired_states::table
        .find((repository.tenant_id(), module_id(requested_module_id)))
        .select(DesiredStateRow::as_select())
        .first::<DesiredStateRow>(&mut connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(mapping::desired_from_row)
        .transpose()
}

pub(super) async fn read_all_desired(
    repository: &RuntimeModuleRepository,
) -> Result<Vec<DesiredStateRecord>, RepositoryError> {
    let mut connection = repository.connection().await?;
    runtime_module_desired_states::table
        .filter(runtime_module_desired_states::tenant_id.eq(repository.tenant_id()))
        .select(DesiredStateRow::as_select())
        .load::<DesiredStateRow>(&mut connection)
        .await
        .map_err(map_error)?
        .into_iter()
        .map(mapping::desired_from_row)
        .collect()
}

pub(super) async fn compare_and_set_desired(
    repository: &RuntimeModuleRepository,
    change: DesiredStateChange,
    required_revisions: Vec<DesiredRevisionGuard>,
) -> Result<CasOutcome<DesiredStateRecord>, RepositoryError> {
    let expected_next = next_desired_revision(change.expected_revision)?;
    let mut locked_modules = required_revisions
        .iter()
        .map(|guard| guard.module_id)
        .collect::<Vec<_>>();
    locked_modules.push(change.next.module_id);
    locked_modules.sort_unstable();
    locked_modules.dedup();
    let mut connection = repository.connection().await?;
    connection
        .transaction::<CasOutcome<DesiredStateRecord>, RuntimeTransactionError, _>(
            async |connection| {
                for locked_module in &locked_modules {
                    let lock = format!("{}:{}", repository.tenant_id(), module_id(*locked_module));
                    lock_key(connection, &lock).await?;
                }
                let current = runtime_module_desired_states::table
                    .find((repository.tenant_id(), module_id(change.next.module_id)))
                    .select(DesiredStateRow::as_select())
                    .for_update()
                    .first::<DesiredStateRow>(connection)
                    .await
                    .optional()?
                    .map(mapping::desired_from_row)
                    .transpose()
                    .map_err(RuntimeTransactionError::Repository)?;
                let current = current.ok_or_else(|| {
                    RuntimeTransactionError::Repository(RepositoryError::Consistency(
                        "runtime desired state is missing".to_owned(),
                    ))
                })?;
                if Some(current.revision) != change.expected_revision {
                    return Ok(CasOutcome::Stale {
                        current: Some(current),
                    });
                }
                for guard in &required_revisions {
                    let guarded_revision = runtime_module_desired_states::table
                        .find((repository.tenant_id(), module_id(guard.module_id)))
                        .select(runtime_module_desired_states::revision)
                        .first::<i64>(connection)
                        .await
                        .optional()?
                        .map(mapping::parse_revision)
                        .transpose()
                        .map_err(RuntimeTransactionError::Repository)?;
                    if guarded_revision != guard.expected_revision {
                        return Ok(CasOutcome::Stale {
                            current: Some(current),
                        });
                    }
                }

                if current.mode == change.next.mode {
                    let event = events::desired_event(
                        &change.next,
                        match current.mode {
                            DesiredMode::Enabled => HistoricalDesiredMode::Enabled,
                            DesiredMode::Disabled => HistoricalDesiredMode::Disabled,
                        },
                        current.revision,
                        Some("noop".to_owned()),
                    );
                    append_runtime_event(connection, repository.tenant_id(), &event)
                        .await
                        .map_err(RuntimeTransactionError::Repository)?;
                    return Ok(CasOutcome::Applied(current));
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
                diesel::update(
                    runtime_module_desired_states::table
                        .find((repository.tenant_id(), module_id(change.next.module_id))),
                )
                .set((
                    runtime_module_desired_states::desired_mode.eq(desired_mode(change.next.mode)),
                    runtime_module_desired_states::revision.eq(revision(change.next.revision)
                        .map_err(RuntimeTransactionError::Repository)?),
                    runtime_module_desired_states::actor_id.eq(actor_id),
                    runtime_module_desired_states::reason.eq(change.next.reason.as_deref()),
                    runtime_module_desired_states::updated_at.eq(updated_at),
                ))
                .execute(connection)
                .await?;
                let event = events::desired_event(
                    &change.next,
                    match current.mode {
                        DesiredMode::Enabled => HistoricalDesiredMode::Enabled,
                        DesiredMode::Disabled => HistoricalDesiredMode::Disabled,
                    },
                    change.next.revision,
                    None,
                );
                append_runtime_event(connection, repository.tenant_id(), &event)
                    .await
                    .map_err(RuntimeTransactionError::Repository)?;
                Ok(CasOutcome::Applied(change.next))
            },
        )
        .await
        .map_err(RuntimeTransactionError::into_repository)
}

pub(super) async fn validate_revision(
    repository: &RuntimeModuleRepository,
    requested_module_id: ModuleId,
    expected: ModuleRevision,
) -> Result<bool, RepositoryError> {
    Ok(read_desired(repository, requested_module_id)
        .await?
        .is_some_and(|record| record.revision == expected))
}

pub(super) fn next_desired_revision(
    expected_revision: Option<ModuleRevision>,
) -> Result<u64, RepositoryError> {
    match expected_revision {
        None => Ok(1),
        Some(revision) => revision.get().checked_add(1).ok_or_else(|| {
            RepositoryError::Consistency("desired revision space is exhausted".to_owned())
        }),
    }
}
