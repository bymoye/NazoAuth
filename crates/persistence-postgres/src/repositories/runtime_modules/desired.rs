use std::collections::BTreeSet;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_runtime_modules::{
    CasOutcome, DesiredMode, DesiredRevisionGuard, DesiredStateChange, DesiredStateRecord,
    ModuleId, ModuleRevision,
};
use uuid::Uuid;

use crate::{
    repositories::audit::{append_runtime_event, desired_mode, map_error, module_id, revision},
    rows::runtime::DesiredStateRow,
    schema::runtime_module_desired_states,
};

use super::{
    RuntimeDefaultPolicyMigration, RuntimeModuleRepository, events,
    mapping::{self, parse_optional_uuid},
    transaction::{RuntimeTransactionError, lock_key},
};

const COMPOSABLE_DEFAULT_POLICY_VERSION: i32 = 2;

#[derive(diesel::QueryableByName)]
struct RuntimeDefaultPolicyVersionRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    version: i32,
}

pub(super) async fn migrate_composable_default_policy(
    repository: &RuntimeModuleRepository,
    legacy_inherited_enabled: &BTreeSet<ModuleId>,
) -> Result<RuntimeDefaultPolicyMigration, RepositoryError> {
    let mut connection = repository.connection().await?;
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
                    let current = mapping::desired_from_row(row)
                        .map_err(RuntimeTransactionError::Repository)?;
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
                        runtime_module_desired_states::revision
                            .eq(revision(next.revision)
                                .map_err(RuntimeTransactionError::Repository)?),
                        runtime_module_desired_states::actor_id.eq(Option::<Uuid>::None),
                        runtime_module_desired_states::reason.eq(next.reason.as_deref()),
                        runtime_module_desired_states::updated_at
                            .eq(DateTime::<Utc>::from(next.updated_at)),
                    ))
                    .execute(connection)
                    .await?;
                    let event =
                        events::desired_event(&next, DesiredMode::Inherit, next.revision, None);
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
                                "materialized missing legacy default before policy v2".to_owned(),
                            ),
                            updated_at: SystemTime::now(),
                        };
                        diesel::insert_into(runtime_module_desired_states::table)
                            .values((
                                runtime_module_desired_states::module_id
                                    .eq(module_id(next.module_id)),
                                runtime_module_desired_states::desired_mode
                                    .eq(desired_mode(next.mode)),
                                runtime_module_desired_states::revision.eq(revision(next.revision)
                                    .map_err(RuntimeTransactionError::Repository)?),
                                runtime_module_desired_states::actor_id.eq(Option::<Uuid>::None),
                                runtime_module_desired_states::reason.eq(next.reason.as_deref()),
                                runtime_module_desired_states::updated_at
                                    .eq(DateTime::<Utc>::from(next.updated_at)),
                            ))
                            .execute(connection)
                            .await?;
                        let event =
                            events::desired_event(&next, DesiredMode::Inherit, next.revision, None);
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

pub(super) async fn read_desired(
    repository: &RuntimeModuleRepository,
    requested_module_id: ModuleId,
) -> Result<Option<DesiredStateRecord>, RepositoryError> {
    let mut connection = repository.connection().await?;
    runtime_module_desired_states::table
        .find(module_id(requested_module_id))
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
                    lock_key(connection, module_id(*locked_module)).await?;
                }
                let current = runtime_module_desired_states::table
                    .find(module_id(change.next.module_id))
                    .select(DesiredStateRow::as_select())
                    .for_update()
                    .first::<DesiredStateRow>(connection)
                    .await
                    .optional()?
                    .map(mapping::desired_from_row)
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
                        .map(mapping::parse_revision)
                        .transpose()
                        .map_err(RuntimeTransactionError::Repository)?;
                    if guarded_revision != guard.expected_revision {
                        return Ok(CasOutcome::Stale { current });
                    }
                }

                if let Some(current) = current.as_ref()
                    && current.mode == change.next.mode
                {
                    let event = events::desired_event(
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
                        runtime_module_desired_states::table.find(module_id(change.next.module_id)),
                    )
                    .set((
                        runtime_module_desired_states::desired_mode
                            .eq(desired_mode(change.next.mode)),
                        runtime_module_desired_states::revision.eq(revision(change.next.revision)
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
                            runtime_module_desired_states::reason.eq(change.next.reason.as_deref()),
                            runtime_module_desired_states::updated_at.eq(updated_at),
                        ))
                        .execute(connection)
                        .await?;
                }
                let event = events::desired_event(
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
