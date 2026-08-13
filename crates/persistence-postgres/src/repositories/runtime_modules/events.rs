use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use nazo_identity::ports::RepositoryError;
use nazo_runtime_modules::{
    DesiredMode, DesiredStateRecord, ModuleEventPage, ModuleEventRecord, ModuleEventState,
    ModuleEventType, ModuleRevision,
};
use uuid::Uuid;

use crate::{
    repositories::audit::map_error, rows::runtime::ModuleEventRow,
    schema::runtime_module_state_events,
};

use super::{RuntimeModuleRepository, mapping};

pub(super) async fn page_events(
    repository: &RuntimeModuleRepository,
    offset: i64,
    limit: i64,
) -> Result<ModuleEventPage, RepositoryError> {
    if offset < 0 || !(1..=100).contains(&limit) {
        return Err(RepositoryError::Consistency(
            "runtime event pagination is out of bounds".to_owned(),
        ));
    }
    let mut connection = repository.connection().await?;
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
        .map(mapping::event_from_row)
        .collect::<Result<_, _>>()?;
    Ok(ModuleEventPage { total, events })
}

pub(super) fn desired_event(
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
