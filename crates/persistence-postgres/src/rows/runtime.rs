use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Debug, diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = crate::schema::runtime_module_desired_states)]
pub(crate) struct DesiredStateRow {
    pub(crate) module_id: String,
    pub(crate) desired_mode: String,
    pub(crate) revision: i64,
    pub(crate) actor_id: Option<Uuid>,
    pub(crate) reason: Option<String>,
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = crate::schema::runtime_module_instance_states)]
pub(crate) struct InstanceStateRow {
    pub(crate) instance_id: String,
    pub(crate) module_id: String,
    pub(crate) actual_state: String,
    pub(crate) transition_revision: i64,
    pub(crate) applied_revision: Option<i64>,
    pub(crate) drain_deadline: Option<DateTime<Utc>>,
    pub(crate) error_code: Option<String>,
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = crate::schema::runtime_module_state_events)]
pub(crate) struct ModuleEventRow {
    pub(crate) event_id: Uuid,
    pub(crate) module_id: String,
    pub(crate) event_type: String,
    pub(crate) revision: i64,
    pub(crate) instance_id: Option<String>,
    pub(crate) actor_id: Option<Uuid>,
    pub(crate) reason: Option<String>,
    pub(crate) before_state: Option<String>,
    pub(crate) after_state: Option<String>,
    pub(crate) outcome_code: Option<String>,
    pub(crate) occurred_at: DateTime<Utc>,
}
