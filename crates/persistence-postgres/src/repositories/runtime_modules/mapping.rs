use nazo_identity::ports::RepositoryError;
use nazo_runtime_modules::{
    DesiredMode, DesiredStateRecord, InstanceStateRecord, ModuleEventRecord, ModuleEventState,
    ModuleEventType, ModuleId, ModuleRevision, ModuleState,
};
use uuid::Uuid;

use crate::rows::runtime::{DesiredStateRow, InstanceStateRow, ModuleEventRow};

use super::transaction::RuntimeTransactionError;

pub(super) fn desired_from_row(
    row: DesiredStateRow,
) -> Result<DesiredStateRecord, RepositoryError> {
    Ok(DesiredStateRecord {
        module_id: parse_module_id(&row.module_id)?,
        mode: parse_desired_mode(&row.desired_mode)?,
        revision: parse_revision(row.revision)?,
        actor_id: row.actor_id.map(|value| value.to_string()),
        reason: row.reason,
        updated_at: row.updated_at.into(),
    })
}

pub(super) fn instance_from_row(
    row: InstanceStateRow,
) -> Result<InstanceStateRecord, RepositoryError> {
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

pub(super) fn event_from_row(row: ModuleEventRow) -> Result<ModuleEventRecord, RepositoryError> {
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

pub(super) fn parse_event_type(value: &str) -> Result<ModuleEventType, RepositoryError> {
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

pub(super) fn parse_event_state(
    event_type: ModuleEventType,
    value: &str,
) -> Result<ModuleEventState, RepositoryError> {
    if event_type == ModuleEventType::DesiredStateChanged {
        parse_desired_mode(value).map(ModuleEventState::Desired)
    } else {
        parse_actual_state(value).map(ModuleEventState::Actual)
    }
}

pub(super) fn parse_optional_uuid(
    value: Option<&str>,
    field: &str,
) -> Result<Option<Uuid>, RuntimeTransactionError> {
    value.map(Uuid::parse_str).transpose().map_err(|error| {
        RuntimeTransactionError::Repository(RepositoryError::Consistency(format!(
            "invalid runtime {field} id: {error}"
        )))
    })
}

pub(super) fn parse_revision(value: i64) -> Result<ModuleRevision, RepositoryError> {
    u64::try_from(value)
        .map(ModuleRevision::new)
        .map_err(|_| RepositoryError::Consistency("negative runtime revision".to_owned()))
}

pub(super) fn parse_desired_mode(value: &str) -> Result<DesiredMode, RepositoryError> {
    match value {
        "inherit" => Ok(DesiredMode::Inherit),
        "enabled" => Ok(DesiredMode::Enabled),
        "disabled" => Ok(DesiredMode::Disabled),
        _ => Err(RepositoryError::Consistency(format!(
            "unknown runtime desired mode: {value}"
        ))),
    }
}

pub(super) fn parse_actual_state(value: &str) -> Result<ModuleState, RepositoryError> {
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

pub(super) fn parse_module_id(value: &str) -> Result<ModuleId, RepositoryError> {
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
