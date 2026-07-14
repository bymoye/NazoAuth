use std::{error::Error, fmt, sync::Arc};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::email::normalize_email_address;
use crate::ports::{
    NewScimUser, PasswordHashInput, RepositoryError, ScimCredentialAuditPort, ScimCredentialUse,
    ScimListQuery, ScimRepositoryPort, UserPage,
};
use crate::{PublicAccount, TenantContext, UserId};

mod cursor;
mod documents;
mod query;

pub use cursor::{
    SCIM_CURSOR_AAD, SCIM_CURSOR_KEY_LABEL, SCIM_CURSOR_NONCE_LEN, SCIM_CURSOR_TAG_LEN,
    SCIM_CURSOR_TIMEOUT_SECONDS, ScimCursorContext, ScimCursorError, ScimCursorPosition,
    ScimCursorSubject, build_scim_cursor_plaintext, decode_scim_cursor_envelope,
    decode_scim_cursor_plaintext, encode_scim_cursor_envelope,
};
pub use documents::{
    scim_cursor_list_document, scim_error_document, scim_index_list_document,
    scim_resource_types_document, scim_schemas_document, scim_service_provider_config_document,
    scim_user_document, scim_user_schema_document,
};
pub use query::{
    SCIM_DEFAULT_PAGE_SIZE, SCIM_MAX_PAGE_SIZE, ScimListRequest, ScimPagination,
    parse_scim_list_query, select_scim_pagination,
};

#[derive(Clone)]
pub struct ScimService {
    repository: Arc<dyn ScimRepositoryPort>,
    credentials: Arc<dyn ScimCredentialAuditPort>,
}

impl ScimService {
    pub fn new(
        repository: Arc<dyn ScimRepositoryPort>,
        credentials: Arc<dyn ScimCredentialAuditPort>,
    ) -> Self {
        Self {
            repository,
            credentials,
        }
    }

    pub async fn list_users(
        &self,
        tenant: TenantContext,
        email: Option<String>,
        after: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
        offset: i64,
    ) -> Result<UserPage, RepositoryError> {
        self.repository
            .list(ScimListQuery {
                tenant_id: tenant.tenant_id,
                email,
                after,
                limit,
                offset,
            })
            .await
    }

    pub async fn create_user(
        &self,
        tenant: TenantContext,
        input: NormalizedScimUser,
        password_hash: PasswordHashInput,
    ) -> Result<PublicAccount, RepositoryError> {
        self.repository
            .create(NewScimUser {
                tenant,
                input,
                password_hash,
            })
            .await
    }

    pub async fn user(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        self.repository.get(tenant, user_id).await
    }

    pub async fn replace_user(
        &self,
        tenant: TenantContext,
        user_id: UserId,
        replacement: NormalizedScimUser,
    ) -> Result<PublicAccount, RepositoryError> {
        self.repository.replace(tenant, user_id, replacement).await
    }

    pub async fn patch_user(
        &self,
        tenant: TenantContext,
        user_id: UserId,
        patch: ScimPatch,
    ) -> Result<PublicAccount, RepositoryError> {
        self.repository.patch(tenant, user_id, patch).await
    }

    pub async fn deactivate_user(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<bool, RepositoryError> {
        self.repository.deactivate(tenant, user_id).await
    }

    pub async fn active_credential(
        &self,
        token_hash: &str,
    ) -> Result<Option<ScimTokenCredential>, RepositoryError> {
        self.credentials.active_credential(token_hash).await
    }

    pub async fn record_credential_use(
        &self,
        usage: ScimCredentialUse,
    ) -> Result<(), RepositoryError> {
        self.credentials.record_use(usage).await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScimRequiredScope {
    Read,
    Write,
}

impl ScimRequiredScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "scim:read",
            Self::Write => "scim:write",
        }
    }
}

pub const SCIM_SCOPE_ALL: &str = "scim:*";

#[must_use]
pub fn scim_credential_allows(scopes: &[String], required: ScimRequiredScope) -> bool {
    scopes
        .iter()
        .any(|scope| scope == SCIM_SCOPE_ALL || scope == required.as_str())
}

pub const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const SCIM_LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const SCIM_PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub const SCIM_SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";
pub const SCIM_RESOURCE_TYPE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScimTokenCredential {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScimUserRequest {
    #[serde(rename = "userName")]
    pub user_name: Option<String>,
    pub active: Option<bool>,
    pub name: Option<ScimName>,
    pub emails: Option<Vec<ScimEmail>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScimName {
    #[serde(rename = "givenName")]
    pub given_name: Option<String>,
    #[serde(rename = "familyName")]
    pub family_name: Option<String>,
    pub formatted: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScimEmail {
    pub value: Option<String>,
    pub primary: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ScimPatchRequest {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimPatchOperation>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ScimPatchOperation {
    pub op: String,
    pub path: Option<String>,
    pub value: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedScimUser {
    pub user_name: String,
    pub email: String,
    pub active: bool,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScimPatch {
    pub user_name: Option<String>,
    pub email: Option<String>,
    pub active: Option<bool>,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScimError {
    pub scim_type: &'static str,
    pub detail: String,
}

impl ScimError {
    #[must_use]
    pub fn new(scim_type: &'static str, detail: impl Into<String>) -> Self {
        Self {
            scim_type,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ScimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.scim_type, self.detail)
    }
}

impl Error for ScimError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScimRepositoryFailure {
    NotFound,
    Uniqueness,
    BackendUnavailable,
}

impl From<&RepositoryError> for ScimRepositoryFailure {
    fn from(error: &RepositoryError) -> Self {
        match error {
            RepositoryError::NotFound => Self::NotFound,
            RepositoryError::Conflict => Self::Uniqueness,
            RepositoryError::Unavailable
            | RepositoryError::AlreadyProcessed
            | RepositoryError::Consistency(_)
            | RepositoryError::Unexpected(_) => Self::BackendUnavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScimDeleteOutcome {
    Deleted,
    NotFound,
}

impl From<bool> for ScimDeleteOutcome {
    fn from(deactivated: bool) -> Self {
        if deactivated {
            Self::Deleted
        } else {
            Self::NotFound
        }
    }
}

pub fn validate_patch_schema(schemas: &[String]) -> Result<(), ScimError> {
    if schemas.is_empty() || schemas.iter().any(|schema| schema == SCIM_PATCH_SCHEMA) {
        Ok(())
    } else {
        Err(ScimError::new("invalidSyntax", "unsupported PATCH schema"))
    }
}

pub fn normalize_scim_user_payload(
    payload: ScimUserRequest,
    require_identity: bool,
) -> Result<NormalizedScimUser, ScimError> {
    let user_name = normalize_scim_string(payload.user_name, 120, "userName", require_identity)?;
    let user_name_email = match user_name {
        Some(value) => normalize_email_address(&value)
            .map_err(|_| ScimError::new("invalidValue", "userName must be an email address"))?,
        None if require_identity => {
            return Err(ScimError::new("invalidValue", "userName required"));
        }
        None => String::new(),
    };
    let email = primary_email(payload.emails, require_identity)?;
    if require_identity && email != user_name_email {
        return Err(ScimError::new(
            "invalidValue",
            "primary email must match userName",
        ));
    }
    let name = payload.name;
    Ok(NormalizedScimUser {
        user_name: user_name_email,
        email,
        active: payload.active.unwrap_or(true),
        display_name: normalize_scim_string(
            name.as_ref().and_then(|name| name.formatted.clone()),
            80,
            "name.formatted",
            false,
        )?,
        given_name: normalize_scim_string(
            name.as_ref().and_then(|name| name.given_name.clone()),
            80,
            "name.givenName",
            false,
        )?,
        family_name: normalize_scim_string(
            name.as_ref().and_then(|name| name.family_name.clone()),
            80,
            "name.familyName",
            false,
        )?,
    })
}

pub fn normalize_patch(operations: Vec<ScimPatchOperation>) -> Result<ScimPatch, ScimError> {
    let mut patch = ScimPatch::default();
    if operations.is_empty() {
        return Err(ScimError::new("invalidSyntax", "PATCH Operations required"));
    }
    for operation in operations {
        if !operation.op.eq_ignore_ascii_case("replace") {
            return Err(ScimError::new("mutability", "only replace is supported"));
        }
        let Some(path) = operation.path.as_deref().map(normalize_scim_path) else {
            apply_patch_object(&mut patch, operation.value)?;
            continue;
        };
        match path.as_str() {
            "username" => {
                patch.user_name = Some(required_email_value(operation.value, "userName")?);
            }
            "active" => patch.active = Some(required_bool_value(operation.value, "active")?),
            "name.formatted" => {
                patch.display_name =
                    Some(required_string_value(operation.value, "name.formatted")?);
            }
            "name.givenname" => {
                patch.given_name = Some(required_string_value(operation.value, "name.givenName")?);
            }
            "name.familyname" => {
                patch.family_name =
                    Some(required_string_value(operation.value, "name.familyName")?);
            }
            "emails" => patch.email = Some(primary_email_from_value(operation.value)?),
            _ => return Err(ScimError::new("invalidPath", "unsupported path")),
        }
    }
    sync_scim_identity(&mut patch)?;
    Ok(patch)
}

pub fn apply_patch_object(patch: &mut ScimPatch, value: Value) -> Result<(), ScimError> {
    let object = value
        .as_object()
        .ok_or_else(|| ScimError::new("invalidSyntax", "PATCH value must be object"))?;
    if let Some(value) = object.get("userName") {
        patch.user_name = Some(required_email_value(value.clone(), "userName")?);
    }
    if let Some(value) = object.get("active") {
        patch.active = Some(required_bool_value(value.clone(), "active")?);
    }
    if let Some(value) = object.get("name") {
        let name = value
            .as_object()
            .ok_or_else(|| ScimError::new("invalidSyntax", "name must be object"))?;
        if let Some(value) = name.get("formatted") {
            patch.display_name = Some(required_string_value(value.clone(), "name.formatted")?);
        }
        if let Some(value) = name.get("givenName") {
            patch.given_name = Some(required_string_value(value.clone(), "name.givenName")?);
        }
        if let Some(value) = name.get("familyName") {
            patch.family_name = Some(required_string_value(value.clone(), "name.familyName")?);
        }
    }
    if let Some(value) = object.get("emails") {
        patch.email = Some(primary_email_from_value(value.clone())?);
    }
    if let (Some(user_name), Some(email)) = (&patch.user_name, &patch.email)
        && user_name != email
    {
        return Err(ScimError::new(
            "invalidValue",
            "primary email must match userName",
        ));
    }
    Ok(())
}

pub fn sync_scim_identity(patch: &mut ScimPatch) -> Result<(), ScimError> {
    match (&patch.user_name, &patch.email) {
        (Some(user_name), Some(email)) if user_name != email => Err(ScimError::new(
            "invalidValue",
            "primary email must match userName",
        )),
        (Some(user_name), None) => {
            patch.email = Some(user_name.clone());
            Ok(())
        }
        (None, Some(email)) => {
            patch.user_name = Some(email.clone());
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn normalize_scim_user_filter(filter: Option<&str>) -> Result<Option<String>, ScimError> {
    let Some(filter) = filter.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let Some((field, value)) = filter.split_once(" eq ") else {
        return Err(ScimError::new(
            "invalidFilter",
            "only eq filters are supported",
        ));
    };
    if !field.trim().eq_ignore_ascii_case("userName") {
        return Err(ScimError::new(
            "invalidFilter",
            "only userName filters are supported",
        ));
    }
    let value = value.trim();
    if !(value.starts_with('"') && value.ends_with('"') && value.len() >= 2) {
        return Err(ScimError::new(
            "invalidFilter",
            "filter value must be quoted",
        ));
    }
    normalize_email_address(&value[1..value.len() - 1])
        .map(Some)
        .map_err(|_| ScimError::new("invalidFilter", "userName filter is invalid"))
}

pub fn primary_email(values: Option<Vec<ScimEmail>>, required: bool) -> Result<String, ScimError> {
    let Some(values) = values else {
        return if required {
            Err(ScimError::new("invalidValue", "email is required"))
        } else {
            Ok(String::new())
        };
    };
    let selected = values
        .iter()
        .find(|email| email.primary.unwrap_or(false))
        .or_else(|| values.first())
        .and_then(|email| email.value.as_deref());
    let Some(value) = selected else {
        return Err(ScimError::new("invalidValue", "email value is required"));
    };
    normalize_email_address(value).map_err(|_| ScimError::new("invalidValue", "email is invalid"))
}

pub fn primary_email_from_value(value: Value) -> Result<String, ScimError> {
    let emails = serde_json::from_value::<Vec<ScimEmail>>(value)
        .map_err(|_| ScimError::new("invalidValue", "emails must be an array"))?;
    primary_email(Some(emails), true)
}

pub fn normalize_scim_string(
    value: Option<String>,
    max_bytes: usize,
    field: &str,
    required: bool,
) -> Result<Option<String>, ScimError> {
    let value = value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    match value {
        Some(value) if value.len() <= max_bytes => Ok(Some(value)),
        Some(_) => Err(ScimError::new("invalidValue", format!("{field} too long"))),
        None if required => Err(ScimError::new("invalidValue", format!("{field} required"))),
        None => Ok(None),
    }
}

pub fn required_string_value(value: Value, field: &str) -> Result<String, ScimError> {
    normalize_scim_string(value.as_str().map(ToOwned::to_owned), 120, field, true)?
        .ok_or_else(|| ScimError::new("invalidValue", "value required"))
}

pub fn required_email_value(value: Value, field: &str) -> Result<String, ScimError> {
    let value = required_string_value(value, field)?;
    normalize_email_address(&value)
        .map_err(|_| ScimError::new("invalidValue", format!("{field} must be an email address")))
}

pub fn required_bool_value(value: Value, field: &str) -> Result<bool, ScimError> {
    value
        .as_bool()
        .ok_or_else(|| ScimError::new("invalidValue", format!("{field} must be boolean")))
}

#[must_use]
pub fn normalize_scim_path(value: &str) -> String {
    value.trim().replace(' ', "").to_ascii_lowercase()
}
