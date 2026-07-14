#[cfg(test)]
use crate::adapters::email::normalize_email_address;
use crate::http::scim::schema::scim_error;
use actix_web::HttpResponse;
use actix_web::http::StatusCode;
#[cfg(test)]
use serde_json::{Value, json};

pub(crate) use nazo_identity::scim::{
    NormalizedScimUser, ScimPatch, ScimPatchOperation, ScimPatchRequest, ScimUserRequest,
};
#[cfg(test)]
pub(crate) use nazo_identity::scim::{ScimEmail, ScimName};

fn normalization_error(error: nazo_identity::scim::ScimError) -> HttpResponse {
    scim_error(StatusCode::BAD_REQUEST, error.scim_type, &error.detail)
}

pub(super) fn normalize_scim_user_payload(
    payload: ScimUserRequest,
    require_identity: bool,
) -> Result<NormalizedScimUser, HttpResponse> {
    nazo_identity::scim::normalize_scim_user_payload(payload, require_identity)
        .map_err(normalization_error)
}

pub(super) fn normalize_patch(
    operations: Vec<ScimPatchOperation>,
) -> Result<ScimPatch, HttpResponse> {
    nazo_identity::scim::normalize_patch(operations).map_err(normalization_error)
}

#[cfg(test)]
fn apply_patch_object(patch: &mut ScimPatch, value: Value) -> Result<(), HttpResponse> {
    nazo_identity::scim::apply_patch_object(patch, value).map_err(normalization_error)
}

#[cfg(test)]
fn sync_scim_identity(patch: &mut ScimPatch) -> Result<(), HttpResponse> {
    nazo_identity::scim::sync_scim_identity(patch).map_err(normalization_error)
}

pub(super) fn normalize_scim_user_filter(
    filter: Option<&str>,
) -> Result<Option<String>, HttpResponse> {
    nazo_identity::scim::normalize_scim_user_filter(filter).map_err(normalization_error)
}

#[cfg(test)]
fn primary_email(values: Option<Vec<ScimEmail>>, required: bool) -> Result<String, HttpResponse> {
    nazo_identity::scim::primary_email(values, required).map_err(normalization_error)
}

#[cfg(test)]
fn primary_email_from_value(value: Value) -> Result<String, HttpResponse> {
    nazo_identity::scim::primary_email_from_value(value).map_err(normalization_error)
}

#[cfg(test)]
fn normalize_scim_string(
    value: Option<String>,
    max_bytes: usize,
    field: &str,
    required: bool,
) -> Result<Option<String>, HttpResponse> {
    nazo_identity::scim::normalize_scim_string(value, max_bytes, field, required)
        .map_err(normalization_error)
}

#[cfg(test)]
fn required_string_value(value: Value, field: &str) -> Result<String, HttpResponse> {
    nazo_identity::scim::required_string_value(value, field).map_err(normalization_error)
}

#[cfg(test)]
fn required_email_value(value: Value, field: &str) -> Result<String, HttpResponse> {
    nazo_identity::scim::required_email_value(value, field).map_err(normalization_error)
}

#[cfg(test)]
fn required_bool_value(value: Value, field: &str) -> Result<bool, HttpResponse> {
    nazo_identity::scim::required_bool_value(value, field).map_err(normalization_error)
}

#[cfg(test)]
fn normalize_scim_path(value: &str) -> String {
    nazo_identity::scim::normalize_scim_path(value)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/scim/tests/normalization.rs"]
mod tests;
