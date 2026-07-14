use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use nazo_http_actix::json_response_status;
use nazo_identity::PublicAccount;
use serde_json::{Value, json};

pub(super) use nazo_identity::scim::{
    SCIM_ERROR_SCHEMA, SCIM_LIST_SCHEMA, SCIM_PATCH_SCHEMA, SCIM_RESOURCE_TYPE_SCHEMA,
    SCIM_SCHEMA_SCHEMA, SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA, SCIM_USER_SCHEMA,
};

pub(super) fn scim_user_json(user: PublicAccount) -> Value {
    scim_base(json!({
        "schemas": [SCIM_USER_SCHEMA],
        "id": user.id(),
        "userName": user.account.email,
        "active": user.principal.active,
        "name": {
            "formatted": user.profile.display_name,
            "givenName": user.profile.given_name,
            "familyName": user.profile.family_name
        },
        "emails": [{
            "value": user.account.email,
            "primary": true
        }],
        "meta": {
            "resourceType": "User",
            "created": user.created_at,
            "lastModified": user.updated_at,
            "location": format!("/scim/v2/Users/{}", user.id())
        }
    }))
}

pub(super) fn scim_user_schema() -> Value {
    scim_base(json!({
        "schemas": [SCIM_SCHEMA_SCHEMA],
        "id": SCIM_USER_SCHEMA,
        "name": "User",
        "description": "Core User",
        "attributes": [
            {"name": "userName", "type": "string", "multiValued": false, "required": true},
            {"name": "active", "type": "boolean", "multiValued": false, "required": false},
            {"name": "name", "type": "complex", "multiValued": false, "required": false},
            {"name": "emails", "type": "complex", "multiValued": true, "required": true}
        ]
    }))
}

pub(super) fn scim_base(value: Value) -> Value {
    value
}

pub(super) fn scim_error(status: StatusCode, scim_type: &str, detail: &str) -> HttpResponse {
    json_response_status(
        status,
        json!({
            "schemas": [SCIM_ERROR_SCHEMA],
            "status": status.as_u16().to_string(),
            "scimType": scim_type,
            "detail": detail
        }),
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/scim/tests/schema.rs"]
mod tests;
