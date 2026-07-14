use serde_json::{Value, json};

use crate::PublicAccount;

use super::{
    SCIM_CURSOR_TIMEOUT_SECONDS, SCIM_DEFAULT_PAGE_SIZE, SCIM_ERROR_SCHEMA, SCIM_LIST_SCHEMA,
    SCIM_MAX_PAGE_SIZE, SCIM_RESOURCE_TYPE_SCHEMA, SCIM_SCHEMA_SCHEMA,
    SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA, SCIM_USER_SCHEMA,
};

#[must_use]
pub fn scim_user_document(user: &PublicAccount) -> Value {
    json!({
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
    })
}

#[must_use]
pub fn scim_user_schema_document() -> Value {
    json!({
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
    })
}

#[must_use]
pub fn scim_service_provider_config_document() -> Value {
    json!({
        "id": "nazo-oauth-scim",
        "schemas": [SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA],
        "patch": {"supported": true},
        "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": true, "maxResults": SCIM_MAX_PAGE_SIZE},
        "changePassword": {"supported": false},
        "sort": {"supported": false},
        "etag": {"supported": false},
        "pagination": {
            "cursor": true,
            "index": true,
            "defaultPaginationMethod": "index",
            "defaultPageSize": SCIM_DEFAULT_PAGE_SIZE,
            "maxPageSize": SCIM_MAX_PAGE_SIZE,
            "cursorTimeout": SCIM_CURSOR_TIMEOUT_SECONDS
        },
        "securityEvents": {"asyncRequest": "none", "eventUris": []},
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "Bearer",
            "description": "Database-backed bearer credential with legacy deployment-token fallback.",
            "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
            "primary": true
        }]
    })
}

#[must_use]
pub fn scim_schemas_document() -> Value {
    json!({
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": 1,
        "startIndex": 1,
        "itemsPerPage": 1,
        "Resources": [scim_user_schema_document()]
    })
}

#[must_use]
pub fn scim_resource_types_document() -> Value {
    json!({
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": 1,
        "startIndex": 1,
        "itemsPerPage": 1,
        "Resources": [{
            "schemas": [SCIM_RESOURCE_TYPE_SCHEMA],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": SCIM_USER_SCHEMA
        }]
    })
}

#[must_use]
pub fn scim_index_list_document(total: i64, start_index: i64, users: &[PublicAccount]) -> Value {
    json!({
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": users.len(),
        "Resources": users.iter().map(scim_user_document).collect::<Vec<_>>()
    })
}

#[must_use]
pub fn scim_cursor_list_document(
    total: i64,
    users: &[PublicAccount],
    next_cursor: Option<&str>,
) -> Value {
    let mut document = json!({
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "itemsPerPage": users.len(),
        "Resources": users.iter().map(scim_user_document).collect::<Vec<_>>()
    });
    if let Some(cursor) = next_cursor {
        document["nextCursor"] = json!(cursor);
    }
    document
}

#[must_use]
pub fn scim_error_document(status: u16, scim_type: &str, detail: &str) -> Value {
    json!({
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": status.to_string(),
        "scimType": scim_type,
        "detail": detail
    })
}
