#![cfg(test)]

//! Legacy SCIM transport contract harness.
//!
//! Production handlers live in `nazo-http-actix`; this module remains only
//! for the existing compatibility fixtures while those tests are migrated.
use nazo_http_actix::{empty_response, json_response, json_response_status};

#[cfg(test)]
use crate::adapters::security::blake3_hex;
use crate::adapters::security::hash_password;
use crate::adapters::security::random_urlsafe_token;
#[cfg(test)]
use crate::domain::DatabaseUserFixture;
use crate::domain::tenancy::default_tenant_context;
use crate::http::client_ip::ClientIpConfig;
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
#[cfg(test)]
use actix_web::web::Query;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Duration;
use chrono::Utc;
use nazo_identity::PublicAccount;
use serde::Deserialize;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;
mod auth;
mod cursor;
mod normalization;
mod schema;

#[cfg(test)]
use auth::{
    SCIM_SCOPE_ALL, SCIM_SCOPE_READ, SCIM_SCOPE_WRITE, bearer_token, scim_credential_allows,
    scim_scope_values,
};
use auth::{ScimCredential, ScimRequiredScope, require_scim_bearer};
use cursor::{
    SCIM_CURSOR_TIMEOUT_SECONDS, ScimCursorContext, ScimCursorError, ScimCursorKey,
    decode_scim_cursor, encode_scim_cursor,
};
#[cfg(test)]
use normalization::{ScimEmail, ScimName, ScimPatchOperation};
use normalization::{
    ScimPatchRequest, ScimUserRequest, normalize_patch, normalize_scim_user_filter,
    normalize_scim_user_payload,
};
#[cfg(test)]
use schema::{SCIM_ERROR_SCHEMA, SCIM_SCHEMA_SCHEMA};
use schema::{
    SCIM_LIST_SCHEMA, SCIM_PATCH_SCHEMA, SCIM_RESOURCE_TYPE_SCHEMA,
    SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA, SCIM_USER_SCHEMA, scim_base, scim_error, scim_user_json,
    scim_user_schema,
};

#[derive(Clone)]
pub(crate) struct ScimConfig {
    legacy_bearer_token: Option<Box<str>>,
    cursor_key: ScimCursorKey,
    client_ip: ClientIpConfig,
}

impl ScimConfig {
    pub(crate) fn new(
        legacy_bearer_token: Option<&str>,
        client_secret_pepper: &str,
        client_ip: ClientIpConfig,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            legacy_bearer_token: legacy_bearer_token.map(Into::into),
            cursor_key: ScimCursorKey::from_client_secret_pepper(client_secret_pepper)?,
            client_ip,
        })
    }
}

#[derive(Clone)]
pub(crate) struct ScimEndpoint {
    service: nazo_identity::scim::ScimService,
    config: ScimConfig,
    admission: ScimRuntimeAdmission,
}

#[derive(Clone)]
pub(crate) struct ScimRuntimeAdmission {
    #[cfg(not(test))]
    runtime_modules: std::sync::Arc<crate::runtime_modules::ServerRuntimeModuleRegistry>,
    #[cfg(test)]
    enabled: bool,
}

impl ScimEndpoint {
    pub(crate) fn new(
        service: nazo_identity::scim::ScimService,
        config: ScimConfig,
        admission: ScimRuntimeAdmission,
    ) -> Self {
        Self {
            service,
            config,
            admission,
        }
    }

    #[cfg(test)]
    fn for_test(service: nazo_identity::scim::ScimService, config: ScimConfig) -> Self {
        Self {
            service,
            config,
            admission: ScimRuntimeAdmission { enabled: true },
        }
    }
}

impl ScimRuntimeAdmission {
    pub(crate) fn new(
        runtime_modules: std::sync::Arc<crate::runtime_modules::ServerRuntimeModuleRegistry>,
    ) -> Self {
        #[cfg(test)]
        let _ = &runtime_modules;
        Self {
            #[cfg(not(test))]
            runtime_modules,
            #[cfg(test)]
            enabled: true,
        }
    }

    fn accepts_new_requests(&self) -> bool {
        #[cfg(not(test))]
        {
            nazo_auth::module_admissible(
                &self.runtime_modules.snapshot(),
                nazo_runtime_modules::ModuleId::Scim,
                nazo_auth::CapabilityAdmission::NewRequest,
            )
        }
        #[cfg(test)]
        {
            self.enabled
        }
    }
}

const SCIM_DEFAULT_PAGE_SIZE: i64 = 100;
const SCIM_MAX_PAGE_SIZE: i64 = 200;

#[derive(Default, Deserialize)]
pub(crate) struct ScimListQuery {
    #[serde(rename = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
    filter: Option<String>,
    cursor: Option<String>,
}

fn parse_scim_list_query(raw_query: &str) -> Result<ScimListQuery, HttpResponse> {
    let mut query = ScimListQuery::default();
    for (name, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "startIndex" => {
                if query.start_index.is_some() {
                    return Err(scim_error(
                        StatusCode::BAD_REQUEST,
                        "invalidValue",
                        "startIndex must not be repeated",
                    ));
                }
                query.start_index = Some(value.parse().map_err(|_| {
                    scim_error(
                        StatusCode::BAD_REQUEST,
                        "invalidValue",
                        "startIndex must be an integer",
                    )
                })?);
            }
            "count" => {
                if query.count.is_some() {
                    return Err(scim_error(
                        StatusCode::BAD_REQUEST,
                        "invalidCount",
                        "count must not be repeated",
                    ));
                }
                query.count = Some(value.parse().map_err(|_| {
                    scim_error(
                        StatusCode::BAD_REQUEST,
                        "invalidCount",
                        "count must be an integer",
                    )
                })?);
            }
            "filter" => {
                if query.filter.is_some() {
                    return Err(scim_error(
                        StatusCode::BAD_REQUEST,
                        "invalidValue",
                        "filter must not be repeated",
                    ));
                }
                query.filter = Some(value.into_owned());
            }
            "cursor" => {
                if query.cursor.is_some() {
                    return Err(scim_error(
                        StatusCode::BAD_REQUEST,
                        "invalidCursor",
                        "cursor must not be repeated",
                    ));
                }
                query.cursor = Some(value.into_owned());
            }
            _ => {}
        }
    }
    Ok(query)
}

#[derive(Debug, PartialEq, Eq)]
enum ScimPagination {
    Index { start_index: i64, count: i64 },
    Cursor { encoded: Option<String>, count: i64 },
}

fn select_scim_pagination(query: &ScimListQuery) -> Result<ScimPagination, HttpResponse> {
    if let Some(cursor) = &query.cursor {
        if query.start_index.is_some() {
            return Err(scim_error(
                StatusCode::BAD_REQUEST,
                "invalidValue",
                "startIndex and cursor cannot be combined",
            ));
        }
        let count = query.count.unwrap_or(SCIM_DEFAULT_PAGE_SIZE).max(0);
        if count > SCIM_MAX_PAGE_SIZE {
            return Err(scim_error(
                StatusCode::BAD_REQUEST,
                "invalidCount",
                "count exceeds the maximum cursor page size",
            ));
        }
        return Ok(ScimPagination::Cursor {
            encoded: (!cursor.is_empty()).then(|| cursor.clone()),
            count,
        });
    }
    Ok(ScimPagination::Index {
        start_index: query.start_index.unwrap_or(1).max(1),
        count: query
            .count
            .unwrap_or(SCIM_DEFAULT_PAGE_SIZE)
            .clamp(0, SCIM_MAX_PAGE_SIZE),
    })
}

pub(crate) async fn scim_service_provider_config(
    endpoint: Data<ScimEndpoint>,
    req: HttpRequest,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&endpoint, &req, ScimRequiredScope::Read).await {
        return response;
    }
    scim_service_provider_config_response()
}

fn scim_service_provider_config_response() -> HttpResponse {
    json_response(scim_base(json!({
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
        "securityEvents": {
            "asyncRequest": "none",
            "eventUris": []
        },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "Bearer",
            "description": "Database-backed bearer credential with legacy deployment-token fallback.",
            "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
            "primary": true
        }]
    })))
}

pub(crate) async fn scim_schemas(endpoint: Data<ScimEndpoint>, req: HttpRequest) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&endpoint, &req, ScimRequiredScope::Read).await {
        return response;
    }
    scim_schemas_response()
}

fn scim_schemas_response() -> HttpResponse {
    json_response(scim_base(json!({
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": 1,
        "startIndex": 1,
        "itemsPerPage": 1,
        "Resources": [scim_user_schema()]
    })))
}

pub(crate) async fn scim_resource_types(
    endpoint: Data<ScimEndpoint>,
    req: HttpRequest,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&endpoint, &req, ScimRequiredScope::Read).await {
        return response;
    }
    scim_resource_types_response()
}

fn scim_resource_types_response() -> HttpResponse {
    json_response(scim_base(json!({
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
    })))
}

pub(crate) async fn scim_list_users(
    endpoint: Data<ScimEndpoint>,
    req: HttpRequest,
) -> HttpResponse {
    let credential = match require_scim_bearer(&endpoint, &req, ScimRequiredScope::Read).await {
        Ok(credential) => credential,
        Err(response) => return response,
    };
    let query = match parse_scim_list_query(req.query_string()) {
        Ok(query) => query,
        Err(response) => return response,
    };
    scim_list_users_authorized(endpoint, query, credential).await
}

#[cfg(test)]
async fn scim_list_users_with_query(
    endpoint: Data<ScimEndpoint>,
    req: HttpRequest,
    Query(query): Query<ScimListQuery>,
) -> HttpResponse {
    let credential = match require_scim_bearer(&endpoint, &req, ScimRequiredScope::Read).await {
        Ok(credential) => credential,
        Err(response) => return response,
    };
    scim_list_users_authorized(endpoint, query, credential).await
}

async fn scim_list_users_authorized(
    endpoint: Data<ScimEndpoint>,
    query: ScimListQuery,
    credential: ScimCredential,
) -> HttpResponse {
    let pagination = match select_scim_pagination(&query) {
        Ok(pagination) => pagination,
        Err(response) => return response,
    };
    let email_filter = match normalize_scim_user_filter(query.filter.as_deref()) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let cursor_position = match &pagination {
        ScimPagination::Cursor {
            encoded: Some(encoded),
            count,
        } => match decode_scim_cursor(
            &endpoint.config.cursor_key,
            encoded,
            &credential,
            query.filter.as_deref(),
            *count,
            Utc::now(),
        ) {
            Ok(position) => Some(position),
            Err(error) => return scim_cursor_error_response(error),
        },
        _ => None,
    };
    let tenant = default_tenant_context();
    let (limit, offset) = match &pagination {
        ScimPagination::Index { start_index, count } => (*count, start_index.saturating_sub(1)),
        ScimPagination::Cursor { count: 0, .. } => (0, 0),
        ScimPagination::Cursor { count, .. } => (count.saturating_add(1), 0),
    };
    let page = match endpoint
        .service
        .list_users(
            tenant
                .as_identity_context()
                .expect("default tenant IDs are valid"),
            email_filter,
            cursor_position.map(|position| (position.last_created_at, position.last_id)),
            limit,
            offset,
        )
        .await
    {
        Ok(page) => page,
        Err(error) => {
            tracing::warn!(%error, "failed to load SCIM users");
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            );
        }
    };
    let total = page.total;
    let mut rows = page.users;
    match pagination {
        ScimPagination::Index { start_index, .. } => {
            scim_list_users_response(total, start_index, rows)
        }
        ScimPagination::Cursor { count, .. } => {
            let has_more = rows.len() > count as usize;
            if has_more {
                rows.truncate(count as usize);
            }
            let next_cursor = if has_more {
                let Some(last) = rows.last() else {
                    tracing::warn!("SCIM cursor query reported more rows without a page marker");
                    return scim_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "backend unavailable",
                    );
                };
                match encode_scim_cursor(
                    &endpoint.config.cursor_key,
                    &ScimCursorContext {
                        credential: &credential,
                        filter: query.filter.as_deref(),
                        count,
                        last_created_at: last.created_at,
                        last_id: last.id(),
                    },
                    Utc::now(),
                ) {
                    Ok(cursor) => Some(cursor),
                    Err(error) => {
                        tracing::warn!(%error, "failed to encode SCIM cursor");
                        return scim_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "server_error",
                            "backend unavailable",
                        );
                    }
                }
            } else {
                None
            };
            scim_cursor_list_users_response(total, rows, next_cursor)
        }
    }
}

fn scim_cursor_error_response(error: ScimCursorError) -> HttpResponse {
    match error {
        ScimCursorError::Invalid => {
            scim_error(StatusCode::BAD_REQUEST, "invalidCursor", "invalid cursor")
        }
        ScimCursorError::Expired => {
            scim_error(StatusCode::BAD_REQUEST, "expiredCursor", "cursor expired")
        }
        ScimCursorError::InvalidCount => scim_error(
            StatusCode::BAD_REQUEST,
            "invalidCount",
            "count does not match cursor",
        ),
    }
}

fn scim_list_users_response(
    total: i64,
    start_index: i64,
    rows: Vec<PublicAccount>,
) -> HttpResponse {
    json_response(scim_base(json!({
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": rows.len(),
        "Resources": rows.into_iter().map(scim_user_json).collect::<Vec<_>>()
    })))
}

fn scim_cursor_list_users_response(
    total: i64,
    rows: Vec<PublicAccount>,
    next_cursor: Option<String>,
) -> HttpResponse {
    let mut body = scim_base(json!({
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "itemsPerPage": rows.len(),
        "Resources": rows.into_iter().map(scim_user_json).collect::<Vec<_>>()
    }));
    if let Some(next_cursor) = next_cursor {
        body["nextCursor"] = json!(next_cursor);
    }
    json_response(body)
}

fn scim_create_user_response(user: PublicAccount) -> HttpResponse {
    json_response_status(StatusCode::CREATED, scim_user_json(user))
}

fn scim_uniqueness_conflict_response() -> HttpResponse {
    scim_error(
        StatusCode::CONFLICT,
        "uniqueness",
        "userName or email already exists",
    )
}

pub(crate) async fn scim_create_user(
    endpoint: Data<ScimEndpoint>,
    req: HttpRequest,
    Json(payload): Json<ScimUserRequest>,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&endpoint, &req, ScimRequiredScope::Write).await {
        return response;
    }
    let input = match normalize_scim_user_payload(payload, true) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let password_hash = match hash_password(&random_urlsafe_token()) {
        Ok(hash) => hash,
        Err(error) => {
            tracing::warn!(%error, "failed to hash random SCIM bootstrap password");
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            );
        }
    };
    let password_hash = match nazo_identity::ports::PasswordHashInput::new(password_hash) {
        Ok(hash) => hash,
        Err(error) => {
            tracing::error!(%error, "generated SCIM password hash is invalid");
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            );
        }
    };
    let tenant = default_tenant_context();
    let row = endpoint
        .service
        .create_user(
            tenant
                .as_identity_context()
                .expect("default tenant IDs are valid"),
            input,
            password_hash,
        )
        .await;
    match row {
        Ok(user) => scim_create_user_response(user),
        Err(nazo_identity::ports::RepositoryError::Conflict) => scim_uniqueness_conflict_response(),
        Err(error) => {
            tracing::warn!(%error, "failed to create SCIM user");
            scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            )
        }
    }
}

pub(crate) async fn scim_get_user(
    endpoint: Data<ScimEndpoint>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&endpoint, &req, ScimRequiredScope::Read).await {
        return response;
    }
    match load_scim_user(&endpoint, path.into_inner()).await {
        Ok(Some(user)) => json_response(scim_user_json(user)),
        Ok(None) => scim_user_not_found_response(),
        Err(response) => response,
    }
}

pub(crate) async fn scim_replace_user(
    endpoint: Data<ScimEndpoint>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<ScimUserRequest>,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&endpoint, &req, ScimRequiredScope::Write).await {
        return response;
    }
    let user_id = path.into_inner();
    let input = match normalize_scim_user_payload(payload, true) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let tenant = default_tenant_context();
    let user_id = match nazo_identity::UserId::new(user_id) {
        Ok(id) => id,
        Err(_) => return scim_user_not_found_response(),
    };
    let updated = endpoint
        .service
        .replace_user(
            tenant
                .as_identity_context()
                .expect("default tenant IDs are valid"),
            user_id,
            input,
        )
        .await;
    match updated {
        Ok(user) => json_response(scim_user_json(user)),
        Err(nazo_identity::ports::RepositoryError::NotFound) => scim_user_not_found_response(),
        Err(nazo_identity::ports::RepositoryError::Conflict) => scim_uniqueness_conflict_response(),
        Err(error) => {
            tracing::warn!(%error, "failed to replace SCIM user");
            scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            )
        }
    }
}

pub(crate) async fn scim_patch_user(
    endpoint: Data<ScimEndpoint>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<ScimPatchRequest>,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&endpoint, &req, ScimRequiredScope::Write).await {
        return response;
    }
    if !payload.schemas.is_empty()
        && !payload
            .schemas
            .iter()
            .any(|schema| schema == SCIM_PATCH_SCHEMA)
    {
        return scim_error(
            StatusCode::BAD_REQUEST,
            "invalidSyntax",
            "unsupported PATCH schema",
        );
    }
    let patch = match normalize_patch(payload.operations) {
        Ok(patch) => patch,
        Err(response) => return response,
    };
    let user_id = path.into_inner();
    let tenant = default_tenant_context();
    let user_id = match nazo_identity::UserId::new(user_id) {
        Ok(id) => id,
        Err(_) => return scim_user_not_found_response(),
    };
    let updated = endpoint
        .service
        .patch_user(
            tenant
                .as_identity_context()
                .expect("default tenant IDs are valid"),
            user_id,
            patch,
        )
        .await;
    match updated {
        Ok(user) => json_response(scim_user_json(user)),
        Err(nazo_identity::ports::RepositoryError::NotFound) => scim_user_not_found_response(),
        Err(nazo_identity::ports::RepositoryError::Conflict) => scim_uniqueness_conflict_response(),
        Err(error) => {
            tracing::warn!(%error, "failed to patch SCIM user");
            scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            )
        }
    }
}

pub(crate) async fn scim_delete_user(
    endpoint: Data<ScimEndpoint>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&endpoint, &req, ScimRequiredScope::Write).await {
        return response;
    }
    let tenant = default_tenant_context();
    let user_id = path.into_inner();
    let user_id = match nazo_identity::UserId::new(user_id) {
        Ok(id) => id,
        Err(_) => return scim_user_not_found_response(),
    };
    match endpoint
        .service
        .deactivate_user(
            tenant
                .as_identity_context()
                .expect("default tenant IDs are valid"),
            user_id,
        )
        .await
    {
        Ok(deleted) => scim_delete_user_response(usize::from(deleted)),
        Err(error) => {
            tracing::warn!(%error, "failed to delete SCIM user");
            scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            )
        }
    }
}

fn scim_user_not_found_response() -> HttpResponse {
    scim_error(StatusCode::NOT_FOUND, "notFound", "user not found")
}

fn scim_delete_user_response(updated_count: usize) -> HttpResponse {
    if updated_count == 0 {
        return scim_user_not_found_response();
    }
    empty_response(StatusCode::NO_CONTENT)
}

async fn load_scim_user(
    endpoint: &ScimEndpoint,
    user_id: Uuid,
) -> Result<Option<PublicAccount>, HttpResponse> {
    let tenant = default_tenant_context();
    let user_id = match nazo_identity::UserId::new(user_id) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };
    endpoint
        .service
        .user(
            tenant
                .as_identity_context()
                .expect("default tenant IDs are valid"),
            user_id,
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to load SCIM user");
            scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            )
        })
}

#[cfg(test)]
#[path = "../../tests/in_source/src/http/tests/scim.rs"]
mod tests;
