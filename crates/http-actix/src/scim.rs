use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Data, Json, Path},
};
use chrono::Utc;
use nazo_identity::{
    TenantContext, UserId,
    ports::{PasswordHashInput, RepositoryError},
    scim::{
        ScimCursorContext, ScimCursorError, ScimCursorSubject, ScimListRequest, ScimPagination,
        ScimPatchRequest, ScimRequiredScope, ScimService, ScimUserRequest,
        build_scim_cursor_plaintext, decode_scim_cursor_envelope, decode_scim_cursor_plaintext,
        encode_scim_cursor_envelope, normalize_patch, normalize_scim_user_filter,
        normalize_scim_user_payload, parse_scim_list_query, scim_cursor_list_document,
        scim_error_document, scim_index_list_document, scim_resource_types_document,
        scim_schemas_document, scim_service_provider_config_document_with_events,
        scim_user_document, select_scim_pagination, validate_patch_schema,
    },
};
use nazo_scim_events::{
    EventPollerPort, EventReceiver, MutationContext, PollRequest, ValidatedPollRequest,
};
use serde_json::json;

use crate::{empty_response, json_response, json_response_status};

pub type ScimFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug)]
pub struct ScimAuthorizedRequest {
    pub tenant: TenantContext,
    pub cursor_subject: ScimCursorSubject,
    pub event_receiver: Option<EventReceiver>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScimAuthorizationError {
    Disabled,
    MissingBearer,
    InvalidBearer,
    InsufficientScope,
    TenantMismatch,
    EventReceiverNotConfigured,
    BackendUnavailable,
}

pub trait ScimRequestAuthorizer: Send + Sync {
    fn authorize<'a>(
        &'a self,
        request: &'a HttpRequest,
        required_scope: ScimRequiredScope,
    ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>>;

    fn security_events_enabled(&self) -> bool {
        false
    }

    fn security_event_delivery_enabled(&self) -> bool {
        self.security_events_enabled()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScimDependencyError {
    Unavailable,
}

pub trait ScimCursorProtector: Send + Sync {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, ScimDependencyError>;
    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, ScimDependencyError>;
}

pub trait ScimBootstrapPasswordProvider: Send + Sync {
    fn password_hash(&self) -> ScimFuture<'_, Result<PasswordHashInput, ScimDependencyError>>;
}

#[derive(Clone)]
pub struct ScimEndpoint {
    service: ScimService,
    authorizer: Arc<dyn ScimRequestAuthorizer>,
    cursors: Arc<dyn ScimCursorProtector>,
    passwords: Arc<dyn ScimBootstrapPasswordProvider>,
    events: Option<Arc<dyn EventPollerPort>>,
}

impl ScimEndpoint {
    pub fn new(
        service: ScimService,
        authorizer: Arc<dyn ScimRequestAuthorizer>,
        cursors: Arc<dyn ScimCursorProtector>,
        passwords: Arc<dyn ScimBootstrapPasswordProvider>,
    ) -> Self {
        Self {
            service,
            authorizer,
            cursors,
            passwords,
            events: None,
        }
    }

    #[must_use]
    pub fn with_security_events(mut self, events: Arc<dyn EventPollerPort>) -> Self {
        self.events = Some(events);
        self
    }

    fn security_events_enabled(&self) -> bool {
        self.events.is_some() && self.authorizer.security_events_enabled()
    }

    fn security_event_delivery_enabled(&self) -> bool {
        self.events.is_some() && self.authorizer.security_event_delivery_enabled()
    }
}

pub async fn scim_service_provider_config(
    endpoint: Data<ScimEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    if let Err(error) = authorize(&endpoint, &request, ScimRequiredScope::Read).await {
        return authorization_error(error);
    }
    json_response(scim_service_provider_config_document_with_events(
        endpoint.security_events_enabled(),
    ))
}

pub async fn scim_poll_security_events(
    endpoint: Data<ScimEndpoint>,
    request: HttpRequest,
    Json(payload): Json<PollRequest>,
) -> HttpResponse {
    if !endpoint.security_event_delivery_enabled() {
        return authorization_error(ScimAuthorizationError::Disabled);
    }
    let authorized = match authorize(&endpoint, &request, ScimRequiredScope::Events).await {
        Ok(authorized) => authorized,
        Err(error) => return authorization_error(error),
    };
    let Some(receiver) = authorized.event_receiver else {
        return authorization_error(ScimAuthorizationError::EventReceiverNotConfigured);
    };
    let has_content_language = request
        .headers()
        .get(header::CONTENT_LANGUAGE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.trim().is_empty() && value.len() <= 128);
    if !payload.set_errors.is_empty() && !has_content_language {
        return empty_response(StatusCode::BAD_REQUEST);
    }
    let validated = match payload.validate() {
        Ok(validated) => validated,
        Err(_) => return empty_response(StatusCode::BAD_REQUEST),
    };
    let Some(events) = endpoint.events.as_ref() else {
        return backend_unavailable();
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut current = validated;
    loop {
        let response = match events.poll(&receiver, &current).await {
            Ok(response) => response,
            Err(_) => return backend_unavailable(),
        };
        if current.return_immediately
            || !response.sets.is_empty()
            || response.more_available
            || tokio::time::Instant::now() >= deadline
        {
            return json_response(json!({
                "sets": response.sets,
                "moreAvailable": response.more_available,
            }));
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        current = ValidatedPollRequest {
            max_events: current.max_events,
            return_immediately: current.return_immediately,
            ack: Vec::new(),
            set_errors: Default::default(),
        };
    }
}

pub async fn scim_schemas(endpoint: Data<ScimEndpoint>, request: HttpRequest) -> HttpResponse {
    if let Err(error) = authorize(&endpoint, &request, ScimRequiredScope::Read).await {
        return authorization_error(error);
    }
    json_response(scim_schemas_document())
}

pub async fn scim_resource_types(
    endpoint: Data<ScimEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    if let Err(error) = authorize(&endpoint, &request, ScimRequiredScope::Read).await {
        return authorization_error(error);
    }
    json_response(scim_resource_types_document())
}

pub async fn scim_list_users(endpoint: Data<ScimEndpoint>, request: HttpRequest) -> HttpResponse {
    let credential = match authorize(&endpoint, &request, ScimRequiredScope::Read).await {
        Ok(credential) => credential,
        Err(error) => return authorization_error(error),
    };
    let query = match parse_scim_list_query(request.query_string()) {
        Ok(query) => query,
        Err(error) => return core_error(StatusCode::BAD_REQUEST, &error),
    };
    list_users(&endpoint, query, credential).await
}

async fn list_users(
    endpoint: &ScimEndpoint,
    query: ScimListRequest,
    credential: ScimAuthorizedRequest,
) -> HttpResponse {
    let pagination = match select_scim_pagination(&query) {
        Ok(pagination) => pagination,
        Err(error) => return core_error(StatusCode::BAD_REQUEST, &error),
    };
    let email_filter = match normalize_scim_user_filter(query.filter.as_deref()) {
        Ok(filter) => filter,
        Err(error) => return core_error(StatusCode::BAD_REQUEST, &error),
    };
    let cursor_position = match &pagination {
        ScimPagination::Cursor {
            encoded: Some(encoded),
            count,
        } => match decode_cursor(
            endpoint,
            encoded,
            &credential.cursor_subject,
            query.filter.as_deref(),
            *count,
        ) {
            Ok(position) => Some(position),
            Err(error) => return cursor_error(error),
        },
        _ => None,
    };
    let (limit, offset) = pagination.repository_window();
    let page = match endpoint
        .service
        .list_users(
            credential.tenant,
            email_filter,
            cursor_position.map(|position| (position.last_created_at, position.last_id)),
            limit,
            offset,
        )
        .await
    {
        Ok(page) => page,
        Err(error) => return repository_error("load SCIM users", error),
    };
    let total = page.total;
    let mut users = page.users;
    match pagination {
        ScimPagination::Index { start_index, .. } => {
            json_response(scim_index_list_document(total, start_index, &users))
        }
        ScimPagination::Cursor { count, .. } => {
            let has_more = users.len() > count as usize;
            if has_more {
                users.truncate(count as usize);
            }
            let next_cursor = if has_more {
                let Some(last) = users.last() else {
                    return backend_unavailable();
                };
                match encode_cursor(
                    endpoint,
                    ScimCursorContext {
                        subject: &credential.cursor_subject,
                        filter: query.filter.as_deref(),
                        count,
                        last_created_at: last.created_at,
                        last_id: last.id(),
                    },
                ) {
                    Ok(cursor) => Some(cursor),
                    Err(ScimDependencyError::Unavailable) => return backend_unavailable(),
                }
            } else {
                None
            };
            json_response(scim_cursor_list_document(
                total,
                &users,
                next_cursor.as_deref(),
            ))
        }
    }
}

pub async fn scim_create_user(
    endpoint: Data<ScimEndpoint>,
    request: HttpRequest,
    Json(payload): Json<ScimUserRequest>,
) -> HttpResponse {
    let credential = match authorize(&endpoint, &request, ScimRequiredScope::Write).await {
        Ok(credential) => credential,
        Err(error) => return authorization_error(error),
    };
    let input = match normalize_scim_user_payload(payload, true) {
        Ok(input) => input,
        Err(error) => return core_error(StatusCode::BAD_REQUEST, &error),
    };
    let password_hash = match endpoint.passwords.password_hash().await {
        Ok(password_hash) => password_hash,
        Err(ScimDependencyError::Unavailable) => return backend_unavailable(),
    };
    match endpoint
        .service
        .create_user_with_mutation(
            credential.tenant,
            input,
            password_hash,
            mutation_context(&endpoint),
        )
        .await
    {
        Ok(user) => json_response_status(StatusCode::CREATED, scim_user_document(&user)),
        Err(RepositoryError::Conflict) => uniqueness_conflict(),
        Err(error) => repository_error("create SCIM user", error),
    }
}

pub async fn scim_get_user(
    endpoint: Data<ScimEndpoint>,
    request: HttpRequest,
    path: Path<uuid::Uuid>,
) -> HttpResponse {
    let credential = match authorize(&endpoint, &request, ScimRequiredScope::Read).await {
        Ok(credential) => credential,
        Err(error) => return authorization_error(error),
    };
    let Some(user_id) = user_id(path.into_inner()) else {
        return user_not_found();
    };
    match endpoint.service.user(credential.tenant, user_id).await {
        Ok(Some(user)) => json_response(scim_user_document(&user)),
        Ok(None) => user_not_found(),
        Err(error) => repository_error("load SCIM user", error),
    }
}

pub async fn scim_replace_user(
    endpoint: Data<ScimEndpoint>,
    request: HttpRequest,
    path: Path<uuid::Uuid>,
    Json(payload): Json<ScimUserRequest>,
) -> HttpResponse {
    let credential = match authorize(&endpoint, &request, ScimRequiredScope::Write).await {
        Ok(credential) => credential,
        Err(error) => return authorization_error(error),
    };
    let input = match normalize_scim_user_payload(payload, true) {
        Ok(input) => input,
        Err(error) => return core_error(StatusCode::BAD_REQUEST, &error),
    };
    let Some(user_id) = user_id(path.into_inner()) else {
        return user_not_found();
    };
    match endpoint
        .service
        .replace_user_with_mutation(
            credential.tenant,
            user_id,
            input,
            mutation_context(&endpoint),
        )
        .await
    {
        Ok(user) => json_response(scim_user_document(&user)),
        Err(RepositoryError::NotFound) => user_not_found(),
        Err(RepositoryError::Conflict) => uniqueness_conflict(),
        Err(error) => repository_error("replace SCIM user", error),
    }
}

pub async fn scim_patch_user(
    endpoint: Data<ScimEndpoint>,
    request: HttpRequest,
    path: Path<uuid::Uuid>,
    Json(payload): Json<ScimPatchRequest>,
) -> HttpResponse {
    let credential = match authorize(&endpoint, &request, ScimRequiredScope::Write).await {
        Ok(credential) => credential,
        Err(error) => return authorization_error(error),
    };
    if let Err(error) = validate_patch_schema(&payload.schemas) {
        return core_error(StatusCode::BAD_REQUEST, &error);
    }
    let patch = match normalize_patch(payload.operations) {
        Ok(patch) => patch,
        Err(error) => return core_error(StatusCode::BAD_REQUEST, &error),
    };
    let Some(user_id) = user_id(path.into_inner()) else {
        return user_not_found();
    };
    match endpoint
        .service
        .patch_user_with_mutation(
            credential.tenant,
            user_id,
            patch,
            mutation_context(&endpoint),
        )
        .await
    {
        Ok(user) => json_response(scim_user_document(&user)),
        Err(RepositoryError::NotFound) => user_not_found(),
        Err(RepositoryError::Conflict) => uniqueness_conflict(),
        Err(error) => repository_error("patch SCIM user", error),
    }
}

pub async fn scim_delete_user(
    endpoint: Data<ScimEndpoint>,
    request: HttpRequest,
    path: Path<uuid::Uuid>,
) -> HttpResponse {
    let credential = match authorize(&endpoint, &request, ScimRequiredScope::Write).await {
        Ok(credential) => credential,
        Err(error) => return authorization_error(error),
    };
    let Some(user_id) = user_id(path.into_inner()) else {
        return user_not_found();
    };
    match endpoint
        .service
        .deactivate_user_with_mutation(credential.tenant, user_id, mutation_context(&endpoint))
        .await
    {
        Ok(true) => empty_response(StatusCode::NO_CONTENT),
        Ok(false) => user_not_found(),
        Err(error) => repository_error("delete SCIM user", error),
    }
}

fn mutation_context(endpoint: &ScimEndpoint) -> MutationContext {
    if endpoint.security_events_enabled() {
        MutationContext::enabled()
    } else {
        MutationContext::disabled()
    }
}

async fn authorize(
    endpoint: &ScimEndpoint,
    request: &HttpRequest,
    required_scope: ScimRequiredScope,
) -> Result<ScimAuthorizedRequest, ScimAuthorizationError> {
    endpoint.authorizer.authorize(request, required_scope).await
}

fn authorization_error(error: ScimAuthorizationError) -> HttpResponse {
    let (status, scim_type, detail) = match error {
        ScimAuthorizationError::Disabled => {
            (StatusCode::NOT_FOUND, "not_found", "SCIM is disabled")
        }
        ScimAuthorizationError::MissingBearer => (
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing bearer token",
        ),
        ScimAuthorizationError::InvalidBearer => (
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid bearer token",
        ),
        ScimAuthorizationError::InsufficientScope => (
            StatusCode::FORBIDDEN,
            "forbidden",
            "SCIM token lacks the required scope",
        ),
        ScimAuthorizationError::TenantMismatch => (
            StatusCode::FORBIDDEN,
            "forbidden",
            "SCIM token is not valid for this tenant",
        ),
        ScimAuthorizationError::EventReceiverNotConfigured => (
            StatusCode::FORBIDDEN,
            "forbidden",
            "SCIM event receiver audience is not configured",
        ),
        ScimAuthorizationError::BackendUnavailable => return backend_unavailable(),
    };
    let mut response = scim_error(status, scim_type, detail);
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer"),
        );
    }
    response
}

fn encode_cursor(
    endpoint: &ScimEndpoint,
    context: ScimCursorContext<'_>,
) -> Result<String, ScimDependencyError> {
    let plaintext = build_scim_cursor_plaintext(&context, Utc::now())
        .map_err(|_| ScimDependencyError::Unavailable)?;
    endpoint
        .cursors
        .protect(&plaintext)
        .map(|protected| encode_scim_cursor_envelope(&protected))
}

fn decode_cursor(
    endpoint: &ScimEndpoint,
    encoded: &str,
    subject: &ScimCursorSubject,
    filter: Option<&str>,
    count: i64,
) -> Result<nazo_identity::scim::ScimCursorPosition, ScimCursorError> {
    let protected = decode_scim_cursor_envelope(encoded)?;
    let plaintext = endpoint
        .cursors
        .unprotect(&protected)
        .map_err(|_| ScimCursorError::Invalid)?;
    decode_scim_cursor_plaintext(&plaintext, subject, filter, count, Utc::now())
}

fn cursor_error(error: ScimCursorError) -> HttpResponse {
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

fn user_id(value: uuid::Uuid) -> Option<UserId> {
    UserId::new(value).ok()
}

fn uniqueness_conflict() -> HttpResponse {
    scim_error(
        StatusCode::CONFLICT,
        "uniqueness",
        "userName or email already exists",
    )
}

fn user_not_found() -> HttpResponse {
    scim_error(StatusCode::NOT_FOUND, "notFound", "user not found")
}

fn backend_unavailable() -> HttpResponse {
    scim_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
}

fn repository_error(operation: &str, error: RepositoryError) -> HttpResponse {
    let _ = (operation, error);
    backend_unavailable()
}

fn core_error(status: StatusCode, error: &nazo_identity::scim::ScimError) -> HttpResponse {
    scim_error(status, error.scim_type, &error.detail)
}

fn scim_error(status: StatusCode, scim_type: &str, detail: &str) -> HttpResponse {
    json_response_status(
        status,
        scim_error_document(status.as_u16(), scim_type, detail),
    )
}
