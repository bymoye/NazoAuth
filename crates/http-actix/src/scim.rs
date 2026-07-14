use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::StatusCode,
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
        scim_schemas_document, scim_service_provider_config_document, scim_user_document,
        select_scim_pagination, validate_patch_schema,
    },
};

use crate::{empty_response, json_response, json_response_status};

pub type ScimFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug)]
pub struct ScimAuthorizedRequest {
    pub tenant: TenantContext,
    pub cursor_subject: ScimCursorSubject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScimAuthorizationError {
    Disabled,
    MissingBearer,
    InvalidBearer,
    InsufficientScope,
    TenantMismatch,
    BackendUnavailable,
}

pub trait ScimRequestAuthorizer: Send + Sync {
    fn authorize<'a>(
        &'a self,
        request: &'a HttpRequest,
        required_scope: ScimRequiredScope,
    ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>>;
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
        }
    }
}

pub async fn scim_service_provider_config(
    endpoint: Data<ScimEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    if let Err(error) = authorize(&endpoint, &request, ScimRequiredScope::Read).await {
        return authorization_error(error);
    }
    json_response(scim_service_provider_config_document())
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
        .create_user(credential.tenant, input, password_hash)
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
        .replace_user(credential.tenant, user_id, input)
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
        .patch_user(credential.tenant, user_id, patch)
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
        .deactivate_user(credential.tenant, user_id)
        .await
    {
        Ok(true) => empty_response(StatusCode::NO_CONTENT),
        Ok(false) => user_not_found(),
        Err(error) => repository_error("delete SCIM user", error),
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
        ScimAuthorizationError::BackendUnavailable => return backend_unavailable(),
    };
    scim_error(status, scim_type, detail)
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

#[cfg(test)]
mod tests {
    use actix_web::{App, test as actix_test, web};
    use nazo_identity::{
        PublicAccount,
        ports::{
            NewScimUser, RepositoryFuture, ScimCredentialAuditPort, ScimCredentialUse,
            ScimListQuery, ScimRepositoryPort, UserPage,
        },
        scim::{NormalizedScimUser, ScimPatch},
    };
    use serde_json::{Value, json};

    use super::*;

    struct UnusedRepository;

    impl ScimRepositoryPort for UnusedRepository {
        fn list<'a>(&'a self, _query: ScimListQuery) -> RepositoryFuture<'a, UserPage> {
            Box::pin(async { Err(RepositoryError::Unavailable) })
        }

        fn get<'a>(
            &'a self,
            _tenant: TenantContext,
            _user_id: UserId,
        ) -> RepositoryFuture<'a, Option<PublicAccount>> {
            Box::pin(async { Err(RepositoryError::Unavailable) })
        }

        fn create<'a>(&'a self, _user: NewScimUser) -> RepositoryFuture<'a, PublicAccount> {
            Box::pin(async { Err(RepositoryError::Unavailable) })
        }

        fn replace<'a>(
            &'a self,
            _tenant: TenantContext,
            _user_id: UserId,
            _replacement: NormalizedScimUser,
        ) -> RepositoryFuture<'a, PublicAccount> {
            Box::pin(async { Err(RepositoryError::Unavailable) })
        }

        fn patch<'a>(
            &'a self,
            _tenant: TenantContext,
            _user_id: UserId,
            _patch: ScimPatch,
        ) -> RepositoryFuture<'a, PublicAccount> {
            Box::pin(async { Err(RepositoryError::Unavailable) })
        }

        fn deactivate<'a>(
            &'a self,
            _tenant: TenantContext,
            _user_id: UserId,
        ) -> RepositoryFuture<'a, bool> {
            Box::pin(async { Err(RepositoryError::Unavailable) })
        }
    }

    struct UnusedAudit;

    impl ScimCredentialAuditPort for UnusedAudit {
        fn active_credential<'a>(
            &'a self,
            _token_hash: &'a str,
        ) -> RepositoryFuture<'a, Option<nazo_identity::scim::ScimTokenCredential>> {
            Box::pin(async { Err(RepositoryError::Unavailable) })
        }

        fn record_use<'a>(&'a self, _usage: ScimCredentialUse) -> RepositoryFuture<'a, ()> {
            Box::pin(async { Err(RepositoryError::Unavailable) })
        }
    }

    struct AllowRequests;

    impl ScimRequestAuthorizer for AllowRequests {
        fn authorize<'a>(
            &'a self,
            _request: &'a HttpRequest,
            _required_scope: ScimRequiredScope,
        ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>> {
            Box::pin(async {
                let tenant = TenantContext::default_system();
                Ok(ScimAuthorizedRequest {
                    tenant,
                    cursor_subject: ScimCursorSubject {
                        tenant_id: tenant.tenant_id.as_uuid(),
                        actor: "test".to_owned(),
                    },
                })
            })
        }
    }

    struct UnusedCursor;

    impl ScimCursorProtector for UnusedCursor {
        fn protect(&self, _plaintext: &[u8]) -> Result<Vec<u8>, ScimDependencyError> {
            Err(ScimDependencyError::Unavailable)
        }

        fn unprotect(&self, _protected: &[u8]) -> Result<Vec<u8>, ScimDependencyError> {
            Err(ScimDependencyError::Unavailable)
        }
    }

    struct UnusedPassword;

    impl ScimBootstrapPasswordProvider for UnusedPassword {
        fn password_hash(&self) -> ScimFuture<'_, Result<PasswordHashInput, ScimDependencyError>> {
            Box::pin(async { Err(ScimDependencyError::Unavailable) })
        }
    }

    fn endpoint() -> Data<ScimEndpoint> {
        Data::new(ScimEndpoint::new(
            ScimService::new(Arc::new(UnusedRepository), Arc::new(UnusedAudit)),
            Arc::new(AllowRequests),
            Arc::new(UnusedCursor),
            Arc::new(UnusedPassword),
        ))
    }

    #[test]
    fn authorization_errors_preserve_scim_documents() {
        let response = authorization_error(ScimAuthorizationError::Disabled);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn provider_config_is_built_by_identity_core() {
        let document = scim_service_provider_config_document();
        assert_eq!(
            document["pagination"]["cursorTimeout"],
            nazo_identity::scim::SCIM_CURSOR_TIMEOUT_SECONDS
        );
    }

    #[actix_web::test]
    async fn provider_config_handler_preserves_http_contract() {
        let app = actix_test::init_service(App::new().app_data(endpoint()).route(
            "/scim/v2/ServiceProviderConfig",
            web::get().to(scim_service_provider_config),
        ))
        .await;
        let response = actix_test::call_service(
            &app,
            actix_test::TestRequest::get()
                .uri("/scim/v2/ServiceProviderConfig")
                .insert_header(("authorization", "Bearer test"))
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
        let document = actix_test::read_body_json::<Value, _>(response).await;
        assert_eq!(document["id"], "nazo-oauth-scim");
        assert_eq!(document["patch"], json!({"supported": true}));
    }
}
