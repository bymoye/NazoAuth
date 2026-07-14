//! 管理端客户端接入申请接口。
use super::clients::ServerAdminClientService;
use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::access_delivery_token;
use crate::adapters::security::blake3_hex;
use crate::http::client_ip::{ClientIpConfig, client_ip_with_config};
use crate::http::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};
use crate::http::views::pagination;
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::http::header::HeaderValue;
use actix_web::web::{Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
use nazo_auth::{AdminClientError, CreateClientRequest};
use nazo_http_actix::{csrf_error, has_valid_csrf_token_for_cookies};
use nazo_http_actix::{json_response, oauth_error};
use nazo_postgres::AccessRequestRepository;
use nazo_valkey::DeliveryStore;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;

pub(crate) struct AdminAccessRequestConfig {
    client_secret_pepper: Box<str>,
    delivery_ttl_seconds: u64,
}

impl AdminAccessRequestConfig {
    pub(crate) fn new(client_secret_pepper: &str, delivery_ttl_seconds: u64) -> Self {
        Self {
            client_secret_pepper: client_secret_pepper.into(),
            delivery_ttl_seconds,
        }
    }
}

type ApprovalDependencies = (
    Data<AccessRequestRepository>,
    Data<DeliveryStore>,
    Data<ServerAdminClientService>,
    Data<AdminAccessRequestConfig>,
    Data<ClientIpConfig>,
);

pub(crate) async fn admin_access_requests(
    admin_sessions: Data<AdminSessionHandles>,
    repository: Data<AccessRequestRepository>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let admin = match require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let (page, page_size, offset) = pagination(&q);
    let status = match parse_access_request_status(&q) {
        Ok(status) => status,
        Err(response) => return response,
    };
    let search = q.get("q").map(String::as_str);
    let result = repository
        .page(
            admin.principal.tenant.tenant_id,
            i64::from(page_size),
            i64::from(offset),
            search,
            status,
        )
        .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(%error, "failed to load access requests");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            );
        }
    };
    access_requests_response(page, page_size, result.total, result.items)
}

fn parse_access_request_status(
    q: &HashMap<String, String>,
) -> Result<Option<nazo_identity::AccessRequestStatus>, HttpResponse> {
    match q
        .get("status")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        Some(value) => value
            .parse::<i16>()
            .ok()
            .and_then(nazo_identity::AccessRequestStatus::from_code)
            .map(Some)
            .ok_or_else(invalid_access_request_status_response),
        None => Ok(None),
    }
}

fn invalid_access_request_status_response() -> HttpResponse {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "status 参数仅支持 0/1/2.",
    )
}

fn client_preparation_error_response(error: AdminClientError) -> HttpResponse {
    match error {
        AdminClientError::InvalidRequest(message) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("客户端创建失败: {message}"),
        ),
        error => {
            tracing::warn!(%error, "failed to prepare oauth client for access request approval");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端创建失败.",
            )
        }
    }
}

fn access_requests_response(
    page: i32,
    page_size: i32,
    total: i64,
    rows: Vec<nazo_identity::AccessRequest>,
) -> HttpResponse {
    let rows = rows
        .into_iter()
        .map(access_request_json)
        .collect::<Vec<_>>();
    json_response(json!({"total": total, "page": page, "page_size": page_size, "items": rows}))
}

pub(crate) async fn admin_approve_access_request(
    admin_sessions: Data<AdminSessionHandles>,
    dependencies: ApprovalDependencies,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<CreateClientRequest>,
) -> HttpResponse {
    let (repository, delivery_store, client_service, config, client_ip_config) = dependencies;
    let request_id = path.into_inner();
    let session_http = admin_sessions.http_config();
    if !has_valid_csrf_token_for_cookies(
        &req,
        None,
        session_http.session_cookie_name(),
        session_http.csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    let admin = match require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let pending_request = match repository
        .by_id(admin.principal.tenant.tenant_id, request_id)
        .await
    {
        Ok(Some(row)) if row.status == nazo_identity::AccessRequestStatus::Pending => row,
        Ok(Some(row)) if row.status == nazo_identity::AccessRequestStatus::Approved => {
            match resume_staged_client_delivery(&delivery_store, &config, &row).await {
                Ok(true) => return json_response(access_request_json(row)),
                Ok(false) => return access_request_already_approved_response(),
                Err(error) => {
                    tracing::warn!(%error, "failed to resume staged client delivery");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "客户端凭据交付恢复失败.",
                    );
                }
            }
        }
        Ok(_) => return access_request_already_approved_response(),
        Err(error) => {
            tracing::warn!(%error, "failed to query pending access request");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            );
        }
    };
    let request_user = pending_request.user_id;
    let request_user_id = request_user.as_uuid();
    let site_name = pending_request.site_name;
    let prepared = match client_service.prepare_registration(payload).await {
        Ok(prepared) => prepared,
        Err(error) => return client_preparation_error_response(error),
    };
    let token = access_delivery_token(&config.client_secret_pepper, request_user_id, request_id);
    let expires_at = Utc::now() + Duration::seconds(config.delivery_ttl_seconds as i64);
    let delivery_payload = json!({
        "delivery_state": "staged",
        "request_id": request_id,
        "user_id": request_user_id,
        "client_id": &prepared.client_id,
        "client_name": &prepared.client_name,
        "client_type": &prepared.client_type,
        "client_secret": prepared.issued_secret.as_deref(),
        "redirect_uris": &prepared.redirect_uris,
        "scopes": &prepared.scopes,
        "grant_types": &prepared.grant_types,
        "token_endpoint_auth_method": &prepared.token_endpoint_auth_method,
        "site_name": site_name,
        "created_at": Utc::now(),
        "expires_at": expires_at
    });
    if let Err(error) = delivery_store
        .store(
            request_user,
            &token,
            &delivery_payload,
            config.delivery_ttl_seconds,
        )
        .await
    {
        tracing::warn!(%error, "failed to persist client delivery payload");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端凭据交付创建失败.",
        );
    }

    let approval = repository
        .approve(
            admin.principal.tenant,
            request_id,
            admin.user_id(),
            &prepared.registration,
            prepared.client_secret_hash.as_deref(),
            prepared.registration_access_token_blake3.as_deref(),
        )
        .await;
    let client = match approval {
        Ok(client) => client,
        Err(error) => {
            if let Err(cleanup_error) = delivery_store.delete(request_user, &token).await {
                tracing::warn!(%cleanup_error, "failed to remove client delivery payload");
            }
            if let Some(response) = access_request_approval_error_response(&error) {
                return response;
            }
            tracing::warn!(%error, "failed to approve access request");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请审批失败.",
            );
        }
    };
    let mut committed_delivery_payload = delivery_payload;
    committed_delivery_payload["delivery_state"] = json!("committed");
    committed_delivery_payload["approved_client_id"] = json!(client.id);
    if let Err(error) = delivery_store
        .store(
            request_user,
            &token,
            &committed_delivery_payload,
            config.delivery_ttl_seconds,
        )
        .await
    {
        tracing::warn!(%error, "failed to activate client delivery payload");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端凭据交付激活失败.",
        );
    }
    audit_event(
        "client_created",
        audit_fields(&[
            ("client_id", json!(client.client_id)),
            ("request_id", json!(request_id)),
            ("admin_user_id", json!(admin.id())),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip_with_config(&req, &client_ip_config))),
            ),
        ]),
    );
    match repository
        .by_id(admin.principal.tenant.tenant_id, request_id)
        .await
    {
        Ok(Some(row)) => json_response(access_request_json(row)),
        Ok(None) => json_response(json!({"id": request_id})),
        Err(error) => {
            tracing::warn!(%error, "failed to load approved access request");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            )
        }
    }
}

async fn resume_staged_client_delivery(
    store: &DeliveryStore,
    config: &AdminAccessRequestConfig,
    request: &nazo_identity::AccessRequest,
) -> anyhow::Result<bool> {
    let Some(approved_client_id) = request.approved_client_id else {
        return Ok(false);
    };
    let user = request.user_id;
    let user_id = user.as_uuid();
    let token = access_delivery_token(&config.client_secret_pepper, user_id, request.id);
    let Some(stored) = DeliveryStore::load(store, user, &token).await? else {
        return Ok(false);
    };
    let mut payload = stored.value().clone();
    if payload["delivery_state"] != "staged"
        || payload["request_id"] != json!(request.id)
        || payload["user_id"] != json!(user_id)
    {
        return Ok(false);
    }
    payload["delivery_state"] = json!("committed");
    payload["approved_client_id"] = json!(approved_client_id);
    store
        .store(user, &token, &payload, config.delivery_ttl_seconds)
        .await?;
    Ok(true)
}

#[derive(Deserialize)]
pub(crate) struct RejectAccessRequest {
    admin_note: String,
}

pub(crate) async fn admin_reject_access_request(
    admin_sessions: Data<AdminSessionHandles>,
    repository: Data<AccessRequestRepository>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<RejectAccessRequest>,
) -> HttpResponse {
    let request_id = path.into_inner();
    let session_http = admin_sessions.http_config();
    if !has_valid_csrf_token_for_cookies(
        &req,
        None,
        session_http.session_cookie_name(),
        session_http.csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    let admin = match require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let updated = match repository
        .reject(
            admin.principal.tenant.tenant_id,
            request_id,
            admin.user_id(),
            payload.admin_note,
        )
        .await
    {
        Ok(()) => true,
        Err(nazo_identity::ports::RepositoryError::Conflict) => false,
        Err(error) => {
            tracing::warn!(%error, "failed to reject access request");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请拒绝失败.",
            );
        }
    };
    if !updated {
        return access_request_already_rejected_response();
    }
    match repository
        .by_id(admin.principal.tenant.tenant_id, request_id)
        .await
    {
        Ok(Some(row)) => json_response(access_request_json(row)),
        Ok(None) => json_response(json!({"id": request_id})),
        Err(error) => {
            tracing::warn!(%error, "failed to load rejected access request");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            )
        }
    }
}

fn access_request_json(row: nazo_identity::AccessRequest) -> Value {
    json!({
        "id": row.id,
        "user_id": row.user_id.as_uuid(),
        "user_email": row.requester_email,
        "site_name": row.site_name,
        "site_url": row.site_url,
        "request_description": row.request_description,
        "status": row.status.code(),
        "admin_note": row.admin_note,
        "approved_client_id": row.approved_client_id,
        "created_at": row.created_at,
        "resolved_at": row.resolved_at
    })
}

fn access_request_already_approved_response() -> HttpResponse {
    oauth_error(
        StatusCode::CONFLICT,
        "invalid_request",
        "该申请已处理,不可重复审批.",
    )
}

fn access_request_approval_error_response(
    error: &nazo_identity::ports::RepositoryError,
) -> Option<HttpResponse> {
    let (mut response, conflict_type) = match error {
        nazo_identity::ports::RepositoryError::AlreadyProcessed => {
            (access_request_already_approved_response(), "request_state")
        }
        nazo_identity::ports::RepositoryError::Conflict => (
            oauth_error(StatusCode::CONFLICT, "invalid_request", "客户端标识已存在."),
            "client_unique",
        ),
        _ => return None,
    };
    response.headers_mut().insert(
        header::HeaderName::from_static("x-nazo-conflict-type"),
        HeaderValue::from_static(conflict_type),
    );
    Some(response)
}

fn access_request_already_rejected_response() -> HttpResponse {
    oauth_error(
        StatusCode::CONFLICT,
        "invalid_request",
        "该申请已处理,不可重复拒绝.",
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/admin/tests/access_requests.rs"]
mod tests;
