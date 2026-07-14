//! 管理端用户授权关系接口。
use crate::http::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};
use crate::http::views::pagination;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse};
use nazo_auth::{AdminGrantRepositoryPort, AdminGrantRevokeError, AdminGrantView};
use nazo_http_actix::{csrf_error, has_valid_csrf_token_for_cookies};
use nazo_http_actix::{json_response, oauth_error};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;
// 授权列表与撤销逻辑只依赖授权表和 refresh token 撤销。

pub(crate) async fn admin_grants(
    admin_sessions: Data<AdminSessionHandles>,
    grants: Data<dyn AdminGrantRepositoryPort>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let admin = match require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let (page, page_size, offset) = pagination(&q);
    let page_result = match grants
        .page(
            admin.tenant().tenant_id.as_uuid(),
            i64::from(page_size),
            i64::from(offset),
        )
        .await
    {
        Ok(page) => page,
        Err(error) => {
            tracing::warn!(%error, "failed to load user client grants");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录查询失败.",
            );
        }
    };
    grants_list_response(page, page_size, page_result.total, page_result.grants)
}

fn grants_list_response(
    page: i32,
    page_size: i32,
    total: i64,
    rows: Vec<AdminGrantView>,
) -> HttpResponse {
    let items: Vec<Value> = rows.into_iter().map(grant_json).collect();
    json_response(json!({"total": total, "page": page, "page_size": page_size, "items": items}))
}

fn grant_json(row: AdminGrantView) -> Value {
    json!({
        "user_id": row.user_id,
        "email": row.email,
        "client_id": row.client_id,
        "client_name": row.client_name,
        "last_authorized_at": row.last_authorized_at,
        "authorization_count": row.authorization_count,
        "last_scopes": row.last_scopes,
        "last_authorization_details": row.last_authorization_details
    })
}

#[derive(Deserialize)]
pub(crate) struct GrantRevokeRequest {
    user_id: String,
    client_id: String,
}

pub(crate) async fn admin_revoke_grant(
    admin_sessions: Data<AdminSessionHandles>,
    grants: Data<dyn AdminGrantRepositoryPort>,
    req: HttpRequest,
    Json(payload): Json<GrantRevokeRequest>,
) -> HttpResponse {
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
    let Ok(user_id) = Uuid::parse_str(&payload.user_id) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "user_id 格式无效.",
        );
    };
    let revoked = match grants
        .revoke_by_client_id(
            admin.tenant().tenant_id.as_uuid(),
            user_id,
            &payload.client_id,
        )
        .await
    {
        Ok(result) => result,
        Err(AdminGrantRevokeError::ClientNotFound) => {
            return oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该客户端.");
        }
        Err(AdminGrantRevokeError::ClientLookup(error)) => {
            tracing::warn!(%error, "failed to query oauth client for grant revocation");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
        Err(AdminGrantRevokeError::Revoke(error)) => {
            tracing::warn!(%error, "failed to get database connection for grant revocation");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录撤销失败.",
            );
        }
    };
    grant_revocation_response(revoked.revoked_refresh_tokens, revoked.removed_grants)
}

fn grant_revocation_response(revoked_refresh_tokens: usize, removed_grants: usize) -> HttpResponse {
    json_response(json!({
        "revoked_refresh_tokens": revoked_refresh_tokens,
        "removed_grants": removed_grants
    }))
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/admin/tests/grants.rs"]
mod tests;
