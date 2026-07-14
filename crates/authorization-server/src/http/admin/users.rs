//! 管理端用户账户接口。
use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::blake3_hex;
use crate::http::client_ip::{ClientIpConfig, client_ip_with_config};
use crate::http::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};
use crate::http::views::admin_user_json;
use crate::http::views::pagination;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{csrf_error, has_valid_csrf_token_for_cookies};
use nazo_http_actix::{json_response, oauth_error};
use nazo_identity::{PublicAccount, ports::AdminUserRepositoryPort};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;
// 只处理用户列表与用户状态更新，不包含客户端或授权关系逻辑。

pub(crate) async fn admin_users(
    admin_sessions: Data<AdminSessionHandles>,
    users: Data<dyn AdminUserRepositoryPort>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let admin = match require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let (page, page_size, offset) = pagination(&q);
    let (total, user_rows) = match users
        .page(admin.tenant().tenant_id, page_size as i64, offset as i64)
        .await
    {
        Ok(page) => (page.total, page.users),
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for user list");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户列表查询失败.",
            );
        }
    };
    admin_users_list_response(page, page_size, total, user_rows)
}

fn admin_users_list_response(
    page: i32,
    page_size: i32,
    total: i64,
    user_rows: Vec<PublicAccount>,
) -> HttpResponse {
    let items: Vec<Value> = user_rows.into_iter().map(admin_user_json).collect();
    json_response(json!({"total": total, "page": page, "page_size": page_size, "items": items}))
}

#[derive(Deserialize)]
pub(crate) struct PatchUserRequest {
    role: Option<String>,
    admin_level: Option<i32>,
    is_active: Option<bool>,
}

pub(crate) async fn admin_patch_user(
    admin_sessions: Data<AdminSessionHandles>,
    users: Data<dyn AdminUserRepositoryPort>,
    client_ip_config: Data<ClientIpConfig>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<PatchUserRequest>,
) -> HttpResponse {
    let user_id = path.into_inner();
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
    if let Some(response) = patch_user_validation_error(&payload) {
        return response;
    }
    let user_id = match nazo_identity::UserId::new(user_id) {
        Ok(user_id) => user_id,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "user_id 格式无效.",
            );
        }
    };
    let actor_id = match nazo_identity::UserId::new(admin.id()) {
        Ok(actor_id) => actor_id,
        Err(error) => {
            tracing::error!(%error, "authenticated administrator has an invalid user id");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "管理员身份无效.",
            );
        }
    };
    let updated = match users
        .update_authorized(
            admin.tenant().tenant_id,
            actor_id,
            user_id,
            nazo_identity::ports::AdminUserUpdate {
                role: payload.role,
                admin_level: payload.admin_level,
                active: payload.is_active,
            },
        )
        .await
    {
        Ok(updated) => updated,
        Err(nazo_identity::ports::RepositoryError::Conflict) => {
            return oauth_error(
                StatusCode::CONFLICT,
                "invalid_request",
                "用户状态发生并发冲突，请重试.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to update user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户更新失败.",
            );
        }
    };
    match updated {
        nazo_identity::AdminUserUpdateOutcome::Updated(user) => {
            audit_event(
                "admin_user_updated",
                audit_fields(&[
                    ("user_id", json!(user.id())),
                    (
                        "source_ip_hash",
                        json!(blake3_hex(&client_ip_with_config(&req, &client_ip_config))),
                    ),
                ]),
            );
            json_response(admin_user_json(*user))
        }
        nazo_identity::AdminUserUpdateOutcome::TargetNotFound => {
            oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该用户.")
        }
        nazo_identity::AdminUserUpdateOutcome::Denied(
            nazo_identity::AdminPolicyError::InvalidRoleLevel,
        ) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "role 与 admin_level 组合无效.",
        ),
        nazo_identity::AdminUserUpdateOutcome::Denied(_) => {
            oauth_error(StatusCode::FORBIDDEN, "access_denied", "不允许修改该用户.")
        }
    }
}

fn patch_user_validation_error(payload: &PatchUserRequest) -> Option<HttpResponse> {
    if payload.admin_level.is_some_and(|level| level < 0) {
        return Some(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "admin_level 不能为负数.",
        ));
    }
    if let Some(role) = payload.role.as_deref() {
        match role {
            "admin" | "user" => {}
            _ => {
                return Some(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "用户角色无效.",
                ));
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/admin/tests/users.rs"]
mod tests;
