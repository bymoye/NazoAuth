//! 管理端客户端更新端点。
use super::{AdminClientConfig, ServerAdminClientService};
use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::blake3_hex;
use crate::http::client_ip::client_ip_with_config;
use crate::http::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};
use crate::http::views::client_json;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use nazo_auth::{AdminClientError, PatchClientRequest};
use nazo_http_actix::{csrf_error, has_valid_csrf_token_for_cookies};
use nazo_http_actix::{json_response, oauth_error};
use serde_json::json;

pub(crate) async fn admin_patch_client(
    admin_sessions: Data<AdminSessionHandles>,
    service: Data<ServerAdminClientService>,
    config: Data<AdminClientConfig>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
    Json(payload): Json<PatchClientRequest>,
) -> HttpResponse {
    let client_id = path.into_inner();
    let session_http = admin_sessions.http_config();
    if !has_valid_csrf_token_for_cookies(
        &req,
        None,
        session_http.session_cookie_name(),
        session_http.csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    if let Err(response) = require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        return response;
    }
    match service.update(&client_id, payload).await {
        Ok(client) => {
            audit_event(
                "client_updated",
                audit_fields(&[
                    ("client_id", json!(client.client_id)),
                    (
                        "source_ip_hash",
                        json!(blake3_hex(&client_ip_with_config(&req, config.client_ip()))),
                    ),
                ]),
            );
            json_response(client_json(client))
        }
        Err(AdminClientError::NotFound) => {
            oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该客户端.")
        }
        Err(AdminClientError::InvalidRequest(message)) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("客户端更新失败: {message}"),
        ),
        Err(AdminClientError::Lookup(error)) => {
            tracing::warn!(%error, "failed to query oauth client for admin update");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            )
        }
        Err(error) => {
            tracing::warn!(%error, "failed to update oauth client");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端更新失败.",
            )
        }
    }
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/admin/clients/tests/update.rs"]
mod tests;
