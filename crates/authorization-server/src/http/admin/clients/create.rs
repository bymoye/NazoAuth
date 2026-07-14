//! 管理端客户端创建端点。
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
use nazo_auth::{AdminClientError, CreateClientRequest};
use nazo_http_actix::{csrf_error, has_valid_csrf_token_for_cookies};
use nazo_http_actix::{json_response_status, oauth_error};
use serde_json::json;

pub(crate) async fn admin_create_client(
    admin_sessions: Data<AdminSessionHandles>,
    service: Data<ServerAdminClientService>,
    config: Data<AdminClientConfig>,
    req: HttpRequest,
    Json(payload): Json<CreateClientRequest>,
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
    if let Err(response) = require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        return response;
    }

    match service.create(payload).await {
        Ok(created) => {
            audit_event(
                "client_created",
                audit_fields(&[
                    ("client_id", json!(created.client.client_id)),
                    (
                        "source_ip_hash",
                        json!(blake3_hex(&client_ip_with_config(&req, config.client_ip()))),
                    ),
                ]),
            );
            let mut body = client_json(created.client);
            if let Some(secret) = created.issued_secret {
                body["client_secret"] = json!(secret);
            }
            json_response_status(StatusCode::CREATED, body)
        }
        Err(error) => create_error_response(error),
    }
}

fn create_error_response(error: AdminClientError) -> HttpResponse {
    match error {
        AdminClientError::InvalidRequest(message) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("客户端创建失败: {message}"),
        ),
        error => {
            tracing::warn!(%error, "failed to create oauth client");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端创建失败.",
            )
        }
    }
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/admin/clients/tests/create.rs"]
mod tests;
