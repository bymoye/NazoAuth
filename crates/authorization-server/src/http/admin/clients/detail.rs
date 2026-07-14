//! 管理端客户端详情端点。
use super::ServerAdminClientService;
use crate::http::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};
use crate::http::views::client_json;
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};
use nazo_auth::AdminClientError;
use nazo_http_actix::{json_response, oauth_error};

pub(crate) async fn admin_get_client(
    admin_sessions: Data<AdminSessionHandles>,
    service: Data<ServerAdminClientService>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    let client_id = path.into_inner();
    if let Err(response) = require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        return response;
    }
    match service.detail(&client_id).await {
        Ok(client) => client_detail_response(client),
        Err(AdminClientError::NotFound) => client_detail_not_found_response(),
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client detail");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            )
        }
    }
}

fn client_detail_response(client: nazo_auth::OAuthClient) -> HttpResponse {
    json_response(client_json(client))
}

fn client_detail_not_found_response() -> HttpResponse {
    oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该客户端.")
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/admin/clients/tests/detail.rs"]
mod tests;
