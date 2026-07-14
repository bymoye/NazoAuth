//! 管理端客户端列表端点。
use super::ServerAdminClientService;
use crate::http::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};
use crate::http::views::{client_json, pagination};
use actix_web::http::StatusCode;
use actix_web::web::{Data, Query};
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{json_response, oauth_error};
use serde_json::json;
use std::collections::HashMap;

pub(crate) async fn admin_clients(
    admin_sessions: Data<AdminSessionHandles>,
    service: Data<ServerAdminClientService>,
    req: HttpRequest,
    Query(query): Query<HashMap<String, String>>,
) -> HttpResponse {
    if let Err(response) = require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        return response;
    }
    let (page, page_size, offset) = pagination(&query);
    match service.page(offset as i64, page_size as i64).await {
        Ok((clients, total)) => clients_list_response(total, page, page_size, clients),
        Err(error) => {
            tracing::warn!(%error, "failed to load oauth clients");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端列表查询失败.",
            )
        }
    }
}

fn clients_list_response(
    total: i64,
    page: i32,
    page_size: i32,
    clients: Vec<nazo_auth::OAuthClient>,
) -> HttpResponse {
    json_response(json!({
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": clients.into_iter().map(client_json).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/admin/clients/tests/list.rs"]
mod tests;
