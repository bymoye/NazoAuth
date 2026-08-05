//! 管理端 HTTP handler 聚合模块。
// 每个子模块按一个管理资源拆分，路由层通过显式模块路径调用。
pub(crate) mod access_requests;
pub(crate) mod clients;
pub(crate) mod federation;
pub(crate) mod grants;
pub(crate) mod mtls_trust;
pub(crate) mod openid4vc;
pub(crate) mod users;

use actix_web::{HttpResponse, http::StatusCode};
use serde_json::{Map, Value};

use crate::adapters::audit::{audit_event_required, ensure_audit_storage};
use nazo_http_actix::oauth_error;

pub(crate) async fn require_durable_audit_or_unavailable() -> Result<(), HttpResponse> {
    ensure_audit_storage().await.map_err(|error| {
        tracing::error!(%error, "durable security audit preflight failed");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Durable security audit storage is unavailable.",
        )
    })?;
    audit_event_required("admin_mutation_intent", Map::new())
        .await
        .map_err(|error| {
            tracing::error!(%error, "durable security audit intent append failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Durable security audit intent could not be persisted.",
            )
        })
}

pub(crate) async fn persist_required_audit_or_unavailable(
    event: &str,
    fields: Map<String, Value>,
) -> Result<(), HttpResponse> {
    audit_event_required(event, fields).await.map_err(|error| {
        tracing::error!(%error, event, "durable security audit append failed");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Durable security audit append failed.",
        )
    })
}
