//! 当前用户外部身份绑定管理。
//! 用户只能查看和解绑自己的 provider subject 绑定，不能修改 provider 配置。
use nazo_http_actix::{empty_response_no_store, json_response_no_store, oauth_error};

use crate::adapters::audit::{audit_event, audit_fields};
#[cfg(test)]
use crate::domain::DatabaseExternalIdentityFixture;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::http::sessions::SessionProfileHandles;
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::web::Path;
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Utc;
use nazo_identity::ports::FederationLink;
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) async fn my_federation_links(
    sessions: Data<SessionProfileHandles>,
    federation: Data<crate::bootstrap::FederationProfileService>,
    req: HttpRequest,
) -> HttpResponse {
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let rows = match federation.list(&user).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, user_id = %user.id(), "failed to load federation links");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "外部身份绑定查询失败.",
            );
        }
    };
    let items = rows
        .into_iter()
        .map(federation_link_json)
        .collect::<Vec<_>>();
    json_response_no_store(json!({ "total": items.len(), "items": items }))
}

pub(crate) async fn unlink_my_federation_link(
    sessions: Data<SessionProfileHandles>,
    federation: Data<crate::bootstrap::FederationProfileService>,
    req: HttpRequest,
    path: Path<Uuid>,
) -> HttpResponse {
    // link_id 来自路径参数，但后续删除仍必须叠加当前 user_id 约束。
    let link_id = path.into_inner();
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let link = match federation.unlink(&user, link_id).await {
        Ok(Some(link)) => link,
        Ok(None) => {
            return oauth_error(
                StatusCode::NOT_FOUND,
                "invalid_request",
                "外部身份绑定不存在.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, user_id = %user.id(), %link_id, "failed to load federation link for unlink");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "外部身份解绑失败.",
            );
        }
    };
    audit_event(
        "external_identity_unlinked",
        audit_fields(&[
            ("user_id", json!(user.id())),
            ("provider_type", json!(link.provider_type)),
            ("provider_id", json!(link.provider_id)),
            ("link_id", json!(link.id)),
        ]),
    );
    empty_response_no_store(StatusCode::NO_CONTENT)
}

fn federation_link_json(link: FederationLink) -> Value {
    // subject 可能是 provider 内稳定标识，但不是本地 secret；claims 可能含上游
    // 扩展字段，列表接口不返回 claims，避免把 provider 原始响应扩散给前端。
    json!({
        "id": link.id,
        "provider_type": link.provider_type,
        "provider_id": link.provider_id,
        "subject": link.subject,
        "email": link.email,
        "created_at": link.created_at,
        "updated_at": link.updated_at,
        "last_login_at": link.last_login_at,
    })
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/federation_links.rs"]
mod tests;
