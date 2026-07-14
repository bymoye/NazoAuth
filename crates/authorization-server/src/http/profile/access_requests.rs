//! 当前用户客户端接入申请接口。
#[cfg(test)]
use crate::domain::DatabaseUserFixture;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_REALM_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_TENANT_ID;
#[cfg(test)]
use crate::http::sessions::SessionPayload;
use crate::http::sessions::SessionProfileHandles;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::test_support::valkey::valkey_set_ex;
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Utc;
use nazo_http_actix::csrf_error;
use nazo_http_actix::{json_response, json_response_status, oauth_error};
#[cfg(test)]
use nazo_identity::AccessRequestStatus;
use serde::Deserialize;
use serde_json::{Value, json};
// 只处理用户侧申请列表和新建申请。

pub(crate) async fn my_access_requests(
    sessions: Data<SessionProfileHandles>,
    service: Data<crate::bootstrap::ClientAccessProfileService>,
    req: HttpRequest,
) -> HttpResponse {
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match service.list(&user).await {
        Ok(items) => access_request_items_response(
            items
                .into_iter()
                .map(|item| user_access_request_json(item.request, item.delivery))
                .collect(),
        ),
        Err(nazo_identity::AccessRequestListError::Repository(error)) => {
            tracing::warn!(%error, "failed to load user access requests");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            )
        }
        Err(nazo_identity::AccessRequestListError::DeliveryStore(error)) => {
            tracing::warn!(%error, "failed to resolve access-request delivery link");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请交付状态查询失败.",
            )
        }
    }
}

#[cfg(test)]
fn my_access_requests_response(rows: Vec<nazo_identity::AccessRequest>) -> HttpResponse {
    let items: Vec<Value> = rows
        .into_iter()
        .map(|row| user_access_request_json(row, None))
        .collect();
    access_request_items_response(items)
}

fn access_request_items_response(items: Vec<Value>) -> HttpResponse {
    let pending_count = items
        .iter()
        .filter(|item| {
            item.get("status").and_then(Value::as_i64)
                == Some(nazo_identity::AccessRequestStatus::Pending.code() as i64)
        })
        .count();
    json_response(json!({"total": items.len(), "pending_count": pending_count, "items": items}))
}

fn user_access_request_json(
    row: nazo_identity::AccessRequest,
    delivery: Option<nazo_identity::AvailableDelivery>,
) -> Value {
    let mut value = json!({
        "id": row.id,
        "site_name": row.site_name,
        "site_url": row.site_url,
        "request_description": row.request_description,
        "status": row.status.code(),
        "admin_note": row.admin_note,
        "approved_client_id": row.approved_client_id,
        "created_at": row.created_at,
        "resolved_at": row.resolved_at,
    });
    if let Some(delivery) = delivery {
        value["delivery_token"] = json!(delivery.token);
        value["delivery_url"] = json!(delivery.url);
    }
    value
}

#[derive(Deserialize)]
pub(crate) struct CreateAccessRequest {
    site_name: String,
    site_url: String,
    request_description: String,
}

pub(crate) async fn create_access_request(
    sessions: Data<SessionProfileHandles>,
    service: Data<crate::bootstrap::ClientAccessProfileService>,
    req: HttpRequest,
    Json(payload): Json<CreateAccessRequest>,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(&req, None) {
        return csrf_error();
    }
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let row = service
        .create(
            &user,
            nazo_identity::NewAccessRequestInput {
                site_name: payload.site_name,
                site_url: payload.site_url,
                request_description: payload.request_description,
            },
        )
        .await;
    match row {
        Ok(r) => create_access_request_response(r),
        Err(nazo_identity::ports::RepositoryError::Conflict) => {
            oauth_error(StatusCode::CONFLICT, "invalid_request", "已有待处理申请.")
        }
        Err(error) => {
            tracing::warn!(%error, "failed to create access request");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请创建失败.",
            )
        }
    }
}

fn create_access_request_response(row: nazo_identity::AccessRequest) -> HttpResponse {
    json_response_status(StatusCode::CREATED, user_access_request_json(row, None))
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/access_requests.rs"]
mod tests;
