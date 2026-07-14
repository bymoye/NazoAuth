//! 一次性客户端凭据领取接口。
use crate::http::sessions::SessionProfileHandles;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Query};
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{json_response, oauth_error};
use serde_json::{Value, json};
use std::collections::HashMap;
// 只处理审批后临时凭据的只读领取。

pub(crate) async fn access_delivery(
    sessions: Data<SessionProfileHandles>,
    service: Data<crate::bootstrap::ClientAccessProfileService>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(token) = q.get("token") else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "缺少 token.");
    };
    let claimed = match service.claim_delivery(&user, token).await {
        Ok(claimed) => claimed,
        Err(nazo_identity::DeliveryReadError::Invalid) => {
            return invalid_delivery_link_response();
        }
        Err(
            nazo_identity::DeliveryReadError::Repository(error)
            | nazo_identity::DeliveryReadError::DeliveryStore(error),
        ) => {
            tracing::warn!(%error, "failed to read or consume client delivery payload");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "凭据读取失败.",
            );
        }
    };
    delivery_value_response(claimed)
}

fn is_committed_delivery(value: &Value) -> bool {
    value.get("delivery_state").and_then(Value::as_str) == Some("committed")
        && value
            .get("request_id")
            .and_then(Value::as_str)
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .is_some()
        && value
            .get("approved_client_id")
            .and_then(Value::as_str)
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .is_some()
        && value.get("client_id").and_then(Value::as_str).is_some()
}

fn invalid_delivery_link_response() -> HttpResponse {
    oauth_error(
        StatusCode::NOT_FOUND,
        "invalid_request",
        "凭据链接无效、已过期或已被读取.",
    )
}

fn delivery_value_response(mut value: Value) -> HttpResponse {
    if is_committed_delivery(&value) {
        value
            .as_object_mut()
            .expect("validated delivery payload is an object")
            .remove("delivery_state");
        value
            .as_object_mut()
            .expect("validated delivery payload is an object")
            .remove("approved_client_id");
        value["read_once_notice"] = json!("此凭据链接已完成一次性读取并销毁，请立即保存敏感信息。");
        json_response(value)
    } else {
        invalid_delivery_link_response()
    }
}

#[cfg(test)]
fn delivery_payload_response(raw: &str) -> HttpResponse {
    match serde_json::from_str(raw) {
        Ok(value) => delivery_value_response(value),
        Err(_) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "凭据内容无效.",
        ),
    }
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/delivery.rs"]
mod tests;
