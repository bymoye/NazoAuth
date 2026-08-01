//! 一次性客户端凭据领取接口。
use crate::http::sessions::SessionProfileHandles;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{authorization_error_response, csrf_error, json_response_no_store};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessDeliveryRequest {
    pub(crate) request_id: Uuid,
}

pub(crate) async fn access_delivery(
    sessions: Data<SessionProfileHandles>,
    service: Data<crate::bootstrap::ClientAccessProfileService>,
    req: HttpRequest,
    Json(payload): Json<AccessDeliveryRequest>,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(&req, None) {
        return csrf_error();
    }
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let claimed = match service.claim_delivery(&user, payload.request_id).await {
        Ok(claimed) => claimed,
        Err(nazo_identity::DeliveryReadError::Invalid) => {
            return invalid_delivery_response();
        }
        Err(
            nazo_identity::DeliveryReadError::Repository(error)
            | nazo_identity::DeliveryReadError::DeliveryStore(error),
        ) => {
            tracing::warn!(%error, "failed to read or consume client delivery payload");
            return authorization_error_response(
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

fn invalid_delivery_response() -> HttpResponse {
    authorization_error_response(
        StatusCode::NOT_FOUND,
        "invalid_request",
        "凭据不存在、已过期或已被读取.",
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
        value["read_once_notice"] = json!("此凭据已完成一次性读取并销毁，请立即保存敏感信息。");
        json_response_no_store(value)
    } else {
        invalid_delivery_response()
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/http/profile/delivery.rs"]
mod tests;
