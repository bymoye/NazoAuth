//! 授权确认页数据端点。
use crate::domain::ConsentPayload;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_REALM_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::http::authorization::{AuthorizationEndpoint, AuthorizationRequestContext};
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::test_support::valkey::valkey_set_ex;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Query};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::{Duration, Utc};
use nazo_http_actix::cookie_value;
use nazo_http_actix::{json_response, oauth_error};
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;
// 前端通过 request_id 读取待确认内容，服务端再次校验该请求属于当前用户。

#[cfg(test)]
fn parse_consent_payload(raw: Option<String>) -> Option<ConsentPayload> {
    raw.and_then(|value| serde_json::from_str::<ConsentPayload>(&value).ok())
}

fn validate_consent_payload_user(
    payload: ConsentPayload,
    current_user_id: Uuid,
) -> Result<ConsentPayload, HttpResponse> {
    if payload.user_id != current_user_id {
        return Err(oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前会话与授权请求不匹配.",
        ));
    }
    Ok(payload)
}

fn malformed_or_missing_consent_response() -> HttpResponse {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "授权请求不存在或已过期,请重新发起授权.",
    )
}

fn consent_page_response(payload: ConsentPayload, csrf_token: Option<String>) -> HttpResponse {
    json_response(json!({
        "request_id": payload.request_id,
        "client_id": payload.client_id,
        "client_name": payload.client_name,
        "redirect_uri": payload.redirect_uri,
        "scopes": payload.scopes,
        "userinfo_claims": payload.userinfo_claims,
        "id_token_claims": payload.id_token_claims,
        "authorization_details": payload.authorization_details,
        "csrf_token": csrf_token
    }))
}

/// 返回授权确认页所需的客户端、scope 和 CSRF 信息。
pub(crate) async fn authorize_consent(
    endpoint: Data<AuthorizationEndpoint>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let context = endpoint.context();
    authorize_consent_with_context(&context, req, q).await
}

async fn authorize_consent_with_context(
    context: &AuthorizationRequestContext<'_>,
    req: HttpRequest,
    q: HashMap<String, String>,
) -> HttpResponse {
    let user = match context.sessions.current_session(&req).await {
        Ok(Some(session)) => session.user,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "授权前必须先登录.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to resolve authorization consent user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话查询失败.",
            );
        }
    };
    let Some(request_id) = q.get("request_id") else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 request_id.",
        );
    };

    let payload = match context.service.load_consent(request_id).await {
        Ok(value) => value,
        Err(nazo_auth::AuthorizationPortError::CorruptData) => {
            tracing::warn!("authorization consent state is malformed");
            return malformed_or_missing_consent_response();
        }
        Err(error) => {
            tracing::warn!(%error, "failed to read authorization consent state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权请求读取失败.",
            );
        }
    };
    let Some(payload) = payload else {
        return malformed_or_missing_consent_response();
    };
    let payload = match validate_consent_payload_user(payload, user.id()) {
        Ok(payload) => payload,
        Err(response) => return response,
    };

    consent_page_response(
        payload,
        cookie_value(&req, context.sessions.http_config().csrf_cookie_name()),
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/authorization/tests/consent.rs"]
mod tests;
