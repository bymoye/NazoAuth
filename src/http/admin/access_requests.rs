//! 管理端客户端接入申请接口。
// 申请审批会创建客户端，因此显式依赖 clients 模块的创建逻辑。
use super::clients::{
    CreateClientRequest, insert_client_error_response, insert_prepared_client,
    prepare_client_insert_with_secret_pepper,
};
use crate::http::prelude::*;
use diesel_async::AsyncConnection;

pub(crate) async fn admin_access_requests(
    state: Data<AppState>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    if let Err(response) = require_admin_or_forbidden(&state, &req).await {
        return response;
    };
    let (page, page_size, offset) = pagination(&q);
    let status = match parse_access_request_status(&q) {
        Ok(status) => status,
        Err(response) => return response,
    };
    let search = q.get("q").map(String::as_str);
    let total = match access_request_count(&state.diesel_db, search, status).await {
        Ok(total) => total,
        Err(error) => {
            tracing::warn!(%error, "failed to count access requests");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            );
        }
    };
    let rows = match access_request_rows(&state.diesel_db, page_size, offset, search, status).await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "failed to load access requests");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            );
        }
    };
    access_requests_response(page, page_size, total, rows)
}

fn parse_access_request_status(
    q: &HashMap<String, String>,
) -> Result<Option<AccessRequestStatus>, HttpResponse> {
    match q
        .get("status")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        Some(value) => value
            .parse::<i16>()
            .ok()
            .and_then(AccessRequestStatus::from_code)
            .map(Some)
            .ok_or_else(invalid_access_request_status_response),
        None => Ok(None),
    }
}

fn invalid_access_request_status_response() -> HttpResponse {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "status 参数仅支持 0/1/2.",
    )
}

fn access_requests_response(
    page: i32,
    page_size: i32,
    total: i64,
    rows: Vec<Value>,
) -> HttpResponse {
    json_response(json!({"total": total, "page": page, "page_size": page_size, "items": rows}))
}

pub(crate) async fn admin_approve_access_request(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<CreateClientRequest>,
) -> HttpResponse {
    let request_id = path.into_inner();
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let admin = match require_admin_or_forbidden(&state, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let pending_request = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => match client_access_requests::table
            .filter(client_access_requests::id.eq(request_id))
            .filter(client_access_requests::status.eq(AccessRequestStatus::Pending.code()))
            .select((
                client_access_requests::user_id,
                client_access_requests::site_name,
            ))
            .first::<PendingAccessRequestRow>(&mut conn)
            .await
            .optional()
        {
            Ok(Some(row)) => row,
            Ok(None) => {
                return access_request_already_approved_response();
            }
            Err(error) => {
                tracing::warn!(%error, "failed to query pending access request");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "接入申请查询失败.",
                );
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for access request approval");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            );
        }
    };
    let request_user_id = pending_request.user_id;
    let site_name = pending_request.site_name;
    let response_signing_algorithms = state
        .keyset
        .snapshot()
        .response_signing_alg_values_supported();
    let prepared = match prepare_client_insert_with_secret_pepper(
        payload,
        state.settings.pairwise_subject_secret.as_deref(),
        &state.settings.client_secret_pepper,
        &state.settings.issuer,
        &response_signing_algorithms,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => return insert_client_error_response(error),
    };
    let token = random_urlsafe_token();
    let delivery_key = format!("oauth:client_delivery:{request_user_id}:{token}");
    let expires_at =
        Utc::now() + Duration::seconds(state.settings.client_delivery_ttl_seconds as i64);
    let delivery_payload = json!({
        "request_id": request_id,
        "user_id": request_user_id,
        "client_id": &prepared.client_id,
        "client_name": &prepared.client_name,
        "client_type": &prepared.client_type,
        "client_secret": prepared.issued_secret.as_deref(),
        "redirect_uris": &prepared.redirect_uris,
        "scopes": &prepared.scopes,
        "grant_types": &prepared.grant_types,
        "token_endpoint_auth_method": &prepared.token_endpoint_auth_method,
        "site_name": site_name,
        "created_at": Utc::now(),
        "expires_at": expires_at
    });
    if let Err(error) = valkey_set_ex(
        &state.valkey,
        &delivery_key,
        delivery_payload.to_string(),
        state.settings.client_delivery_ttl_seconds,
    )
    .await
    {
        tracing::warn!(%error, "failed to persist client delivery payload");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端凭据交付创建失败.",
        );
    }

    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for access request approval");
            let _ = valkey_del(&state.valkey, &delivery_key).await;
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请审批失败.",
            );
        }
    };
    let approval = conn
        .transaction::<ClientRow, diesel::result::Error, _>(async |conn| {
            let client = insert_prepared_client(conn, &prepared).await?;
            let updated =
                diesel::update(client_access_requests::table.find(request_id).filter(
                    client_access_requests::status.eq(AccessRequestStatus::Pending.code()),
                ))
                .set((
                    client_access_requests::status.eq(AccessRequestStatus::Approved.code()),
                    client_access_requests::resolved_by_user_id.eq(admin.id),
                    client_access_requests::approved_client_id.eq(client.id),
                    client_access_requests::resolved_at.eq(diesel_now),
                    client_access_requests::updated_at.eq(diesel_now),
                ))
                .execute(conn)
                .await?;
            if updated == 0 {
                return Err(diesel::result::Error::NotFound);
            }
            Ok(client)
        })
        .await;
    let client = match approval {
        Ok(client) => client,
        Err(error) => {
            if let Err(cleanup_error) = valkey_del(&state.valkey, &delivery_key).await {
                tracing::warn!(%cleanup_error, "failed to remove client delivery payload");
            }
            if matches!(error, diesel::result::Error::NotFound) {
                return access_request_already_approved_response();
            }
            tracing::warn!(%error, "failed to approve access request");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请审批失败.",
            );
        }
    };
    audit_event(
        "client_created",
        audit_fields(&[
            ("client_id", json!(client.client_id)),
            ("request_id", json!(request_id)),
            ("admin_user_id", json!(admin.id)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(&req, &state.settings))),
            ),
        ]),
    );
    match access_request_by_id(&state.diesel_db, request_id).await {
        Ok(Some(row)) => json_response(row),
        Ok(None) => json_response(json!({"id": request_id})),
        Err(error) => {
            tracing::warn!(%error, "failed to load approved access request");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            )
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct RejectAccessRequest {
    admin_note: String,
}

pub(crate) async fn admin_reject_access_request(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<RejectAccessRequest>,
) -> HttpResponse {
    let request_id = path.into_inner();
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let admin = match require_admin_or_forbidden(&state, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let updated = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => match diesel::update(
            client_access_requests::table
                .find(request_id)
                .filter(client_access_requests::status.eq(AccessRequestStatus::Pending.code())),
        )
        .set((
            client_access_requests::status.eq(AccessRequestStatus::Rejected.code()),
            client_access_requests::admin_note.eq(payload.admin_note),
            client_access_requests::resolved_by_user_id.eq(admin.id),
            client_access_requests::resolved_at.eq(diesel_now),
            client_access_requests::updated_at.eq(diesel_now),
        ))
        .execute(&mut conn)
        .await
        {
            Ok(updated) => updated,
            Err(error) => {
                tracing::warn!(%error, "failed to reject access request");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "接入申请拒绝失败.",
                );
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for access request rejection");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请拒绝失败.",
            );
        }
    };
    if updated == 0 {
        return access_request_already_rejected_response();
    }
    match access_request_by_id(&state.diesel_db, request_id).await {
        Ok(Some(row)) => json_response(row),
        Ok(None) => json_response(json!({"id": request_id})),
        Err(error) => {
            tracing::warn!(%error, "failed to load rejected access request");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "接入申请查询失败.",
            )
        }
    }
}

fn access_request_already_approved_response() -> HttpResponse {
    oauth_error(
        StatusCode::CONFLICT,
        "invalid_request",
        "该申请已处理,不可重复审批.",
    )
}

fn access_request_already_rejected_response() -> HttpResponse {
    oauth_error(
        StatusCode::CONFLICT,
        "invalid_request",
        "该申请已处理,不可重复拒绝.",
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/admin/tests/access_requests.rs"]
mod tests;
