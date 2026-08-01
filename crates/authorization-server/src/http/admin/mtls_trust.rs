//! Administrative review and revocation of deployment mTLS trust anchors.

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Data, Json, Path, Query},
};
use nazo_http_actix::{
    csrf_error, has_valid_csrf_token_for_cookies, json_response_no_store, oauth_error,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use uuid::Uuid;

use crate::{
    adapters::audit::{audit_event, audit_fields},
    bootstrap::MtlsTrustAnchorService,
    http::{
        sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles},
        views::pagination,
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustDecision {
    #[serde(default)]
    admin_note: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustRevocation {
    reason: String,
}

pub(crate) async fn admin_mtls_trust_requests(
    sessions: Data<AdminSessionHandles>,
    service: Data<MtlsTrustAnchorService>,
    req: HttpRequest,
    Query(query): Query<HashMap<String, String>>,
) -> HttpResponse {
    let admin = match require_admin_or_forbidden_with_handles(&sessions, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let (page, page_size, offset) = pagination(&query);
    let status = match query.get("status") {
        None => None,
        Some(value) => match value
            .parse::<i16>()
            .ok()
            .and_then(nazo_identity::MtlsTrustAnchorStatus::from_code)
        {
            Some(status) => Some(status),
            None => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "status 仅支持 0/1/2/3.",
                );
            }
        },
    };
    match service
        .page(
            admin.principal.tenant.tenant_id,
            status,
            i64::from(page_size),
            i64::from(offset),
        )
        .await
    {
        Ok(result) => json_response_no_store(serde_json::json!({
            "total": result.total, "page": page, "page_size": page_size, "items": result.items
        })),
        Err(error) => {
            tracing::warn!(%error, "failed to load mTLS trust requests");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "mTLS 信任申请查询失败.",
            )
        }
    }
}

pub(crate) async fn admin_approve_mtls_trust_request(
    sessions: Data<AdminSessionHandles>,
    service: Data<MtlsTrustAnchorService>,
    req: HttpRequest,
    path: Path<Uuid>,
    Json(decision): Json<TrustDecision>,
) -> HttpResponse {
    resolve(
        &sessions,
        &service,
        &req,
        path.into_inner(),
        decision.admin_note,
        true,
    )
    .await
}

pub(crate) async fn admin_reject_mtls_trust_request(
    sessions: Data<AdminSessionHandles>,
    service: Data<MtlsTrustAnchorService>,
    req: HttpRequest,
    path: Path<Uuid>,
    Json(decision): Json<TrustDecision>,
) -> HttpResponse {
    resolve(
        &sessions,
        &service,
        &req,
        path.into_inner(),
        decision.admin_note,
        false,
    )
    .await
}

async fn resolve(
    sessions: &AdminSessionHandles,
    service: &MtlsTrustAnchorService,
    req: &HttpRequest,
    request_id: Uuid,
    note: Option<String>,
    approve: bool,
) -> HttpResponse {
    if !valid_csrf(sessions, req) {
        return csrf_error();
    }
    let admin = match require_admin_or_forbidden_with_handles(sessions, req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let note = match normalized_decision_note(note, approve) {
        Ok(note) => note,
        Err(response) => return response,
    };
    let result = if approve {
        service
            .approve(
                admin.principal.tenant.tenant_id,
                request_id,
                admin.user_id(),
                note,
            )
            .await
    } else {
        service
            .reject(
                admin.principal.tenant.tenant_id,
                request_id,
                admin.user_id(),
                note,
            )
            .await
    };
    match result {
        Ok(value) => {
            audit_event(
                if approve {
                    "mtls_trust_anchor_approved"
                } else {
                    "mtls_trust_anchor_rejected"
                },
                audit_fields(&[
                    ("request_id", serde_json::json!(request_id)),
                    ("admin_user_id", serde_json::json!(admin.id())),
                ]),
            );
            json_response_no_store(value)
        }
        Err(nazo_identity::ports::RepositoryError::Conflict) => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "申请已处理、证书已过期、审批人与申请人相同，或活动信任锚已达到部署安全上限.",
        ),
        Err(error) => {
            tracing::warn!(%error, "failed to resolve mTLS trust request");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "mTLS 信任申请处理失败.",
            )
        }
    }
}

fn normalized_decision_note(
    note: Option<String>,
    approve: bool,
) -> Result<Option<String>, HttpResponse> {
    let note = note
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if note.as_ref().is_some_and(|value| value.len() > 1000) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "审批说明不得超过 1000 字节.",
        ));
    }
    if !approve && note.is_none() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "拒绝申请时必须提供原因.",
        ));
    }
    Ok(note)
}

pub(crate) async fn admin_revoke_mtls_trust_anchor(
    sessions: Data<AdminSessionHandles>,
    service: Data<MtlsTrustAnchorService>,
    req: HttpRequest,
    path: Path<Uuid>,
    Json(payload): Json<TrustRevocation>,
) -> HttpResponse {
    if !valid_csrf(&sessions, &req) {
        return csrf_error();
    }
    let admin = match require_admin_or_forbidden_with_handles(&sessions, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let request_id = path.into_inner();
    let reason = payload.reason.trim();
    if reason.is_empty() || reason.len() > 1000 {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "撤销原因不能为空且不得超过 1000 字节.",
        );
    }
    match service
        .revoke(
            admin.principal.tenant.tenant_id,
            request_id,
            admin.user_id(),
            reason.to_owned(),
        )
        .await
    {
        Ok(value) => {
            audit_event(
                "mtls_trust_anchor_revoked",
                audit_fields(&[
                    ("request_id", serde_json::json!(request_id)),
                    ("admin_user_id", serde_json::json!(admin.id())),
                ]),
            );
            json_response_no_store(value)
        }
        Err(nazo_identity::ports::RepositoryError::Conflict) => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "仅已批准且尚未撤销的信任锚可撤销.",
        ),
        Err(error) => {
            tracing::warn!(%error, "failed to revoke mTLS trust anchor");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "mTLS 信任锚撤销失败.",
            )
        }
    }
}

pub(crate) async fn admin_mtls_trust_bundle(
    sessions: Data<AdminSessionHandles>,
    service: Data<MtlsTrustAnchorService>,
    req: HttpRequest,
) -> HttpResponse {
    let admin = match require_admin_or_forbidden_with_handles(&sessions, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    match service
        .active_bundle(admin.principal.tenant.tenant_id)
        .await
    {
        Ok(bundle) => {
            let bundle_sha256 = sha256_hex(bundle.as_bytes());
            let certificate_count = bundle.matches("-----BEGIN CERTIFICATE-----").count();
            audit_event(
                "mtls_trust_bundle_exported",
                audit_fields(&[
                    ("admin_user_id", serde_json::json!(admin.id())),
                    ("bundle_sha256", serde_json::json!(bundle_sha256)),
                    ("certificate_count", serde_json::json!(certificate_count)),
                ]),
            );
            HttpResponse::Ok()
                .insert_header((header::CONTENT_TYPE, "application/x-pem-file"))
                .insert_header((header::CACHE_CONTROL, "no-store"))
                .insert_header((
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=mtls-trust-anchors.pem",
                ))
                .body(bundle)
        }
        Err(error) => {
            tracing::warn!(%error, "failed to export mTLS trust bundle");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "mTLS 信任锚导出失败.",
            )
        }
    }
}

fn valid_csrf(sessions: &AdminSessionHandles, req: &HttpRequest) -> bool {
    let config = sessions.http_config();
    has_valid_csrf_token_for_cookies(
        req,
        None,
        config.session_cookie_name(),
        config.csrf_cookie_name(),
    )
}

fn sha256_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
            output
        })
}

#[cfg(test)]
#[path = "../../../tests/unit/http/admin/mtls_trust.rs"]
mod tests;
