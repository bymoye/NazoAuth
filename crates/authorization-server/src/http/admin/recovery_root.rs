//! 管理端 Recovery Root 接口（04A D12）。
//!
//! 审批签发要求管理员会话具备最近的交互式 MFA step-up（与控制器槽位流程
//! 相同的固定新鲜度上限）；提交端点消费一次性审批令牌，令牌校验与根替换
//! 在同一个数据库事务内原子完成。明文审批令牌只在签发响应中出现一次，
//! 永不写入日志或审计载荷；任何载荷都不存在可携带 Recovery Secret 的字段。

use crate::adapters::audit::audit_fields;
use crate::http::admin::{
    persist_required_audit_or_unavailable, require_durable_audit_or_unavailable,
};
use crate::http::sessions::{
    AdminSessionHandles, require_admin_or_forbidden_with_handles,
    require_admin_with_recent_mfa_or_forbidden_with_handles,
};
use crate::recovery_root::{RecoveryRootChangeRequest, RecoveryRootService};
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
use nazo_http_actix::{csrf_error, has_valid_csrf_token_for_cookies, json_response, oauth_error};
use nazo_postgres::IdentityApprovalError;
use std::collections::HashMap;

fn ensure_csrf(
    admin_sessions: &AdminSessionHandles,
    req: &HttpRequest,
) -> Result<(), HttpResponse> {
    let http = admin_sessions.http_config();
    if has_valid_csrf_token_for_cookies(
        req,
        None,
        http.session_cookie_name(),
        http.csrf_cookie_name(),
    ) {
        Ok(())
    } else {
        Err(csrf_error())
    }
}

/// GET /admin/controller-registry/recovery-root?deployment_id=...
///
/// Read-only admin view of the current Recovery Root: presence, kid, pinned
/// KDF id, generation, and timestamps.  Public key bytes are never returned.
pub(crate) async fn admin_recovery_root(
    admin_sessions: Data<AdminSessionHandles>,
    recovery: Data<RecoveryRootService>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let _admin = match require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let Some(deployment_id) = q
        .get("deployment_id")
        .map(String::as_str)
        .filter(|value| !value.is_empty())
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 deployment_id 查询参数.",
        );
    };
    match recovery.current_root(deployment_id).await {
        Ok(Some(root)) => json_response(serde_json::json!({
            "deployment_id": root.deployment_id,
            "present": true,
            "recovery_kid": root.recovery_kid,
            "kdf": root.kdf,
            "generation": root.generation,
            "created_at": root.created_at.to_rfc3339(),
            "updated_at": root.updated_at.to_rfc3339(),
        })),
        Ok(None) => json_response(serde_json::json!({
            "deployment_id": deployment_id,
            "present": false,
        })),
        Err(error) => service_error_response(error),
    }
}

/// POST /admin/controller-registry/recovery-root/approvals
///
/// Issues one single-use approval bound to the exact `recovery-root-rotate`
/// payload digest.  Requires a fresh interactive MFA step-up.
pub(crate) async fn admin_recovery_root_approval(
    admin_sessions: Data<AdminSessionHandles>,
    recovery: Data<RecoveryRootService>,
    req: HttpRequest,
    Json(body): Json<RecoveryRootChangeRequest>,
) -> HttpResponse {
    if let Err(response) = ensure_csrf(&admin_sessions, &req) {
        return response;
    }
    let admin = match require_admin_with_recent_mfa_or_forbidden_with_handles(&admin_sessions, &req)
        .await
    {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    if let Err(response) = require_durable_audit_or_unavailable().await {
        return response;
    }
    match recovery
        .issue_rotation_approval(admin.id(), &body, Utc::now())
        .await
    {
        Ok(issued) => {
            // Durable evidence that a fresh-MFA administrator approved this
            // exact rotation digest.  The plaintext token is never audited.
            if let Err(response) = persist_required_audit_or_unavailable(
                "controller_recovery_root_rotation_approved",
                audit_fields(&[
                    ("actor_user_id", serde_json::json!(admin.id().to_string())),
                    ("deployment_id", serde_json::json!(body.deployment_id)),
                    ("action", serde_json::json!("recovery-root-rotate")),
                    ("action_sha256", serde_json::json!(issued.action_sha256)),
                    (
                        "expires_at",
                        serde_json::json!(issued.expires_at.to_rfc3339()),
                    ),
                ]),
            )
            .await
            {
                return response;
            }
            json_response(serde_json::json!({
                "approval_token": issued.token,
                "action": "recovery-root-rotate",
                "action_sha256": issued.action_sha256,
                "expires_at": issued.expires_at.to_rfc3339(),
                "single_use": true,
            }))
        }
        Err(error) => service_error_response(error),
    }
}

/// POST /admin/controller-registry/recovery-root/rotate
///
/// Commits an approved replacement.  Consumption and replacement share one
/// transaction; the previous generation stops verifying at commit time.
pub(crate) async fn admin_recovery_root_rotate(
    admin_sessions: Data<AdminSessionHandles>,
    recovery: Data<RecoveryRootService>,
    req: HttpRequest,
    Json(body): Json<RotateRecoveryRootBody>,
) -> HttpResponse {
    if let Err(response) = ensure_csrf(&admin_sessions, &req) {
        return response;
    }
    let admin = match require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    if let Err(response) = require_durable_audit_or_unavailable().await {
        return response;
    }
    let change = RecoveryRootChangeRequest {
        deployment_id: body.deployment_id.clone(),
        recovery_public_key: body.recovery_public_key.clone(),
        kid: body.kid.clone(),
    };
    match recovery
        .commit_rotation(&body.approval_token, &change, Utc::now())
        .await
    {
        Ok(root) => {
            if let Err(response) = persist_required_audit_or_unavailable(
                "controller_recovery_root_rotated",
                audit_fields(&[
                    ("actor_user_id", serde_json::json!(admin.id().to_string())),
                    ("deployment_id", serde_json::json!(root.deployment_id)),
                    ("generation", serde_json::json!(root.generation)),
                    ("recovery_kid", serde_json::json!(root.recovery_kid)),
                    ("kdf", serde_json::json!(root.kdf)),
                ]),
            )
            .await
            {
                return response;
            }
            json_response(serde_json::json!({
                "recovery_root": {
                    "deployment_id": root.deployment_id,
                    "recovery_kid": root.recovery_kid,
                    "kdf": root.kdf,
                    "generation": root.generation,
                    "created_at": root.created_at.to_rfc3339(),
                    "updated_at": root.updated_at.to_rfc3339(),
                },
                "previous_generation_invalid": true,
            }))
        }
        Err(error) => service_error_response(error),
    }
}

/// POST /admin/controller-registry/recovery-root/rotate 请求体。
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RotateRecoveryRootBody {
    pub approval_token: String,
    pub deployment_id: String,
    pub recovery_public_key: String,
    pub kid: String,
}

fn service_error_response(error: crate::recovery_root::RecoveryRootServiceError) -> HttpResponse {
    use crate::recovery_root::RecoveryRootServiceError as Error;
    match error {
        Error::Invalid(description) => {
            oauth_error(StatusCode::BAD_REQUEST, "invalid_request", description)
        }
        Error::Root(recovery_error) => root_error_response(recovery_error),
        Error::Rotation(rotation_error) => rotation_error_response(rotation_error),
    }
}

fn rotation_error_response(error: nazo_postgres::RecoveryRotationError) -> HttpResponse {
    match error {
        nazo_postgres::RecoveryRotationError::Approval(rejection) => {
            let (status, description) = match rejection {
                IdentityApprovalError::UnknownToken => (StatusCode::BAD_REQUEST, "审批令牌不存在."),
                IdentityApprovalError::Replayed => (
                    StatusCode::CONFLICT,
                    "审批令牌已被使用；身份变更需要重新批准.",
                ),
                IdentityApprovalError::Expired => (
                    StatusCode::BAD_REQUEST,
                    "审批令牌已过期；请在十分钟窗口内完成提交.",
                ),
                IdentityApprovalError::ActionMismatch => (
                    StatusCode::BAD_REQUEST,
                    "审批令牌与本次提交的动作内容不一致.",
                ),
                IdentityApprovalError::Transport(inner) => {
                    tracing::warn!(%inner, "controller identity approval storage failure");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "审批状态查询失败.",
                    );
                }
            };
            oauth_error(status, "invalid_request", description)
        }
        nazo_postgres::RecoveryRotationError::Mutation(recovery_error) => {
            root_error_response(recovery_error)
        }
        nazo_postgres::RecoveryRotationError::Transport(inner) => {
            tracing::warn!(%inner, "recovery root rotation storage failure");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "恢复根状态暂不可用.",
            )
        }
    }
}

fn root_error_response(error: nazo_postgres::RecoveryRootError) -> HttpResponse {
    use nazo_postgres::RecoveryRootError as Error;
    match error {
        Error::ControllersStillAdmitted(admitted) => {
            let items: Vec<serde_json::Value> = admitted
                .iter()
                .map(|controller| {
                    serde_json::json!({
                        "controller_id": controller.controller_id,
                        "kid": controller.kid,
                        "expires_at": controller.expires_at.to_rfc3339(),
                    })
                })
                .collect();
            HttpResponse::build(StatusCode::CONFLICT).json(serde_json::json!({
                "error": "controller_still_admitted",
                "error_description":
                    "该 deployment 仍有可用的 Controller Key；普通身份变更应走 fresh-2FA 流程.",
                "admitted_controllers": items,
            }))
        }
        Error::ChallengePending => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "该 deployment 已有待完成的恢复挑战；等待其过期或完成后重试.",
        ),
        Error::ChallengeUnknown => oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "未找到该恢复挑战.",
        ),
        Error::ChallengeExpired => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "恢复挑战已过期；请重新发起挑战.",
        ),
        Error::ChallengeExhausted => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "恢复挑战失败次数已达上限并已作废；请重新发起挑战.",
        ),
        Error::ChallengeReplayed => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "恢复挑战已被使用；挑战只能提交一次.",
        ),
        Error::NonceMismatch | Error::InvalidSignature => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "恢复答案验证失败；请核对 Recovery Secret 与挑战内容后重试.",
        ),
        Error::RootMissing => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "该 deployment 尚未登记 Recovery Root；无法执行恢复.",
        ),
        Error::InvalidIdentity(reason) => {
            oauth_error(StatusCode::BAD_REQUEST, "invalid_request", reason)
        }
        Error::Transport(inner) => {
            tracing::warn!(%inner, "controller recovery storage failure");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "恢复状态暂不可用.",
            )
        }
    }
}
