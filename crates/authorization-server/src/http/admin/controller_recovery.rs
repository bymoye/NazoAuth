//! 恢复挑战/恢复提交接口（04A D11）。
//!
//! 这两个端点在设计上不经过管理员会话：Controller Key 全失时管理员身份
//! 可能正是不可用的部分。它们因此全部 fail-closed——挑战一次性、固定十
//! 分钟窗口、绑定 deployment 与确切的提案密钥材料、失败次数封顶、每
//! deployment 同时至多一个未决挑战。创建任何 pending 行之前，客户端
//! 必须用当前 Recovery Root 对完整提案和客户端随机 nonce 签名。
//! 端点不产生任何会话副作用，也不写攻击者可控的审计事件。

use crate::recovery_root::{RecoveryAnswerRequest, RecoveryChallengeRequest, RecoveryRootService};
use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use nazo_http_actix::{json_response, oauth_error};

/// POST /controller-recovery/challenges
///
/// Verify current-root possession, then issue one nonce-bound challenge.
/// Refused with 409 while any controller slot would admit operations: the
/// break-glass path only unlocks once ordinary identity paths are unusable.
pub(crate) async fn controller_recovery_challenge(
    recovery: Data<RecoveryRootService>,
    Json(body): Json<RecoveryChallengeRequest>,
) -> HttpResponse {
    match recovery.issue_challenge(&body, Utc::now()).await {
        Ok(issued) => json_response(serde_json::json!({
            "challenge_id": issued.challenge_id.to_string(),
            "deployment_id": issued.deployment_id,
            // The nonce is a public value the control side must sign over.
            "nonce": URL_SAFE_NO_PAD.encode(issued.nonce),
            "expires_at": issued.expires_at.to_rfc3339(),
            "algorithm": {
                "type": "Ed25519",
            },
            "single_use": true,
        })),
        Err(error) => challenge_error_response(error),
    }
}

fn challenge_error_response(error: crate::recovery_root::RecoveryRootServiceError) -> HttpResponse {
    use crate::recovery_root::RecoveryRootServiceError as Error;
    match error {
        Error::Root(
            nazo_postgres::RecoveryRootError::RootMissing
            | nazo_postgres::RecoveryRootError::InvalidAllocationProof,
        ) => invalid_allocation_proof_response(),
        other => service_error_response(other),
    }
}

fn invalid_allocation_proof_response() -> HttpResponse {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "恢复挑战分配证明无效；未创建任何待处理状态.",
    )
}

/// POST /controller-recovery/recover
///
/// Verify one signed answer against the CURRENT Recovery Public Key and, on
/// success, atomically revoke every controller slot of the deployment, install
/// exactly one recovered slot (fresh server-assigned `controller_id`, fixed
/// 30-day expiry), and replace the Recovery Root at generation+1.
pub(crate) async fn controller_recovery_commit(
    recovery: Data<RecoveryRootService>,
    Json(body): Json<RecoveryAnswerRequest>,
) -> HttpResponse {
    match recovery.recover(&body, Utc::now()).await {
        Ok(commit) => json_response(serde_json::json!({
            "slot": {
                "deployment_id": commit.slot.deployment_id,
                "controller_id": commit.slot.controller_id,
                "label": commit.slot.label,
                "kid": commit.slot.kid,
                "slot_index": commit.slot.slot_index,
                "issued_at": commit.slot.issued_at.to_rfc3339(),
                "expires_at": commit.slot.expires_at.to_rfc3339(),
                "status": "active",
            },
            "recovery_generation": commit.recovery_generation,
            "old_recovery_secret_invalid": true,
        })),
        Err(error) => service_error_response(error),
    }
}

fn service_error_response(error: crate::recovery_root::RecoveryRootServiceError) -> HttpResponse {
    use crate::recovery_root::RecoveryRootServiceError as Error;
    match error {
        Error::Invalid(description) => {
            oauth_error(StatusCode::BAD_REQUEST, "invalid_request", description)
        }
        Error::Root(recovery_error) => root_error_response(recovery_error),
        Error::Rotation(_) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "该端点不接受轮换审批载荷.",
        ),
    }
}

pub(super) fn root_error_response(error: nazo_postgres::RecoveryRootError) -> HttpResponse {
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
        Error::InvalidAllocationProof => invalid_allocation_proof_response(),
        Error::AllocationProofReplayed => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "恢复挑战分配证明已经使用或过期；请生成新的随机 nonce 和证明.",
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

#[cfg(test)]
#[path = "../../../tests/unit/http/admin/controller_recovery.rs"]
mod tests;
