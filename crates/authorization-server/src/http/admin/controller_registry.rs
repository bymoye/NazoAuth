//! 管理端控制器注册表接口（D01/D02/D05）。
//!
//! 审批签发端点要求管理员会话具备最近的交互式 MFA step-up（复用既有
//! `require_admin_with_recent_mfa_*` 语义，固定 5 分钟新鲜度上限）；提交端点
//! 消费一次性审批令牌，令牌校验与注册表变更在同一个数据库事务内原子完成。
//! 明文审批令牌只在签发响应中出现一次，永不写入日志或审计载荷。
use crate::adapters::audit::audit_fields;
use crate::controller_registry::{
    ControllerKeyWarning, ControllerRegistryService, ControllerRegistryServiceError,
    IdentityChange, RevokeRequest, RotateRequest, SlotChangeRequest, expiry_warning,
};
use crate::http::admin::{
    persist_required_audit_or_unavailable, require_durable_audit_or_unavailable,
};
use crate::http::sessions::{
    AdminSessionHandles, require_admin_or_forbidden_with_handles,
    require_admin_with_recent_mfa_or_forbidden_with_handles,
};
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
use nazo_http_actix::{csrf_error, has_valid_csrf_token_for_cookies, json_response, oauth_error};
use nazo_postgres::{
    ControllerIdentityAction, ControllerSlotStatus, IdentityApprovalError,
    MAX_ACTIVE_CONTROLLER_SLOTS, StoredControllerSlot,
};
use serde::Deserialize;
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

/// GET /admin/controller-registry/slots?deployment_id=...
///
/// Authoritative answer to "which controllers exist for this deployment and
/// when do they expire"; read-only admin view.
pub(crate) async fn admin_controller_slots(
    admin_sessions: Data<AdminSessionHandles>,
    registry: Data<ControllerRegistryService>,
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
    match registry.list_slots(deployment_id).await {
        Ok(slots) => slots_list_response(deployment_id, &slots),
        Err(error) => service_error_response(error),
    }
}

/// 审批签发请求：`action` 判别必需载荷；字段显式声明以保持严格反序列化。
/// bind/add 需要 label/public_key/kid；rotate 额外需要 controller_id；
/// revoke 只允许 deployment_id/controller_id，携带其余字段一律拒绝。
/// P0-3：仅 bind 允许携带 recovery_public_key/recovery_kid（原子首绑）。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalRequestBody {
    pub action: String,
    pub deployment_id: String,
    #[serde(default)]
    pub controller_id: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub recovery_public_key: Option<String>,
    #[serde(default)]
    pub recovery_kid: Option<String>,
}

impl ApprovalRequestBody {
    fn missing(field: &'static str) -> HttpResponse {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            oauth_error_description_field(field),
        )
    }

    fn unexpected(field: &'static str) -> HttpResponse {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            oauth_error_unexpected_field(field),
        )
    }

    fn slot_fields(&self) -> Result<(String, String, String), HttpResponse> {
        let Some(label) = self.label.clone() else {
            return Err(Self::missing("label"));
        };
        let Some(public_key) = self.public_key.clone() else {
            return Err(Self::missing("public_key"));
        };
        let Some(kid) = self.kid.clone() else {
            return Err(Self::missing("kid"));
        };
        Ok((label, public_key, kid))
    }

    fn change(&self) -> Result<IdentityChange, HttpResponse> {
        match self.action.as_str() {
            "bind" | "add" => {
                if self.controller_id.is_some() {
                    return Err(Self::unexpected("controller_id"));
                }
                if (self.recovery_public_key.is_some() || self.recovery_kid.is_some())
                    && self.action != "bind"
                {
                    return Err(Self::unexpected("recovery_public_key/recovery_kid"));
                }
                let (label, public_key, kid) = self.slot_fields()?;
                let request = SlotChangeRequest {
                    deployment_id: self.deployment_id.clone(),
                    label,
                    kid,
                    public_key,
                    recovery_public_key: self.recovery_public_key.clone(),
                    recovery_kid: self.recovery_kid.clone(),
                };
                Ok(if self.action == "bind" {
                    IdentityChange::Bind(request)
                } else {
                    IdentityChange::Add(request)
                })
            }
            "rotate" => {
                let controller_id = self
                    .controller_id
                    .clone()
                    .ok_or_else(|| Self::missing("controller_id"))?;
                let (label, public_key, kid) = self.slot_fields()?;
                Ok(IdentityChange::Rotate(RotateRequest {
                    deployment_id: self.deployment_id.clone(),
                    controller_id,
                    label,
                    kid,
                    public_key,
                }))
            }
            "revoke" => {
                if self.label.is_some() || self.public_key.is_some() || self.kid.is_some() {
                    return Err(Self::unexpected("label/public_key/kid"));
                }
                let controller_id = self
                    .controller_id
                    .clone()
                    .ok_or_else(|| Self::missing("controller_id"))?;
                Ok(IdentityChange::Revoke(RevokeRequest {
                    deployment_id: self.deployment_id.clone(),
                    controller_id,
                }))
            }
            _ => Err(invalid_action()),
        }
    }
}

fn invalid_action() -> HttpResponse {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "action 必须是 bind/add/rotate/revoke，且携带对应载荷.",
    )
}

fn oauth_error_description_field(field: &str) -> &'static str {
    match field {
        "label" => "缺少 label 字段.",
        "public_key" => "缺少 public_key 字段.",
        "kid" => "缺少 kid 字段.",
        _ => "缺少 controller_id 字段.",
    }
}

fn oauth_error_unexpected_field(_field: &str) -> &'static str {
    "该动作不允许携带此字段."
}

/// POST /admin/controller-registry/approvals
///
/// Issues one single-use approval token bound to the exact action payload.
/// Requires a fresh interactive MFA step-up: an old privileged session can
/// browse, but it cannot authorize a machine identity change.
pub(crate) async fn admin_controller_approval(
    admin_sessions: Data<AdminSessionHandles>,
    registry: Data<ControllerRegistryService>,
    req: HttpRequest,
    Json(body): Json<ApprovalRequestBody>,
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
    let change = match body.change() {
        Ok(change) => change,
        Err(response) => return response,
    };
    match registry
        .issue_approval(admin.id(), &change, Utc::now())
        .await
    {
        Ok(issued) => {
            // Durable evidence that a fresh-MFA administrator approved this
            // exact action digest.  The plaintext token is never audited.
            if let Err(response) = persist_required_audit_or_unavailable(
                "controller_identity_approval_issued",
                audit_fields(&[
                    ("actor_user_id", serde_json::json!(admin.id().to_string())),
                    ("deployment_id", serde_json::json!(change.deployment_id())),
                    ("action", serde_json::json!(issued.action.as_str())),
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
                // The plaintext token appears here and nowhere else — never in
                // logs or audit payloads.
                "approval_token": issued.token,
                "action": issued.action.as_str(),
                "action_sha256": issued.action_sha256,
                "expires_at": issued.expires_at.to_rfc3339(),
                "single_use": true,
            }))
        }
        Err(error) => service_error_response(error),
    }
}

/// POST /admin/controller-registry/slots 请求体。
///
/// bind 与 add 共用该载荷；`action` 决定审批绑定语义。字段显式声明以保持
/// 严格反序列化（serde flatten 会削弱 deny_unknown_fields 的严格性）。
/// P0-3：仅 bind 允许携带 recovery 双字段（与审批同一原子载荷）。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SlotCommitBody {
    pub approval_token: String,
    pub action: String,
    pub deployment_id: String,
    pub label: String,
    pub public_key: String,
    pub kid: String,
    #[serde(default)]
    pub recovery_public_key: Option<String>,
    #[serde(default)]
    pub recovery_kid: Option<String>,
}

impl SlotCommitBody {
    fn request(&self) -> SlotChangeRequest {
        SlotChangeRequest {
            deployment_id: self.deployment_id.clone(),
            label: self.label.clone(),
            kid: self.kid.clone(),
            public_key: self.public_key.clone(),
            recovery_public_key: self.recovery_public_key.clone(),
            recovery_kid: self.recovery_kid.clone(),
        }
    }

    fn action(&self) -> Result<ControllerIdentityAction, HttpResponse> {
        match self.action.as_str() {
            "bind" => Ok(ControllerIdentityAction::Bind),
            "add" => Ok(ControllerIdentityAction::Add),
            _ => Err(invalid_action()),
        }
    }
}

/// POST /admin/controller-registry/slots
///
/// Commits an approved bind/add.  The approval token must be unconsumed,
/// unexpired, and bound to exactly this payload; consumption and enrollment
/// share one transaction.
pub(crate) async fn admin_controller_slot_commit(
    admin_sessions: Data<AdminSessionHandles>,
    registry: Data<ControllerRegistryService>,
    req: HttpRequest,
    Json(body): Json<SlotCommitBody>,
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
    let action = match body.action() {
        Ok(action) => action,
        Err(response) => return response,
    };
    match registry
        .commit_creation(&body.approval_token, action, &body.request(), Utc::now())
        .await
    {
        Ok(slot) => emit_slot_event("controller_slot_created", admin.id(), &slot).await,
        Err(error) => service_error_response(error),
    }
}

/// POST /admin/controller-registry/slots/rotate 请求体。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SlotRotateBody {
    pub approval_token: String,
    pub deployment_id: String,
    pub controller_id: String,
    pub label: String,
    pub public_key: String,
    pub kid: String,
}

impl SlotRotateBody {
    fn request(&self) -> RotateRequest {
        RotateRequest {
            deployment_id: self.deployment_id.clone(),
            controller_id: self.controller_id.clone(),
            label: self.label.clone(),
            kid: self.kid.clone(),
            public_key: self.public_key.clone(),
        }
    }
}

/// POST /admin/controller-registry/slots/rotate
pub(crate) async fn admin_controller_slot_rotate(
    admin_sessions: Data<AdminSessionHandles>,
    registry: Data<ControllerRegistryService>,
    req: HttpRequest,
    Json(body): Json<SlotRotateBody>,
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
    match registry
        .commit_rotation(&body.approval_token, &body.request(), Utc::now())
        .await
    {
        Ok(slot) => emit_slot_event("controller_slot_rotated", admin.id(), &slot).await,
        Err(error) => service_error_response(error),
    }
}

/// POST /admin/controller-registry/slots/revoke 请求体。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SlotRevokeBody {
    pub approval_token: String,
    pub deployment_id: String,
    pub controller_id: String,
}

impl SlotRevokeBody {
    fn request(&self) -> RevokeRequest {
        RevokeRequest {
            deployment_id: self.deployment_id.clone(),
            controller_id: self.controller_id.clone(),
        }
    }
}

/// POST /admin/controller-registry/slots/revoke
pub(crate) async fn admin_controller_slot_revoke(
    admin_sessions: Data<AdminSessionHandles>,
    registry: Data<ControllerRegistryService>,
    req: HttpRequest,
    Json(body): Json<SlotRevokeBody>,
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
    match registry
        .commit_revocation(&body.approval_token, &body.request(), Utc::now())
        .await
    {
        Ok(slot) => emit_slot_event("controller_slot_revoked", admin.id(), &slot).await,
        Err(error) => service_error_response(error),
    }
}

async fn emit_slot_event(
    event: &'static str,
    actor: uuid::Uuid,
    slot: &StoredControllerSlot,
) -> HttpResponse {
    if let Err(response) = persist_required_audit_or_unavailable(
        event,
        audit_fields(&[
            ("actor_user_id", serde_json::json!(actor.to_string())),
            ("deployment_id", serde_json::json!(slot.deployment_id)),
            ("controller_id", serde_json::json!(slot.controller_id)),
            ("kid", serde_json::json!(slot.kid)),
            ("slot_index", serde_json::json!(slot.slot_index)),
            (
                "expires_at",
                serde_json::json!(slot.expires_at.to_rfc3339()),
            ),
        ]),
    )
    .await
    {
        return response;
    }
    slot_response(slot)
}

fn status_str(status: ControllerSlotStatus) -> &'static str {
    match status {
        ControllerSlotStatus::Active => "active",
        ControllerSlotStatus::Revoked => "revoked",
    }
}

fn slot_view(slot: &StoredControllerSlot) -> serde_json::Value {
    serde_json::json!({
        "deployment_id": slot.deployment_id,
        "controller_id": slot.controller_id,
        "label": slot.label,
        "kid": slot.kid,
        "slot_index": slot.slot_index,
        "issued_at": slot.issued_at.to_rfc3339(),
        "expires_at": slot.expires_at.to_rfc3339(),
        "status": status_str(slot.status),
        "warning": expiry_warning(Utc::now(), slot.expires_at).map(|warning| match warning {
            ControllerKeyWarning::Urgent => "urgent_24h",
            ControllerKeyWarning::Expiring => "expiring_7d",
        }),
    })
}

fn slot_response(slot: &StoredControllerSlot) -> HttpResponse {
    json_response(serde_json::json!({ "slot": slot_view(slot) }))
}

fn slots_list_response(deployment_id: &str, slots: &[StoredControllerSlot]) -> HttpResponse {
    let items: Vec<serde_json::Value> = slots.iter().map(slot_view).collect();
    json_response(serde_json::json!({
        "deployment_id": deployment_id,
        "total": items.len(),
        "max_active_slots": MAX_ACTIVE_CONTROLLER_SLOTS,
        "items": items,
    }))
}

/// Typed mapping onto the admin error conventions; infrastructure faults stay
/// opaque while operator mistakes get actionable descriptions.  Audit payloads
/// and logs never include approval tokens or key material.
fn service_error_response(error: ControllerRegistryServiceError) -> HttpResponse {
    match error {
        ControllerRegistryServiceError::Invalid(description) => {
            oauth_error(StatusCode::BAD_REQUEST, "invalid_request", description)
        }
        ControllerRegistryServiceError::SlotLimit(summaries) => {
            let items: Vec<serde_json::Value> = summaries
                .iter()
                .map(|summary| {
                    serde_json::json!({
                        "controller_id": summary.controller_id,
                        "label": summary.label,
                        "kid": summary.kid,
                        "slot_index": summary.slot_index,
                        "expires_at": summary.expires_at.to_rfc3339(),
                    })
                })
                .collect();
            HttpResponse::build(StatusCode::CONFLICT).json(serde_json::json!({
                "error": "controller_slot_limit",
                "error_description":
                    "该 deployment 已有三个未撤销控制器槽位；必须先撤销再新增.",
                "active_slots": items,
            }))
        }
        ControllerRegistryServiceError::UnknownController => oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "未找到该 controller_id 对应的控制器槽位.",
        ),
        ControllerRegistryServiceError::AlreadyRevoked => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "该控制器槽位已处于撤销终态.",
        ),
        ControllerRegistryServiceError::DuplicateKid => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "同一 deployment 下已存在相同 kid 的控制器密钥.",
        ),
        ControllerRegistryServiceError::ApprovalRejected(rejection) => {
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
        ControllerRegistryServiceError::Transport(error) => {
            tracing::warn!(%error, "controller registry storage failure");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "控制器注册表暂不可用.",
            )
        }
    }
}
