//! Controller Registry service layer (D01/D02/D05).
//!
//! NazoAuth is the single authority for Controller Public Keys, their fixed
//! 30-day lifetime, the three-slot bound, and the fresh-2FA approvals that
//! authorize every identity change.  This module is the typed surface between
//! the admin HTTP plane and the selected persistence adapter; it owns
//!
//! * request-shape validation (identifier formats, key material decoding,
//!   `kid`/key binding) before anything reaches storage;
//! * the action digest binding: every approval carries the SHA-256 of the
//!   exact canonical payload it authorizes, and commit re-computes and
//!   enforces that binding inside the same transaction as the mutation;
//! * expiry-warning classification (7-day / 24-hour, 04 §2) as a pure
//!   function shared by status surfaces.
//!
//! The service APIs here are what the later D04/D06 streams (bind proposal
//! flow, atomic first-bind commit) and E04 (operation admission by
//! deployment id) consume; this stream intentionally does not rewrite the
//! operator task binary.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub use nazo_persistence::control_plane::{
    CONTROLLER_KEY_TTL_SECONDS, IDENTITY_APPROVAL_TTL_SECONDS, MAX_ACTIVE_CONTROLLER_SLOTS,
};

use nazo_persistence::control_plane::{
    AdmittedController, CommitWithApprovalError, ControllerIdentityAction, ControllerRegistryError,
    ControllerRegistryPort, ControllerSlotSummary, IdentityApprovalError, IssuedIdentityApproval,
    NewControllerSlot, NewRecoveryRoot, RotateControllerKey, StoredControllerSlot,
};

/// Fixed 7-day pre-expiry warning threshold (04 §2).
pub const EXPIRY_WARNING_DAYS: i64 = 7;
/// Fixed 24-hour urgent pre-expiry warning threshold (04 §2).
pub const EXPIRY_URGENT_HOURS: i64 = 24;

/// Pre-expiry warning level of a controller slot at time `now`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerKeyWarning {
    /// Fewer than 24 hours remain.
    Urgent,
    /// Fewer than 7 days remain.
    Expiring,
}

/// Pure policy predicate shared by status surfaces (D09 consumes the render).
#[must_use]
pub fn expiry_warning(
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Option<ControllerKeyWarning> {
    let remaining = expires_at - now;
    if remaining <= Duration::hours(EXPIRY_URGENT_HOURS) {
        Some(ControllerKeyWarning::Urgent)
    } else if remaining <= Duration::days(EXPIRY_WARNING_DAYS) {
        Some(ControllerKeyWarning::Expiring)
    } else {
        None
    }
}

/// One pending controller identity change offered for fresh-2FA approval.
///
/// The wire shape mirrors the proposal fields of 04 §6 for this stream's scope
/// (recovery-root fields land with 04A).  Deserialization is strict: unknown
/// members are rejected so an approval can never silently cover more than the
/// administrator saw.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SlotChangeRequest {
    pub deployment_id: String,
    pub label: String,
    /// Unpadded base64url encoding of the raw 32-byte Ed25519 public key.
    pub public_key: String,
    /// Unpadded base64url SHA-256 of the public key bytes.
    pub kid: String,
    /// P0-3 atomic first binding: the replacement Recovery Public Key that
    /// the SAME transaction must enroll as generation 1. Only `bind` may
    /// carry it — a fresh install can never be left without a Recovery Root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_public_key: Option<String>,
    /// Unpadded base64url SHA-256 of `recovery_public_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_kid: Option<String>,
}

/// Rotation keeps the same `controller_id` and replaces its key material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RotateRequest {
    pub deployment_id: String,
    pub controller_id: String,
    pub label: String,
    pub public_key: String,
    pub kid: String,
}

/// Revocation requires the exact controller id; label matching is refused.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    pub deployment_id: String,
    pub controller_id: String,
}

/// The exact payload an approval covers.  The digest input is compact JSON
/// with sorted keys (`serde_json`'s default map), so both the issuing screen
/// and the committing call derive identical digests from identical payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityChange {
    Bind(SlotChangeRequest),
    Add(SlotChangeRequest),
    Rotate(RotateRequest),
    Revoke(RevokeRequest),
}

impl IdentityChange {
    #[must_use]
    pub fn action(&self) -> ControllerIdentityAction {
        match self {
            Self::Bind(_) => ControllerIdentityAction::Bind,
            Self::Add(_) => ControllerIdentityAction::Add,
            Self::Rotate(_) => ControllerIdentityAction::Rotate,
            Self::Revoke(_) => ControllerIdentityAction::Revoke,
        }
    }

    #[must_use]
    pub fn deployment_id(&self) -> &str {
        match self {
            Self::Bind(request) | Self::Add(request) => &request.deployment_id,
            Self::Rotate(request) => &request.deployment_id,
            Self::Revoke(request) => &request.deployment_id,
        }
    }

    fn validate(&self) -> Result<(), ControllerRegistryServiceError> {
        match self {
            Self::Bind(request) => {
                validate_slot_request(
                    &request.deployment_id,
                    &request.label,
                    &request.kid,
                    &request.public_key,
                )?;
                // P0-3: the first binding MUST enroll a Recovery Root in the
                // same transaction; a deployment can never be left without
                // one. Both fields must arrive together and bind to each other.
                let (Some(recovery_public_key), Some(recovery_kid)) = (
                    request.recovery_public_key.as_deref(),
                    request.recovery_kid.as_deref(),
                ) else {
                    return Err(ControllerRegistryServiceError::Invalid(
                        "bind 必须携带 recovery_public_key/recovery_kid，首次绑定与 Recovery Root 是一个原子事务.",
                    ));
                };
                validate_recovery_binding(recovery_public_key, recovery_kid)?;
                Ok(())
            }
            Self::Add(request) => {
                if request.recovery_public_key.is_some() || request.recovery_kid.is_some() {
                    return Err(ControllerRegistryServiceError::Invalid(
                        "add 不允许携带 recovery 字段；Recovery Root 只随首次 bind 建立.",
                    ));
                }
                validate_slot_request(
                    &request.deployment_id,
                    &request.label,
                    &request.kid,
                    &request.public_key,
                )?;
                Ok(())
            }
            Self::Rotate(request) => {
                validate_controller_id(&request.controller_id)?;
                validate_slot_request(
                    &request.deployment_id,
                    &request.label,
                    &request.kid,
                    &request.public_key,
                )?;
                Ok(())
            }
            Self::Revoke(request) => {
                validate_deployment(&request.deployment_id)?;
                validate_controller_id(&request.controller_id)?;
                Ok(())
            }
        }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        // serde_json maps are BTreeMap-backed in this workspace, so member
        // order is sorted-key deterministic; compact serialization makes the
        // digest independent of transport formatting.
        let value = match self {
            Self::Bind(request) => {
                // P0-3: the recovery fields belong to the approved payload
                // whenever present, so the digest binds exactly what the
                // administrator saw and what the commit will enroll.
                let mut map = serde_json::Map::from_iter([
                    ("action".to_owned(), serde_json::json!("bind")),
                    (
                        "deployment_id".to_owned(),
                        serde_json::json!(request.deployment_id),
                    ),
                    ("kid".to_owned(), serde_json::json!(request.kid)),
                    ("label".to_owned(), serde_json::json!(request.label)),
                    (
                        "public_key".to_owned(),
                        serde_json::json!(request.public_key),
                    ),
                ]);
                if let Some(recovery_kid) = &request.recovery_kid {
                    map.insert("recovery_kid".to_owned(), serde_json::json!(recovery_kid));
                }
                if let Some(recovery_public_key) = &request.recovery_public_key {
                    map.insert(
                        "recovery_public_key".to_owned(),
                        serde_json::json!(recovery_public_key),
                    );
                }
                serde_json::Value::Object(map)
            }
            Self::Add(request) => serde_json::json!({
                "action": "add",
                "deployment_id": request.deployment_id,
                "kid": request.kid,
                "label": request.label,
                "public_key": request.public_key,
            }),
            Self::Rotate(request) => serde_json::json!({
                "action": "rotate",
                "controller_id": request.controller_id,
                "deployment_id": request.deployment_id,
                "kid": request.kid,
                "label": request.label,
                "public_key": request.public_key,
            }),
            Self::Revoke(request) => serde_json::json!({
                "action": "revoke",
                "controller_id": request.controller_id,
                "deployment_id": request.deployment_id,
            }),
        };
        serde_json::to_vec(&value).expect("sorted-key JSON serialization cannot fail")
    }

    /// Lowercase hex SHA-256 of the canonical payload; the value an approval
    /// is bound to and a commit must reproduce exactly.
    #[must_use]
    pub fn action_sha256(&self) -> String {
        let mut encoded = String::with_capacity(64);
        for byte in Sha256::digest(self.canonical_bytes()) {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("hex writing cannot fail");
        }
        encoded
    }
}

fn validate_deployment(value: &str) -> Result<(), ControllerRegistryServiceError> {
    nazo_operator_protocol::validate_file_identifier_value(value).map_err(|_| {
        ControllerRegistryServiceError::Invalid("deployment_id 不是合法的文件安全标识符.")
    })
}

fn validate_controller_id(value: &str) -> Result<(), ControllerRegistryServiceError> {
    nazo_operator_protocol::validate_controller_id(value).map_err(|_| {
        ControllerRegistryServiceError::Invalid("controller_id 必须是规范的小写 UUIDv7.")
    })
}

/// Decode and fully bind one slot change request: identifier shapes, bounded
/// label, 32-byte key material, and `kid == base64url(SHA-256(key))`.  The
/// server never trusts a `kid` that does not match its key bytes.
fn validate_slot_request(
    deployment_id: &str,
    label: &str,
    kid: &str,
    public_key_text: &str,
) -> Result<[u8; 32], ControllerRegistryServiceError> {
    validate_deployment(deployment_id)?;
    if label.is_empty() || label.len() > 128 || label.chars().any(char::is_control) {
        return Err(ControllerRegistryServiceError::Invalid(
            "label 必须为 1..=128 个受限文本字符.",
        ));
    }
    let public_key = decode_public_key(public_key_text)?;
    let derived_kid = URL_SAFE_NO_PAD.encode(Sha256::digest(public_key));
    if derived_kid != kid {
        return Err(ControllerRegistryServiceError::Invalid(
            "kid 与公钥材料不匹配.",
        ));
    }
    Ok(public_key)
}

/// Typed service failures; the HTTP boundary maps these onto the admin error
/// conventions without losing the distinction between operator mistakes and
/// infrastructure faults.
#[derive(Debug)]
pub enum ControllerRegistryServiceError {
    /// Malformed request; nothing was persisted or approved.
    Invalid(&'static str),
    /// Fourth active slot requested; carries non-secret active summaries.
    SlotLimit(Vec<ControllerSlotSummary>),
    UnknownController,
    AlreadyRevoked,
    DuplicateKid,
    ApprovalRejected(IdentityApprovalError),
    Transport(anyhow::Error),
}

impl From<CommitWithApprovalError> for ControllerRegistryServiceError {
    fn from(error: CommitWithApprovalError) -> Self {
        match error {
            CommitWithApprovalError::Approval(inner) => Self::ApprovalRejected(inner),
            CommitWithApprovalError::Mutation(ControllerRegistryError::SlotLimit(summaries)) => {
                Self::SlotLimit(summaries)
            }
            CommitWithApprovalError::Mutation(ControllerRegistryError::UnknownController) => {
                Self::UnknownController
            }
            CommitWithApprovalError::Mutation(ControllerRegistryError::AlreadyRevoked) => {
                Self::AlreadyRevoked
            }
            CommitWithApprovalError::Mutation(ControllerRegistryError::DuplicateKid) => {
                Self::DuplicateKid
            }
            CommitWithApprovalError::Mutation(ControllerRegistryError::InvalidIdentity(reason)) => {
                Self::Invalid(reason)
            }
            CommitWithApprovalError::Mutation(ControllerRegistryError::Transport(inner))
            | CommitWithApprovalError::Transport(inner) => Self::Transport(inner),
        }
    }
}

impl From<ControllerRegistryError> for ControllerRegistryServiceError {
    fn from(error: ControllerRegistryError) -> Self {
        match error {
            ControllerRegistryError::SlotLimit(summaries) => Self::SlotLimit(summaries),
            ControllerRegistryError::UnknownController => Self::UnknownController,
            ControllerRegistryError::AlreadyRevoked => Self::AlreadyRevoked,
            ControllerRegistryError::DuplicateKid => Self::DuplicateKid,
            ControllerRegistryError::InvalidIdentity(reason) => Self::Invalid(reason),
            ControllerRegistryError::Transport(inner) => Self::Transport(inner),
        }
    }
}

/// One issued approval as surfaced to the approving administrator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedApprovalView {
    /// Single-use bearer token; shown exactly once, never logged or stored.
    pub token: String,
    pub action: ControllerIdentityAction,
    pub action_sha256: String,
    pub expires_at: DateTime<Utc>,
}

/// Service facade over the registry repository.  Cheap to clone.
#[derive(Clone)]
pub struct ControllerRegistryService {
    repository: Arc<dyn ControllerRegistryPort>,
}

impl ControllerRegistryService {
    #[must_use]
    pub fn new(repository: Arc<dyn ControllerRegistryPort>) -> Self {
        Self { repository }
    }

    /// Issue a single-use approval for one exact identity change.  The
    /// caller's fresh-MFA obligation is enforced at the HTTP boundary; this
    /// method validates the payload shape and binds the approval to its
    /// digest, deployment, action, and the approving administrator.
    pub async fn issue_approval(
        &self,
        actor_admin_user_id: Uuid,
        change: &IdentityChange,
        now: DateTime<Utc>,
    ) -> Result<IssuedApprovalView, ControllerRegistryServiceError> {
        change.validate()?;
        let issued: IssuedIdentityApproval = self
            .repository
            .issue_identity_approval(
                change.deployment_id(),
                change.action(),
                &change.action_sha256(),
                actor_admin_user_id,
                now,
            )
            .await
            .map_err(ControllerRegistryServiceError::approval_transport)?;
        Ok(IssuedApprovalView {
            token: issued.token,
            action: issued.action,
            action_sha256: issued.action_sha256,
            expires_at: issued.expires_at,
        })
    }

    /// Consume one approval and enroll the approved slot atomically
    /// (bind/add share the storage shape; the action distinguishes them).
    pub async fn commit_creation(
        &self,
        approval_token: &str,
        action: ControllerIdentityAction,
        request: &SlotChangeRequest,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, ControllerRegistryServiceError> {
        if !matches!(
            action,
            ControllerIdentityAction::Bind | ControllerIdentityAction::Add
        ) {
            return Err(ControllerRegistryServiceError::Invalid(
                "该端点只接受 bind/add 动作.",
            ));
        }
        let change = if action == ControllerIdentityAction::Bind {
            IdentityChange::Bind(request.clone())
        } else {
            IdentityChange::Add(request.clone())
        };
        change.validate()?;
        let slot = NewControllerSlot {
            deployment_id: request.deployment_id.clone(),
            label: request.label.clone(),
            kid: request.kid.clone(),
            public_key: decode_public_key(&request.public_key)?,
        };
        // P0-3: a bind carries the initial Recovery Root; the repository
        // enrolls it inside the SAME transaction as approval consumption and
        // slot insertion, refusing if a root already exists.
        let initial_root = match (
            action,
            request.recovery_public_key.as_deref(),
            request.recovery_kid.as_deref(),
        ) {
            (ControllerIdentityAction::Bind, Some(recovery_public_key), Some(recovery_kid)) => {
                Some(NewRecoveryRoot {
                    deployment_id: request.deployment_id.clone(),
                    kid: recovery_kid.to_owned(),
                    public_key: decode_public_key(recovery_public_key)?,
                })
            }
            _ => None,
        };
        let committed = self
            .repository
            .commit_slot_creation(
                approval_token,
                action,
                &change.action_sha256(),
                slot,
                initial_root,
                now,
            )
            .await?;
        Ok(committed)
    }

    /// Consume one approval and rotate the approved slot atomically.
    pub async fn commit_rotation(
        &self,
        approval_token: &str,
        request: &RotateRequest,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, ControllerRegistryServiceError> {
        let change = IdentityChange::Rotate(request.clone());
        change.validate()?;
        let rotation = RotateControllerKey {
            deployment_id: request.deployment_id.clone(),
            controller_id: request.controller_id.clone(),
            label: request.label.clone(),
            kid: request.kid.clone(),
            public_key: decode_public_key(&request.public_key)?,
        };
        let committed = self
            .repository
            .commit_slot_rotation(
                approval_token,
                &request.deployment_id,
                &change.action_sha256(),
                rotation,
                now,
            )
            .await?;
        Ok(committed)
    }

    /// Consume one approval and revoke the approved slot atomically.
    pub async fn commit_revocation(
        &self,
        approval_token: &str,
        request: &RevokeRequest,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, ControllerRegistryServiceError> {
        let change = IdentityChange::Revoke(request.clone());
        change.validate()?;
        let committed = self
            .repository
            .commit_slot_revocation(
                approval_token,
                &request.deployment_id,
                &change.action_sha256(),
                &request.controller_id,
                now,
            )
            .await?;
        Ok(committed)
    }

    /// Authoritative answer to "which controllers exist for this deployment
    /// and when do they expire".  Includes revoked history rows.
    pub async fn list_slots(
        &self,
        deployment_id: &str,
    ) -> Result<Vec<StoredControllerSlot>, ControllerRegistryServiceError> {
        Ok(self.repository.list_slots(deployment_id).await?)
    }

    /// E04 verification-order lookup ("按 deployment_id 查 controller
    /// kid/public key"): all keys that would admit a new operation at `now`.
    pub async fn admitted_controllers(
        &self,
        deployment_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<AdmittedController>, ControllerRegistryServiceError> {
        Ok(self
            .repository
            .admitted_controllers(deployment_id, now)
            .await?)
    }

    /// Single-kid admission check used when verifying one presented envelope.
    pub async fn admitted_controller_by_kid(
        &self,
        deployment_id: &str,
        kid: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AdmittedController>, ControllerRegistryServiceError> {
        Ok(self
            .repository
            .admitted_controller_by_kid(deployment_id, kid, now)
            .await?)
    }
}

impl ControllerRegistryServiceError {
    fn approval_transport<E>(error: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::Transport(error.into())
    }
}

fn decode_public_key(text: &str) -> Result<[u8; 32], ControllerRegistryServiceError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or(ControllerRegistryServiceError::Invalid(
            "public_key 必须是 32 字节 Ed25519 公钥的未填充 base64url 编码.",
        ))
}

/// P0-3: shape + binding check for the recovery material a bind carries.
fn validate_recovery_binding(
    recovery_public_key: &str,
    recovery_kid: &str,
) -> Result<(), ControllerRegistryServiceError> {
    let key = decode_public_key(recovery_public_key)?;
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(key));
    if digest != recovery_kid {
        return Err(ControllerRegistryServiceError::Invalid(
            "recovery_kid 与 recovery_public_key 不匹配.",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/controller_registry.rs"]
mod tests;
