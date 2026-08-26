//! Recovery Root service layer (04A D10/D11/D12).
//!
//! Typed surface between the admin HTTP plane and the PostgreSQL recovery
//! repository.  This module owns request-shape validation (identifier
//! formats, key-material decoding, kid/key binding through the shared
//! `nazo-operator-protocol` validators) before anything reaches storage.
//!
//! Authority boundaries pinned here:
//!
//! * only PUBLIC key material is representable in every request/response
//!   shape — there is no field anywhere that could carry the 32-byte Recovery
//!   Secret towards NazoAuth;
//! * D12 rotation reuses the fresh-2FA approval machinery under its own
//!   `recovery-root-rotate` action digest;
//! * D11 challenges are refused while any controller slot still admits,
//!   keeping the break-glass path unreachable whenever ordinary paths exist.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

pub use nazo_postgres::{MAX_RECOVERY_CHALLENGE_ATTEMPTS, RECOVERY_CHALLENGE_TTL_SECONDS};

use nazo_operator_protocol::{RecoveryProposal, RecoveryRootRotation};
use nazo_postgres::{
    IssuedIdentityApproval, NewRecoveryChallenge, NewRecoveryRoot, RecoveredSlotCommit,
    RecoveryRootError, RecoveryRootRepository, RecoveryRotationError, RecoverySubmission,
    StoredRecoveryRoot,
};

/// A pending replacement of the deployment's Recovery Public Key (D12).
/// Strict deserialization keeps an approval from ever covering more than the
/// administrator saw — and makes any attempt to smuggle a secret-shaped field
/// into NazoAuth a hard parse error.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRootChangeRequest {
    pub deployment_id: String,
    /// Unpadded base64url encoding of the raw 32-byte Ed25519 public key.
    pub recovery_public_key: String,
    /// Unpadded base64url SHA-256 of the public key bytes.
    pub kid: String,
}

/// One recovery challenge request (D11 steps 1–3): the exact proposed
/// replacement controller key and replacement Recovery Public Key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryChallengeRequest {
    pub deployment_id: String,
    pub label: String,
    pub controller_public_key: String,
    pub kid: String,
    pub recovery_public_key: String,
    pub recovery_kid: String,
}

/// The signed answer to one challenge (D11 steps 4–5).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAnswerRequest {
    pub deployment_id: String,
    pub challenge_id: String,
    /// Unpadded base64url encoding of the 32-byte nonce echo.
    pub nonce: String,
    /// Unpadded base64url encoding of the 64-byte Ed25519 signature over the
    /// canonical challenge message.
    pub signature: String,
}

/// Typed service failures; the HTTP boundary maps these onto the admin error
/// conventions without losing operator-mistake versus infrastructure-fault.
#[derive(Debug)]
pub enum RecoveryRootServiceError {
    Invalid(&'static str),
    Root(RecoveryRootError),
    Rotation(RecoveryRotationError),
}

impl From<RecoveryRootError> for RecoveryRootServiceError {
    fn from(error: RecoveryRootError) -> Self {
        Self::Root(error)
    }
}

impl From<RecoveryRotationError> for RecoveryRootServiceError {
    fn from(error: RecoveryRotationError) -> Self {
        Self::Rotation(error)
    }
}

/// One issued approval as surfaced to the approving administrator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedRotationApprovalView {
    /// Single-use bearer token; shown exactly once, never logged or stored.
    pub token: String,
    pub action_sha256: String,
    pub expires_at: DateTime<Utc>,
}

/// Service facade over the recovery repository.  Cheap to clone.
#[derive(Clone)]
pub struct RecoveryRootService {
    repository: Arc<RecoveryRootRepository>,
}

impl RecoveryRootService {
    #[must_use]
    pub fn new(repository: Arc<RecoveryRootRepository>) -> Self {
        Self { repository }
    }

    // -- Views ---------------------------------------------------------------

    /// Current Recovery Root of one deployment, if any.
    pub async fn current_root(
        &self,
        deployment_id: &str,
    ) -> Result<Option<StoredRecoveryRoot>, RecoveryRootServiceError> {
        Ok(self.repository.current_root(deployment_id).await?)
    }

    // -- D12: proactive rotation behind fresh 2FA -----------------------------

    /// Validate the change payload and issue its single-use approval bound to
    /// the exact canonical digest.  Fresh-MFA obligation sits at the HTTP
    /// boundary, mirroring the controller slot flow.
    pub async fn issue_rotation_approval(
        &self,
        actor_admin_user_id: Uuid,
        request: &RecoveryRootChangeRequest,
        now: DateTime<Utc>,
    ) -> Result<IssuedRotationApprovalView, RecoveryRootServiceError> {
        let rotation = validate_rotation_request(request)?;
        let issued: IssuedIdentityApproval = self
            .repository
            .issue_rotation_approval(
                &rotation.deployment_id,
                &rotation.action_sha256(),
                actor_admin_user_id,
                now,
            )
            .await?;
        Ok(IssuedRotationApprovalView {
            token: issued.token,
            action_sha256: issued.action_sha256,
            expires_at: issued.expires_at,
        })
    }

    /// Consume the approval and replace the root atomically.
    pub async fn commit_rotation(
        &self,
        approval_token: &str,
        request: &RecoveryRootChangeRequest,
        now: DateTime<Utc>,
    ) -> Result<StoredRecoveryRoot, RecoveryRootServiceError> {
        let rotation = validate_rotation_request(request)?;
        Ok(self
            .repository
            .commit_rotation(
                approval_token,
                &rotation.deployment_id,
                &rotation.action_sha256(),
                NewRecoveryRoot {
                    deployment_id: rotation.deployment_id.clone(),
                    kid: rotation.kid.clone(),
                    public_key: rotation.public_key,
                },
                now,
            )
            .await?)
    }

    // -- D11: break-glass challenge/response ----------------------------------

    /// Issue one challenge bound to the deployment plus the exact proposed
    /// key material.
    pub async fn issue_challenge(
        &self,
        request: &RecoveryChallengeRequest,
        now: DateTime<Utc>,
    ) -> Result<nazo_postgres::IssuedRecoveryChallenge, RecoveryRootServiceError> {
        let proposal = validate_challenge_request(request)?;
        let next_material = self
            .repository
            .issue_recovery_challenge(proposal, now)
            .await?;
        Ok(next_material)
    }

    /// Verify one signed answer against the current root and commit the
    /// recovery atomically.
    pub async fn recover(
        &self,
        request: &RecoveryAnswerRequest,
        now: DateTime<Utc>,
    ) -> Result<RecoveredSlotCommit, RecoveryRootServiceError> {
        let submission = validate_answer_request(request)?;
        Ok(self
            .repository
            .submit_recovery_challenge(submission, now)
            .await?)
    }
}

fn decode_key(text: &str) -> Result<[u8; 32], RecoveryRootServiceError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or(RecoveryRootServiceError::Invalid(
            "public_key 必须是 32 字节 Ed25519 公钥的未填充 base64url 编码.",
        ))
}

fn decode_fixed<const LENGTH: usize>(
    text: &str,
    description: &'static str,
) -> Result<[u8; LENGTH], RecoveryRootServiceError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|bytes| <[u8; LENGTH]>::try_from(bytes).ok())
        .ok_or(RecoveryRootServiceError::Invalid(description))
}

fn validate_rotation_request(
    request: &RecoveryRootChangeRequest,
) -> Result<RecoveryRootRotation, RecoveryRootServiceError> {
    let public_key = decode_key(&request.recovery_public_key)?;
    let rotation = RecoveryRootRotation {
        deployment_id: request.deployment_id.clone(),
        kid: request.kid.clone(),
        public_key,
    };
    rotation
        .validate()
        .map_err(|_| RecoveryRootServiceError::Invalid("deployment_id 或 kid 与公钥材料不匹配."))?;
    Ok(rotation)
}

fn validate_challenge_request(
    request: &RecoveryChallengeRequest,
) -> Result<NewRecoveryChallenge, RecoveryRootServiceError> {
    let controller_public_key = decode_key(&request.controller_public_key)?;
    let recovery_public_key = decode_key(&request.recovery_public_key)?;
    let proposal = RecoveryProposal {
        deployment_id: request.deployment_id.clone(),
        controller_label: request.label.clone(),
        controller_kid: request.kid.clone(),
        controller_public_key,
        recovery_kid: request.recovery_kid.clone(),
        recovery_public_key,
    };
    proposal.validate().map_err(|_| {
        RecoveryRootServiceError::Invalid(
            "恢复提案字段不合法：deployment/label/kid 必须与密钥材料绑定.",
        )
    })?;
    Ok(NewRecoveryChallenge {
        deployment_id: proposal.deployment_id,
        controller_label: proposal.controller_label,
        controller_kid: proposal.controller_kid,
        controller_public_key: proposal.controller_public_key,
        recovery_kid: proposal.recovery_kid,
        recovery_public_key: proposal.recovery_public_key,
    })
}

fn validate_answer_request(
    request: &RecoveryAnswerRequest,
) -> Result<RecoverySubmission, RecoveryRootServiceError> {
    let challenge_id = Uuid::parse_str(&request.challenge_id)
        .map_err(|_| RecoveryRootServiceError::Invalid("challenge_id 必须是规范 UUID."))?;
    Ok(RecoverySubmission {
        deployment_id: request.deployment_id.clone(),
        challenge_id,
        nonce: decode_fixed::<32>(
            &request.nonce,
            "nonce 必须是 32 字节的未填充 base64url 编码.",
        )?,
        signature: decode_fixed::<64>(
            &request.signature,
            "signature 必须是 64 字节 Ed25519 签名的未填充 base64url 编码.",
        )?,
    })
}

#[cfg(test)]
#[path = "../tests/unit/recovery_root.rs"]
mod tests;
