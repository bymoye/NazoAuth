//! Database-independent controller identity and recovery capabilities.
//!
//! Each mutating method expresses the complete atomic business operation. An
//! adapter may use transactions, locks and durable receipts internally, but
//! none of those backend mechanisms cross this boundary.

use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;
use uuid::Uuid;

pub const CONTROLLER_KEY_TTL_SECONDS: i64 = 2_592_000;
pub const IDENTITY_APPROVAL_TTL_SECONDS: i64 = 600;
pub const MAX_ACTIVE_CONTROLLER_SLOTS: usize = 3;
pub const RECOVERY_CHALLENGE_TTL_SECONDS: i64 = 600;
pub const MAX_RECOVERY_CHALLENGE_ATTEMPTS: i32 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerSlotStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredControllerSlot {
    pub deployment_id: String,
    pub controller_id: String,
    pub label: String,
    pub kid: String,
    pub public_key: Vec<u8>,
    pub slot_index: i16,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub status: ControllerSlotStatus,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl StoredControllerSlot {
    #[must_use]
    pub fn summary(&self) -> ControllerSlotSummary {
        ControllerSlotSummary {
            controller_id: self.controller_id.clone(),
            label: self.label.clone(),
            kid: self.kid.clone(),
            slot_index: self.slot_index,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            status: self.status,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerSlotSummary {
    pub controller_id: String,
    pub label: String,
    pub kid: String,
    pub slot_index: i16,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: ControllerSlotStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedController {
    pub controller_id: String,
    pub kid: String,
    pub public_key: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct NewControllerSlot {
    pub deployment_id: String,
    pub label: String,
    pub kid: String,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct RotateControllerKey {
    pub deployment_id: String,
    pub controller_id: String,
    pub label: String,
    pub kid: String,
    pub public_key: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerIdentityAction {
    Bind,
    Add,
    Rotate,
    Revoke,
    RecoveryRootRotate,
}

impl ControllerIdentityAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Add => "add",
            Self::Rotate => "rotate",
            Self::Revoke => "revoke",
            Self::RecoveryRootRotate => "recovery-root-rotate",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "bind" => Some(Self::Bind),
            "add" => Some(Self::Add),
            "rotate" => Some(Self::Rotate),
            "revoke" => Some(Self::Revoke),
            "recovery-root-rotate" => Some(Self::RecoveryRootRotate),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum IdentityApprovalError {
    UnknownToken,
    Replayed,
    Expired,
    ActionMismatch,
    Transport(anyhow::Error),
}

impl std::fmt::Display for IdentityApprovalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownToken => formatter.write_str("unknown approval token"),
            Self::Replayed => formatter.write_str("approval token already consumed"),
            Self::Expired => formatter.write_str("approval token expired"),
            Self::ActionMismatch => formatter.write_str("approval does not cover this action"),
            Self::Transport(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for IdentityApprovalError {}

#[derive(Debug)]
pub enum ControllerRegistryError {
    SlotLimit(Vec<ControllerSlotSummary>),
    UnknownController,
    AlreadyRevoked,
    DuplicateKid,
    InvalidIdentity(&'static str),
    Transport(anyhow::Error),
}

impl std::fmt::Display for ControllerRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SlotLimit(_) => formatter.write_str("CONTROLLER_SLOT_LIMIT"),
            Self::UnknownController => formatter.write_str("unknown controller slot"),
            Self::AlreadyRevoked => formatter.write_str("controller slot already revoked"),
            Self::DuplicateKid => formatter.write_str("controller kid already registered"),
            Self::InvalidIdentity(reason) => formatter.write_str(reason),
            Self::Transport(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for ControllerRegistryError {}

#[derive(Debug)]
pub enum CommitWithApprovalError {
    Approval(IdentityApprovalError),
    Mutation(ControllerRegistryError),
    Transport(anyhow::Error),
}

impl std::fmt::Display for CommitWithApprovalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approval(error) => write!(formatter, "{error}"),
            Self::Mutation(error) => write!(formatter, "{error}"),
            Self::Transport(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for CommitWithApprovalError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedIdentityApproval {
    pub approval_id: Uuid,
    pub action: ControllerIdentityAction,
    pub action_sha256: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRecoveryRoot {
    pub deployment_id: String,
    pub recovery_kid: String,
    pub recovery_public_key: Vec<u8>,
    pub kdf: String,
    pub generation: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRootSummary {
    pub deployment_id: String,
    pub recovery_kid: String,
    pub kdf: String,
    pub generation: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl StoredRecoveryRoot {
    #[must_use]
    pub fn summary(&self) -> RecoveryRootSummary {
        RecoveryRootSummary {
            deployment_id: self.deployment_id.clone(),
            recovery_kid: self.recovery_kid.clone(),
            kdf: self.kdf.clone(),
            generation: self.generation,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedControllerSummary {
    pub controller_id: String,
    pub kid: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct NewRecoveryRoot {
    pub deployment_id: String,
    pub kid: String,
    pub public_key: [u8; 32],
}

#[derive(Clone)]
pub struct NewRecoveryChallenge {
    pub deployment_id: String,
    pub controller_label: String,
    pub controller_kid: String,
    pub controller_public_key: [u8; 32],
    pub recovery_kid: String,
    pub recovery_public_key: [u8; 32],
    pub allocation_nonce: [u8; 32],
    pub allocation_signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedRecoveryChallenge {
    pub challenge_id: Uuid,
    pub deployment_id: String,
    pub nonce: [u8; 32],
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct RecoverySubmission {
    pub deployment_id: String,
    pub challenge_id: Uuid,
    pub nonce: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredSlotCommit {
    pub slot: StoredControllerSlot,
    pub recovery_generation: i32,
}

#[derive(Debug)]
pub enum RecoveryRootError {
    ControllersStillAdmitted(Vec<AdmittedControllerSummary>),
    ChallengePending,
    InvalidAllocationProof,
    AllocationProofReplayed,
    ChallengeUnknown,
    ChallengeExpired,
    ChallengeExhausted,
    ChallengeReplayed,
    NonceMismatch,
    InvalidSignature,
    RootMissing,
    InvalidIdentity(&'static str),
    Transport(anyhow::Error),
}

impl std::fmt::Display for RecoveryRootError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ControllersStillAdmitted(_) => formatter.write_str("CONTROLLER_STILL_ADMITTED"),
            Self::ChallengePending => formatter.write_str("RECOVERY_CHALLENGE_PENDING"),
            Self::InvalidAllocationProof => {
                formatter.write_str("invalid recovery allocation proof")
            }
            Self::AllocationProofReplayed => {
                formatter.write_str("recovery allocation proof already used")
            }
            Self::ChallengeUnknown => formatter.write_str("unknown recovery challenge"),
            Self::ChallengeExpired => formatter.write_str("recovery challenge expired"),
            Self::ChallengeExhausted => formatter.write_str("recovery challenge exhausted"),
            Self::ChallengeReplayed => formatter.write_str("recovery challenge already consumed"),
            Self::NonceMismatch => formatter.write_str("challenge nonce mismatch"),
            Self::InvalidSignature => formatter.write_str("invalid recovery signature"),
            Self::RootMissing => formatter.write_str("no recovery root anchored"),
            Self::InvalidIdentity(reason) => formatter.write_str(reason),
            Self::Transport(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for RecoveryRootError {}

#[derive(Debug)]
pub enum RecoveryRotationError {
    Approval(IdentityApprovalError),
    Mutation(RecoveryRootError),
    Transport(anyhow::Error),
}

impl std::fmt::Display for RecoveryRotationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approval(error) => write!(formatter, "{error}"),
            Self::Mutation(error) => write!(formatter, "{error}"),
            Self::Transport(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for RecoveryRotationError {}

pub trait ControllerRegistryPort: Send + Sync {
    fn issue_identity_approval<'a>(
        &'a self,
        deployment_id: &'a str,
        action: ControllerIdentityAction,
        action_sha256: &'a str,
        admin_user_id: Uuid,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<IssuedIdentityApproval, IdentityApprovalError>>;
    fn commit_slot_creation<'a>(
        &'a self,
        approval_token: &'a str,
        expected_action: ControllerIdentityAction,
        expected_action_sha256: &'a str,
        slot: NewControllerSlot,
        initial_root: Option<NewRecoveryRoot>,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<StoredControllerSlot, CommitWithApprovalError>>;
    fn commit_slot_rotation<'a>(
        &'a self,
        approval_token: &'a str,
        expected_deployment_id: &'a str,
        expected_action_sha256: &'a str,
        rotation: RotateControllerKey,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<StoredControllerSlot, CommitWithApprovalError>>;
    fn commit_slot_revocation<'a>(
        &'a self,
        approval_token: &'a str,
        expected_deployment_id: &'a str,
        expected_action_sha256: &'a str,
        controller_id: &'a str,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<StoredControllerSlot, CommitWithApprovalError>>;
    fn list_slots<'a>(
        &'a self,
        deployment_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<StoredControllerSlot>, ControllerRegistryError>>;
    fn admitted_controllers<'a>(
        &'a self,
        deployment_id: &'a str,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<Vec<AdmittedController>, ControllerRegistryError>>;
    fn admitted_controller_by_kid<'a>(
        &'a self,
        deployment_id: &'a str,
        kid: &'a str,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<Option<AdmittedController>, ControllerRegistryError>>;
}

pub trait RecoveryRootPort: Send + Sync {
    fn current_root<'a>(
        &'a self,
        deployment_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredRecoveryRoot>, RecoveryRootError>>;
    fn issue_rotation_approval<'a>(
        &'a self,
        deployment_id: &'a str,
        action_sha256: &'a str,
        admin_user_id: Uuid,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<IssuedIdentityApproval, RecoveryRotationError>>;
    fn commit_rotation<'a>(
        &'a self,
        approval_token: &'a str,
        expected_deployment_id: &'a str,
        expected_action_sha256: &'a str,
        root: NewRecoveryRoot,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<StoredRecoveryRoot, RecoveryRotationError>>;
    fn issue_recovery_challenge(
        &self,
        challenge: NewRecoveryChallenge,
        now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<IssuedRecoveryChallenge, RecoveryRootError>>;
    fn submit_recovery_challenge(
        &self,
        submission: RecoverySubmission,
        now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<RecoveredSlotCommit, RecoveryRootError>>;
}
