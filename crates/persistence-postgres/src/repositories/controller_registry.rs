//! Authoritative per-deployment Controller Public Key registry (D01/D02) and
//! single-use fresh-2FA identity approvals (D05).
//!
//! Storage ownership follows the dominant pattern for deployment-scoped
//! authoritative state in this workspace: PostgreSQL tables behind a Diesel
//! migration (`20260824000100_controller_registry`).  Unlike the E03 control
//! operation journal — which deliberately lives outside the database because
//! `migrate-apply` must work before any database exists — enrollment state is
//! written through the admin plane, whose approval flow already requires the
//! application database, and every lifecycle mutation must consume its fresh
//! 2FA approval in the *same* transaction that mutates the registry.
//!
//! Hard invariants enforced here (mirrored by CHECK/unique constraints in the
//! migration):
//!
//! * fixed 30-day TTL: `expires_at` is always computed server-side as
//!   `issued_at + CONTROLLER_KEY_TTL_SECONDS`; caller-supplied expiry is not a
//!   concept;
//! * at most [`MAX_ACTIVE_CONTROLLER_SLOTS`] concurrently non-revoked slots
//!   per deployment, serialized per deployment by an advisory transaction lock
//!   with the partial unique index as the race backstop;
//! * revocation is terminal: no code path moves a revoked slot back to
//!   `active`, rotation of a revoked slot is refused, and a second revoke is
//!   an explicit error instead of a silent success;
//! * admission ([`Self::admitted_controller_by_kid`] /
//!   [`Self::admitted_controllers`]) accepts only `active` slots with
//!   `expires_at > now`: an expired key fails new-operation admission exactly
//!   at the boundary, while already-accepted operations are unaffected (the
//!   control operation journal owns post-accept authorization);
//! * `kid` binding is validated server-side: `kid` must equal
//!   `base64url(SHA-256(public_key))`, so the registry can never store a key
//!   whose id does not match its material.
//!
//! Only public key material is ever persisted or returned; summaries shown on
//! limit errors carry identifiers and timestamps but never key bytes.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use diesel::OptionalExtension;
use diesel::QueryableByName;
use diesel::result::Error as QueryError;
use diesel::sql_query;
use diesel::sql_types::{
    BigInt, Binary, Nullable, SmallInt, Timestamptz, Uuid as DieselUuid, Varchar,
};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{DbPool, get_conn};

/// Fixed controller key lifetime in seconds: exactly 30 days (04 §2).  Not a
/// configuration item, never derived from a natural month, never renewed in
/// place.
pub const CONTROLLER_KEY_TTL_SECONDS: i64 = 2_592_000;

/// Maximum number of concurrently non-revoked controller slots per deployment.
pub const MAX_ACTIVE_CONTROLLER_SLOTS: usize = 3;

/// Fresh-2FA approval lifetime in seconds: a fixed 10-minute ceiling (04 §3).
pub const IDENTITY_APPROVAL_TTL_SECONDS: i64 = 600;

/// Advisory-lock seed namespace for the per-deployment identity lock. Slot
/// mutations AND Recovery Root/challenge mutations share this single lock so
/// a break-glass recovery cannot interleave its active-slot re-check and
/// batch revoke with a concurrent bind/rotate commit (P0-5): one deployment,
/// one identity, one lock order.
pub const DEPLOYMENT_IDENTITY_LOCK_SEED: i64 = 0x4E5A_4354_5200_0001;

/// Legal slot indices; the migration pins this range with a CHECK constraint.
const SLOT_INDEX_RANGE: [i16; 3] = [0, 1, 2];

/// Status catalog of a stored controller slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerSlotStatus {
    /// Enrolled and eligible for admission until `expires_at`.
    Active,
    /// Terminal state; can never admit operations again.
    Revoked,
}

impl ControllerSlotStatus {
    const ACTIVE: &'static str = "active";
    const REVOKED: &'static str = "revoked";

    fn from_str(value: &str) -> Option<Self> {
        match value {
            Self::ACTIVE => Some(Self::Active),
            Self::REVOKED => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// One authoritative controller slot (public material only).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredControllerSlot {
    pub deployment_id: String,
    /// Server-assigned canonical UUIDv7; stable across rotations.
    pub controller_id: String,
    pub label: String,
    pub kid: String,
    /// Raw Ed25519 public key bytes (32).
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
    /// Non-secret summary for human-facing surfaces.  Never carries public key
    /// bytes.
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

/// Non-secret slot summary used in limit errors and approval screens.
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

/// A controller slot that would admit a new application-level operation at the
/// instant of the lookup: exists, non-revoked, and unexpired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedController {
    pub controller_id: String,
    pub kid: String,
    /// Raw Ed25519 public key bytes used to verify operation signatures.
    pub public_key: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

/// Server-side input for enrolling one new controller slot.  Bind and add
/// share this shape; the distinction lives in the approval action only.  The
/// `controller_id` is assigned by the server, never by callers.
#[derive(Clone, Debug)]
pub struct NewControllerSlot {
    pub deployment_id: String,
    pub label: String,
    /// Unpadded base64url SHA-256 of `public_key`.
    pub kid: String,
    /// Raw Ed25519 public key bytes (32); private halves are not representable here.
    pub public_key: [u8; 32],
}

/// Atomic same-`controller_id` key replacement (rotate).  The active-slot
/// count is unchanged by construction.
#[derive(Clone, Debug)]
pub struct RotateControllerKey {
    pub deployment_id: String,
    pub controller_id: String,
    pub label: String,
    pub kid: String,
    pub public_key: [u8; 32],
}

/// Typed registry failures.  Transport failures are infrastructure faults;
/// everything else is an authoritative operation outcome.
#[derive(Debug)]
pub enum ControllerRegistryError {
    /// A fourth active slot was requested; carries non-secret summaries of the
    /// current active set (`CONTROLLER_SLOT_LIMIT`, 04 D02).  No partial row
    /// survives.
    SlotLimit(Vec<ControllerSlotSummary>),
    /// No slot with this exact controller id under this deployment.
    UnknownController,
    /// The target slot is already revoked; revoke refuses and rotate is impossible.
    AlreadyRevoked,
    /// Another slot of this deployment already holds this key material.
    DuplicateKid,
    /// Malformed deployment/controller/kid/key shape rejected before storage.
    InvalidIdentity(&'static str),
    /// Infrastructure failure; nothing about outcomes can be inferred from it.
    Transport(anyhow::Error),
}

impl std::fmt::Display for ControllerRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SlotLimit(_) => write!(formatter, "CONTROLLER_SLOT_LIMIT"),
            Self::UnknownController => write!(formatter, "unknown controller slot"),
            Self::AlreadyRevoked => write!(formatter, "controller slot already revoked"),
            Self::DuplicateKid => write!(formatter, "controller kid already registered"),
            Self::InvalidIdentity(reason) => write!(formatter, "{reason}"),
            Self::Transport(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for ControllerRegistryError {}

impl From<QueryError> for ControllerRegistryError {
    fn from(error: QueryError) -> Self {
        Self::Transport(anyhow::Error::from(error))
    }
}

fn transport<E>(error: E) -> ControllerRegistryError
where
    E: Into<anyhow::Error>,
{
    ControllerRegistryError::Transport(error.into())
}

// ---------------------------------------------------------------------------
// Identity approvals (D05)
// ---------------------------------------------------------------------------

/// Closed catalog of controller identity actions requiring fresh 2FA approval
/// (bind/add/rotate/revoke plus the recovery-root rotation of 04A D12, which
/// reuses this exact approval machinery with its own action value).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerIdentityAction {
    Bind,
    Add,
    Rotate,
    Revoke,
    RecoveryRootRotate,
}

impl ControllerIdentityAction {
    const BIND: &'static str = "bind";
    const ADD: &'static str = "add";
    const ROTATE: &'static str = "rotate";
    const REVOKE: &'static str = "revoke";
    const RECOVERY_ROOT_ROTATE: &'static str = "recovery-root-rotate";

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bind => Self::BIND,
            Self::Add => Self::ADD,
            Self::Rotate => Self::ROTATE,
            Self::Revoke => Self::REVOKE,
            Self::RecoveryRootRotate => Self::RECOVERY_ROOT_ROTATE,
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            Self::BIND => Some(Self::Bind),
            Self::ADD => Some(Self::Add),
            Self::ROTATE => Some(Self::Rotate),
            Self::REVOKE => Some(Self::Revoke),
            Self::RECOVERY_ROOT_ROTATE => Some(Self::RecoveryRootRotate),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum IdentityApprovalError {
    /// The plaintext token does not correspond to any issued approval.
    UnknownToken,
    /// The token matches an approval that was already consumed: replay.
    Replayed,
    /// The token matches an unconsumed approval whose window has passed.
    Expired,
    /// The token is valid but was issued for a different deployment, action,
    /// or exact action digest; nothing may be committed with it.
    ActionMismatch,
    /// Infrastructure failure.
    Transport(anyhow::Error),
}

impl std::fmt::Display for IdentityApprovalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownToken => write!(formatter, "unknown approval token"),
            Self::Replayed => write!(formatter, "approval token already consumed"),
            Self::Expired => write!(formatter, "approval token expired"),
            Self::ActionMismatch => write!(formatter, "approval does not cover this action"),
            Self::Transport(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for IdentityApprovalError {}

fn approval_transport<E>(error: E) -> IdentityApprovalError
where
    E: Into<anyhow::Error>,
{
    IdentityApprovalError::Transport(error.into())
}

/// Failure of an approval-gated commit.  Either the approval boundary rejected
/// redemption before anything happened, or the registry mutation failed after
/// consumption — the transaction rolls both back, leaving the approval
/// unconsumed and the registry untouched.
#[derive(Debug)]
pub enum CommitWithApprovalError {
    Approval(IdentityApprovalError),
    Mutation(ControllerRegistryError),
    Transport(anyhow::Error),
}

impl CommitWithApprovalError {
    fn transport<E>(error: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::Transport(error.into())
    }

    fn approval<E>(error: E) -> Self
    where
        E: Into<IdentityApprovalError>,
    {
        Self::Approval(error.into())
    }
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

impl From<QueryError> for CommitWithApprovalError {
    fn from(error: QueryError) -> Self {
        Self::Transport(anyhow::Error::from(error))
    }
}

impl From<ControllerRegistryError> for CommitWithApprovalError {
    fn from(error: ControllerRegistryError) -> Self {
        Self::Mutation(error)
    }
}

impl From<IdentityApprovalError> for CommitWithApprovalError {
    fn from(error: IdentityApprovalError) -> Self {
        Self::Approval(error)
    }
}

#[derive(QueryableByName)]
struct SlotRow {
    #[diesel(sql_type = Varchar)]
    deployment_id: String,
    #[diesel(sql_type = Varchar)]
    controller_id: String,
    #[diesel(sql_type = Varchar)]
    label: String,
    #[diesel(sql_type = Varchar)]
    kid: String,
    #[diesel(sql_type = Binary)]
    public_key: Vec<u8>,
    #[diesel(sql_type = SmallInt)]
    slot_index: i16,
    #[diesel(sql_type = Timestamptz)]
    issued_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    last_used_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Varchar)]
    status: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: DateTime<Utc>,
}

impl TryFrom<SlotRow> for StoredControllerSlot {
    type Error = anyhow::Error;

    fn try_from(row: SlotRow) -> Result<Self, Self::Error> {
        Ok(Self {
            deployment_id: row.deployment_id,
            controller_id: row.controller_id,
            label: row.label,
            kid: row.kid,
            public_key: row.public_key,
            slot_index: row.slot_index,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            status: ControllerSlotStatus::from_str(&row.status)
                .ok_or_else(|| anyhow::anyhow!("stored controller slot has unknown status"))?,
            revoked_at: row.revoked_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(QueryableByName)]
struct AdmittedRow {
    #[diesel(sql_type = Varchar)]
    controller_id: String,
    #[diesel(sql_type = Varchar)]
    kid: String,
    #[diesel(sql_type = Binary)]
    public_key: Vec<u8>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
}

impl TryFrom<AdmittedRow> for AdmittedController {
    type Error = anyhow::Error;

    fn try_from(row: AdmittedRow) -> Result<Self, Self::Error> {
        Ok(Self {
            controller_id: row.controller_id,
            kid: row.kid,
            public_key: row.public_key,
            expires_at: row.expires_at,
        })
    }
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct ApprovalRow {
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Varchar)]
    deployment_id: String,
    #[diesel(sql_type = Varchar)]
    action: String,
    #[diesel(sql_type = Varchar)]
    action_sha256: String,
}

macro_rules! slot_columns {
    () => {
        "deployment_id, controller_id, label, kid, public_key, \
         slot_index, issued_at, expires_at, last_used_at, status, revoked_at, \
         created_at, updated_at"
    };
}

/// Validate identifier shapes before anything reaches SQL.
///
/// * `deployment_id` mirrors the operator protocol's file-safe identifier rule.
/// * `controller_id` is the authoritative format defined by D01: a canonical
///   lowercase RFC 9562 UUIDv7 string assigned by NazoAuth when the slot is
///   created and kept stable across rotations.  It therefore survives key
///   rotation (unlike the `kid`, which changes with key material), fits every
///   bounded-text/file-safety rule of the control operation journal, and this
///   definition resolves the E03 open question about the snapshot field.
pub(crate) fn validate_deployment_id(value: &str) -> Result<(), ControllerRegistryError> {
    nazo_operator_protocol::validate_file_identifier_value(value).map_err(|_| {
        ControllerRegistryError::InvalidIdentity(
            "deployment_id is not a valid file-safe identifier",
        )
    })
}

fn validate_controller_id(value: &str) -> Result<(), ControllerRegistryError> {
    nazo_operator_protocol::validate_controller_id(value).map_err(|_| {
        ControllerRegistryError::InvalidIdentity(
            "controller_id must be a canonical lowercase UUIDv7",
        )
    })
}

pub(crate) fn validate_kid(value: &str) -> Result<(), ControllerRegistryError> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ControllerRegistryError::InvalidIdentity(
            "kid must be unpadded base64url SHA-256 of the public key",
        ));
    }
    Ok(())
}

pub(crate) fn validate_label(value: &str) -> Result<(), ControllerRegistryError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(ControllerRegistryError::InvalidIdentity(
            "controller label must be 1..=128 bounded text",
        ));
    }
    Ok(())
}

/// Registry self-consistency: `kid` must be exactly `base64url(SHA-256(key))`.
pub(crate) fn validate_kid_binding(
    kid: &str,
    public_key: &[u8; 32],
) -> Result<(), ControllerRegistryError> {
    if kid != URL_SAFE_NO_PAD.encode(Sha256::digest(public_key)) {
        return Err(ControllerRegistryError::InvalidIdentity(
            "kid does not match the controller public key material",
        ));
    }
    Ok(())
}

fn validate_slot_input(
    deployment_id: &str,
    label: &str,
    kid: &str,
    public_key: &[u8; 32],
) -> Result<(), ControllerRegistryError> {
    validate_deployment_id(deployment_id)?;
    validate_label(label)?;
    validate_kid(kid)?;
    validate_kid_binding(kid, public_key)
}

/// Hash one plaintext approval token for storage/lookup.  Tokens are random
/// 32-byte values; only their BLAKE3 digest is ever persisted, mirroring every
/// other one-time token in this schema.  Plaintext tokens are never logged.
fn approval_token_digest(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

async fn lock_deployment_slots(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
) -> Result<(), ControllerRegistryError> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
        .bind::<Varchar, _>(deployment_id)
        .bind::<BigInt, _>(DEPLOYMENT_IDENTITY_LOCK_SEED)
        .execute(connection)
        .await?;
    Ok(())
}

async fn load_slot_for_update(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
    controller_id: &str,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    let row = sql_query(format!(
        "SELECT {} FROM controller_registry_slots \
         WHERE deployment_id = $1 AND controller_id = $2 FOR UPDATE",
        slot_columns!()
    ))
    .bind::<Varchar, _>(deployment_id)
    .bind::<Varchar, _>(controller_id)
    .get_result::<SlotRow>(connection)
    .await
    .optional()
    .map_err(transport)?
    .map(StoredControllerSlot::try_from)
    .transpose()
    .map_err(transport)?;
    row.ok_or(ControllerRegistryError::UnknownController)
}

async fn active_slots_on_connection(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
) -> Result<Vec<StoredControllerSlot>, ControllerRegistryError> {
    let rows = sql_query(format!(
        "SELECT {} FROM controller_registry_slots \
         WHERE deployment_id = $1 AND status = 'active' \
         ORDER BY slot_index, controller_id",
        slot_columns!()
    ))
    .bind::<Varchar, _>(deployment_id)
    .load::<SlotRow>(connection)
    .await
    .map_err(transport)?;
    rows.into_iter()
        .map(StoredControllerSlot::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(transport)
}

fn lowest_free_slot_index(active: &[StoredControllerSlot]) -> Option<i16> {
    SLOT_INDEX_RANGE
        .into_iter()
        .find(|index| !active.iter().any(|slot| slot.slot_index == *index))
}

async fn read_slot_row(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
    controller_id: &str,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    sql_query(format!(
        "SELECT {} FROM controller_registry_slots \
         WHERE deployment_id = $1 AND controller_id = $2",
        slot_columns!()
    ))
    .bind::<Varchar, _>(deployment_id)
    .bind::<Varchar, _>(controller_id)
    .get_result::<SlotRow>(connection)
    .await?
    .try_into()
    .map_err(transport)
}

/// Insert one new active slot under the held advisory lock, picking the lowest
/// free index.  The partial unique active-slot index is the hard backstop for
/// any path that could bypass the lock.
pub(crate) async fn insert_slot_on_connection(
    connection: &mut AsyncPgConnection,
    slot: &NewControllerSlot,
    now: DateTime<Utc>,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    lock_deployment_slots(connection, &slot.deployment_id).await?;
    let active = active_slots_on_connection(connection, &slot.deployment_id).await?;
    let Some(slot_index) = lowest_free_slot_index(&active) else {
        return Err(ControllerRegistryError::SlotLimit(
            active.iter().map(StoredControllerSlot::summary).collect(),
        ));
    };
    let controller_id = Uuid::now_v7().to_string();
    let inserted = sql_query(
        "INSERT INTO controller_registry_slots
            (deployment_id, controller_id, label, kid, public_key, slot_index,
             issued_at, expires_at, last_used_at, status, revoked_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, 'active', NULL, $7, $7)",
    )
    .bind::<Varchar, _>(&slot.deployment_id)
    .bind::<Varchar, _>(&controller_id)
    .bind::<Varchar, _>(&slot.label)
    .bind::<Varchar, _>(&slot.kid)
    .bind::<Binary, _>(&slot.public_key[..])
    .bind::<SmallInt, _>(slot_index)
    .bind::<Timestamptz, _>(now)
    .bind::<Timestamptz, _>(now + Duration::seconds(CONTROLLER_KEY_TTL_SECONDS))
    .execute(connection)
    .await;
    if let Err(error) = inserted {
        // Under the per-deployment advisory lock the only reachable unique
        // violation on this path is the per-deployment kid backstop.
        return Err(map_insert_conflict(error));
    }
    read_slot_row(connection, &slot.deployment_id, &controller_id).await
}

fn map_insert_conflict(error: QueryError) -> ControllerRegistryError {
    match &error {
        QueryError::DatabaseError(kind, _) => {
            if matches!(kind, diesel::result::DatabaseErrorKind::UniqueViolation) {
                ControllerRegistryError::DuplicateKid
            } else {
                transport(error)
            }
        }
        _ => transport(error),
    }
}

async fn rotate_slot_on_connection(
    connection: &mut AsyncPgConnection,
    rotation: &RotateControllerKey,
    now: DateTime<Utc>,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    lock_deployment_slots(connection, &rotation.deployment_id).await?;
    let current =
        load_slot_for_update(connection, &rotation.deployment_id, &rotation.controller_id).await?;
    if current.status == ControllerSlotStatus::Revoked {
        return Err(ControllerRegistryError::AlreadyRevoked);
    }
    let conflict = sql_query(
        "SELECT count(*) AS count FROM controller_registry_slots
         WHERE deployment_id = $1 AND kid = $2 AND controller_id <> $3",
    )
    .bind::<Varchar, _>(&rotation.deployment_id)
    .bind::<Varchar, _>(&rotation.kid)
    .bind::<Varchar, _>(&rotation.controller_id)
    .get_result::<CountRow>(connection)
    .await?;
    if conflict.count > 0 {
        return Err(ControllerRegistryError::DuplicateKid);
    }
    sql_query(
        "UPDATE controller_registry_slots
         SET label = $3, kid = $4, public_key = $5,
             issued_at = $6, expires_at = $7,
             last_used_at = NULL, updated_at = $6
         WHERE deployment_id = $1 AND controller_id = $2",
    )
    .bind::<Varchar, _>(&rotation.deployment_id)
    .bind::<Varchar, _>(&rotation.controller_id)
    .bind::<Varchar, _>(&rotation.label)
    .bind::<Varchar, _>(&rotation.kid)
    .bind::<Binary, _>(&rotation.public_key[..])
    .bind::<Timestamptz, _>(now)
    .bind::<Timestamptz, _>(now + Duration::seconds(CONTROLLER_KEY_TTL_SECONDS))
    .execute(connection)
    .await?;
    load_slot_for_update(connection, &rotation.deployment_id, &rotation.controller_id).await
}

async fn revoke_slot_on_connection(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
    controller_id: &str,
    now: DateTime<Utc>,
) -> Result<StoredControllerSlot, ControllerRegistryError> {
    lock_deployment_slots(connection, deployment_id).await?;
    let current = load_slot_for_update(connection, deployment_id, controller_id).await?;
    if current.status == ControllerSlotStatus::Revoked {
        return Err(ControllerRegistryError::AlreadyRevoked);
    }
    sql_query(
        "UPDATE controller_registry_slots
         SET status = 'revoked', revoked_at = $3, updated_at = $3
         WHERE deployment_id = $1 AND controller_id = $2",
    )
    .bind::<Varchar, _>(deployment_id)
    .bind::<Varchar, _>(controller_id)
    .bind::<Timestamptz, _>(now)
    .execute(connection)
    .await?;
    load_slot_for_update(connection, deployment_id, controller_id).await
}

/// Consume an approval row inside an open transaction.  Enforces single use,
/// the fixed expiry window, and the exact `(deployment_id, action,
/// action_sha256)` binding; sets `consumed_at` only when everything matches.
/// A later failure of the authorized mutation rolls the consumption back too.
pub(crate) async fn consume_approval_on_connection(
    connection: &mut AsyncPgConnection,
    token_hash: &str,
    expected_deployment_id: &str,
    expected_action: ControllerIdentityAction,
    expected_action_sha256: &str,
    now: DateTime<Utc>,
) -> Result<(), IdentityApprovalError> {
    let row = sql_query(
        "SELECT expires_at, consumed_at, deployment_id, action, action_sha256
         FROM controller_identity_approvals
         WHERE token_hash = $1
         FOR UPDATE",
    )
    .bind::<Varchar, _>(token_hash)
    .get_result::<ApprovalRow>(connection)
    .await
    .optional()
    .map_err(approval_transport)?;
    let Some(row) = row else {
        return Err(IdentityApprovalError::UnknownToken);
    };
    if row.consumed_at.is_some() {
        return Err(IdentityApprovalError::Replayed);
    }
    if row.expires_at <= now {
        return Err(IdentityApprovalError::Expired);
    }
    if row.deployment_id != expected_deployment_id
        || row.action != expected_action.as_str()
        || row.action_sha256 != expected_action_sha256
    {
        return Err(IdentityApprovalError::ActionMismatch);
    }
    sql_query("UPDATE controller_identity_approvals SET consumed_at = $2 WHERE token_hash = $1")
        .bind::<Varchar, _>(token_hash)
        .bind::<Timestamptz, _>(now)
        .execute(connection)
        .await
        .map_err(approval_transport)?;
    Ok(())
}

/// One issued approval as returned to the administrator.  The plaintext token
/// exists exactly once — in this return value — and is never logged or stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedIdentityApproval {
    pub approval_id: Uuid,
    pub action: ControllerIdentityAction,
    /// Digest the approval is bound to; recomputed and re-checked at commit.
    pub action_sha256: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// Repository facade over the controller registry tables.  All validity times
/// come from the caller-supplied server clock; nothing derives authorization
/// from client input.
#[derive(Clone)]
pub struct ControllerRegistryRepository {
    pool: DbPool,
}

impl ControllerRegistryRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    // -- Slot lifecycle ------------------------------------------------------

    /// Enroll one new controller slot (bind or add).  Assigns the authoritative
    /// `controller_id`, computes the fixed 30-day expiry server-side, picks the
    /// lowest free slot index, and refuses a fourth concurrent active slot with
    /// [`ControllerRegistryError::SlotLimit`] carrying the non-secret active
    /// summaries.  No partial row survives any rejection.
    pub async fn create_slot(
        &self,
        slot: NewControllerSlot,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, ControllerRegistryError> {
        validate_slot_input(
            &slot.deployment_id,
            &slot.label,
            &slot.kid,
            &slot.public_key,
        )?;
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        connection
            .transaction::<_, ControllerRegistryError, _>(async move |connection| {
                insert_slot_on_connection(connection, &slot, now).await
            })
            .await
    }

    /// Atomically replace the key material of one existing active slot without
    /// changing the deployment's active-slot count.  Rotation of a revoked slot
    /// is refused, the old key stops admitting at commit time, and the
    /// replacement gets a fresh fixed 30-day window computed server-side.
    pub async fn rotate_slot(
        &self,
        rotation: RotateControllerKey,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, ControllerRegistryError> {
        validate_controller_id(&rotation.controller_id)?;
        validate_slot_input(
            &rotation.deployment_id,
            &rotation.label,
            &rotation.kid,
            &rotation.public_key,
        )?;
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        connection
            .transaction::<_, ControllerRegistryError, _>(async move |connection| {
                rotate_slot_on_connection(connection, &rotation, now).await
            })
            .await
    }

    /// Revoke one slot by exact controller id.  Terminal: a second call fails
    /// with [`ControllerRegistryError::AlreadyRevoked`] so no caller can
    /// mistake an already-dead key for a fresh revocation.
    pub async fn revoke_slot(
        &self,
        deployment_id: &str,
        controller_id: &str,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, ControllerRegistryError> {
        validate_deployment_id(deployment_id)?;
        validate_controller_id(controller_id)?;
        let deployment_id = deployment_id.to_owned();
        let controller_id = controller_id.to_owned();
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        connection
            .transaction::<_, ControllerRegistryError, _>(async move |connection| {
                revoke_slot_on_connection(connection, &deployment_id, &controller_id, now).await
            })
            .await
    }

    /// Every slot of one deployment ordered by assignment, including revoked
    /// rows: history is part of the authority answer ("does this key exist and
    /// what happened to it").
    pub async fn list_slots(
        &self,
        deployment_id: &str,
    ) -> Result<Vec<StoredControllerSlot>, ControllerRegistryError> {
        validate_deployment_id(deployment_id)?;
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        let rows = sql_query(format!(
            "SELECT {} FROM controller_registry_slots \
             WHERE deployment_id = $1 ORDER BY slot_index, controller_id",
            slot_columns!()
        ))
        .bind::<Varchar, _>(deployment_id)
        .load::<SlotRow>(&mut connection)
        .await
        .map_err(transport)?;
        rows.into_iter()
            .map(StoredControllerSlot::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(transport)
    }

    /// E04 verification-order lookup ("by deployment id, find the controller
    /// kids/public keys"): every slot that would admit a new operation right
    /// now.  Expired-but-not-yet-replaced keys are absent because admission
    /// requires `expires_at > now`.
    pub async fn admitted_controllers(
        &self,
        deployment_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<AdmittedController>, ControllerRegistryError> {
        validate_deployment_id(deployment_id)?;
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        let rows = sql_query(
            "SELECT controller_id, kid, public_key, expires_at
             FROM controller_registry_slots
             WHERE deployment_id = $1 AND status = 'active' AND expires_at > $2
             ORDER BY slot_index",
        )
        .bind::<Varchar, _>(deployment_id)
        .bind::<Timestamptz, _>(now)
        .load::<AdmittedRow>(&mut connection)
        .await
        .map_err(transport)?;
        rows.into_iter()
            .map(AdmittedController::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(transport)
    }

    /// Single-kid admission lookup used to verify one presented envelope key.
    /// Returns `None` for unknown, revoked, and expired keys alike; callers map
    /// the outcome onto their closed error taxonomy
    /// (`CONTROLLER_KEY_UNTRUSTED` / `CONTROLLER_KEY_EXPIRED`).
    pub async fn admitted_controller_by_kid(
        &self,
        deployment_id: &str,
        kid: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AdmittedController>, ControllerRegistryError> {
        validate_deployment_id(deployment_id)?;
        validate_kid(kid)?;
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        let row = sql_query(
            "SELECT controller_id, kid, public_key, expires_at
             FROM controller_registry_slots
             WHERE deployment_id = $1 AND kid = $2
               AND status = 'active' AND expires_at > $3",
        )
        .bind::<Varchar, _>(deployment_id)
        .bind::<Varchar, _>(kid)
        .bind::<Timestamptz, _>(now)
        .get_result::<AdmittedRow>(&mut connection)
        .await
        .optional()
        .map_err(transport)?
        .map(AdmittedController::try_from)
        .transpose()
        .map_err(transport)?;
        Ok(row)
    }

    // -- Approvals (D05) -----------------------------------------------------

    /// Issue one single-use approval bound to `(deployment_id, action,
    /// action_sha256)` and to the approving administrator.  Freshness of the
    /// administrator's MFA is enforced at the HTTP boundary before this call;
    /// here the record itself gets its fixed 10-minute life.
    pub async fn issue_identity_approval(
        &self,
        deployment_id: &str,
        action: ControllerIdentityAction,
        action_sha256: &str,
        admin_user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<IssuedIdentityApproval, IdentityApprovalError> {
        if validate_deployment_id(deployment_id).is_err() {
            return Err(approval_transport(anyhow::anyhow!(
                "approval deployment_id is invalid"
            )));
        }
        if action_sha256.len() != 64
            || !action_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(approval_transport(anyhow::anyhow!(
                "approval action digest is not lowercase sha256 hex"
            )));
        }
        let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let token_hash = approval_token_digest(&token);
        let approval_id = Uuid::now_v7();
        let expires_at = now + Duration::seconds(IDENTITY_APPROVAL_TTL_SECONDS);
        let mut connection = get_conn(&self.pool).await.map_err(approval_transport)?;
        sql_query(
            "INSERT INTO controller_identity_approvals
                (approval_id, deployment_id, action, action_sha256,
                 admin_user_id, token_hash, expires_at, consumed_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8)",
        )
        .bind::<DieselUuid, _>(approval_id)
        .bind::<Varchar, _>(deployment_id)
        .bind::<Varchar, _>(action.as_str())
        .bind::<Varchar, _>(action_sha256)
        .bind::<DieselUuid, _>(admin_user_id)
        .bind::<Varchar, _>(&token_hash)
        .bind::<Timestamptz, _>(expires_at)
        .bind::<Timestamptz, _>(now)
        .execute(&mut connection)
        .await
        .map_err(approval_transport)?;
        Ok(IssuedIdentityApproval {
            approval_id,
            action,
            action_sha256: action_sha256.to_owned(),
            token,
            expires_at,
        })
    }

    /// Consume one approval and enroll a new slot in the same transaction.
    /// Replay/expiry/binding-mismatch aborts the whole transaction, so a
    /// consumed approval can never exist without its mutation having committed,
    /// and no slot can exist without its approval having been consumed.
    pub async fn commit_slot_creation(
        &self,
        approval_token: &str,
        expected_action: ControllerIdentityAction,
        expected_action_sha256: &str,
        slot: NewControllerSlot,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, CommitWithApprovalError> {
        validate_slot_input(
            &slot.deployment_id,
            &slot.label,
            &slot.kid,
            &slot.public_key,
        )?;
        let token_hash = approval_token_digest(approval_token);
        let expected_action_sha256 = expected_action_sha256.to_owned();
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(CommitWithApprovalError::transport)?;
        connection
            .transaction::<_, CommitWithApprovalError, _>(async move |connection| {
                consume_approval_on_connection(
                    connection,
                    &token_hash,
                    &slot.deployment_id,
                    expected_action,
                    &expected_action_sha256,
                    now,
                )
                .await?;
                insert_slot_on_connection(connection, &slot, now)
                    .await
                    .map_err(CommitWithApprovalError::Mutation)
            })
            .await
    }

    /// Consume one approval and rotate an existing slot in the same
    /// transaction.
    pub async fn commit_slot_rotation(
        &self,
        approval_token: &str,
        expected_deployment_id: &str,
        expected_action_sha256: &str,
        rotation: RotateControllerKey,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, CommitWithApprovalError> {
        validate_controller_id(&rotation.controller_id)?;
        validate_slot_input(
            &rotation.deployment_id,
            &rotation.label,
            &rotation.kid,
            &rotation.public_key,
        )?;
        if rotation.deployment_id != expected_deployment_id {
            return Err(CommitWithApprovalError::approval(
                IdentityApprovalError::ActionMismatch,
            ));
        }
        let token_hash = approval_token_digest(approval_token);
        let expected_action_sha256 = expected_action_sha256.to_owned();
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(CommitWithApprovalError::transport)?;
        connection
            .transaction::<_, CommitWithApprovalError, _>(async move |connection| {
                consume_approval_on_connection(
                    connection,
                    &token_hash,
                    &rotation.deployment_id,
                    ControllerIdentityAction::Rotate,
                    &expected_action_sha256,
                    now,
                )
                .await?;
                rotate_slot_on_connection(connection, &rotation, now)
                    .await
                    .map_err(CommitWithApprovalError::Mutation)
            })
            .await
    }

    /// Consume one approval and revoke an existing slot in the same
    /// transaction.
    pub async fn commit_slot_revocation(
        &self,
        approval_token: &str,
        expected_deployment_id: &str,
        expected_action_sha256: &str,
        controller_id: &str,
        now: DateTime<Utc>,
    ) -> Result<StoredControllerSlot, CommitWithApprovalError> {
        validate_deployment_id(expected_deployment_id)?;
        validate_controller_id(controller_id)?;
        let token_hash = approval_token_digest(approval_token);
        let expected_deployment_id = expected_deployment_id.to_owned();
        let controller_id = controller_id.to_owned();
        let expected_action_sha256 = expected_action_sha256.to_owned();
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(CommitWithApprovalError::transport)?;
        connection
            .transaction::<_, CommitWithApprovalError, _>(async move |connection| {
                consume_approval_on_connection(
                    connection,
                    &token_hash,
                    &expected_deployment_id,
                    ControllerIdentityAction::Revoke,
                    &expected_action_sha256,
                    now,
                )
                .await?;
                revoke_slot_on_connection(connection, &expected_deployment_id, &controller_id, now)
                    .await
                    .map_err(CommitWithApprovalError::Mutation)
            })
            .await
    }
}

#[cfg(test)]
#[path = "../../tests/unit/repositories/controller_registry.rs"]
mod tests;
