//! Authoritative per-deployment Recovery Root storage (04A D10/D11/D12).
//!
//! NazoAuth never sees the 32-byte Recovery Secret: the control side derives
//! `Ed25519(HKDF-SHA-256(secret, salt=deployment_id,
//! info="nazoauthctl/recovery"))` entirely offline and only the resulting
//! public key crosses the wire.  This module persists exactly that anchor —
//! one root per deployment, pinned to KDF id `hkdf-sha256-v1` — and owns two
//! flows around it:
//!
//! * **D12 proactive rotation**: replacing the root consumes a single-use
//!   fresh-2FA approval (`recovery-root-rotate`) through the exact D05
//!   machinery; consumption and replacement share one transaction.
//! * **D11 break-glass recovery**: when no controller slot would admit a new
//!   operation anymore, an unauthenticated-by-design challenge/response lets
//!   the OLD Recovery Key re-establish exactly one controller slot and
//!   install the NEW Recovery Public Key atomically.  It bypasses admin 2FA
//!   because the admin identity may be the unavailable part, so it fails
//!   closed everywhere else: challenges bind the deployment plus the exact
//!   proposed key material, live for a fixed ten minutes, accept at most five
//!   failed submissions, exist at most once pending per deployment, are
//!   single-use, and verify against the CURRENT root — which the same
//!   transaction replaces, instantly killing the old secret (old generation).
//!
//! Hard invariants enforced here (mirrored by CHECK/unique/FK constraints in
//! migration `20260825000100_controller_recovery_root`):
//!
//! * one Recovery Root per deployment; every approved replacement bumps
//!   `generation`, and verification always uses the current row, so secrets
//!   of earlier generations fail immediately after a commit (04A §1);
//! * a recovered slot obeys the ordinary registry rules unchanged: fixed
//!   30-day server-computed expiry, three-slot bound, revocation terminality
//!   — recovery reuses [`insert_slot_on_connection`] verbatim;
//! * recovery cannot resurrect authority silently: committing revokes EVERY
//!   active slot of the deployment before installing exactly one new slot
//!   with a freshly assigned `controller_id`;
//! * only public key material is ever persisted or returned; summaries carry
//!   identifiers and timestamps but never key bytes, and no API here accepts
//!   a secret-shaped input at all.

use blake3::Hasher;
use chrono::{DateTime, Duration, Utc};
use diesel::OptionalExtension;
use diesel::QueryableByName;
use diesel::result::Error as QueryError;
use diesel::sql_query;
use diesel::sql_types::{
    BigInt, Binary, Integer, Nullable, SmallInt, Timestamptz, Uuid as DieselUuid, Varchar,
};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use nazo_operator_protocol::RECOVERY_KDF_ID;

use super::controller_registry::{
    AdmittedController, ControllerIdentityAction, ControllerRegistryError,
    ControllerRegistryRepository, IdentityApprovalError, IssuedIdentityApproval,
    consume_approval_on_connection, insert_slot_on_connection, validate_deployment_id,
    validate_kid, validate_kid_binding, validate_label,
};
use super::controller_registry::{
    CommitWithApprovalError, ControllerSlotStatus, NewControllerSlot, StoredControllerSlot,
};
use crate::{DbPool, get_conn};

/// Fixed challenge lifetime in seconds: a single short window, computed
/// server-side and pinned by the migration CHECK constraint.
#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
}

pub const RECOVERY_CHALLENGE_TTL_SECONDS: i64 = 600;

/// Maximum number of failed submissions per challenge before it is dead.
/// The 256-bit secret makes brute force hopeless anyway; the cap exists so
/// the unauthenticated endpoint cannot be used as an oracle or noise source.
pub const MAX_RECOVERY_CHALLENGE_ATTEMPTS: i32 = 5;

/// Recovery Root/challenge mutations take the SHARED per-deployment identity
/// lock (`controller_registry::DEPLOYMENT_IDENTITY_LOCK_SEED`) so they
/// serialize against concurrent slot binds/rotates/revokes (P0-5). The old
/// separate RECOVERY seed let a bind commit slip between the challenge's
/// active-slot re-check and its batch revoke.
use super::controller_registry::DEPLOYMENT_IDENTITY_LOCK_SEED;

/// One stored Recovery Root (public material only).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRecoveryRoot {
    pub deployment_id: String,
    pub recovery_kid: String,
    /// Raw Ed25519 public key bytes (32) of the derived Recovery Key.
    pub recovery_public_key: Vec<u8>,
    /// Pinned derivation parameter set; always `hkdf-sha256-v1`.
    pub kdf: String,
    /// Monotonic counter bumped by every approved replacement.
    pub generation: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl StoredRecoveryRoot {
    /// Non-secret summary for human-facing surfaces.  Never carries key bytes.
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

/// Non-secret Recovery Root view used by status surfaces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRootSummary {
    pub deployment_id: String,
    pub recovery_kid: String,
    pub kdf: String,
    pub generation: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Non-secret summary of one still-admitting controller slot.  Carried by the
/// `CONTROLLER_STILL_ADMITTED` refusal so the unauthenticated gate response
/// can explain WHY recovery is blocked without exposing raw public key bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedControllerSummary {
    pub controller_id: String,
    pub kid: String,
    pub expires_at: DateTime<Utc>,
}

impl From<&AdmittedController> for AdmittedControllerSummary {
    fn from(admitted: &AdmittedController) -> Self {
        Self {
            controller_id: admitted.controller_id.clone(),
            kid: admitted.kid.clone(),
            expires_at: admitted.expires_at,
        }
    }
}

/// Server-side input for enrolling or rotating the Recovery Public Key.
/// Secret material is not representable here by construction.
#[derive(Clone, Debug)]
pub struct NewRecoveryRoot {
    pub deployment_id: String,
    /// Unpadded base64url SHA-256 of `public_key`.
    pub kid: String,
    pub public_key: [u8; 32],
}

/// Server-side input for issuing one recovery challenge (D11 steps 1–3): the
/// exact proposed replacement controller key and replacement Recovery Public
/// Key, both bound into the challenge and its canonical message.
#[derive(Clone, Debug)]
pub struct NewRecoveryChallenge {
    pub deployment_id: String,
    pub controller_label: String,
    pub controller_kid: String,
    pub controller_public_key: [u8; 32],
    pub recovery_kid: String,
    pub recovery_public_key: [u8; 32],
}

/// One issued challenge as returned to the control side.  The nonce is a
/// public value — the signer needs it verbatim — and appears exactly once
/// here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedRecoveryChallenge {
    pub challenge_id: Uuid,
    pub deployment_id: String,
    pub nonce: [u8; 32],
    pub expires_at: DateTime<Utc>,
}

/// Signed answer to one challenge (D11 step 4): Ed25519 signature over the
/// canonical challenge message made with the OLD Recovery Key.
#[derive(Clone, Debug)]
pub struct RecoverySubmission {
    pub deployment_id: String,
    pub challenge_id: Uuid,
    pub nonce: [u8; 32],
    pub signature: [u8; 64],
}

/// Outcome of one accepted recovery: exactly one new active slot plus the
/// generation of the freshly installed Recovery Root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredSlotCommit {
    pub slot: StoredControllerSlot,
    pub recovery_generation: i32,
}

/// Typed recovery-plane failures.  Transport failures are infrastructure
/// faults; everything else is an authoritative operation outcome.
#[derive(Debug)]
pub enum RecoveryRootError {
    /// At least one controller slot would still admit operations, so the
    /// ordinary fresh-2FA identity paths remain available and the break-glass
    /// path must not run (04A §2 权限).  Carries non-secret summaries only.
    ControllersStillAdmitted(Vec<AdmittedControllerSummary>),
    /// Another challenge of this deployment is still outstanding.
    ChallengePending,
    /// No such challenge under this deployment.
    ChallengeUnknown,
    /// The challenge window has passed.
    ChallengeExpired,
    /// The challenge accumulated the maximum number of failed submissions.
    ChallengeExhausted,
    /// The challenge was already answered successfully: replay.
    ChallengeReplayed,
    /// The echoed nonce does not match the issued one.
    NonceMismatch,
    /// The answer does not verify against the CURRENT Recovery Public Key.
    InvalidSignature,
    /// No Recovery Root is anchored for this deployment.
    RootMissing,
    /// Malformed input rejected before anything reached storage.
    InvalidIdentity(&'static str),
    /// Infrastructure failure; nothing about outcomes can be inferred from it.
    Transport(anyhow::Error),
}

impl std::fmt::Display for RecoveryRootError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ControllersStillAdmitted(_) => {
                write!(formatter, "CONTROLLER_STILL_ADMITTED")
            }
            Self::ChallengePending => write!(formatter, "RECOVERY_CHALLENGE_PENDING"),
            Self::ChallengeUnknown => write!(formatter, "unknown recovery challenge"),
            Self::ChallengeExpired => write!(formatter, "recovery challenge expired"),
            Self::ChallengeExhausted => write!(formatter, "recovery challenge exhausted"),
            Self::ChallengeReplayed => write!(formatter, "recovery challenge already consumed"),
            Self::NonceMismatch => write!(formatter, "challenge nonce mismatch"),
            Self::InvalidSignature => write!(formatter, "invalid recovery signature"),
            Self::RootMissing => write!(formatter, "no recovery root anchored"),
            Self::InvalidIdentity(reason) => write!(formatter, "{reason}"),
            Self::Transport(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for RecoveryRootError {}

impl From<QueryError> for RecoveryRootError {
    fn from(error: QueryError) -> Self {
        Self::Transport(anyhow::Error::from(error))
    }
}

impl From<ControllerRegistryError> for RecoveryRootError {
    fn from(error: ControllerRegistryError) -> Self {
        match error {
            // The only registry conflicts a recovery commit can legitimately
            // hit: the proposed controller kid already exists on some row of
            // this deployment (including revoked history).
            ControllerRegistryError::DuplicateKid => {
                Self::InvalidIdentity("proposed controller key material is already registered")
            }
            ControllerRegistryError::InvalidIdentity(reason) => Self::InvalidIdentity(reason),
            other => transport(anyhow::anyhow!(
                "controller registry failure during recovery commit: {other:#}"
            )),
        }
    }
}

fn transport<E>(error: E) -> RecoveryRootError
where
    E: Into<anyhow::Error>,
{
    RecoveryRootError::Transport(error.into())
}

/// Failure of an approval-gated Recovery Root rotation.  Either the approval
/// boundary rejected redemption before anything happened, or the root
/// replacement failed after consumption — the transaction rolls both back,
/// leaving the approval unconsumed and the root untouched.
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

impl From<CommitWithApprovalError> for RecoveryRotationError {
    fn from(error: CommitWithApprovalError) -> Self {
        match error {
            CommitWithApprovalError::Approval(inner) => Self::Approval(inner),
            CommitWithApprovalError::Mutation(ControllerRegistryError::InvalidIdentity(reason)) => {
                Self::Mutation(RecoveryRootError::InvalidIdentity(reason))
            }
            CommitWithApprovalError::Mutation(other) => Self::Transport(anyhow::anyhow!(
                "unexpected registry failure during recovery-root rotation: {other:#}"
            )),
            CommitWithApprovalError::Transport(inner) => Self::Transport(inner),
        }
    }
}

impl From<IdentityApprovalError> for RecoveryRotationError {
    fn from(error: IdentityApprovalError) -> Self {
        Self::Approval(error)
    }
}

impl From<QueryError> for RecoveryRotationError {
    fn from(error: QueryError) -> Self {
        Self::Transport(anyhow::Error::from(error))
    }
}

impl From<RecoveryRootError> for RecoveryRotationError {
    fn from(error: RecoveryRootError) -> Self {
        Self::Mutation(error)
    }
}

#[derive(QueryableByName)]
struct RecoveryRootRow {
    #[diesel(sql_type = Varchar)]
    deployment_id: String,
    #[diesel(sql_type = Varchar)]
    recovery_kid: String,
    #[diesel(sql_type = Binary)]
    recovery_public_key: Vec<u8>,
    #[diesel(sql_type = Varchar)]
    kdf: String,
    #[diesel(sql_type = Integer)]
    generation: i32,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: DateTime<Utc>,
}

impl TryFrom<RecoveryRootRow> for StoredRecoveryRoot {
    type Error = anyhow::Error;

    fn try_from(row: RecoveryRootRow) -> Result<Self, Self::Error> {
        Ok(Self {
            deployment_id: row.deployment_id,
            recovery_kid: row.recovery_kid,
            recovery_public_key: row.recovery_public_key,
            kdf: row.kdf,
            generation: row.generation,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(QueryableByName)]
struct ChallengeRow {
    #[diesel(sql_type = Varchar)]
    deployment_id: String,
    #[diesel(sql_type = Binary)]
    nonce: Vec<u8>,
    #[diesel(sql_type = Varchar)]
    controller_label: String,
    #[diesel(sql_type = Varchar)]
    controller_kid: String,
    #[diesel(sql_type = Binary)]
    controller_public_key: Vec<u8>,
    #[diesel(sql_type = Varchar)]
    recovery_kid: String,
    #[diesel(sql_type = Binary)]
    recovery_public_key: Vec<u8>,
    #[diesel(sql_type = SmallInt)]
    attempts: i16,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Binary>)]
    accepted_signature_sha256: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Varchar>)]
    recovered_controller_id: Option<String>,
    #[diesel(sql_type = Nullable<SmallInt>)]
    recovered_slot_index: Option<i16>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    recovered_slot_issued_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    recovered_slot_expires_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Integer>)]
    recovery_generation: Option<i32>,
}

const CHALLENGE_COLUMNS: &str = "challenge_id, deployment_id, nonce, controller_label, controller_kid, \
     controller_public_key, recovery_kid, recovery_public_key, attempts, \
     expires_at, consumed_at, created_at, accepted_signature_sha256, \
     recovered_controller_id, recovered_slot_index, recovered_slot_issued_at, \
     recovered_slot_expires_at, recovery_generation";

const ROOT_COLUMNS: &str =
    "deployment_id, recovery_kid, recovery_public_key, kdf, generation, created_at, updated_at";

/// Constant-time-flavoured comparison of two equal-length public byte strings:
/// both sides are hashed first so the comparison operates on digests instead
/// of attacker-controlled raw bytes.  These values are non-secret (the nonce
/// is handed out at issuance); the sensitive comparison boundary of the
/// recovery plane is the Ed25519 signature verification itself.
fn digest_matches(left: &[u8], right: &[u8]) -> bool {
    let mut hasher = Hasher::new();
    hasher.update(left);
    let left = hasher.finalize().to_hex().to_string();
    let mut hasher = Hasher::new();
    hasher.update(right);
    let right = hasher.finalize().to_hex().to_string();
    left == right
}

fn signature_sha256(signature: &[u8; 64]) -> [u8; 32] {
    Sha256::digest(signature).into()
}

async fn lock_deployment_recovery(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
) -> Result<(), RecoveryRootError> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
        .bind::<Varchar, _>(deployment_id)
        .bind::<BigInt, _>(DEPLOYMENT_IDENTITY_LOCK_SEED)
        .execute(connection)
        .await?;
    Ok(())
}

async fn read_root_on_connection(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
) -> Result<Option<StoredRecoveryRoot>, RecoveryRootError> {
    sql_query(format!(
        "SELECT {ROOT_COLUMNS} FROM controller_recovery_roots WHERE deployment_id = $1"
    ))
    .bind::<Varchar, _>(deployment_id)
    .get_result::<RecoveryRootRow>(connection)
    .await
    .optional()
    .map_err(transport)?
    .map(StoredRecoveryRoot::try_from)
    .transpose()
    .map_err(transport)
}

/// P0-3 sibling-module surface for the atomic first-bind commit: the registry
/// checks root absence and enrolls generation 1 inside ITS transaction, so
/// slot + root become one atomic unit.
pub(crate) async fn read_root_on_connection_for_registry(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
) -> Result<Option<StoredRecoveryRoot>, RecoveryRootError> {
    read_root_on_connection(connection, deployment_id).await
}

/// Generation-1-only INSERT: unlike `replace_root_on_connection` this never
/// bumps an existing row — the caller must have verified absence first.
pub(crate) async fn enroll_initial_root_on_connection(
    connection: &mut AsyncPgConnection,
    root: &NewRecoveryRoot,
    now: DateTime<Utc>,
) -> Result<StoredRecoveryRoot, RecoveryRootError> {
    sql_query(
        "INSERT INTO controller_recovery_roots
            (deployment_id, recovery_kid, recovery_public_key, kdf, generation,
             created_at, updated_at)
         VALUES ($1, $2, $3, $4, 1, $5, $5)",
    )
    .bind::<Varchar, _>(&root.deployment_id)
    .bind::<Varchar, _>(&root.kid)
    .bind::<Binary, _>(&root.public_key[..])
    .bind::<Varchar, _>(RECOVERY_KDF_ID)
    .bind::<Timestamptz, _>(now)
    .execute(connection)
    .await
    .map_err(transport)?;
    read_root_on_connection(connection, &root.deployment_id)
        .await?
        .ok_or_else(|| transport(anyhow::anyhow!("recovery root missing after insert")))
}

/// Replace the root inside an open transaction: insert at generation 1 or
/// bump the existing generation.  The old public key stops verifying at
/// commit time because every verification reads this row.
async fn replace_root_on_connection(
    connection: &mut AsyncPgConnection,
    root: &NewRecoveryRoot,
    now: DateTime<Utc>,
) -> Result<StoredRecoveryRoot, RecoveryRootError> {
    sql_query(
        "INSERT INTO controller_recovery_roots
            (deployment_id, recovery_kid, recovery_public_key, kdf, generation,
             created_at, updated_at)
         VALUES ($1, $2, $3, $4, 1, $5, $5)
         ON CONFLICT (deployment_id) DO UPDATE
         SET recovery_kid = EXCLUDED.recovery_kid,
             recovery_public_key = EXCLUDED.recovery_public_key,
             generation = controller_recovery_roots.generation + 1,
             updated_at = EXCLUDED.updated_at",
    )
    .bind::<Varchar, _>(&root.deployment_id)
    .bind::<Varchar, _>(&root.kid)
    .bind::<Binary, _>(&root.public_key[..])
    .bind::<Varchar, _>(RECOVERY_KDF_ID)
    .bind::<Timestamptz, _>(now)
    .execute(connection)
    .await
    .map_err(transport)?;
    read_root_on_connection(connection, &root.deployment_id)
        .await?
        .ok_or_else(|| transport(anyhow::anyhow!("recovery root missing after upsert")))
}

fn validate_challenge_input(challenge: &NewRecoveryChallenge) -> Result<(), RecoveryRootError> {
    validate_deployment_id(&challenge.deployment_id)
        .map_err(|_| RecoveryRootError::InvalidIdentity("deployment_id is invalid"))?;
    validate_label(&challenge.controller_label)
        .map_err(|_| RecoveryRootError::InvalidIdentity("controller label is invalid"))?;
    for (kid, key) in [
        (&challenge.controller_kid, &challenge.controller_public_key),
        (&challenge.recovery_kid, &challenge.recovery_public_key),
    ] {
        validate_kid(kid).map_err(|_| {
            RecoveryRootError::InvalidIdentity("kid must be unpadded base64url SHA-256")
        })?;
        validate_kid_binding(kid, key).map_err(|_| {
            RecoveryRootError::InvalidIdentity("kid does not match the proposed key material")
        })?;
    }
    Ok(())
}

/// Repository facade over the Recovery Root tables.  Shares the pool with the
/// controller registry so approvals and slots live in one authority domain.
#[derive(Clone)]
pub struct RecoveryRootRepository {
    pool: DbPool,
    registry: ControllerRegistryRepository,
}

impl RecoveryRootRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        let registry = ControllerRegistryRepository::new(pool.clone());
        Self { pool, registry }
    }

    /// Registry facade over the same pool; recovery commits mutate controller
    /// slots through it so both planes share one implementation.
    #[must_use]
    pub fn registry(&self) -> &ControllerRegistryRepository {
        &self.registry
    }

    // -- Root lifecycle (D10 enrollment / D12 rotation) -----------------------

    /// Current Recovery Root of one deployment, if any.
    pub async fn current_root(
        &self,
        deployment_id: &str,
    ) -> Result<Option<StoredRecoveryRoot>, RecoveryRootError> {
        validate_deployment_id(deployment_id)
            .map_err(|_| RecoveryRootError::InvalidIdentity("deployment_id is invalid"))?;
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        read_root_on_connection(&mut connection, deployment_id).await
    }

    /// Issue one single-use fresh-2FA approval bound to the exact
    /// `recovery-root-rotate` payload (D12 step 4).  Freshness of the
    /// administrator's MFA is enforced at the HTTP boundary; this call only
    /// validates shapes and delegates to the shared D05 machinery so the
    /// approval table keeps one authoritative implementation.
    pub async fn issue_rotation_approval(
        &self,
        deployment_id: &str,
        action_sha256: &str,
        admin_user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<IssuedIdentityApproval, RecoveryRotationError> {
        use super::controller_registry::ControllerIdentityAction;
        validate_deployment_id(deployment_id)
            .map_err(|_| RecoveryRootError::InvalidIdentity("deployment_id is invalid"))?;
        Ok(self
            .registry
            .issue_identity_approval(
                deployment_id,
                ControllerIdentityAction::RecoveryRootRotate,
                action_sha256,
                admin_user_id,
                now,
            )
            .await?)
    }

    /// Consume one `recovery-root-rotate` approval and replace the root in the
    /// same transaction (D12 step 5).  A missing root is enrolled at
    /// generation 1 through the identical path, so first enrollment and later
    /// rotations cannot diverge.  Replay/expiry/binding-mismatch aborts the
    /// whole transaction: a consumed approval can never exist without its
    /// replacement having committed, and no replacement can exist without its
    /// approval having been consumed.
    pub async fn commit_rotation(
        &self,
        approval_token: &str,
        expected_deployment_id: &str,
        expected_action_sha256: &str,
        root: NewRecoveryRoot,
        now: DateTime<Utc>,
    ) -> Result<StoredRecoveryRoot, RecoveryRotationError> {
        validate_deployment_id(expected_deployment_id)
            .map_err(|_| RecoveryRootError::InvalidIdentity("deployment_id is invalid"))?;
        validate_deployment_id(&root.deployment_id)
            .map_err(|_| RecoveryRootError::InvalidIdentity("deployment_id is invalid"))?;
        validate_kid(&root.kid).map_err(|_| {
            RecoveryRootError::InvalidIdentity("kid must be unpadded base64url SHA-256")
        })?;
        validate_kid_binding(&root.kid, &root.public_key).map_err(|_| {
            RecoveryRootError::InvalidIdentity("kid does not match the recovery public key")
        })?;
        if root.deployment_id != expected_deployment_id {
            return Err(RecoveryRotationError::Approval(
                IdentityApprovalError::ActionMismatch,
            ));
        }
        let token_hash = blake3::hash(approval_token.as_bytes()).to_hex().to_string();
        let expected_action_sha256 = expected_action_sha256.to_owned();
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(RecoveryRotationError::Transport)?;
        connection
            .transaction::<_, RecoveryRotationError, _>(async move |connection| {
                lock_deployment_recovery(connection, &root.deployment_id).await?;
                consume_approval_on_connection(
                    connection,
                    &token_hash,
                    &root.deployment_id,
                    ControllerIdentityAction::RecoveryRootRotate,
                    &expected_action_sha256,
                    now,
                )
                .await?;
                replace_root_on_connection(connection, &root, now)
                    .await
                    .map_err(RecoveryRotationError::Mutation)
            })
            .await
    }

    // -- Challenges (D11) -----------------------------------------------------

    /// Issue one recovery challenge bound to the deployment and the exact
    /// proposed key material.  Refused while ANY controller slot would admit
    /// operations: with working keys the ordinary fresh-2FA identity paths
    /// remain the correct route (04A §2 权限), and the break-glass path only
    /// unlocks once the deployment has no admitting key left.
    pub async fn issue_recovery_challenge(
        &self,
        challenge: NewRecoveryChallenge,
        now: DateTime<Utc>,
    ) -> Result<IssuedRecoveryChallenge, RecoveryRootError> {
        validate_challenge_input(&challenge)?;
        let admitted = self
            .registry
            .admitted_controllers(&challenge.deployment_id, now)
            .await?;
        if !admitted.is_empty() {
            return Err(RecoveryRootError::ControllersStillAdmitted(
                admitted
                    .iter()
                    .map(AdmittedControllerSummary::from)
                    .collect(),
            ));
        }
        // The FK guarantees a root exists; read it so the error taxonomy stays
        // explicit instead of surfacing as an insert failure.
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        if read_root_on_connection(&mut connection, &challenge.deployment_id)
            .await?
            .is_none()
        {
            return Err(RecoveryRootError::RootMissing);
        }
        let challenge_id = Uuid::now_v7();
        let nonce = rand::random::<[u8; 32]>();
        let expires_at = now + Duration::seconds(RECOVERY_CHALLENGE_TTL_SECONDS);
        // A lapsed challenge must not brick recovery forever: clear expired
        // pending rows first so a fresh challenge can be issued.  A live
        // pending row survives and keeps the unique-index refusal below
        // truthful (ChallengePending only ever means "one is still running").
        sql_query(
            "DELETE FROM controller_recovery_challenges
             WHERE deployment_id = $1 AND consumed_at IS NULL AND expires_at <= $2",
        )
        .bind::<Varchar, _>(&challenge.deployment_id)
        .bind::<Timestamptz, _>(now)
        .execute(&mut connection)
        .await
        .map_err(transport)?;
        let inserted = sql_query(
            "INSERT INTO controller_recovery_challenges
                (challenge_id, deployment_id, nonce, controller_label,
                 controller_kid, controller_public_key, recovery_kid,
                 recovery_public_key, attempts, expires_at, consumed_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9, NULL, $10)",
        )
        .bind::<DieselUuid, _>(challenge_id)
        .bind::<Varchar, _>(&challenge.deployment_id)
        .bind::<Binary, _>(&nonce[..])
        .bind::<Varchar, _>(&challenge.controller_label)
        .bind::<Varchar, _>(&challenge.controller_kid)
        .bind::<Binary, _>(&challenge.controller_public_key[..])
        .bind::<Varchar, _>(&challenge.recovery_kid)
        .bind::<Binary, _>(&challenge.recovery_public_key[..])
        .bind::<Timestamptz, _>(expires_at)
        .bind::<Timestamptz, _>(now)
        .execute(&mut connection)
        .await;
        if let Err(error) = inserted {
            // Under the pending-per-deployment unique index the only expected
            // conflict is an outstanding challenge.
            if matches!(
                error,
                QueryError::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)
            ) {
                return Err(RecoveryRootError::ChallengePending);
            }
            return Err(transport(error));
        }
        Ok(IssuedRecoveryChallenge {
            challenge_id,
            deployment_id: challenge.deployment_id,
            nonce,
            expires_at,
        })
    }

    /// Record one failed submission outside the accepting transaction so the
    /// counter survives the rollback of the rejected attempt.  The challenge
    /// dies (becomes consumed) with the attempt that reaches the cap.
    async fn record_failed_attempt(
        &self,
        challenge_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), RecoveryRootError> {
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        sql_query(
            "UPDATE controller_recovery_challenges
             SET attempts = attempts + 1,
                 consumed_at = CASE
                     WHEN attempts + 1 >= $2 THEN $3 ELSE consumed_at END
             WHERE challenge_id = $1
               AND consumed_at IS NULL
               AND expires_at > $3",
        )
        .bind::<DieselUuid, _>(challenge_id)
        .bind::<Integer, _>(MAX_RECOVERY_CHALLENGE_ATTEMPTS)
        .bind::<Timestamptz, _>(now)
        .execute(&mut connection)
        .await
        .map_err(transport)?;
        Ok(())
    }

    /// Verify one signed answer and, on success, atomically: mark the
    /// challenge consumed, revoke EVERY active controller slot of the
    /// deployment, enroll exactly one new slot (fresh server-assigned
    /// `controller_id`, lowest free index, fixed 30-day expiry computed
    /// server-side), and replace the Recovery Root with the proposed next
    /// public key at generation+1.  Any rejection leaves the whole deployment
    /// state untouched except the failed-attempt counter.
    ///
    /// Verification always runs against the CURRENT stored root inside the
    /// serialization window of the per-deployment recovery lock, so a secret
    /// of an older generation — including one rotated away milliseconds ago —
    /// can never complete an in-flight challenge.
    pub async fn submit_recovery_challenge(
        &self,
        submission: RecoverySubmission,
        now: DateTime<Utc>,
    ) -> Result<RecoveredSlotCommit, RecoveryRootError> {
        validate_deployment_id(&submission.deployment_id)
            .map_err(|_| RecoveryRootError::InvalidIdentity("deployment_id is invalid"))?;
        let mut connection = get_conn(&self.pool).await.map_err(transport)?;
        let outcome = connection
            .transaction::<_, RecoveryRootError, _>(async move |connection| {
                lock_deployment_recovery(connection, &submission.deployment_id).await?;
                let challenge = sql_query(format!(
                    "SELECT {CHALLENGE_COLUMNS}
                     FROM controller_recovery_challenges
                     WHERE challenge_id = $1
                     FOR UPDATE"
                ))
                .bind::<DieselUuid, _>(submission.challenge_id)
                .get_result::<ChallengeRow>(connection)
                .await
                .optional()
                .map_err(transport)?
                .filter(|row| row.deployment_id == submission.deployment_id)
                .ok_or(RecoveryRootError::ChallengeUnknown)?;
                if challenge.consumed_at.is_some() {
                    if i32::from(challenge.attempts) >= MAX_RECOVERY_CHALLENGE_ATTEMPTS
                        && challenge.accepted_signature_sha256.is_none()
                    {
                        return Err(RecoveryRootError::ChallengeExhausted);
                    }
                    let submitted_signature_sha256 = signature_sha256(&submission.signature);
                    if !digest_matches(&submission.nonce, &challenge.nonce)
                        || !challenge
                            .accepted_signature_sha256
                            .as_deref()
                            .is_some_and(|stored| {
                                digest_matches(&submitted_signature_sha256, stored)
                            })
                    {
                        return Err(RecoveryRootError::ChallengeReplayed);
                    }
                    let (
                        Some(controller_id),
                        Some(slot_index),
                        Some(issued_at),
                        Some(expires_at),
                        Some(recovery_generation),
                    ) = (
                        challenge.recovered_controller_id.clone(),
                        challenge.recovered_slot_index,
                        challenge.recovered_slot_issued_at,
                        challenge.recovered_slot_expires_at,
                        challenge.recovery_generation,
                    )
                    else {
                        return Err(transport(anyhow::anyhow!(
                            "consumed recovery challenge has no complete result receipt"
                        )));
                    };
                    return Ok(RecoveredSlotCommit {
                        slot: StoredControllerSlot {
                            deployment_id: challenge.deployment_id,
                            controller_id,
                            label: challenge.controller_label,
                            kid: challenge.controller_kid,
                            public_key: challenge.controller_public_key,
                            slot_index,
                            issued_at,
                            expires_at,
                            last_used_at: None,
                            status: ControllerSlotStatus::Active,
                            revoked_at: None,
                            created_at: issued_at,
                            updated_at: issued_at,
                        },
                        recovery_generation,
                    });
                }
                if challenge.expires_at <= now {
                    return Err(RecoveryRootError::ChallengeExpired);
                }
                if !digest_matches(&submission.nonce, &challenge.nonce) {
                    return Err(RecoveryRootError::NonceMismatch);
                }
                let root = read_root_on_connection(connection, &submission.deployment_id)
                    .await?
                    .ok_or(RecoveryRootError::RootMissing)?;
                let proposal = nazo_operator_protocol::RecoveryProposal {
                    deployment_id: challenge.deployment_id.clone(),
                    controller_label: challenge.controller_label.clone(),
                    controller_kid: challenge.controller_kid.clone(),
                    controller_public_key: challenge
                        .controller_public_key
                        .clone()
                        .try_into()
                        .map_err(|_| {
                            transport(anyhow::anyhow!("stored challenge holds invalid key length"))
                        })?,
                    recovery_kid: challenge.recovery_kid.clone(),
                    recovery_public_key: challenge.recovery_public_key.clone().try_into().map_err(
                        |_| transport(anyhow::anyhow!("stored challenge holds invalid key length")),
                    )?,
                };
                let verified = proposal.verify_challenge_signature(
                    &submission.challenge_id.to_string(),
                    &submission.nonce,
                    root.recovery_public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| {
                            transport(anyhow::anyhow!(
                                "stored recovery root holds invalid key length"
                            ))
                        })?,
                    &submission.signature,
                );
                if !verified {
                    return Err(RecoveryRootError::InvalidSignature);
                }

                // W3.5: re-check admitted slots INSIDE this transaction so a
                // slot bound after challenge issuance blocks the recovery.
                // Without this, a concurrent bind would be silently revoked
                // by the break-glass commit below.
                let active_count = sql_query(
                    "SELECT COUNT(*) AS count FROM controller_registry_slots \
                     WHERE deployment_id = $1 AND status = 'active' AND expires_at > $2",
                )
                .bind::<Varchar, _>(&submission.deployment_id)
                .bind::<Timestamptz, _>(now)
                .get_result::<CountRow>(connection)
                .await
                .map_err(transport)?;
                if active_count.count > 0 {
                    return Err(RecoveryRootError::ControllersStillAdmitted(Vec::new()));
                }

                // Accepted: commit the recovery and its exact retry receipt in
                // the same transaction. A lost HTTP response can then be
                // recovered by resending the byte-identical signed answer;
                // no new authority is exercised on that readback path.
                sql_query(
                    "UPDATE controller_registry_slots
                     SET status = 'revoked', revoked_at = $2, updated_at = $2
                     WHERE deployment_id = $1 AND status = 'active'",
                )
                .bind::<Varchar, _>(&submission.deployment_id)
                .bind::<Timestamptz, _>(now)
                .execute(connection)
                .await
                .map_err(transport)?;
                let slot = insert_slot_on_connection(
                    connection,
                    &NewControllerSlot {
                        deployment_id: challenge.deployment_id.clone(),
                        label: challenge.controller_label.clone(),
                        kid: challenge.controller_kid.clone(),
                        public_key: challenge.controller_public_key.clone().try_into().map_err(
                            |_| {
                                transport(anyhow::anyhow!(
                                    "stored challenge holds invalid key length"
                                ))
                            },
                        )?,
                    },
                    now,
                )
                .await?;
                let replaced = replace_root_on_connection(
                    connection,
                    &NewRecoveryRoot {
                        deployment_id: submission.deployment_id.clone(),
                        kid: challenge.recovery_kid,
                        public_key: challenge.recovery_public_key.clone().try_into().map_err(
                            |_| {
                                transport(anyhow::anyhow!(
                                    "stored challenge holds invalid key length"
                                ))
                            },
                        )?,
                    },
                    now,
                )
                .await?;
                let accepted_signature_sha256 = signature_sha256(&submission.signature);
                sql_query(
                    "UPDATE controller_recovery_challenges
                     SET consumed_at = $2,
                         accepted_signature_sha256 = $3,
                         recovered_controller_id = $4,
                         recovered_slot_index = $5,
                         recovered_slot_issued_at = $6,
                         recovered_slot_expires_at = $7,
                         recovery_generation = $8
                     WHERE challenge_id = $1",
                )
                .bind::<DieselUuid, _>(submission.challenge_id)
                .bind::<Timestamptz, _>(now)
                .bind::<Binary, _>(accepted_signature_sha256.to_vec())
                .bind::<Varchar, _>(&slot.controller_id)
                .bind::<SmallInt, _>(slot.slot_index)
                .bind::<Timestamptz, _>(slot.issued_at)
                .bind::<Timestamptz, _>(slot.expires_at)
                .bind::<Integer, _>(replaced.generation)
                .execute(connection)
                .await
                .map_err(transport)?;
                Ok(RecoveredSlotCommit {
                    slot,
                    recovery_generation: replaced.generation,
                })
            })
            .await;
        match outcome {
            Ok(commit) => Ok(commit),
            Err(
                error @ (RecoveryRootError::NonceMismatch | RecoveryRootError::InvalidSignature),
            ) => {
                self.record_failed_attempt(submission.challenge_id, now)
                    .await?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }
}
