//! One-shot application operator entry (E04/E05).
//!
//! The process admits exactly one signed [`ControlOperation`] per run and
//! executes it under operation-journal discipline.  The admission order is
//! fixed by NazoAuthCtl-goal-plan/05 E04 and must not be reordered:
//!
//! ```text
//! 1. parse schema / size / closed operation enum (reject unknown fields)
//! 2. look up the controller kid/public key BY deployment_id in the
//!    Controller Registry repository (D01/D02 authority)
//! 3. verify the Ed25519 signature over the canonical bytes
//! 4. key expiry/revocation at first admission (the registry lookup only
//!    returns active, unexpired slots)
//! 5. deployment binding and config_revision fencing
//! 6. enter the operation journal accept checkpoint (E03)
//! 7. execute strictly per journal checkpoints; internal steps never
//!    re-authenticate
//! ```
//!
//! There is deliberately no human 2FA re-check, no receipt/audit key, and no
//! `iat`/`nbf`/`exp` request authorization here: the frozen envelope carries
//! no time claims, replay defense is accept-once journaling, and Controller
//! Key validity is evaluated exactly once, at first accept (05 §2/§5).  An
//! already-accepted operation resumes from the journal alone — including its
//! authorization snapshot — and is unaffected by later key expiry or
//! revocation.
//!
//! Everything before the journal accept checkpoint is an admission decision:
//! failures exit non-zero with a closed stderr classification line
//! (`nazoauth-operator-rejection=<class>`).  Everything after acceptance is a
//! durable [`nazo_operator_protocol::ControlResult`] printed on stdout as
//! typed JSON; it is the only output channel.

use std::{
    env,
    fs::{self, OpenOptions},
    future::Future,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, bail};
use chrono::Utc;
use fs2::FileExt as _;
use nazo_operator_protocol::{
    ControlOperation, MAX_COMPACT_JWS_BYTES, encode_control_result,
    verify_control_operation_signature,
};

mod admission;
mod control_journal;
mod execution;
mod identity;

pub(crate) use identity::release_identity;

const CONFIG_REVISION_PATH: &str = "/run/nazauth-operator/config-revision";
const STATE_DIRECTORY: &str = "/var/lib/nazauth/operator-state";
const TASK_LOCK_TIMEOUT: Duration = Duration::from_secs(25);
const TASK_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(100);
pub type OperatorBackendFuture<'a, T> =
    Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;

/// Backend capabilities required by the one-shot operator workflow.
///
/// The application owns operation admission and journaling; each database
/// adapter owns its connection lifecycle and the atomic persistence commands.
pub trait OperatorPersistence: Send + Sync {
    fn controller_registry(&self) -> Arc<dyn nazo_persistence::ControllerRegistryPort>;

    fn recovery_invalidations(&self) -> Arc<dyn nazo_persistence::RecoveryInvalidationStore>;

    fn admin_clients(&self) -> Arc<dyn nazo_auth::AdminClientRepositoryPort>;

    fn tenant_resource_executor(
        &self,
        tenant: nazo_identity::TenantContext,
        data_encryption_key: Option<[u8; 32]>,
        preparation: Arc<dyn nazo_persistence::tenant_resources::TenantResourcePreparation>,
    ) -> Arc<dyn nazo_persistence::tenant_resources::TenantResourceExecutorPort>;

    fn run_migrations(&self) -> OperatorBackendFuture<'_, bool>;

    fn initialize_tenant_directory(
        &self,
        binding: nazo_identity::TenantDirectoryBinding,
    ) -> OperatorBackendFuture<'_, bool>;
}

pub async fn run(persistence: Arc<dyn OperatorPersistence>) -> anyhow::Result<()> {
    let mut compact = String::new();
    std::io::stdin()
        .take((MAX_COMPACT_JWS_BYTES + 1) as u64)
        .read_to_string(&mut compact)
        .context("failed to read control operation from stdin")?;
    let compact = compact.trim_end_matches(['\r', '\n']);

    let state_directory = configured_path("NAZOAUTH_OPERATOR_STATE_DIRECTORY", STATE_DIRECTORY);
    fs::create_dir_all(&state_directory)?;
    ensure_real_state_directory(&state_directory)?;
    let lock_path = state_directory.join("task.lock");
    if state_path_present(&lock_path)? {
        regular_state_file_present(&lock_path, "operator task lock")?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    regular_state_file_present(&state_directory.join("task.lock"), "operator task lock")?;
    // Keep the OS lock held through admission, journal publication, and
    // execution so only one one-shot process ever drives one state directory.
    // A pre-admission lock timeout is transport failure, not an authoritative
    // outcome: ctl preserves intent and retries.
    let _task_lock = acquire_task_lock(lock).await?;

    let outcome = execute_compact(&state_directory, compact, persistence.as_ref()).await;

    // Bounded retention cleanup rides at the tail of the one-shot entry (E03
    // note): terminal results stay recoverable for thirty days, after which
    // the next successful operator run deletes them.  Housekeeping must never
    // fail an executed operation, so its errors are swallowed here.
    if outcome.is_ok() {
        let cutoff =
            Utc::now().timestamp() - control_journal::CONTROL_JOURNAL_COMPLETED_RETENTION_SECONDS;
        let _ = control_journal::cleanup_completed_before(&state_directory, cutoff);
    }

    outcome
}

/// Full E04 pipeline for one presented compact JWS.  Prints the durable
/// [`nazo_operator_protocol::ControlResult`] on success.
async fn execute_compact(
    state_directory: &Path,
    compact: &str,
    persistence: &dyn OperatorPersistence,
) -> anyhow::Result<()> {
    // (1) Parse schema/size/closed enum before any authority is consulted.
    let presented = reject(admission::present(compact), RejectionClass::Request)?;
    let request_hash = reject(
        nazo_operator_protocol::control_operation_request_hash(&presented)
            .map_err(anyhow::Error::new),
        RejectionClass::Request,
    )?;

    // Resume-first: an accepted journal record owns authorization for this
    // exact canonical request (same id + same hash implies byte-equal
    // payload), so the operation resumes without any registry lookup,
    // signature check, or key lifecycle evaluation (05 §5).  A different hash
    // under the same id is the permanent OPERATION_ID_CONFLICT.
    let snapshot =
        control_journal::accepted_snapshot(state_directory, &presented.operation_id, &request_hash)
            .map_err(map_journal_error)?;
    if let Some(snapshot) = snapshot {
        return journaled_execution(
            state_directory,
            &presented,
            &request_hash,
            &snapshot,
            persistence,
        )
        .await;
    }

    // (2)+(4) Registry authority: find the controller key for this deployment
    // and admit it only while it is active and unexpired at admission time.
    let repository = persistence.controller_registry();
    let admitted = match admission::admit_controller(
        repository.as_ref(),
        &presented.deployment_id,
        &presented.kid,
        Utc::now(),
    )
    .await
    {
        Ok(admitted) => admitted,
        Err(admission::AdmissionError::Unauthorized) => {
            rejection_line(RejectionClass::Authorization);
            bail!("controller key admission rejected");
        }
        Err(admission::AdmissionError::Transport(error)) => {
            rejection_line(RejectionClass::Unavailable);
            return Err(error.context("controller registry is unavailable"));
        }
    };

    // (3) Signature over the canonical bytes through the single frozen
    // verifier API; it re-validates header, encoding, envelope policy, and
    // key binding.  The verified operation replaces the pre-parsed one from
    // here on, so there is no parse/verify TOCTOU gap.
    let verified = reject(
        verify_control_operation_signature(compact, &admitted.kid, &admitted.verifying_key)
            .map_err(anyhow::Error::new),
        RejectionClass::Authorization,
    )?;

    // (5) Fencing: the operation names this local deployment and its
    // config_revision matches the local revision marker.
    let local_deployment_id = reject(
        identity::validate_local_operation_identity(&verified.operation),
        RejectionClass::Deployment,
    )?;
    if local_deployment_id != verified.deployment_id {
        rejection_line(RejectionClass::Deployment);
        bail!("operator task deployment identity is not local");
    }
    // Persist/verify the operator state anchor only after the signed
    // deployment binding proved local, so an unadmitted request can never
    // seed state directory identity.
    identity::persist_operator_state_identity(state_directory, &local_deployment_id)?;
    reject(
        identity::validate_config_revision(&verified),
        RejectionClass::Revision,
    )?;

    // (6)+(7) Journal accept-before-side-effect, then checkpoint-driven
    // execution with per-operation resume ownership (E05 mapping table in
    // execution.rs).
    let snapshot = control_journal::AuthorizationSnapshot {
        controller_id: admitted.controller_id.clone(),
        kid: admitted.kid.clone(),
        accepted_at: Utc::now().timestamp(),
    };
    journaled_execution(
        state_directory,
        &verified,
        &request_hash,
        &snapshot,
        persistence,
    )
    .await
}

/// Run one operation under journal discipline and print its durable result.
async fn journaled_execution(
    state_directory: &Path,
    operation: &ControlOperation,
    request_hash: &str,
    snapshot: &control_journal::AuthorizationSnapshot,
    persistence: &dyn OperatorPersistence,
) -> anyhow::Result<()> {
    let resume_allowed = execution::resume_allowed(&operation.operation);
    let context = execution::ExecutionContext {
        operation_id: &operation.operation_id,
        deployment_id: &operation.deployment_id,
        controller_id: &snapshot.controller_id,
        kid: &snapshot.kid,
        request_hash,
    };
    let outcome = control_journal::run_journaled_operation(
        state_directory,
        operation,
        request_hash,
        snapshot,
        resume_allowed,
        &|name| {
            let _ = pause_at_test_failpoint(name);
        },
        || execution::execute_with_persistence(&operation.operation, &context, persistence),
    )
    .await
    .map_err(map_journal_error)?;
    let bytes = reject(
        encode_control_result(&outcome.result).map_err(anyhow::Error::new),
        RejectionClass::Request,
    )?;
    print!("{}", String::from_utf8_lossy(&bytes));
    Ok(())
}

fn map_journal_error(error: control_journal::JournalFlowError) -> anyhow::Error {
    match error {
        control_journal::JournalFlowError::OperationIdConflict => {
            rejection_line(RejectionClass::Conflict);
            anyhow::Error::new(error).context("operation id conflict")
        }
        control_journal::JournalFlowError::UnknownOutcome => anyhow::Error::new(error)
            .context("operator task may have executed without a durable result; refusing replay"),
        other => anyhow::Error::new(other),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectionClass {
    Request,
    Authorization,
    Deployment,
    Revision,
    Conflict,
    Unavailable,
}

impl RejectionClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Authorization => "authorization",
            Self::Deployment => "deployment",
            Self::Revision => "revision",
            Self::Conflict => "conflict",
            Self::Unavailable => "unavailable",
        }
    }
}

fn rejection_line(class: RejectionClass) {
    // A closed, non-secret classification for ctl probes.  Do not include key
    // material, envelope content, or parser detail.
    eprintln!("nazoauth-operator-rejection={}", class.as_str());
}

fn reject<T>(result: anyhow::Result<T>, class: RejectionClass) -> anyhow::Result<T> {
    result.inspect_err(|_| rejection_line(class))
}

#[cfg(unix)]
pub(super) fn sync_directory(path: &Path) -> anyhow::Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn sync_directory(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

pub(super) fn configured_path(variable: &str, fallback: &str) -> PathBuf {
    env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(fallback))
}

pub(super) fn regular_state_file_present(path: &Path, description: &str) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => bail!("{description} is not a regular non-symlink file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {description}")),
    }
}

pub(super) fn state_path_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

pub(super) fn ensure_real_state_directory(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect operator state directory {}",
            path.display()
        )
    })?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        bail!("operator state directory is not a real non-symlink directory")
    }
}

async fn acquire_task_lock(lock: std::fs::File) -> anyhow::Result<std::fs::File> {
    acquire_task_lock_with_timeout(lock, TASK_LOCK_TIMEOUT).await
}

async fn acquire_task_lock_with_timeout(
    lock: std::fs::File,
    timeout: Duration,
) -> anyhow::Result<std::fs::File> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match lock.try_lock_exclusive() {
            Ok(()) => return Ok(lock),
            Err(error) if task_lock_is_contended(&error) => {
                if tokio::time::Instant::now() >= deadline {
                    bail!("operator task lock acquisition timed out");
                }
                tokio::time::sleep(TASK_LOCK_RETRY_INTERVAL).await;
            }
            Err(error) => return Err(error).context("failed to acquire operator task lock"),
        }
    }
}

fn task_lock_is_contended(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || cfg!(windows) && error.raw_os_error() == Some(33)
}

#[cfg(debug_assertions)]
fn pause_at_test_failpoint(name: &str) -> anyhow::Result<()> {
    if env::var("NAZOAUTH_OPERATOR_TEST_FAILPOINT").ok().as_deref() != Some(name) {
        return Ok(());
    }
    let marker = env::var_os("NAZOAUTH_OPERATOR_TEST_FAILPOINT_MARKER")
        .map(PathBuf::from)
        .context("operator test failpoint marker is unavailable")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)?;
    file.write_all(name.as_bytes())?;
    file.sync_all()?;
    if let Some(parent) = marker.parent() {
        sync_directory(parent)?;
    }
    loop {
        std::thread::park();
    }
}

#[cfg(not(debug_assertions))]
fn pause_at_test_failpoint(_name: &str) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/operator_task.rs"]
mod tests;
