//! Application operation journal for signed [`ControlOperation`]s (E03,
//! NazoAuthCtl-goal-plan/05 §4/§5).
//!
//! Core invariants:
//!
//! ```text
//! same operation_id + same request_hash
//!     => one operation lifetime; side effects run at most once
//! same operation_id + different request_hash
//!     => permanent OPERATION_ID_CONFLICT
//! ```
//!
//! The accepted record (including the authorization snapshot:
//! `controller_id`, `kid`, `accepted_at`, `request_hash`) is durably
//! persisted *before* any side effect starts, and the terminal
//! [`ControlResult`] is durably persisted *before* the caller outputs
//! success.  Crash recovery therefore never replays a mutation and never
//! loses a completed outcome.
//!
//! # Storage medium
//!
//! One JSON record per operation id under
//! `<operator-state>/control-journal/{operation_id}.journal.json`,
//! published with the same audited durability pattern as the operator task
//! lifecycle: `create_new` temporary + `sync_all` + `hard_link` (or
//! `rename`) + directory sync, all under the exclusive operator task lock.
//! A database table was deliberately rejected: `migrate-apply` legitimately
//! runs before any database exists, so accept-time persistence must not
//! depend on DB connectivity, and the one-shot operator process already owns
//! this state directory.
//!
//! # Phase model
//!
//! `accepted -> executing -> completed`, monotonically.  `accepted` is the
//! pre-side-effect checkpoint; `executing` means the business action may
//! have started or finished without a durable result; `completed` carries
//! the final result.  A restarted process may cross `accepted -> executing`
//! freely, may re-enter `executing` only when the operation class has a
//! proven-idempotent state owner (`resume_allowed`, E05 decides per
//! operation), and otherwise fails closed with
//! [`JournalFlowError::UnknownOutcome`] instead of guessing.
//!
//! Torn publication windows (temporary file present, final missing or
//! stale) are recovered monotonically: a fully written temporary whose
//! phase is greater than or equal to the published record is adopted;
//! anything else fails closed and leaves the files untouched.
//!
//! # Retention
//!
//! [`cleanup_completed_before`] deletes only `completed` records whose
//! result age exceeds the cutoff.  `accepted`/`executing` records are never
//! deleted automatically: deleting them would either revoke a still
//! resumable authorization or fabricate evidence that an authorized
//! operation never happened.  Their count is bounded by the operational
//! fact that each one represents an unresolved incident an operator must
//! resolve (or decommission with the deployment state directory).
//!
//! # Test failpoints
//!
//! The flow calls the injected `pause` hook at exactly these points so
//! process-level tests (once E04 wires the binary entry) and unit tests can
//! kill/restart at every boundary:
//!
//! ```text
//! control-journal-before-accept
//! control-journal-after-accept
//! control-journal-before-side-effect
//! control-journal-after-side-effect
//! control-journal-before-result   (result not yet durable)
//! control-journal-after-result    (result durable, caller output pending)
//! ```

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use chrono::Utc;
use nazo_operator_protocol::{
    CONTROL_RESULT_SCHEMA, ControlErrorCode, ControlOperation, ControlOutcome, ControlResult,
    validate_control_result,
};

use super::*;

/// Storage schema tag for one journal record.  Bumping it is a breaking
/// change: records written by newer code are refused, never misread.
pub(crate) const CONTROL_JOURNAL_SCHEMA: u32 = 1;

/// Terminal results stay recoverable for at least this long after their
/// recorded completion time.  ctl response-loss recovery (E06) only has to
/// outlive a controller restart, so thirty days bounds growth while never
/// deleting anything that could plausibly still be fetched.
#[allow(dead_code)] // Consumed by the retention job E04 wires next stream.
pub(crate) const CONTROL_JOURNAL_COMPLETED_RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Authorization snapshot persisted at accept time (05 §5).  After
/// acceptance the journal owns authorization: resumed executions must not
/// re-run Controller Key lifecycle checks, because they are not new
/// authorizations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthorizationSnapshot {
    /// Controller registry identity that authorized the operation (D02
    /// lookup output); opaque to the journal.
    pub controller_id: String,
    /// Controller key id whose signature admitted the operation.
    pub kid: String,
    /// Unix seconds at first accept.
    pub accepted_at: i64,
}

/// Outcome of offering an operation to the journal.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AcceptOutcome {
    /// This call published the accepted record; side effects may begin.
    Created,
    /// Same id + hash was accepted before; resume by checkpoint.
    Resumed(JournalCheckpoint),
}

/// Current durable checkpoint of one accepted operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JournalCheckpoint {
    /// Persisted before any side effect.
    Accepted,
    /// Side effects may have run; no durable result yet.
    Executing,
    /// Final result is durable.
    Completed(Box<ControlResult>),
}

/// Typed journal failures.  E04 maps the first two onto the closed
/// [`nazo_operator_protocol::ControlErrorCode`] taxonomy; transport failures
/// are retryable infrastructure faults, never operation outcomes.
#[derive(Debug)]
pub(crate) enum JournalFlowError {
    /// Same `operation_id` with a different canonical request hash.
    /// Permanent for the lifetime of the state directory.
    OperationIdConflict,
    /// A crash left the record `executing` and this operation class has no
    /// proven-idempotent owner, so re-entry could duplicate a mutation.
    /// Fail-closed; requires operator resolution.
    UnknownOutcome,
    /// Durable-state or I/O failure.  Nothing about the operation outcome
    /// can be inferred from it.
    Transport(anyhow::Error),
}

impl std::fmt::Display for JournalFlowError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalFlowError::OperationIdConflict => {
                write!(formatter, "OPERATION_ID_CONFLICT")
            }
            JournalFlowError::UnknownOutcome => {
                write!(
                    formatter,
                    "operation journal has an unresolved executing record"
                )
            }
            JournalFlowError::Transport(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for JournalFlowError {}

fn transport<E>(error: E) -> JournalFlowError
where
    E: Into<anyhow::Error>,
{
    JournalFlowError::Transport(error.into())
}

/// One durable journal record.  Deliberately a flat struct with a closed
/// member set: `deny_unknown_fields` works reliably on structs, and the
/// phase/result pairing is validated explicitly instead of relying on
/// serde enum tagging (which silently ignores unknown members).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OperationJournalRecord {
    schema: u32,
    operation_id: String,
    request_hash: String,
    controller_id: String,
    kid: String,
    accepted_at: i64,
    /// `accepted` | `executing` | `completed`.
    phase: String,
    /// Present if and only if `phase` is `completed`.
    result: Option<ControlResult>,
}

const PHASE_ACCEPTED: &str = "accepted";
const PHASE_EXECUTING: &str = "executing";
const PHASE_COMPLETED: &str = "completed";

fn phase_rank(phase: &str) -> Option<u8> {
    match phase {
        PHASE_ACCEPTED => Some(0),
        PHASE_EXECUTING => Some(1),
        PHASE_COMPLETED => Some(2),
        _ => None,
    }
}

pub(crate) fn control_journal_directory(state_directory: &Path) -> PathBuf {
    state_directory.join("control-journal")
}

fn record_path(directory: &Path, operation_id: &str) -> PathBuf {
    directory.join(format!("{operation_id}.journal.json"))
}

fn record_temporary_path(path: &Path) -> PathBuf {
    path.with_extension("journal.json.tmp")
}

/// Storage-layer defense against path traversal: the operation id becomes a
/// file name, so only the canonical UUID character set may reach this point.
/// Semantic UUIDv7 enforcement stays upstream in envelope validation.
fn ensure_file_safe_identifier(value: &str) -> Result<(), JournalFlowError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(transport(anyhow::anyhow!(
            "journal identifier is not file-safe"
        )));
    }
    Ok(())
}

fn ensure_bounded_text(field: &'static str, value: &str) -> Result<(), JournalFlowError> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(|character| character.is_control())
    {
        return Err(transport(anyhow::anyhow!(
            "journal snapshot field '{field}' is unbounded or empty"
        )));
    }
    Ok(())
}

fn ensure_request_hash_shape(value: &str) -> Result<(), JournalFlowError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(transport(anyhow::anyhow!(
            "journal request hash is not lowercase sha256 hex"
        )));
    }
    Ok(())
}

/// Validate structural invariants of any record read back from disk.
fn validate_record(record: &OperationJournalRecord) -> anyhow::Result<()> {
    if record.schema != CONTROL_JOURNAL_SCHEMA {
        bail!("control operation journal record has an unsupported schema");
    }
    ensure_file_safe_identifier(&record.operation_id)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    ensure_request_hash_shape(&record.request_hash).map_err(|error| anyhow::anyhow!("{error}"))?;
    ensure_bounded_text("controller_id", &record.controller_id)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    ensure_bounded_text("kid", &record.kid).map_err(|error| anyhow::anyhow!("{error}"))?;
    if record.accepted_at <= 0 {
        bail!("control operation journal record has an invalid acceptance time");
    }
    match record.phase.as_str() {
        PHASE_ACCEPTED | PHASE_EXECUTING => {
            if record.result.is_some() {
                bail!("non-terminal control operation journal record carries a result");
            }
        }
        PHASE_COMPLETED => {
            let result = record
                .result
                .as_ref()
                .context("completed control operation journal record carries no result")?;
            validate_control_result(result)
                .map_err(|error| anyhow::anyhow!("journal result is invalid: {error}"))?;
            if result.operation_id != record.operation_id
                || result.request_hash != record.request_hash
                || result.accepted_at != record.accepted_at
            {
                bail!("journal result is not bound to its accepted operation");
            }
        }
        other => bail!("control operation journal record has unknown phase '{other}'"),
    }
    Ok(())
}

fn read_record(path: &Path) -> anyhow::Result<OperationJournalRecord> {
    let record: OperationJournalRecord =
        serde_json::from_slice(&fs::read(path)?).with_context(|| {
            format!(
                "control operation journal record {} is invalid",
                path.display()
            )
        })?;
    validate_record(&record)?;
    Ok(record)
}

fn checkpoint(record: OperationJournalRecord) -> JournalCheckpoint {
    match record.phase.as_str() {
        PHASE_EXECUTING => JournalCheckpoint::Executing,
        PHASE_COMPLETED => JournalCheckpoint::Completed(Box::new(
            record.result.expect("validated completed record"),
        )),
        _ => JournalCheckpoint::Accepted,
    }
}

/// Recover a torn publication window monotonically.  A fully written and
/// fsynced temporary always represents a phase this process intended to
/// publish; adopting it is safe when it does not move the record backwards.
fn recover_temporary(path: &Path) -> Result<(), JournalFlowError> {
    let temporary = record_temporary_path(path);
    if !state_path_present(&temporary).map_err(transport)? {
        return Ok(());
    }
    regular_state_file_present(&temporary, "control operation journal temporary")
        .map_err(transport)?;
    let temporary_record = read_record(&temporary).map_err(transport)?;
    let parent = path
        .parent()
        .context("journal record has no parent directory");
    let parent = parent.map_err(transport)?;
    if !state_path_present(path).map_err(transport)? {
        // The publication itself was interrupted before any execution
        // boundary; finishing it cannot hide a side effect.
        fs::rename(&temporary, path).map_err(transport)?;
        sync_directory(parent).map_err(transport)?;
        return Ok(());
    }
    regular_state_file_present(path, "control operation journal record").map_err(transport)?;
    let published = read_record(path).map_err(transport)?;
    if published.operation_id != temporary_record.operation_id
        || published.request_hash != temporary_record.request_hash
    {
        return Err(transport(anyhow::anyhow!(
            "control operation journal temporary belongs to a different request; refusing recovery"
        )));
    }
    let (published_rank, temporary_rank) = match (
        phase_rank(&published.phase),
        phase_rank(&temporary_record.phase),
    ) {
        (Some(published_rank), Some(temporary_rank)) => (published_rank, temporary_rank),
        _ => {
            return Err(transport(anyhow::anyhow!(
                "control operation journal record has an unknown phase"
            )));
        }
    };
    if temporary_rank > published_rank
        || (temporary_rank == published_rank && temporary_record == published)
    {
        fs::rename(&temporary, path).map_err(transport)?;
        sync_directory(parent).map_err(transport)?;
        Ok(())
    } else {
        Err(transport(anyhow::anyhow!(
            "control operation journal temporary is stale behind the published record; refusing recovery"
        )))
    }
}

/// Publish the initial accepted record with create-once semantics: exactly
/// one concurrent offer wins the hard-link publication, every other observer
/// reads the winner and compares request hashes.  The temporary name is
/// per-publication unique (claim_request pattern) so losing racers can never
/// clobber or fail on the winner's in-flight file; a fully synced orphan
/// left by a killed publisher is inert and never adopted.
fn publish_accepted(
    path: &Path,
    record: &OperationJournalRecord,
) -> Result<bool, JournalFlowError> {
    let parent = path
        .parent()
        .context("journal record has no parent directory");
    let parent = parent.map_err(transport)?;
    let temporary = parent.join(format!(
        ".journal-publish-{}-{:032x}.tmp",
        std::process::id(),
        rand::random::<u128>()
    ));
    let bytes = serde_json::to_vec(record).context("journal record serialization failed");
    let bytes = bytes.map_err(transport)?;
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // Astronomically unlikely random-name collision: behave like a
            // racing publisher and observe the final record instead.
            return Ok(false);
        }
        Err(error) => {
            return Err(transport(
                anyhow::Error::new(error).context("failed to create journal temporary"),
            ));
        }
    };
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        return Err(transport(error));
    }
    drop(file);

    let publish = fs::hard_link(&temporary, path);
    let cleanup = fs::remove_file(&temporary);
    if let Err(error) = cleanup {
        return Err(transport(error));
    }
    match publish {
        Ok(()) => {
            sync_directory(parent).map_err(transport)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(transport(error)),
    }
}

/// Atomically replace the published record with a later phase
/// (`write_lifecycle_atomic` pattern: fsynced temporary + rename).
fn replace_record(path: &Path, record: &OperationJournalRecord) -> Result<(), JournalFlowError> {
    let temporary = record_temporary_path(path);
    if state_path_present(&temporary).map_err(transport)? {
        return Err(transport(anyhow::anyhow!(
            "control operation journal has an incomplete durable transition; refusing recovery"
        )));
    }
    let bytes = serde_json::to_vec(record).context("journal record serialization failed");
    let bytes = bytes.map_err(transport)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(transport)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        return Err(transport(error));
    }
    drop(file);
    let parent = path
        .parent()
        .context("journal record has no parent directory");
    let parent = parent.map_err(transport)?;
    fs::rename(&temporary, path).map_err(transport)?;
    sync_directory(parent).map_err(transport)?;
    Ok(())
}

/// Durably accept one operation before any side effect (05 §4).
///
/// Creates the accepted record exactly once.  A repeated offer with the same
/// id and request hash resumes by checkpoint; a repeated offer with the same
/// id and a different request hash is a permanent conflict.
pub(crate) fn accept(
    state_directory: &Path,
    operation: &ControlOperation,
    request_hash: &str,
    snapshot: &AuthorizationSnapshot,
) -> Result<AcceptOutcome, JournalFlowError> {
    ensure_file_safe_identifier(&operation.operation_id)?;
    ensure_request_hash_shape(request_hash)?;
    ensure_bounded_text("controller_id", &snapshot.controller_id)?;
    ensure_bounded_text("kid", &snapshot.kid)?;
    if snapshot.accepted_at <= 0 {
        return Err(transport(anyhow::anyhow!(
            "journal acceptance time must be positive"
        )));
    }
    let directory = control_journal_directory(state_directory);
    fs::create_dir_all(&directory).map_err(transport)?;
    let path = record_path(&directory, &operation.operation_id);
    recover_temporary(&path)?;

    let record = OperationJournalRecord {
        schema: CONTROL_JOURNAL_SCHEMA,
        operation_id: operation.operation_id.clone(),
        request_hash: request_hash.to_owned(),
        controller_id: snapshot.controller_id.clone(),
        kid: snapshot.kid.clone(),
        accepted_at: snapshot.accepted_at,
        phase: PHASE_ACCEPTED.to_owned(),
        result: None,
    };

    if state_path_present(&path).map_err(transport)? {
        regular_state_file_present(&path, "control operation journal record").map_err(transport)?;
        return observe_existing(&path, &record);
    }
    if publish_accepted(&path, &record)? {
        Ok(AcceptOutcome::Created)
    } else {
        observe_existing(&path, &record)
    }
}

fn observe_existing(
    path: &Path,
    offered: &OperationJournalRecord,
) -> Result<AcceptOutcome, JournalFlowError> {
    let existing = read_record(path).map_err(transport)?;
    if existing.operation_id != offered.operation_id
        || existing.request_hash != offered.request_hash
    {
        return Err(JournalFlowError::OperationIdConflict);
    }
    Ok(AcceptOutcome::Resumed(checkpoint(existing)))
}

/// Load the current checkpoint for an accepted operation.  `Ok(None)` means
/// the id was never accepted; a stored record with a different request hash
/// is the permanent conflict.
#[allow(dead_code)] // E04/E06 consume the resume/recovery lookup next stream.
pub(crate) fn status(
    state_directory: &Path,
    operation_id: &str,
    request_hash: &str,
) -> Result<Option<JournalCheckpoint>, JournalFlowError> {
    ensure_file_safe_identifier(operation_id)?;
    ensure_request_hash_shape(request_hash)?;
    let path = record_path(&control_journal_directory(state_directory), operation_id);
    recover_temporary(&path)?;
    if !state_path_present(&path).map_err(transport)? {
        return Ok(None);
    }
    regular_state_file_present(&path, "control operation journal record").map_err(transport)?;
    let record = read_record(&path).map_err(transport)?;
    if record.request_hash != request_hash {
        return Err(JournalFlowError::OperationIdConflict);
    }
    Ok(Some(checkpoint(record)))
}

/// Move the durable checkpoint to `executing` (still before any side
/// effect).  Re-entering `executing` requires the operation class to own a
/// proven-idempotent state owner (`resume_allowed`); a terminal record
/// refuses re-entry outright.
pub(crate) fn begin_execution(
    state_directory: &Path,
    operation_id: &str,
    request_hash: &str,
    resume_allowed: bool,
) -> Result<(), JournalFlowError> {
    ensure_file_safe_identifier(operation_id)?;
    ensure_request_hash_shape(request_hash)?;
    let path = record_path(&control_journal_directory(state_directory), operation_id);
    recover_temporary(&path)?;
    let mut record = read_record(&path).map_err(transport)?;
    if record.request_hash != request_hash {
        return Err(JournalFlowError::OperationIdConflict);
    }
    match record.phase.as_str() {
        PHASE_ACCEPTED => {
            record.phase = PHASE_EXECUTING.to_owned();
            replace_record(&path, &record)
        }
        PHASE_EXECUTING if resume_allowed => Ok(()),
        PHASE_EXECUTING => Err(JournalFlowError::UnknownOutcome),
        _ => Err(JournalFlowError::UnknownOutcome),
    }
}

/// Persist the terminal result.  Callers must treat this function's return
/// as the only permission to report success: once it returns, the result is
/// durable and response-loss recovery can serve it verbatim.
pub(crate) fn complete(
    state_directory: &Path,
    result: &ControlResult,
) -> Result<(), JournalFlowError> {
    validate_control_result(result).map_err(transport)?;
    ensure_file_safe_identifier(&result.operation_id)?;
    ensure_request_hash_shape(&result.request_hash)?;
    let path = record_path(
        &control_journal_directory(state_directory),
        &result.operation_id,
    );
    recover_temporary(&path)?;
    let mut record = read_record(&path).map_err(transport)?;
    if record.request_hash != result.request_hash || record.accepted_at != result.accepted_at {
        return Err(JournalFlowError::OperationIdConflict);
    }
    record.phase = PHASE_COMPLETED.to_owned();
    record.result = Some(result.clone());
    replace_record(&path, &record)
}

/// Delete only terminal records whose completion time precedes `cutoff`
/// (Unix seconds).  Non-terminal records and unreadable files are never
/// touched: deletion must never fabricate "never happened" or destroy a
/// resumable authorization.  Returns the number of deleted records.
#[allow(dead_code)] // Consumed by the retention job E04 wires next stream.
pub(crate) fn cleanup_completed_before(
    state_directory: &Path,
    cutoff: i64,
) -> Result<usize, JournalFlowError> {
    let directory = control_journal_directory(state_directory);
    if !state_path_present(&directory).map_err(transport)? {
        return Ok(0);
    }
    let mut deleted = 0usize;
    let entries = fs::read_dir(&directory).map_err(transport)?;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => return Err(transport(error)),
        };
        let path = entry.path();
        if path.extension().is_some_and(|extension| extension == "tmp")
            || !regular_state_file_present(&path, "control operation journal record")
                .unwrap_or(false)
        {
            continue;
        }
        let eligible = read_record(&path).ok().is_some_and(|record| {
            record.phase == PHASE_COMPLETED
                && record
                    .result
                    .as_ref()
                    .is_some_and(|result| result.completed_at.is_some_and(|at| at <= cutoff))
        });
        if eligible {
            fs::remove_file(&path).map_err(transport)?;
            deleted += 1;
        }
    }
    if deleted > 0 {
        sync_directory(&directory).map_err(transport)?;
    }
    Ok(deleted)
}

/// Outcome of the journaled flow: the (possibly recovered) terminal result.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct JournaledOutcome {
    pub result: ControlResult,
    /// True when the result came from the journal instead of a fresh
    /// execution (response-loss recovery).
    pub recovered: bool,
}

/// Run one control operation under journal discipline (E03 flow E04 calls
/// after signature verification):
///
/// accept (durable) -> mark executing -> side effect (exactly once per
/// journal rules) -> persist result (durable) -> return to caller.
///
/// `resume_allowed` must be true only for operation classes whose state
/// owner proved idempotent re-entry (the migration ledger today, E05 owns
/// the mapping).  `pause` receives every failpoint name in order; production
/// wires the debug-gated process failpoint helper, tests record calls.
#[allow(dead_code)] // E04 wires the one-shot binary entry next stream.
pub(crate) async fn run_journaled_operation<F, Fut>(
    state_directory: &Path,
    operation: &ControlOperation,
    request_hash: &str,
    snapshot: &AuthorizationSnapshot,
    resume_allowed: bool,
    pause: &dyn Fn(&str),
    side_effect: F,
) -> Result<JournaledOutcome, JournalFlowError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    pause("control-journal-before-accept");
    match accept(state_directory, operation, request_hash, snapshot)? {
        AcceptOutcome::Created | AcceptOutcome::Resumed(JournalCheckpoint::Accepted) => {}
        AcceptOutcome::Resumed(JournalCheckpoint::Completed(result)) => {
            // Response-loss recovery: the terminal result is already
            // durable; the side effect must not run again.
            return Ok(JournaledOutcome {
                result: *result,
                recovered: true,
            });
        }
        AcceptOutcome::Resumed(JournalCheckpoint::Executing) => {}
    }
    pause("control-journal-after-accept");

    // Re-entering an ambiguous `executing` checkpoint is refused here for
    // operation classes without a proven-idempotent owner; with one, the
    // owner's ledger deduplicates the re-application.
    begin_execution(
        state_directory,
        &operation.operation_id,
        request_hash,
        resume_allowed,
    )?;
    pause("control-journal-before-side-effect");

    let (outcome, error) = match side_effect().await {
        Ok(()) => (ControlOutcome::Succeeded, None),
        Err(_) => (
            ControlOutcome::Failed,
            Some(ControlErrorCode::ExecutionFailed),
        ),
    };
    pause("control-journal-after-side-effect");

    let result = ControlResult {
        schema: CONTROL_RESULT_SCHEMA,
        operation_id: operation.operation_id.clone(),
        request_hash: request_hash.to_owned(),
        outcome,
        error,
        accepted_at: snapshot.accepted_at,
        completed_at: Some(Utc::now().timestamp()),
    };
    validate_control_result(&result).map_err(transport)?;
    pause("control-journal-before-result");

    complete(state_directory, &result)?;
    pause("control-journal-after-result");
    Ok(JournaledOutcome {
        result,
        recovered: false,
    })
}

/// Convenience wrapper E04 will extend; uses the production debug-gated
/// failpoint helper.
#[cfg(debug_assertions)]
#[allow(dead_code)] // E04 wires the one-shot binary entry next stream.
pub(crate) async fn run_journaled_operation_with_process_failpoints<F, Fut>(
    state_directory: &Path,
    operation: &ControlOperation,
    request_hash: &str,
    snapshot: &AuthorizationSnapshot,
    resume_allowed: bool,
    side_effect: F,
) -> Result<JournaledOutcome, JournalFlowError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    run_journaled_operation(
        state_directory,
        operation,
        request_hash,
        snapshot,
        resume_allowed,
        &|name| {
            let _ = pause_at_test_failpoint(name);
        },
        side_effect,
    )
    .await
}

#[cfg(test)]
#[path = "../../tests/unit/control_operation_journal.rs"]
mod tests;
