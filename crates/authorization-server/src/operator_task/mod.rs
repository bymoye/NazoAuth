//! Privileged task entry point. It accepts only a signed, non-secret envelope on stdin.

use std::{
    env,
    fs::{self, OpenOptions},
    io::{Cursor, Read as _, Write as _},
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use fs2::FileExt as _;
use nazo_operator_protocol::{
    EmbeddedIdentity, RuntimeReceipt, SecretBinding, TaskEnvelope, TaskOperation, TaskOutcome,
    TaskResult, compact_sha256, sign_runtime_receipt, validate_runtime_receipt_deployment_binding,
    validate_task_deployment_binding, verify_runtime_receipt, verify_task_signature,
    verify_task_window,
};
use sha2::{Digest as _, Sha256};
use yaml_serde::Value as YamlValue;

use crate::control_discovery::read_identifier;

const CONTEXT_PATH: &str = "/run/nazoauth-operator/context.json";
const CONTROLLER_PUBLIC_KEY_PATH: &str = "/run/nazoauth-operator/controller.pub";
const RECEIPT_PRIVATE_KEY_PATH: &str = "/run/nazoauth-operator/receipt.key";
const SECRET_REVISION_PATH: &str = "/run/nazoauth-operator/secret-revision";
const EXTERNAL_PUBLIC_JWK_PATH: &str = "/run/nazoauth-operator/public.jwk";
const STATE_DIRECTORY: &str = "/var/lib/nazoauth/operator-state";
const CONFIG_MANIFEST_PATH: &str = "/run/nazoauth-operator/config-manifest.json";
const TASK_LOCK_TIMEOUT: Duration = Duration::from_secs(25);
const TASK_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskContext {
    controller_key_id: String,
    receipt_key_id: String,
}

/// Durable, per-request lifecycle state.
///
/// `Executing` is terminal for operations whose state owner cannot prove
/// idempotent recovery.  `migrate-apply` is the one exception: the Diesel
/// migration ledger is the state owner and makes the same request safe to
/// re-enter after a process died before publishing its receipt.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "phase", rename_all = "kebab-case", deny_unknown_fields)]
enum TaskLifecycle {
    Prepared { request_sha256: String },
    Executing { request_sha256: String },
    Completed { request_sha256: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestClaim {
    Created,
    Current,
    Legacy,
}

const REQUEST_CLAIM_PREFIX: &str = "nazoauth-operator-request-v1:";

mod execution;
mod identity;
mod lifecycle;
mod receipts;

use execution::execute;
pub(crate) use identity::embedded_identity;
use identity::{
    operation_name, persist_operator_state_identity, validate_config_manifest,
    validate_embedded_identity, validate_local_task_identity, validate_secret_binding,
};
#[cfg(test)]
use identity::{
    validate_config_manifest_at, validate_local_task_identity_at, validate_secret_binding_at,
};
use lifecycle::{
    acquire_task_lock, can_reenter_migration, claim_request, ensure_current_claim,
    load_or_prepare_lifecycle, mark_task_executing, write_lifecycle_atomic,
};
#[cfg(test)]
use lifecycle::{
    acquire_task_lock_with_timeout, lifecycle_temporary_path, read_lifecycle,
    write_initial_lifecycle,
};
use receipts::{
    read_published_receipt, read_verifying_key, recover_receipt_temporary, sign_task_outcome,
    stable_error_code, verify_public_jwk, write_receipt_atomic,
};
#[cfg(test)]
use receipts::{
    read_signing_key, receipt_temporary_path, validate_receipt_for_task, verify_public_jwk_at,
};

pub async fn run() -> anyhow::Result<()> {
    let mut compact = String::new();
    std::io::stdin()
        .take((nazo_operator_protocol::MAX_COMPACT_JWS_BYTES + 1) as u64)
        .read_to_string(&mut compact)
        .context("failed to read operator task envelope from stdin")?;
    let compact = compact.trim_end_matches(['\r', '\n']);
    let context_path = configured_path("NAZOAUTH_OPERATOR_CONTEXT_FILE", CONTEXT_PATH);
    let context: TaskContext = serde_json::from_slice(
        &fs::read(context_path).context("failed to read operator task context")?,
    )
    .context("operator task context is invalid")?;
    let controller_key = read_verifying_key(&configured_path(
        "NAZOAUTH_OPERATOR_CONTROLLER_PUBLIC_KEY_FILE",
        CONTROLLER_PUBLIC_KEY_PATH,
    ))?;
    let task = match verify_task_signature(compact, &context.controller_key_id, &controller_key) {
        Ok(task) => task,
        Err(error) => {
            // A closed, non-secret classification for the ctl retirement probe.
            // Do not include key material, envelope content, or parser detail.
            eprintln!("nazoauth-operator-rejection=authorization");
            return Err(error).context("operator task authorization failed");
        }
    };
    validate_embedded_identity(&task)?;
    validate_config_manifest(&task)?;
    // Secret rotation is an authorization boundary, not merely controller
    // metadata.  Validate the local authority before creating or reusing a
    // durable request claim so a rotated deployment cannot resume an older
    // envelope, including one that was already claimed before restart.
    validate_secret_binding(&task)?;
    let expected_deployment_id = validate_local_task_identity(&task)?;
    let state = configured_path("NAZOAUTH_OPERATOR_STATE_DIRECTORY", STATE_DIRECTORY);
    fs::create_dir_all(&state)?;
    ensure_real_state_directory(&state)?;
    let lock_path = state.join("task.lock");
    if state_path_present(&lock_path)? {
        regular_state_file_present(&lock_path, "operator task lock")?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)?;
    regular_state_file_present(&state.join("task.lock"), "operator task lock")?;

    let request_sha256 = compact_sha256(compact);
    let receipt_path = state.join(format!("{}.receipt.jws", task.jti));
    let request_path = state.join(format!("{}.request.sha256", task.jti));
    let receipt_key_path = configured_path(
        "NAZOAUTH_OPERATOR_RECEIPT_PRIVATE_KEY_FILE",
        RECEIPT_PRIVATE_KEY_PATH,
    );
    // Keep the OS lock held through state publication and operation execution.
    // A pre-claim lock timeout is transport failure, not an authoritative
    // operation outcome: another holder may still publish the same JTI's
    // success receipt.  The bounded error lets ctl preserve intent and retry.
    let _task_lock = acquire_task_lock(lock).await?;

    let request_was_claimed = regular_state_file_present(&request_path, "operator request claim")?;
    if !request_was_claimed {
        // A versioned claim is published only after the envelope was accepted
        // inside its authorization window.  Its durable presence therefore
        // lets a restarted runtime finish a previously accepted Prepared task
        // without treating expiry as permission to mint or execute a new task.
        verify_task_window(&task, Utc::now().timestamp())
            .context("operator task authorization failed")?;
    }
    let claim = claim_request(&request_path, &request_sha256)?;
    persist_operator_state_identity(&state, &expected_deployment_id)?;
    if let Some(prior) = read_published_receipt(
        &receipt_path,
        &task,
        &request_sha256,
        &expected_deployment_id,
        &context.receipt_key_id,
        &receipt_key_path,
    )? {
        print!("{prior}");
        return Ok(());
    }

    if let Some(prior) = recover_receipt_temporary(
        &receipt_path,
        &task,
        &request_sha256,
        &expected_deployment_id,
        &context.receipt_key_id,
        &receipt_key_path,
    )? {
        print!("{prior}");
        return Ok(());
    }

    ensure_current_claim(claim)?;
    let lifecycle_path = state.join(format!("{}.lifecycle.json", task.jti));
    let lifecycle = load_or_prepare_lifecycle(&lifecycle_path, &request_sha256)?;

    let migration_reentry = can_reenter_migration(&task.operation, &lifecycle);
    if !migration_reentry {
        mark_task_executing(&lifecycle_path, &lifecycle, &request_sha256)?;
        pause_at_test_failpoint("after-executing")?;
    }

    let started_at = Utc::now().timestamp();
    let outcome = execute(&task.operation).await;
    pause_at_test_failpoint("after-operation")?;
    let completed_at = Utc::now().timestamp();
    let compact_receipt = sign_task_outcome(
        &task,
        &request_sha256,
        outcome,
        &context.receipt_key_id,
        &receipt_key_path,
        started_at,
        completed_at,
    )?;
    write_receipt_atomic(&receipt_path, compact_receipt.as_bytes())?;
    write_lifecycle_atomic(
        &lifecycle_path,
        &TaskLifecycle::Completed { request_sha256 },
    )?;
    print!("{compact_receipt}");
    Ok(())
}
#[cfg(unix)]
fn sync_directory(path: &Path) -> anyhow::Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn configured_path(variable: &str, fallback: &str) -> PathBuf {
    env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(fallback))
}

fn regular_state_file_present(path: &Path, description: &str) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => bail!("{description} is not a regular non-symlink file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {description}")),
    }
}

fn state_path_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn ensure_real_state_directory(path: &Path) -> anyhow::Result<()> {
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
