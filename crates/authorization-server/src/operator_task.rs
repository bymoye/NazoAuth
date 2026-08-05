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

async fn execute(operation: &TaskOperation) -> TaskOutcome {
    let result = match operation {
        TaskOperation::MigrateApply => crate::cli::run_migrations()
            .await
            .map(|applied| TaskResult::Migration { applied }),
        TaskOperation::ConformanceLeaseCreate {
            profile,
            material_sha256,
            public_material,
            ttl_seconds,
        } => {
            crate::conformance_lease::operator_create(
                profile,
                material_sha256,
                public_material.clone(),
                *ttl_seconds,
            )
            .await
        }
        TaskOperation::ConformanceLeaseList => crate::conformance_lease::operator_list().await,
        TaskOperation::ConformanceLeaseRevoke { lease_id } => {
            crate::conformance_lease::operator_revoke(lease_id).await
        }
        TaskOperation::ConformanceLeaseCleanup => {
            crate::conformance_lease::operator_cleanup().await
        }
        TaskOperation::KeysList => crate::keyctl::operator_list()
            .await
            .map(|keyset_revision| TaskResult::KeyList { keyset_revision }),
        TaskOperation::KeysValidate => crate::keyctl::operator_validate()
            .await
            .map(|keyset_revision| TaskResult::KeyValidation { keyset_revision }),
        TaskOperation::KeysGenerateLocal { alg, purposes } => {
            crate::keyctl::operator_generate_local(alg, purposes)
                .await
                .map(|(kid, keyset_revision)| TaskResult::KeyGenerated {
                    kid,
                    keyset_revision,
                })
        }
        TaskOperation::KeysRegisterExternal {
            kid,
            alg,
            key_ref,
            public_jwk_sha256,
        } => match verify_public_jwk(public_jwk_sha256) {
            Ok(path) => crate::keyctl::operator_register_external(kid, alg, key_ref, path)
                .await
                .map(|keyset_revision| TaskResult::ExternalKeyRegistered {
                    kid: kid.clone(),
                    keyset_revision,
                }),
            Err(error) => Err(error),
        },
    };
    match result {
        Ok(result) => TaskOutcome::Succeeded { result },
        Err(error) => TaskOutcome::Failed {
            code: stable_error_code(&error),
        },
    }
}

fn validate_embedded_identity(task: &TaskEnvelope) -> anyhow::Result<()> {
    let actual = embedded_identity();
    if actual != task.embedded {
        bail!("embedded build identity does not match the authorized task target");
    }
    if task.config.manifest_version != nazo_operator_protocol::CONFIG_MANIFEST_VERSION {
        bail!("unsupported canonical config manifest version");
    }
    if matches!(task.config.secret_binding, SecretBinding::OpaqueRevision { ref revision } if revision.is_empty())
    {
        bail!("secret revision must not be empty");
    }
    Ok(())
}

fn validate_config_manifest(task: &TaskEnvelope) -> anyhow::Result<()> {
    let manifest_path = configured_path(
        "NAZOAUTH_OPERATOR_CONFIG_MANIFEST_FILE",
        CONFIG_MANIFEST_PATH,
    );
    let server_config_path = configured_path("NAZOAUTH_SERVER_CONFIG_FILE", "/app/.env.yaml");
    validate_config_manifest_at(task, &manifest_path, &server_config_path)
}

fn validate_config_manifest_at(
    task: &TaskEnvelope,
    manifest_path: &Path,
    server_config_path: &Path,
) -> anyhow::Result<()> {
    let bytes = fs::read(manifest_path).context("canonical config manifest is unavailable")?;
    let manifest: nazo_operator_protocol::CanonicalConfigManifest =
        serde_json::from_slice(&bytes).context("canonical config manifest is invalid")?;
    let digest = nazo_operator_protocol::canonical_config_sha256(&manifest)?;
    if digest != task.config.config_sha256 {
        bail!("canonical config manifest digest mismatch");
    }
    let expected_keys = ["deployment_id", "operation", "server_config_sha256"];
    if manifest.entries.len() != expected_keys.len()
        || expected_keys
            .iter()
            .any(|key| !manifest.entries.contains_key(*key))
        || manifest.entries.get("deployment_id") != Some(&task.deployment_id)
        || manifest.entries.get("operation") != Some(&operation_name(&task.operation).to_owned())
    {
        bail!("canonical config manifest is not the closed task manifest");
    }
    let actual: String = Sha256::digest(fs::read(server_config_path)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if manifest.entries.get("server_config_sha256") != Some(&actual) {
        bail!("server configuration digest mismatch");
    }
    Ok(())
}

/// Bind the signed task to the deployment identity that is local to this
/// runtime.  The controller signature is necessary but not sufficient: a
/// stale controller mount can carry a valid envelope for another deployment.
///
/// Managed runtimes normally persist `DATA_DIR/instance/deployment-id`; the
/// operator state directory also keeps a local anchor so containerized tasks
/// do not need the full server data mount.  The migration task may legitimately
/// run before the first server start, so the canonical server config is a
/// bootstrap source for that operation only when both anchors are absent. Once
/// either anchor exists, all available sources must agree; non-bootstrap
/// operations also require the operator-state anchor. An explicit
/// `NAZOAUTH_OPERATOR_DEPLOYMENT_ID_FILE` always requires that file and is
/// useful for systemd/container layouts with a separate identity mount.
fn validate_local_task_identity(task: &TaskEnvelope) -> anyhow::Result<String> {
    let server_config_path = configured_path("NAZOAUTH_SERVER_CONFIG_FILE", "/app/.env.yaml");
    let explicit_identity_path =
        env::var_os("NAZOAUTH_OPERATOR_DEPLOYMENT_ID_FILE").map(PathBuf::from);
    let state_directory = configured_path("NAZOAUTH_OPERATOR_STATE_DIRECTORY", STATE_DIRECTORY);
    validate_local_task_identity_at(
        task,
        &server_config_path,
        explicit_identity_path.as_deref(),
        Some(&state_directory),
    )
}

fn validate_local_task_identity_at(
    task: &TaskEnvelope,
    server_config_path: &Path,
    explicit_identity_path: Option<&Path>,
    operator_state_directory: Option<&Path>,
) -> anyhow::Result<String> {
    let config = fs::read(server_config_path).with_context(|| {
        format!(
            "failed to read server configuration for deployment identity {}",
            server_config_path.display()
        )
    })?;
    let value: YamlValue = yaml_serde::from_reader(Cursor::new(config.as_slice()))
        .context("server configuration is invalid while reading deployment identity")?;
    let YamlValue::Mapping(entries) = value else {
        bail!("server configuration must be a top-level key/value mapping");
    };
    let configured_deployment_id = yaml_mapping_scalar(&entries, "DEPLOYMENT_ID")?;
    let configured_data_dir = yaml_mapping_scalar(&entries, "DATA_DIR")?;
    let identity_path = explicit_identity_path
        .map(|path| path.to_path_buf())
        .unwrap_or_else(|| {
            let data_dir = configured_data_dir
                .clone()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "runtime".to_owned());
            let data_dir = PathBuf::from(data_dir);
            let data_dir = if data_dir.is_absolute() {
                data_dir
            } else {
                server_config_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(data_dir)
            };
            data_dir.join("instance").join("deployment-id")
        });
    let persisted_deployment_id =
        match regular_state_file_present(&identity_path, "persisted deployment identity")? {
            true => Some(read_identifier(&identity_path)?),
            false if explicit_identity_path.is_some() => {
                bail!("configured persisted deployment identity is unavailable")
            }
            false => None,
        };
    let operator_state_identity =
        operator_state_directory.map(|directory| directory.join("deployment-id"));
    let state_deployment_id = match operator_state_identity.as_deref() {
        Some(path) if regular_state_file_present(path, "operator state deployment identity")? => {
            Some(read_identifier(path)?)
        }
        Some(_) | None => None,
    };
    if let (Some(configured), Some(persisted)) =
        (&configured_deployment_id, &persisted_deployment_id)
        && configured != persisted
    {
        bail!("server configuration and persisted deployment identity do not match");
    }
    if let (Some(configured), Some(state)) = (&configured_deployment_id, &state_deployment_id)
        && configured != state
    {
        bail!("server configuration and operator state deployment identity do not match");
    }
    if let (Some(persisted), Some(state)) = (&persisted_deployment_id, &state_deployment_id)
        && persisted != state
    {
        bail!("persisted and operator state deployment identities do not match");
    }
    if state_deployment_id.is_none() && !matches!(&task.operation, TaskOperation::MigrateApply) {
        bail!(
            "operator state deployment identity is unavailable for a non-bootstrap operator task"
        );
    }
    let expected = if let Some(state) = state_deployment_id {
        state
    } else if let Some(persisted) = persisted_deployment_id {
        persisted
    } else if let Some(configured) = configured_deployment_id {
        if !matches!(&task.operation, TaskOperation::MigrateApply) {
            bail!("persisted deployment identity is unavailable for a non-bootstrap operator task");
        }
        configured
    } else {
        bail!("no local deployment identity is available");
    };
    validate_task_deployment_binding(task, &expected).map_err(|error| {
        anyhow::anyhow!("operator task deployment identity is not local: {error}")
    })?;
    Ok(expected)
}

fn persist_operator_state_identity(
    state_directory: &Path,
    deployment_id: &str,
) -> anyhow::Result<()> {
    let path = state_directory.join("deployment-id");
    if regular_state_file_present(&path, "operator state deployment identity")? {
        let existing = read_identifier(&path)?;
        if existing != deployment_id {
            bail!("operator state deployment identity changed unexpectedly");
        }
        return Ok(());
    }
    let temporary = state_directory.join(format!(
        ".deployment-id-{}-{:032x}.tmp",
        std::process::id(),
        rand::random::<u128>()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o400);
    let mut file = options.open(&temporary)?;
    file.write_all(format!("{deployment_id}\n").as_bytes())?;
    file.sync_all()?;
    drop(file);
    let publish = fs::hard_link(&temporary, &path);
    let cleanup = fs::remove_file(&temporary);
    if let Err(error) = cleanup {
        return Err(error).context("failed to remove temporary operator state identity");
    }
    match publish {
        Ok(()) => sync_directory(state_directory),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_identifier(&path)?;
            if existing == deployment_id {
                Ok(())
            } else {
                bail!("operator state deployment identity changed unexpectedly");
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn yaml_mapping_scalar(
    entries: &yaml_serde::Mapping,
    name: &str,
) -> anyhow::Result<Option<String>> {
    let Some((_, value)) = entries.iter().find(|(key, _)| key.as_str() == Some(name)) else {
        return Ok(None);
    };
    let value = match value {
        YamlValue::String(value) => value.clone(),
        YamlValue::Bool(value) => value.to_string(),
        YamlValue::Number(value) => value.to_string(),
        _ => bail!("server configuration key {name} must be a scalar"),
    };
    Ok(Some(value.trim().to_owned()).filter(|value| !value.is_empty()))
}

fn operation_name(operation: &TaskOperation) -> &'static str {
    match operation {
        TaskOperation::MigrateApply => "migrate-apply",
        TaskOperation::ConformanceLeaseCreate { .. } => "conformance-lease-create",
        TaskOperation::ConformanceLeaseList => "conformance-lease-list",
        TaskOperation::ConformanceLeaseRevoke { .. } => "conformance-lease-revoke",
        TaskOperation::ConformanceLeaseCleanup => "conformance-lease-cleanup",
        TaskOperation::KeysList => "keys-list",
        TaskOperation::KeysValidate => "keys-validate",
        TaskOperation::KeysGenerateLocal { .. } => "keys-generate-local",
        TaskOperation::KeysRegisterExternal { .. } => "keys-register-external",
    }
}

pub(crate) fn embedded_identity() -> EmbeddedIdentity {
    EmbeddedIdentity {
        release: option_env!("NAZOAUTH_BUILD_RELEASE")
            .unwrap_or("development")
            .to_owned(),
        revision: option_env!("NAZOAUTH_BUILD_REVISION")
            .unwrap_or("development")
            .to_owned(),
        protocol: nazo_operator_protocol::PROTOCOL_VERSION,
        build_id: option_env!("NAZOAUTH_BUILD_ID")
            .unwrap_or("local:development")
            .to_owned(),
    }
}

async fn acquire_task_lock(lock: std::fs::File) -> anyhow::Result<std::fs::File> {
    acquire_task_lock_with_timeout(lock, TASK_LOCK_TIMEOUT).await
}

fn can_reenter_migration(operation: &TaskOperation, lifecycle: &TaskLifecycle) -> bool {
    matches!(
        (operation, lifecycle),
        (TaskOperation::MigrateApply, TaskLifecycle::Executing { .. })
    )
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

fn claim_request(path: &Path, digest: &str) -> anyhow::Result<RequestClaim> {
    let parent = path
        .parent()
        .context("request claim has no state directory")?;
    let temporary = parent.join(format!(
        ".request-claim-{}-{:032x}.tmp",
        std::process::id(),
        rand::random::<u128>()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(format!("{REQUEST_CLAIM_PREFIX}{digest}\n").as_bytes())?;
    file.sync_all()?;
    drop(file);

    let publish = fs::hard_link(&temporary, path);
    let cleanup = fs::remove_file(&temporary);
    if let Err(error) = cleanup {
        return Err(error).context("failed to remove temporary request claim");
    }
    match publish {
        Ok(()) => {
            sync_directory(parent)?;
            Ok(RequestClaim::Created)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let claim = fs::read_to_string(path)?;
            if claim.trim() == format!("{REQUEST_CLAIM_PREFIX}{digest}") {
                Ok(RequestClaim::Current)
            } else if claim.trim() == digest {
                Ok(RequestClaim::Legacy)
            } else {
                bail!("request identifier was already claimed by a different envelope")
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn load_or_prepare_lifecycle(path: &Path, request_sha256: &str) -> anyhow::Result<TaskLifecycle> {
    let lifecycle = if regular_state_file_present(path, "operator task lifecycle")? {
        Some(read_lifecycle(path)?)
    } else {
        None
    };
    if let Some(ref lifecycle) = lifecycle {
        ensure_lifecycle_digest(lifecycle, request_sha256)?;
    }

    let temporary = lifecycle_temporary_path(path);
    if state_path_present(&temporary)? {
        regular_state_file_present(&temporary, "operator task lifecycle temporary")?;
        let temporary_lifecycle = read_lifecycle(&temporary)
            .context("operator task lifecycle has an incomplete durable transition")?;
        ensure_lifecycle_digest(&temporary_lifecycle, request_sha256)?;
        match lifecycle.as_ref() {
            Some(existing)
                if matches!(existing, TaskLifecycle::Prepared { .. })
                    && existing == &temporary_lifecycle =>
            {
                // A fully written duplicate of Prepared can only be left by
                // the create-new/hard-link publication window.  It crossed no
                // execution boundary, so remove the duplicate and continue.
                fs::remove_file(&temporary)?;
                sync_directory(
                    path.parent()
                        .context("operator task lifecycle has no state directory")?,
                )?;
            }
            None if matches!(temporary_lifecycle, TaskLifecycle::Prepared { .. }) => {
                // The process died before publishing the first Prepared
                // record.  Recreating that record is safe because execution
                // has not started.
                fs::remove_file(&temporary)?;
                sync_directory(
                    path.parent()
                        .context("operator task lifecycle has no state directory")?,
                )?;
            }
            _ => bail!(
                "operator task lifecycle has an incomplete durable transition; refusing recovery"
            ),
        }
    }

    if let Some(lifecycle) = lifecycle {
        return Ok(lifecycle);
    }

    let lifecycle = TaskLifecycle::Prepared {
        request_sha256: request_sha256.to_owned(),
    };
    write_initial_lifecycle(path, &lifecycle)?;
    Ok(lifecycle)
}

fn read_lifecycle(path: &Path) -> anyhow::Result<TaskLifecycle> {
    serde_json::from_slice(&fs::read(path)?).context("operator task lifecycle is invalid")
}

fn ensure_lifecycle_digest(lifecycle: &TaskLifecycle, request_sha256: &str) -> anyhow::Result<()> {
    let actual = match lifecycle {
        TaskLifecycle::Prepared { request_sha256 }
        | TaskLifecycle::Executing { request_sha256 }
        | TaskLifecycle::Completed { request_sha256 } => request_sha256,
    };
    if actual == request_sha256 {
        Ok(())
    } else {
        bail!("operator task lifecycle belongs to a different envelope")
    }
}

fn ensure_current_claim(claim: RequestClaim) -> anyhow::Result<()> {
    if claim == RequestClaim::Legacy {
        bail!("legacy request claim has no runtime receipt; refusing unknown privileged outcome");
    }
    Ok(())
}

fn sign_task_outcome(
    task: &TaskEnvelope,
    request_sha256: &str,
    outcome: TaskOutcome,
    receipt_key_id: &str,
    started_at: i64,
    completed_at: i64,
) -> anyhow::Result<String> {
    let receipt = RuntimeReceipt {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: format!("runtime:{}", task.deployment_id),
        aud: task.iss.clone(),
        jti: task.jti.clone(),
        request_sha256: request_sha256.to_owned(),
        deployment_id: task.deployment_id.clone(),
        actor: task.actor.clone(),
        operation: operation_name(&task.operation).to_owned(),
        started_at,
        completed_at,
        embedded: embedded_identity(),
        config: task.config.clone(),
        outcome,
    };
    validate_runtime_receipt_deployment_binding(&receipt, &task.deployment_id).map_err(
        |error| anyhow::anyhow!("runtime receipt deployment identity is invalid: {error}"),
    )?;
    let receipt_key = read_signing_key(&configured_path(
        "NAZOAUTH_OPERATOR_RECEIPT_PRIVATE_KEY_FILE",
        RECEIPT_PRIVATE_KEY_PATH,
    ))?;
    Ok(sign_runtime_receipt(
        &receipt,
        receipt_key_id,
        &receipt_key,
    )?)
}

fn read_published_receipt(
    path: &Path,
    task: &TaskEnvelope,
    request_sha256: &str,
    expected_deployment_id: &str,
    receipt_key_id: &str,
) -> anyhow::Result<Option<String>> {
    if !regular_state_file_present(path, "operator task receipt")? {
        return Ok(None);
    }
    let compact = fs::read_to_string(path)?;
    validate_receipt_for_task(
        &compact,
        task,
        request_sha256,
        expected_deployment_id,
        receipt_key_id,
    )?;
    Ok(Some(compact))
}

fn recover_receipt_temporary(
    path: &Path,
    task: &TaskEnvelope,
    request_sha256: &str,
    expected_deployment_id: &str,
    receipt_key_id: &str,
) -> anyhow::Result<Option<String>> {
    let temporary = receipt_temporary_path(path);
    if !state_path_present(&temporary)? {
        return Ok(None);
    }
    regular_state_file_present(&temporary, "operator task receipt temporary")?;
    let compact = fs::read_to_string(&temporary)?;
    validate_receipt_for_task(
        &compact,
        task,
        request_sha256,
        expected_deployment_id,
        receipt_key_id,
    )?;
    fs::rename(&temporary, path)?;
    sync_directory(
        path.parent()
            .context("operator task receipt has no state directory")?,
    )?;
    Ok(Some(compact))
}

fn validate_receipt_for_task(
    compact: &str,
    task: &TaskEnvelope,
    request_sha256: &str,
    expected_deployment_id: &str,
    receipt_key_id: &str,
) -> anyhow::Result<()> {
    let receipt_key = read_signing_key(&configured_path(
        "NAZOAUTH_OPERATOR_RECEIPT_PRIVATE_KEY_FILE",
        RECEIPT_PRIVATE_KEY_PATH,
    ))?;
    let receipt = verify_runtime_receipt(compact, receipt_key_id, &receipt_key.verifying_key())
        .map_err(|error| anyhow::anyhow!("operator task receipt is invalid: {error}"))?;
    validate_runtime_receipt_deployment_binding(&receipt, expected_deployment_id).map_err(
        |error| anyhow::anyhow!("operator task receipt deployment identity is invalid: {error}"),
    )?;
    if receipt.jti != task.jti
        || receipt.request_sha256 != request_sha256
        || receipt.actor != task.actor
        || receipt.operation != operation_name(&task.operation)
        || receipt.embedded != task.embedded
        || receipt.config != task.config
    {
        bail!("operator task receipt is not bound to this request");
    }
    Ok(())
}

fn mark_task_executing(
    path: &Path,
    lifecycle: &TaskLifecycle,
    request_sha256: &str,
) -> anyhow::Result<()> {
    ensure_lifecycle_digest(lifecycle, request_sha256)?;
    match lifecycle {
        TaskLifecycle::Prepared { .. } => write_lifecycle_atomic(
            path,
            &TaskLifecycle::Executing {
                request_sha256: request_sha256.to_owned(),
            },
        ),
        TaskLifecycle::Executing { .. } => bail!(
            "operator task may have executed without a receipt; refusing to replay privileged action"
        ),
        TaskLifecycle::Completed { .. } => {
            bail!("operator task completed without a receipt; refusing to replay privileged action")
        }
    }
}

fn write_initial_lifecycle(path: &Path, lifecycle: &TaskLifecycle) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("operator task lifecycle has no state directory")?;
    let temporary = lifecycle_temporary_path(path);
    if state_path_present(&temporary)? {
        bail!("operator task lifecycle has an incomplete durable transition; refusing recovery");
    }
    let bytes = serde_json::to_vec(lifecycle)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);

    match fs::hard_link(&temporary, path) {
        Ok(()) => {
            fs::remove_file(&temporary)?;
            sync_directory(parent)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // This temporary file was completely written by this process and
            // has not crossed an execution boundary.  It is safe to remove;
            // unlike a pre-existing temporary file, it cannot conceal a
            // killed execution or receipt publication.
            fs::remove_file(&temporary)?;
            Err(error.into())
        }
        Err(error) => Err(error.into()),
    }
}

fn write_lifecycle_atomic(path: &Path, lifecycle: &TaskLifecycle) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("operator task lifecycle has no state directory")?;
    let temporary = lifecycle_temporary_path(path);
    if state_path_present(&temporary)? {
        bail!("operator task lifecycle has an incomplete durable transition; refusing recovery");
    }
    let bytes = serde_json::to_vec(lifecycle)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    sync_directory(parent)
}

fn lifecycle_temporary_path(path: &Path) -> PathBuf {
    path.with_extension("lifecycle.json.tmp")
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

fn write_receipt_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let temporary = receipt_temporary_path(path);
    if state_path_present(&temporary)? {
        bail!("operator task receipt has an incomplete durable publication; refusing recovery");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    pause_at_test_failpoint("after-receipt-sync")?;
    fs::rename(temporary, path)?;
    sync_directory(
        path.parent()
            .context("operator task receipt has no state directory")?,
    )?;
    Ok(())
}

fn receipt_temporary_path(path: &Path) -> PathBuf {
    path.with_extension("receipt.jws.tmp")
}

fn verify_public_jwk(expected_sha256: &str) -> anyhow::Result<PathBuf> {
    let path = configured_path(
        "NAZOAUTH_OPERATOR_PUBLIC_JWK_FILE",
        EXTERNAL_PUBLIC_JWK_PATH,
    );
    verify_public_jwk_at(expected_sha256, path)
}

fn verify_public_jwk_at(expected_sha256: &str, path: PathBuf) -> anyhow::Result<PathBuf> {
    let bytes = fs::read(&path).context("external public JWK was not mounted")?;
    let actual: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if actual != expected_sha256 {
        bail!("external public JWK digest mismatch");
    }
    Ok(path)
}

fn read_verifying_key(path: &Path) -> anyhow::Result<VerifyingKey> {
    let bytes = read_key_bytes(path)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public key length"))?;
    VerifyingKey::from_bytes(&bytes).context("invalid controller public key")
}

fn read_signing_key(path: &Path) -> anyhow::Result<SigningKey> {
    let bytes = read_key_bytes(path)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid private key length"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn read_key_bytes(path: &Path) -> anyhow::Result<Vec<u8>> {
    let value = fs::read_to_string(path)?;
    URL_SAFE_NO_PAD
        .decode(value.trim())
        .context("operator key is not canonical base64url")
}

fn stable_error_code(error: &anyhow::Error) -> String {
    let digest = Sha256::digest(format!("{error:#}").as_bytes());
    format!(
        "operation-failed-{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
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
#[path = "../tests/unit/operator_task.rs"]
mod tests;
