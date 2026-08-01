use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nazo_operator_protocol::{
    Actor, ActorKind, CanonicalConfigManifest, ConfigBinding, ControllerTrustTransition,
    EmbeddedIdentity, FinalReceipt, ManagementAuditEvent, RuntimeReceipt, RuntimeTargetClaim,
    SecretBinding, TaskEnvelope, TaskOperation, TaskOutcome, TaskResult, TransitionAuthorization,
    canonical_config_sha256, compact_sha256, protected_header, sign_final_receipt,
    sign_management_event, sign_task, sign_trust_transition, verify_final_receipt,
    verify_management_event, verify_runtime_receipt, verify_task_signature,
    verify_trust_transition,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    filesystem::{atomic_write, sha256},
    model::UpdateConfig,
    runtime::Runtime,
};

#[cfg(debug_assertions)]
use crate::process::Process;

#[derive(Clone, Debug)]
pub(crate) struct ExpectedReleaseTarget {
    pub(crate) embedded: EmbeddedIdentity,
    pub(crate) image_digest: String,
    pub(crate) binary_digest: String,
}

#[derive(Clone, Debug)]
pub(crate) struct OperationResult {
    pub(crate) request_id: String,
    pub(crate) result: TaskResult,
    pub(crate) final_receipt: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditHead {
    sequence: u64,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RotationIntent {
    schema: u32,
    previous_key_id: String,
    next_key_id: String,
    previous_audit_key_id: String,
    next_audit_key_id: String,
    previous_break_glass_key_id: String,
    next_break_glass_key_id: String,
    transition_file: String,
    compact_transition: String,
}

pub(crate) fn execute(
    config: &UpdateConfig,
    target: &str,
    expected: &ExpectedReleaseTarget,
    operation: TaskOperation,
    public_jwk: Option<&Path>,
) -> anyhow::Result<OperationResult> {
    #[cfg(debug_assertions)]
    if std::env::var_os("NAZOAUTHCTL_TESTING").is_some() {
        return execute_test_task(config, target, operation);
    }
    let manifest = canonical_manifest(config, &operation)?;
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let config_sha256 = canonical_config_sha256(&manifest)?;

    // Runtime/image, network, mounts, task context and sandbox are prepared before issuance.
    let runtime = Runtime::new(config);
    let prepared = runtime.prepare_app_task(target, &operation, public_jwk, &manifest_bytes)?;
    verify_target_expectation(&prepared.target, expected)?;

    let secret_revision = read_single_line(&config.operator.secret_revision_file)?;
    let config_binding = ConfigBinding {
        manifest_version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
        config_sha256,
        secret_binding: SecretBinding::OpaqueRevision {
            revision: secret_revision,
        },
    };
    let (task, compact_task, intent_path) = load_or_issue_task(
        config,
        target_expectation(&prepared.target),
        expected.embedded.clone(),
        config_binding.clone(),
        operation,
    )?;
    let request_id = task.jti.clone();
    if let Some(result) = existing_final_result(config, &task, &compact_task)? {
        if intent_path.exists() {
            fs::remove_file(&intent_path)?;
        }
        return Ok(result);
    }

    let compact_runtime_receipt = prepared.execute(&compact_task)?;
    let receipt_key = read_verifying_key(&config.operator.receipt_public_key)?;
    let runtime_receipt = verify_runtime_receipt(
        compact_runtime_receipt.trim(),
        &config.operator.receipt_key_id,
        &receipt_key,
    )?;
    validate_runtime_receipt(&runtime_receipt, &task, &compact_task)?;
    runtime.verify_prepared_target(&prepared.target)?;

    let (sequence, previous) = audit_head(config)?;
    let final_receipt = FinalReceipt {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: task.iss.clone(),
        aud: "operator-audit".to_owned(),
        jti: request_id.clone(),
        request_sha256: compact_sha256(&compact_task),
        deployment_id: config.operator.deployment_id.clone(),
        actor: task.actor.clone(),
        operation: operation_name(&task.operation).to_owned(),
        completed_at: runtime_receipt.completed_at,
        audit_sequence: sequence,
        audit_previous_sha256: previous,
        controller_verified_target: prepared.target,
        embedded: runtime_receipt.embedded.clone(),
        config: runtime_receipt.config.clone(),
        runtime_receipt_sha256: compact_sha256(compact_runtime_receipt.trim()),
        outcome: runtime_receipt.outcome.clone(),
    };
    let audit_key = read_signing_key(&config.operator.audit_private_key)?;
    let compact_final =
        sign_final_receipt(&final_receipt, &config.operator.audit_key_id, &audit_key)?;
    let final_path = append_audit(config, sequence, &request_id, &compact_final)?;
    fs::remove_file(&intent_path)?;
    match runtime_receipt.outcome {
        TaskOutcome::Succeeded { result } => Ok(OperationResult {
            request_id,
            result,
            final_receipt: final_path,
        }),
        TaskOutcome::Failed { code } => bail!(
            "operator task failed with code {code}; request_id={request_id}; receipt={}",
            final_path.display()
        ),
    }
}

fn load_or_issue_task(
    config: &UpdateConfig,
    target: nazo_operator_protocol::TargetExpectation,
    embedded: EmbeddedIdentity,
    config_binding: ConfigBinding,
    operation: TaskOperation,
) -> anyhow::Result<(TaskEnvelope, String, PathBuf)> {
    let actor = Actor {
        kind: ActorKind::LocalRoot,
        id: "uid:0".to_owned(),
    };
    let fingerprint = encode_hex(&Sha256::digest(serde_json::to_vec(&serde_json::json!({
        "deployment_id": config.operator.deployment_id,
        "target": target,
        "embedded": embedded,
        "config": config_binding,
        "operation": operation,
        "actor": actor,
    }))?));
    let directory = config.operator.audit_directory.join("intents");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{fingerprint}.jws"));
    let now = Utc::now().timestamp();
    if path.exists() {
        let compact = fs::read_to_string(&path)?;
        let header = protected_header(&compact)?;
        let task = verify_task_signature(
            &compact,
            &header.kid,
            &trusted_controller_key(config, &header.kid)?,
        )?;
        let matches = task.deployment_id == config.operator.deployment_id
            && task.iss == format!("controller:{}", config.operator.deployment_id)
            && task.aud == format!("runtime:{}", config.operator.deployment_id)
            && task.actor == actor
            && task.target == target
            && task.embedded == embedded
            && task.config == config_binding
            && task.operation == operation;
        if !matches {
            bail!("persisted operator intent does not match the requested operation");
        }
        let cached_receipt = config
            .operator
            .state_directory
            .join(format!("{}.receipt.jws", task.jti));
        if task.exp >= now || cached_receipt.is_file() {
            return Ok((task, compact, path));
        }
        fs::remove_file(&path)?;
    }
    let request_id = format!("request-{}", encode_hex(&rand::random::<[u8; 16]>()));
    let task = TaskEnvelope {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: format!("controller:{}", config.operator.deployment_id),
        aud: format!("runtime:{}", config.operator.deployment_id),
        jti: request_id,
        iat: now,
        nbf: now,
        exp: now + nazo_operator_protocol::MAX_TASK_LIFETIME_SECONDS,
        deployment_id: config.operator.deployment_id.clone(),
        actor,
        target,
        embedded,
        config: config_binding,
        operation,
    };
    let controller_key = read_signing_key(&config.operator.controller_private_key)?;
    let compact = sign_task(&task, &config.operator.controller_key_id, &controller_key)?;
    atomic_write(&path, compact.as_bytes(), 0o400)?;
    Ok((task, compact, path))
}

fn existing_final_result(
    config: &UpdateConfig,
    task: &TaskEnvelope,
    compact_task: &str,
) -> anyhow::Result<Option<OperationResult>> {
    let request_id = &task.jti;
    let directory = config.operator.audit_directory.join("receipts");
    if !directory.exists() {
        return Ok(None);
    }
    let suffix = format!("-{request_id}.jws");
    let mut matches = fs::read_dir(&directory)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(&suffix))
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        bail!("audit contains duplicate final receipts for one request ID");
    }
    let Some(entry) = matches.pop() else {
        return Ok(None);
    };
    let compact = fs::read_to_string(entry.path())?;
    let header = protected_header(&compact)?;
    let receipt = verify_final_receipt(
        &compact,
        &header.kid,
        &trusted_audit_key(config, &header.kid)?,
    )?;
    let target = match &task.target {
        nazo_operator_protocol::TargetExpectation::OciImage {
            image_ref,
            image_digest,
        } => RuntimeTargetClaim::OciImage {
            image_ref: image_ref.clone(),
            image_digest: image_digest.clone(),
        },
        nazo_operator_protocol::TargetExpectation::HostBinary { path, sha256 } => {
            RuntimeTargetClaim::HostBinary {
                path: path.clone(),
                sha256: sha256.clone(),
            }
        }
    };
    if receipt.request_sha256 != compact_sha256(compact_task)
        || receipt.deployment_id != task.deployment_id
        || receipt.actor != task.actor
        || receipt.operation != operation_name(&task.operation)
        || receipt.controller_verified_target != target
        || receipt.embedded != task.embedded
        || receipt.config != task.config
    {
        bail!("persisted final receipt is not bound to the pending intent");
    }
    match receipt.outcome {
        TaskOutcome::Succeeded { result } => Ok(Some(OperationResult {
            request_id: request_id.clone(),
            result,
            final_receipt: entry.path(),
        })),
        TaskOutcome::Failed { code } => bail!(
            "operator task previously failed with code {code}; request_id={request_id}; receipt={}",
            entry.path().display()
        ),
    }
}

#[cfg(debug_assertions)]
fn execute_test_task(
    config: &UpdateConfig,
    target: &str,
    operation: TaskOperation,
) -> anyhow::Result<OperationResult> {
    let arguments = match &operation {
        TaskOperation::MigrateApply => vec!["migrate".to_owned()],
        TaskOperation::KeysList => vec!["keyctl".to_owned(), "list".to_owned()],
        TaskOperation::KeysValidate => vec!["keyctl".to_owned(), "validate".to_owned()],
        TaskOperation::KeysGenerateLocal { .. } | TaskOperation::KeysRegisterExternal { .. } => {
            bail!("test task adapter does not implement key mutation")
        }
    };
    if config.runtime.engine == "host" {
        Process::new(target).args(arguments).run_quiet()?;
    } else {
        Process::new(
            config
                .container_engine()
                .context("test task requires a container engine")?,
        )
        .args(["run", "--rm"])
        .arg(target)
        .arg("nazoauth")
        .args(arguments)
        .run_quiet()?;
    }
    let request_id = format!("request-test-{}", encode_hex(&rand::random::<[u8; 8]>()));
    let directory = config.operator.audit_directory.join("test-receipts");
    fs::create_dir_all(&directory)?;
    let receipt = directory.join(format!("{request_id}.txt"));
    atomic_write(&receipt, b"debug-build-test-adapter", 0o400)?;
    Ok(OperationResult {
        request_id,
        result: match operation {
            TaskOperation::MigrateApply => TaskResult::Migration { applied: true },
            TaskOperation::KeysList => TaskResult::KeyList {
                keyset_revision: "test".to_owned(),
            },
            TaskOperation::KeysValidate => TaskResult::KeyValidation {
                keyset_revision: "test".to_owned(),
            },
            TaskOperation::KeysGenerateLocal { .. }
            | TaskOperation::KeysRegisterExternal { .. } => unreachable!(),
        },
        final_receipt: receipt,
    })
}

fn canonical_manifest(
    config: &UpdateConfig,
    operation: &TaskOperation,
) -> anyhow::Result<CanonicalConfigManifest> {
    let server_config = if config.runtime.engine == "host" {
        config.runtime.working_directory.join(".env.yaml")
    } else {
        config
            .runtime
            .mounts
            .iter()
            .find(|mount| mount.target == Path::new("/app/.env.yaml"))
            .context("server configuration mount is unavailable")?
            .source
            .clone()
    };
    Ok(CanonicalConfigManifest {
        version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
        entries: BTreeMap::from([
            (
                "deployment_id".to_owned(),
                config.operator.deployment_id.clone(),
            ),
            ("operation".to_owned(), operation_name(operation).to_owned()),
            ("server_config_sha256".to_owned(), sha256(&server_config)?),
        ]),
    })
}

fn operation_name(operation: &TaskOperation) -> &'static str {
    match operation {
        TaskOperation::MigrateApply => "migrate-apply",
        TaskOperation::KeysList => "keys-list",
        TaskOperation::KeysValidate => "keys-validate",
        TaskOperation::KeysGenerateLocal { .. } => "keys-generate-local",
        TaskOperation::KeysRegisterExternal { .. } => "keys-register-external",
    }
}

fn verify_target_expectation(
    actual: &RuntimeTargetClaim,
    expected: &ExpectedReleaseTarget,
) -> anyhow::Result<()> {
    match actual {
        RuntimeTargetClaim::OciImage { image_digest, .. } => {
            if image_digest != &expected.image_digest {
                bail!("actual OCI image digest does not match the signed Release manifest");
            }
        }
        RuntimeTargetClaim::HostBinary { sha256, .. } => {
            if sha256 != &expected.binary_digest {
                bail!("actual host binary digest does not match the signed Release manifest");
            }
        }
    }
    Ok(())
}

fn target_expectation(target: &RuntimeTargetClaim) -> nazo_operator_protocol::TargetExpectation {
    match target {
        RuntimeTargetClaim::OciImage {
            image_ref,
            image_digest,
        } => nazo_operator_protocol::TargetExpectation::OciImage {
            image_ref: image_ref.clone(),
            image_digest: image_digest.clone(),
        },
        RuntimeTargetClaim::HostBinary { path, sha256 } => {
            nazo_operator_protocol::TargetExpectation::HostBinary {
                path: path.clone(),
                sha256: sha256.clone(),
            }
        }
    }
}

fn validate_runtime_receipt(
    receipt: &RuntimeReceipt,
    task: &TaskEnvelope,
    compact_task: &str,
) -> anyhow::Result<()> {
    if receipt.jti != task.jti
        || receipt.request_sha256 != compact_sha256(compact_task)
        || receipt.deployment_id != task.deployment_id
        || receipt.actor != task.actor
        || receipt.operation != operation_name(&task.operation)
        || receipt.embedded != task.embedded
        || receipt.config != task.config
        || receipt.started_at < task.iat
        || receipt.completed_at < receipt.started_at
    {
        bail!("runtime receipt is not bound to the authorized task");
    }
    Ok(())
}

pub(crate) fn expected_release_target(
    config: &UpdateConfig,
    embedded: EmbeddedIdentity,
    image_digest: String,
    binary_digest: String,
) -> anyhow::Result<ExpectedReleaseTarget> {
    if embedded.protocol != nazo_operator_protocol::PROTOCOL_VERSION {
        bail!("Release operator protocol version is unsupported");
    }
    if config.runtime.engine == "host" && binary_digest.len() != 64 {
        bail!("Release binary digest is invalid");
    }
    Ok(ExpectedReleaseTarget {
        embedded,
        image_digest,
        binary_digest,
    })
}

fn audit_head(config: &UpdateConfig) -> anyhow::Result<(u64, String)> {
    verify_audit(config)?;
    let path = config.operator.audit_directory.join("head.json");
    if !path.exists() {
        return Ok((1, "0".repeat(64)));
    }
    let head: AuditHead = serde_json::from_slice(&fs::read(path)?)?;
    Ok((head.sequence + 1, head.sha256))
}

fn append_audit(
    config: &UpdateConfig,
    sequence: u64,
    request_id: &str,
    compact_final: &str,
) -> anyhow::Result<PathBuf> {
    let receipts = config.operator.audit_directory.join("receipts");
    fs::create_dir_all(&receipts)?;
    let path = receipts.join(format!("{sequence:020}-{request_id}.jws"));
    atomic_write(&path, compact_final.as_bytes(), 0o400)?;
    let digest = compact_sha256(compact_final);
    atomic_write(
        &config.operator.audit_directory.join("head.json"),
        &serde_json::to_vec_pretty(&AuditHead {
            sequence,
            sha256: digest,
        })?,
        0o600,
    )?;
    Ok(path)
}

pub(crate) fn verify_audit(config: &UpdateConfig) -> anyhow::Result<()> {
    let receipts = config.operator.audit_directory.join("receipts");
    if !receipts.exists() {
        println!("audit: empty chain verified");
        verify_pending_intents(config)?;
        verify_management_events(config)?;
        verify_trust_transitions(config)?;
        return Ok(());
    }
    let mut paths = fs::read_dir(&receipts)?.collect::<Result<Vec<_>, _>>()?;
    paths.sort_by_key(std::fs::DirEntry::file_name);
    let mut previous = "0".repeat(64);
    let mut sequence = 0_u64;
    let mut checkpoints = BTreeMap::from([(0_u64, previous.clone())]);
    for entry in paths {
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|v| v.to_str()) != Some("jws")
        {
            bail!("audit receipt directory contains an unexpected entry");
        }
        let compact = fs::read_to_string(entry.path())?;
        let header = protected_header(&compact)?;
        let key = trusted_audit_key(config, &header.kid)?;
        let receipt = verify_final_receipt(&compact, &header.kid, &key)?;
        if receipt.audit_sequence != sequence + 1 || receipt.audit_previous_sha256 != previous {
            bail!(
                "audit receipt chain is discontinuous at {}",
                entry.path().display()
            );
        }
        sequence = receipt.audit_sequence;
        previous = compact_sha256(&compact);
        checkpoints.insert(sequence, previous.clone());
    }
    let head_path = config.operator.audit_directory.join("head.json");
    let head = if head_path.exists() {
        Some(serde_json::from_slice::<AuditHead>(&fs::read(&head_path)?)?)
    } else {
        None
    };
    if let Some(head) = &head
        && (head.sequence > sequence || checkpoints.get(&head.sequence) != Some(&head.sha256))
    {
        bail!("audit head conflicts with the verified receipt chain");
    }
    if head.is_none_or(|head| head.sequence != sequence || head.sha256 != previous) {
        atomic_write(
            &head_path,
            &serde_json::to_vec_pretty(&AuditHead {
                sequence,
                sha256: previous.clone(),
            })?,
            0o600,
        )?;
    }
    println!("audit: verified {sequence} signed checkpoints; head={previous}");
    verify_pending_intents(config)?;
    verify_management_events(config)?;
    verify_trust_transitions(config)?;
    Ok(())
}

pub(crate) fn show_audit(config: &UpdateConfig, request_id: Option<&str>) -> anyhow::Result<()> {
    verify_audit(config)?;
    let mut entries = Vec::new();
    let intents = config.operator.audit_directory.join("intents");
    if intents.exists() {
        let mut paths = fs::read_dir(&intents)?.collect::<Result<Vec<_>, _>>()?;
        paths.sort_by_key(std::fs::DirEntry::file_name);
        for entry in paths {
            let compact = fs::read_to_string(entry.path())?;
            let header = protected_header(&compact)?;
            let task = verify_task_signature(
                &compact,
                &header.kid,
                &trusted_controller_key(config, &header.kid)?,
            )?;
            if request_id.is_none_or(|expected| expected == task.jti) {
                entries.push(serde_json::json!({
                    "kind": "pending-task-intent",
                    "key_id": header.kid,
                    "task": task,
                }));
            }
        }
    }
    let receipts = config.operator.audit_directory.join("receipts");
    if receipts.exists() {
        let mut paths = fs::read_dir(&receipts)?.collect::<Result<Vec<_>, _>>()?;
        paths.sort_by_key(std::fs::DirEntry::file_name);
        for entry in paths {
            let compact = fs::read_to_string(entry.path())?;
            let header = protected_header(&compact)?;
            let receipt = verify_final_receipt(
                &compact,
                &header.kid,
                &trusted_audit_key(config, &header.kid)?,
            )?;
            if request_id.is_none_or(|expected| expected == receipt.jti) {
                entries.push(serde_json::json!({
                    "kind": "task-receipt",
                    "key_id": header.kid,
                    "receipt": receipt,
                }));
            }
        }
    }
    let management = config.operator.audit_directory.join("management");
    if management.exists() {
        let mut paths = fs::read_dir(&management)?.collect::<Result<Vec<_>, _>>()?;
        paths.sort_by_key(std::fs::DirEntry::file_name);
        for entry in paths {
            let compact = fs::read_to_string(entry.path())?;
            let header = protected_header(&compact)?;
            let event = verify_management_event(
                &compact,
                &header.kid,
                &trusted_audit_key(config, &header.kid)?,
            )?;
            if request_id.is_none_or(|expected| expected == event.request_id) {
                entries.push(serde_json::json!({
                    "kind": "management-event",
                    "key_id": header.kid,
                    "event": event,
                }));
            }
        }
    }
    if request_id.is_none() {
        let transitions = config.operator.audit_directory.join("trust-transitions");
        if transitions.exists() {
            let mut paths = fs::read_dir(&transitions)?.collect::<Result<Vec<_>, _>>()?;
            paths.sort_by_key(std::fs::DirEntry::file_name);
            for entry in paths {
                let compact = fs::read_to_string(entry.path())?;
                let header = protected_header(&compact)?;
                let key = if header.kid.starts_with("break-glass-") {
                    trusted_break_glass_key(config, &header.kid)?
                } else {
                    trusted_controller_key(config, &header.kid)?
                };
                entries.push(serde_json::json!({
                    "kind": "trust-transition",
                    "key_id": header.kid,
                    "transition": verify_trust_transition(&compact, &header.kid, &key)?,
                }));
            }
        }
    }
    println!("{}", serde_json::to_string_pretty(&entries)?);
    Ok(())
}

fn verify_pending_intents(config: &UpdateConfig) -> anyhow::Result<()> {
    let directory = config.operator.audit_directory.join("intents");
    if !directory.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("jws")
        {
            bail!("operator intent directory contains an unexpected entry");
        }
        let compact = fs::read_to_string(entry.path())?;
        let header = protected_header(&compact)?;
        let task = verify_task_signature(
            &compact,
            &header.kid,
            &trusted_controller_key(config, &header.kid)?,
        )?;
        if task.deployment_id != config.operator.deployment_id {
            bail!("operator intent belongs to a different deployment");
        }
    }
    Ok(())
}

pub(crate) fn append_management_event(
    config: &UpdateConfig,
    operation: &str,
    release: &str,
    recovery_boundary: &str,
) -> anyhow::Result<PathBuf> {
    verify_audit(config)?;
    let directory = config.operator.audit_directory.join("management");
    fs::create_dir_all(&directory)?;
    let head_path = config.operator.audit_directory.join("management-head.json");
    let (sequence, previous) = if head_path.exists() {
        let head: AuditHead = serde_json::from_slice(&fs::read(&head_path)?)?;
        (head.sequence + 1, head.sha256)
    } else {
        (1, "0".repeat(64))
    };
    let request_id = format!("request-{}", encode_hex(&rand::random::<[u8; 16]>()));
    let event = ManagementAuditEvent {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        deployment_id: config.operator.deployment_id.clone(),
        sequence,
        previous_sha256: previous,
        request_id: request_id.clone(),
        issued_at: Utc::now().timestamp(),
        actor: Actor {
            kind: ActorKind::LocalRoot,
            id: "uid:0".to_owned(),
        },
        operation: operation.to_owned(),
        release: release.to_owned(),
        recovery_boundary: recovery_boundary.to_owned(),
    };
    let key = read_signing_key(&config.operator.audit_private_key)?;
    let compact = sign_management_event(&event, &config.operator.audit_key_id, &key)?;
    let path = directory.join(format!("{sequence:020}-{request_id}.jws"));
    atomic_write(&path, compact.as_bytes(), 0o400)?;
    atomic_write(
        &head_path,
        &serde_json::to_vec_pretty(&AuditHead {
            sequence,
            sha256: compact_sha256(&compact),
        })?,
        0o600,
    )?;
    Ok(path)
}

pub(crate) fn load_management_event(
    config: &UpdateConfig,
    file_name: &str,
) -> anyhow::Result<ManagementAuditEvent> {
    verify_audit(config)?;
    let candidate = Path::new(file_name);
    if candidate.components().count() != 1 || candidate.file_name().is_none() {
        bail!("management audit event must be a plain file name");
    }
    let path = config
        .operator
        .audit_directory
        .join("management")
        .join(candidate);
    let compact = fs::read_to_string(&path)
        .with_context(|| format!("failed to read management audit event {}", path.display()))?;
    let header = protected_header(&compact)?;
    let key = trusted_audit_key(config, &header.kid)?;
    let event = verify_management_event(&compact, &header.kid, &key)?;
    if event.deployment_id != config.operator.deployment_id {
        bail!("management audit event belongs to a different deployment");
    }
    Ok(event)
}

fn verify_management_events(config: &UpdateConfig) -> anyhow::Result<()> {
    let directory = config.operator.audit_directory.join("management");
    if !directory.exists() {
        return Ok(());
    }
    let mut paths = fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
    paths.sort_by_key(std::fs::DirEntry::file_name);
    let mut sequence = 0;
    let mut previous = "0".repeat(64);
    let mut checkpoints = BTreeMap::from([(0_u64, previous.clone())]);
    for entry in paths {
        if !entry.file_type()?.is_file() {
            bail!("management audit directory contains an unexpected entry");
        }
        let compact = fs::read_to_string(entry.path())?;
        let header = protected_header(&compact)?;
        let key = trusted_audit_key(config, &header.kid)?;
        let event = verify_management_event(&compact, &header.kid, &key)?;
        if event.sequence != sequence + 1
            || event.previous_sha256 != previous
            || event.deployment_id != config.operator.deployment_id
        {
            bail!("management audit chain is discontinuous");
        }
        sequence = event.sequence;
        previous = compact_sha256(&compact);
        checkpoints.insert(sequence, previous.clone());
    }
    let head_path = config.operator.audit_directory.join("management-head.json");
    let head = if head_path.exists() {
        Some(serde_json::from_slice::<AuditHead>(&fs::read(&head_path)?)?)
    } else {
        None
    };
    if let Some(head) = &head
        && (head.sequence > sequence || checkpoints.get(&head.sequence) != Some(&head.sha256))
    {
        bail!("management audit head conflicts with the verified chain");
    }
    if head.is_none_or(|head| head.sequence != sequence || head.sha256 != previous) {
        atomic_write(
            &head_path,
            &serde_json::to_vec_pretty(&AuditHead {
                sequence,
                sha256: previous,
            })?,
            0o600,
        )?;
    }
    Ok(())
}

fn verify_trust_transitions(config: &UpdateConfig) -> anyhow::Result<()> {
    let directory = config.operator.audit_directory.join("trust-transitions");
    if !directory.exists() {
        return Ok(());
    }
    let mut paths = fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
    paths.sort_by_key(std::fs::DirEntry::file_name);
    let mut expected_previous: Option<(String, String, String)> = None;
    for entry in paths {
        if !entry.file_type()?.is_file() {
            bail!("trust transition directory contains an unexpected entry");
        }
        let compact = fs::read_to_string(entry.path())?;
        let header = protected_header(&compact)?;
        let key = if header.kid.starts_with("break-glass-") {
            trusted_break_glass_key(config, &header.kid)?
        } else {
            trusted_controller_key(config, &header.kid)?
        };
        let transition = verify_trust_transition(&compact, &header.kid, &key)?;
        if transition.deployment_id != config.operator.deployment_id
            || expected_previous
                .as_ref()
                .is_some_and(|(controller, audit, break_glass)| {
                    controller != &transition.previous_key_id
                        || audit != &transition.previous_audit_key_id
                        || break_glass != &transition.previous_break_glass_key_id
                })
        {
            bail!("controller trust transition chain is discontinuous");
        }
        let next = trusted_controller_key(config, &transition.next_key_id)?;
        if encode_hex(&Sha256::digest(next.to_bytes())) != transition.next_public_key_sha256 {
            bail!("controller trust transition public key digest mismatch");
        }
        let next_audit = trusted_audit_key(config, &transition.next_audit_key_id)?;
        if encode_hex(&Sha256::digest(next_audit.to_bytes()))
            != transition.next_audit_public_key_sha256
        {
            bail!("audit trust transition public key digest mismatch");
        }
        let next_break_glass =
            trusted_break_glass_key(config, &transition.next_break_glass_key_id)?;
        if encode_hex(&Sha256::digest(next_break_glass.to_bytes()))
            != transition.next_break_glass_public_key_sha256
        {
            bail!("break-glass trust transition public key digest mismatch");
        }
        match transition.authorization {
            TransitionAuthorization::Controller if header.kid != transition.previous_key_id => {
                bail!("normal controller rotation was not signed by the previous controller")
            }
            TransitionAuthorization::BreakGlass
                if header.kid != transition.previous_break_glass_key_id =>
            {
                bail!("break-glass recovery was not signed by the break-glass identity")
            }
            _ => {}
        }
        expected_previous = Some((
            transition.next_key_id,
            transition.next_audit_key_id,
            transition.next_break_glass_key_id,
        ));
    }
    Ok(())
}

pub(crate) fn rotate_controller(
    config_path: &Path,
    config: &UpdateConfig,
    break_glass: bool,
    reason: &str,
) -> anyhow::Result<()> {
    let operator_directory = config
        .operator
        .controller_private_key
        .parent()
        .context("operator directory is unavailable")?;
    let new_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let new_public = new_key.verifying_key().to_bytes();
    let new_digest = encode_hex(&Sha256::digest(new_public));
    let new_key_id = format!("controller-{}", &new_digest[..16]);
    let new_audit_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let new_audit_public = new_audit_key.verifying_key().to_bytes();
    let new_audit_digest = encode_hex(&Sha256::digest(new_audit_public));
    let new_audit_key_id = format!("audit-{}", &new_audit_digest[..16]);
    let current_break_glass_public = read_verifying_key(&config.operator.break_glass_public_key)?;
    let mut next_break_glass_key_id = config.operator.break_glass_key_id.clone();
    let mut next_break_glass_public = current_break_glass_public.to_bytes();
    let mut next_break_glass_private = None;
    if break_glass {
        let replacement = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        next_break_glass_public = replacement.verifying_key().to_bytes();
        let digest = encode_hex(&Sha256::digest(next_break_glass_public));
        next_break_glass_key_id = format!("break-glass-{}", &digest[..16]);
        next_break_glass_private = Some(replacement);
    }
    let next_break_glass_digest = encode_hex(&Sha256::digest(next_break_glass_public));
    let (authorization, signer_id, signer) = if break_glass {
        (
            TransitionAuthorization::BreakGlass,
            config.operator.break_glass_key_id.as_str(),
            read_signing_key(&config.operator.break_glass_private_key)?,
        )
    } else {
        (
            TransitionAuthorization::Controller,
            config.operator.controller_key_id.as_str(),
            read_signing_key(&config.operator.controller_private_key)?,
        )
    };
    let transition = ControllerTrustTransition {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        deployment_id: config.operator.deployment_id.clone(),
        issued_at: Utc::now().timestamp(),
        authorization,
        previous_key_id: config.operator.controller_key_id.clone(),
        next_key_id: new_key_id.clone(),
        next_public_key_sha256: new_digest,
        previous_audit_key_id: config.operator.audit_key_id.clone(),
        next_audit_key_id: new_audit_key_id.clone(),
        next_audit_public_key_sha256: new_audit_digest,
        previous_break_glass_key_id: config.operator.break_glass_key_id.clone(),
        next_break_glass_key_id: next_break_glass_key_id.clone(),
        next_break_glass_public_key_sha256: next_break_glass_digest,
        reason: reason.to_owned(),
    };
    let compact = sign_trust_transition(&transition, signer_id, &signer)?;
    let staged_private = operator_directory.join("controller.next.key");
    let staged_public = operator_directory.join("controller.next.pub");
    let staged_audit_private = operator_directory.join("audit.next.key");
    let staged_audit_public = operator_directory.join("audit.next.pub");
    let staged_break_glass_private = operator_directory.join("break-glass.next.key");
    let staged_break_glass_public = operator_directory.join("break-glass.next.pub");
    let transitions = config.operator.audit_directory.join("trust-transitions");
    fs::create_dir_all(&transitions)?;
    let transition_file = format!(
        "{}-{}-to-{}.jws",
        Utc::now().format("%Y%m%dT%H%M%S%.6fZ"),
        config.operator.controller_key_id,
        new_key_id
    );
    let transition_path = transitions.join(&transition_file);
    atomic_write(
        &staged_private,
        URL_SAFE_NO_PAD.encode(new_key.to_bytes()).as_bytes(),
        0o400,
    )?;
    atomic_write(
        &staged_public,
        URL_SAFE_NO_PAD.encode(new_public).as_bytes(),
        0o444,
    )?;
    atomic_write(
        &staged_audit_private,
        URL_SAFE_NO_PAD.encode(new_audit_key.to_bytes()).as_bytes(),
        0o400,
    )?;
    atomic_write(
        &staged_audit_public,
        URL_SAFE_NO_PAD.encode(new_audit_public).as_bytes(),
        0o444,
    )?;
    if let Some(replacement) = &next_break_glass_private {
        atomic_write(
            &staged_break_glass_private,
            URL_SAFE_NO_PAD.encode(replacement.to_bytes()).as_bytes(),
            0o400,
        )?;
        atomic_write(
            &staged_break_glass_public,
            URL_SAFE_NO_PAD.encode(next_break_glass_public).as_bytes(),
            0o444,
        )?;
    }
    atomic_write(
        &operator_directory.join("rotation-intent.json"),
        &serde_json::to_vec_pretty(&RotationIntent {
            schema: 1,
            previous_key_id: config.operator.controller_key_id.clone(),
            next_key_id: new_key_id.clone(),
            previous_audit_key_id: config.operator.audit_key_id.clone(),
            next_audit_key_id: new_audit_key_id.clone(),
            previous_break_glass_key_id: config.operator.break_glass_key_id.clone(),
            next_break_glass_key_id: next_break_glass_key_id.clone(),
            transition_file,
            compact_transition: compact.clone(),
        })?,
        0o600,
    )?;
    atomic_write(&transition_path, compact.as_bytes(), 0o400)?;
    let trusted = operator_directory.join("trusted-controllers");
    fs::create_dir_all(&trusted)?;
    atomic_write(
        &trusted.join(format!("{}.pub", config.operator.controller_key_id)),
        fs::read(&config.operator.controller_public_key)?.as_slice(),
        0o444,
    )?;
    let trusted_audit = operator_directory.join("trusted-audit");
    fs::create_dir_all(&trusted_audit)?;
    atomic_write(
        &trusted_audit.join(format!("{}.pub", config.operator.audit_key_id)),
        fs::read(&config.operator.audit_public_key)?.as_slice(),
        0o444,
    )?;
    if break_glass {
        let trusted_break_glass = operator_directory.join("trusted-break-glass");
        fs::create_dir_all(&trusted_break_glass)?;
        atomic_write(
            &trusted_break_glass.join(format!("{}.pub", config.operator.break_glass_key_id)),
            fs::read(&config.operator.break_glass_public_key)?.as_slice(),
            0o444,
        )?;
    }
    fs::rename(&staged_private, &config.operator.controller_private_key)?;
    fs::rename(&staged_public, &config.operator.controller_public_key)?;
    fs::rename(&staged_audit_private, &config.operator.audit_private_key)?;
    fs::rename(&staged_audit_public, &config.operator.audit_public_key)?;
    if break_glass {
        fs::rename(
            &staged_break_glass_private,
            &config.operator.break_glass_private_key,
        )?;
        fs::rename(
            &staged_break_glass_public,
            &config.operator.break_glass_public_key,
        )?;
    }
    atomic_write(
        &operator_directory.join("controller.kid"),
        new_key_id.as_bytes(),
        0o444,
    )?;
    atomic_write(
        &operator_directory.join("audit.kid"),
        new_audit_key_id.as_bytes(),
        0o444,
    )?;
    atomic_write(
        &operator_directory.join("break-glass.kid"),
        next_break_glass_key_id.as_bytes(),
        0o444,
    )?;
    let mut next_config = config.clone();
    next_config.operator.controller_key_id = new_key_id.clone();
    next_config.operator.audit_key_id = new_audit_key_id.clone();
    next_config.operator.break_glass_key_id = next_break_glass_key_id.clone();
    atomic_write(
        config_path,
        &serde_json::to_vec_pretty(&next_config)?,
        0o600,
    )?;
    fs::remove_file(operator_directory.join("rotation-intent.json"))?;
    println!(
        "controller/audit identity rotated: previous={} next={} previous_audit={} next_audit={} previous_break_glass={} next_break_glass={} authorization={authorization:?} transition={}",
        config.operator.controller_key_id,
        new_key_id,
        config.operator.audit_key_id,
        new_audit_key_id,
        config.operator.break_glass_key_id,
        next_break_glass_key_id,
        transition_path.display()
    );
    Ok(())
}

pub(crate) fn recover_pending_rotation(
    config_path: &Path,
    config: &mut UpdateConfig,
) -> anyhow::Result<()> {
    let directory = config
        .operator
        .controller_private_key
        .parent()
        .context("operator directory is unavailable")?;
    let intent_path = directory.join("rotation-intent.json");
    if !intent_path.exists() {
        for path in [
            directory.join("controller.next.key"),
            directory.join("controller.next.pub"),
            directory.join("audit.next.key"),
            directory.join("audit.next.pub"),
            directory.join("break-glass.next.key"),
            directory.join("break-glass.next.pub"),
        ] {
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        return Ok(());
    }
    let intent: RotationIntent = serde_json::from_slice(&fs::read(&intent_path)?)?;
    if intent.transition_file.is_empty()
        || intent.transition_file.starts_with('.')
        || intent.transition_file.contains(['/', '\\'])
    {
        bail!("controller rotation intent has an unsafe transition path");
    }
    if intent.schema != 1 {
        bail!("unsupported controller rotation intent");
    }
    let transitions = config.operator.audit_directory.join("trust-transitions");
    fs::create_dir_all(&transitions)?;
    let transition_path = transitions.join(&intent.transition_file);
    if !transition_path.exists() {
        atomic_write(
            &transition_path,
            intent.compact_transition.as_bytes(),
            0o400,
        )?;
    }
    if intent.next_key_id == config.operator.controller_key_id
        && intent.next_audit_key_id == config.operator.audit_key_id
        && intent.next_break_glass_key_id == config.operator.break_glass_key_id
    {
        let private = read_signing_key(&config.operator.controller_private_key)?;
        let public = read_verifying_key(&config.operator.controller_public_key)?;
        let audit_private = read_signing_key(&config.operator.audit_private_key)?;
        let audit_public = read_verifying_key(&config.operator.audit_public_key)?;
        let break_glass_private = read_signing_key(&config.operator.break_glass_private_key)?;
        let break_glass_public = read_verifying_key(&config.operator.break_glass_public_key)?;
        if private.verifying_key() != public
            || audit_private.verifying_key() != audit_public
            || break_glass_private.verifying_key() != break_glass_public
        {
            bail!("activated identity rotation has inconsistent key material");
        }
        fs::remove_file(intent_path)?;
        return Ok(());
    }
    if intent.previous_key_id != config.operator.controller_key_id
        || intent.previous_audit_key_id != config.operator.audit_key_id
        || intent.previous_break_glass_key_id != config.operator.break_glass_key_id
    {
        bail!("controller rotation intent does not match the active trust state");
    }
    let staged_private = directory.join("controller.next.key");
    let staged_public = directory.join("controller.next.pub");
    let staged_audit_private = directory.join("audit.next.key");
    let staged_audit_public = directory.join("audit.next.pub");
    let staged_break_glass_private = directory.join("break-glass.next.key");
    let staged_break_glass_public = directory.join("break-glass.next.pub");
    let trusted = directory.join("trusted-controllers");
    fs::create_dir_all(&trusted)?;
    let archived = trusted.join(format!("{}.pub", intent.previous_key_id));
    if !archived.exists() {
        atomic_write(
            &archived,
            fs::read(&config.operator.controller_public_key)?.as_slice(),
            0o444,
        )?;
    }
    let trusted_audit = directory.join("trusted-audit");
    fs::create_dir_all(&trusted_audit)?;
    let archived_audit = trusted_audit.join(format!("{}.pub", intent.previous_audit_key_id));
    if !archived_audit.exists() {
        atomic_write(
            &archived_audit,
            fs::read(&config.operator.audit_public_key)?.as_slice(),
            0o444,
        )?;
    }
    if intent.next_break_glass_key_id != intent.previous_break_glass_key_id {
        let trusted_break_glass = directory.join("trusted-break-glass");
        fs::create_dir_all(&trusted_break_glass)?;
        let archived_break_glass =
            trusted_break_glass.join(format!("{}.pub", intent.previous_break_glass_key_id));
        if !archived_break_glass.exists() {
            atomic_write(
                &archived_break_glass,
                fs::read(&config.operator.break_glass_public_key)?.as_slice(),
                0o444,
            )?;
        }
    }
    if staged_private.exists() {
        fs::rename(&staged_private, &config.operator.controller_private_key)?;
    }
    if staged_public.exists() {
        fs::rename(&staged_public, &config.operator.controller_public_key)?;
    }
    if staged_audit_private.exists() {
        fs::rename(&staged_audit_private, &config.operator.audit_private_key)?;
    }
    if staged_audit_public.exists() {
        fs::rename(&staged_audit_public, &config.operator.audit_public_key)?;
    }
    if staged_break_glass_private.exists() {
        fs::rename(
            &staged_break_glass_private,
            &config.operator.break_glass_private_key,
        )?;
    }
    if staged_break_glass_public.exists() {
        fs::rename(
            &staged_break_glass_public,
            &config.operator.break_glass_public_key,
        )?;
    }
    let private = read_signing_key(&config.operator.controller_private_key)?;
    let public = read_verifying_key(&config.operator.controller_public_key)?;
    if private.verifying_key() != public {
        bail!("interrupted controller rotation cannot be recovered safely");
    }
    let audit_private = read_signing_key(&config.operator.audit_private_key)?;
    let audit_public = read_verifying_key(&config.operator.audit_public_key)?;
    if audit_private.verifying_key() != audit_public {
        bail!("interrupted audit rotation cannot be recovered safely");
    }
    let break_glass_private = read_signing_key(&config.operator.break_glass_private_key)?;
    let break_glass_public = read_verifying_key(&config.operator.break_glass_public_key)?;
    if break_glass_private.verifying_key() != break_glass_public {
        bail!("interrupted break-glass rotation cannot be recovered safely");
    }
    atomic_write(
        &directory.join("controller.kid"),
        intent.next_key_id.as_bytes(),
        0o444,
    )?;
    atomic_write(
        &directory.join("audit.kid"),
        intent.next_audit_key_id.as_bytes(),
        0o444,
    )?;
    atomic_write(
        &directory.join("break-glass.kid"),
        intent.next_break_glass_key_id.as_bytes(),
        0o444,
    )?;
    config.operator.controller_key_id = intent.next_key_id;
    config.operator.audit_key_id = intent.next_audit_key_id;
    config.operator.break_glass_key_id = intent.next_break_glass_key_id;
    atomic_write(config_path, &serde_json::to_vec_pretty(config)?, 0o600)?;
    fs::remove_file(intent_path)?;
    Ok(())
}

fn trusted_controller_key(config: &UpdateConfig, key_id: &str) -> anyhow::Result<VerifyingKey> {
    if key_id == config.operator.controller_key_id {
        return read_verifying_key(&config.operator.controller_public_key);
    }
    let directory = config
        .operator
        .controller_public_key
        .parent()
        .context("operator directory is unavailable")?
        .join("trusted-controllers");
    read_verifying_key(&directory.join(format!("{key_id}.pub")))
}

fn trusted_audit_key(config: &UpdateConfig, key_id: &str) -> anyhow::Result<VerifyingKey> {
    if key_id == config.operator.audit_key_id {
        return read_verifying_key(&config.operator.audit_public_key);
    }
    let directory = config
        .operator
        .audit_public_key
        .parent()
        .context("operator directory is unavailable")?
        .join("trusted-audit");
    read_verifying_key(&directory.join(format!("{key_id}.pub")))
}

fn trusted_break_glass_key(config: &UpdateConfig, key_id: &str) -> anyhow::Result<VerifyingKey> {
    if key_id == config.operator.break_glass_key_id {
        return read_verifying_key(&config.operator.break_glass_public_key);
    }
    let directory = config
        .operator
        .break_glass_public_key
        .parent()
        .context("operator directory is unavailable")?
        .join("trusted-break-glass");
    read_verifying_key(&directory.join(format!("{key_id}.pub")))
}

fn read_signing_key(path: &Path) -> anyhow::Result<SigningKey> {
    let bytes = read_key(path)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid signing key length"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn read_verifying_key(path: &Path) -> anyhow::Result<VerifyingKey> {
    let bytes = read_key(path)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid verifying key length"))?;
    VerifyingKey::from_bytes(&bytes).context("invalid verifying key")
}

fn read_key(path: &Path) -> anyhow::Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(read_single_line(path)?)
        .context("operator key is not canonical base64url")
}

fn read_single_line(path: &Path) -> anyhow::Result<String> {
    let value =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    if value.is_empty() || value.contains(['\r', '\n']) {
        bail!("operator identity file is invalid: {}", path.display());
    }
    Ok(value)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[path = "../tests/unit/operator.rs"]
mod tests;
