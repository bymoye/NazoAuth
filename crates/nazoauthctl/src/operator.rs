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
    #[serde(default)]
    next_generation: String,
    previous_key_id: String,
    next_key_id: String,
    previous_audit_key_id: String,
    next_audit_key_id: String,
    previous_break_glass_key_id: String,
    next_break_glass_key_id: String,
    transition_file: String,
    compact_transition: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyAdoptionIntent {
    schema: u32,
    generation: String,
    controller_key_id: String,
    audit_key_id: String,
    break_glass_key_id: String,
}

/// A generation is immutable before it becomes active.  The one small active
/// record is the only commit point that selects controller, audit and recovery
/// material together; it deliberately contains no secret bytes or paths.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveIdentity {
    schema: u32,
    pub(crate) generation: String,
    pub(crate) controller_key_id: String,
    pub(crate) audit_key_id: String,
    pub(crate) break_glass_key_id: String,
}

#[derive(Clone, Debug)]
struct IdentityLayout {
    operator_directory: PathBuf,
    active_file: PathBuf,
    generations: PathBuf,
    recovery_generations: PathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct RotationResult {
    pub(crate) previous_controller_key_id: String,
    pub(crate) previous_controller_public_sha256: String,
    retirement_probe: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetirementProbeExecution {
    /// Verified by nazoauthctl and the runtime adapter; the application does
    /// not and cannot attest its containing OCI image digest by itself.
    controller_verified_target: RuntimeTargetClaim,
    application_reported_embedded_identity: EmbeddedIdentity,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum RetirementProbeAuditEvidence {
    RuntimeAuthorizationRejected {
        schema: u32,
        previous_controller_key_id: String,
        active_controller_key_id: String,
        probe_sha256: String,
        controller_verified_target: RuntimeTargetClaim,
        application_reported_embedded_identity: EmbeddedIdentity,
    },
    NotIssued {
        schema: u32,
        previous_controller_key_id: String,
        previous_controller_public_sha256: String,
        reason: String,
    },
}

/// The recovery path must remain usable when the active controller private key
/// is genuinely unavailable.  A rehearsal carries a copy only in memory,
/// then makes every subsequent controller signing read fail closed.
enum ControllerSigningAccess {
    Available,
    ForbiddenForRehearsal(Box<SigningKey>),
    Unavailable,
}

impl ControllerSigningAccess {
    fn controller_for_retirement_probe(&self, path: &Path) -> anyhow::Result<Option<SigningKey>> {
        match self {
            Self::Available => Ok(Some(read_signing_key(path)?)),
            Self::ForbiddenForRehearsal(key) => Ok(Some(key.as_ref().clone())),
            Self::Unavailable => Ok(None),
        }
    }

    fn controller_for_normal_rotation(&self, path: &Path) -> anyhow::Result<SigningKey> {
        match self {
            Self::Available => read_signing_key(path),
            Self::ForbiddenForRehearsal(_) | Self::Unavailable => {
                bail!("controller signing access is forbidden for this recovery operation")
            }
        }
    }
}

pub(crate) fn execute(
    config: &UpdateConfig,
    target: &str,
    expected: &ExpectedReleaseTarget,
    operation: TaskOperation,
    public_jwk: Option<&Path>,
) -> anyhow::Result<OperationResult> {
    // A privileged operation is admissible only while the existing audit,
    // intent and trust-transition state is verifiably intact.  Checking after
    // the runtime side effect would be too late: the mutation could succeed
    // even though ctl can no longer append a trustworthy receipt.
    verify_audit(config).context("operator audit preflight failed")?;
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

    // Revalidate immediately before reading the head and appending.  The
    // lifecycle lock excludes another ctl writer; this second check also
    // catches out-of-band corruption during the runtime operation.
    verify_audit(config).context("operator audit changed during task execution")?;
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
    if path_present(&path)? {
        if !is_regular_non_symlink(&path)? {
            bail!("persisted operator intent is not a regular non-symlink file");
        }
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
        let request_claim = config
            .operator
            .state_directory
            .join(format!("{}.request.sha256", task.jti));
        let lifecycle = config
            .operator
            .state_directory
            .join(format!("{}.lifecycle.json", task.jti));
        let receipt_temporary = cached_receipt.with_extension("receipt.jws.tmp");
        let cached_receipt_present = path_present(&cached_receipt)?;
        if cached_receipt_present && !is_regular_non_symlink(&cached_receipt)? {
            bail!("cached runtime receipt is not a regular non-symlink file");
        }
        let runtime_has_observed_request = path_present(&request_claim)?
            || path_present(&lifecycle)?
            || path_present(&receipt_temporary)?;
        if task.exp >= now || cached_receipt_present || runtime_has_observed_request {
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
    if !is_real_directory_or_missing(&directory, "audit receipt directory")? {
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
        TaskOperation::ConformanceLeaseCreate { .. }
        | TaskOperation::ConformanceLeaseList
        | TaskOperation::ConformanceLeaseRevoke { .. }
        | TaskOperation::ConformanceLeaseCleanup => {
            bail!("test task adapter does not implement conformance lease operations")
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
            | TaskOperation::KeysRegisterExternal { .. }
            | TaskOperation::ConformanceLeaseCreate { .. }
            | TaskOperation::ConformanceLeaseList
            | TaskOperation::ConformanceLeaseRevoke { .. }
            | TaskOperation::ConformanceLeaseCleanup => unreachable!(),
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
    verify_audit_chain(config)?;
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
    let (sequence, head) = verify_audit_chain(config)?;
    if sequence == 0 {
        eprintln!("audit: empty chain verified");
    } else {
        eprintln!("audit: verified {sequence} signed checkpoints; head={head}");
    }
    Ok(())
}

fn verify_audit_chain(config: &UpdateConfig) -> anyhow::Result<(u64, String)> {
    let receipts = config.operator.audit_directory.join("receipts");
    let head_path = config.operator.audit_directory.join("head.json");
    if !is_real_directory_or_missing(&receipts, "audit receipt directory")? {
        if path_present(&head_path)? {
            bail!("audit receipt directory is missing while an audit head exists");
        }
        verify_pending_intents(config)?;
        verify_management_events(config)?;
        verify_trust_transitions(config)?;
        return Ok((0, "0".repeat(64)));
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
    verify_pending_intents(config)?;
    verify_management_events(config)?;
    verify_trust_transitions(config)?;
    Ok((sequence, previous))
}

pub(crate) fn show_audit(config: &UpdateConfig, request_id: Option<&str>) -> anyhow::Result<()> {
    let entries = audit_entries(config, request_id)?;
    println!("{}", serde_json::to_string_pretty(&entries)?);
    Ok(())
}

fn audit_entries(
    config: &UpdateConfig,
    request_id: Option<&str>,
) -> anyhow::Result<Vec<serde_json::Value>> {
    verify_audit_chain(config)?;
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
    if is_real_directory_or_missing(&receipts, "audit receipt directory")? {
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
    if is_real_directory_or_missing(&management, "management audit directory")? {
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
    Ok(entries)
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
    let request_id = format!("request-{}", encode_hex(&rand::random::<[u8; 16]>()));
    append_management_event_idempotent(config, &request_id, operation, release, recovery_boundary)
}

pub(crate) fn append_management_event_idempotent(
    config: &UpdateConfig,
    request_id: &str,
    operation: &str,
    release: &str,
    recovery_boundary: &str,
) -> anyhow::Result<PathBuf> {
    verify_audit_chain(config)?;
    let directory = config.operator.audit_directory.join("management");
    fs::create_dir_all(&directory)?;
    let suffix = format!("-{request_id}.jws");
    let existing = fs::read_dir(&directory)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_file())
                && entry.file_name().to_string_lossy().ends_with(&suffix)
        })
        .collect::<Vec<_>>();
    if existing.len() > 1 {
        bail!("management audit request id is not unique");
    }
    if let Some(entry) = existing.first() {
        let file_name = entry.file_name();
        let event = load_management_event(config, &file_name.to_string_lossy())?;
        if event.request_id != request_id
            || event.operation != operation
            || event.release != release
            || event.recovery_boundary != recovery_boundary
        {
            bail!("management audit request id was reused with different content");
        }
        return Ok(entry.path());
    }
    let head_path = config.operator.audit_directory.join("management-head.json");
    let (sequence, previous) = if head_path.exists() {
        let head: AuditHead = serde_json::from_slice(&fs::read(&head_path)?)?;
        (head.sequence + 1, head.sha256)
    } else {
        (1, "0".repeat(64))
    };
    let event = ManagementAuditEvent {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        deployment_id: config.operator.deployment_id.clone(),
        sequence,
        previous_sha256: previous,
        request_id: request_id.to_owned(),
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
    verify_audit_chain(config)?;
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
    let head_path = config.operator.audit_directory.join("management-head.json");
    if !is_real_directory_or_missing(&directory, "management audit directory")? {
        if path_present(&head_path)? {
            bail!("management audit directory is missing while a management audit head exists");
        }
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
        if event.operation == "controller-retirement-probe" {
            validate_retirement_probe_audit_evidence(&event.recovery_boundary)?;
        }
        sequence = event.sequence;
        previous = compact_sha256(&compact);
        checkpoints.insert(sequence, previous.clone());
    }
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

fn validate_retirement_probe_audit_evidence(value: &str) -> anyhow::Result<()> {
    let encoded = value
        .strip_prefix("evidence-v1.")
        .context("controller retirement probe evidence prefix is invalid")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("controller retirement probe evidence is not canonical base64url")?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        bail!("controller retirement probe evidence is not canonical base64url")
    }
    let evidence: RetirementProbeAuditEvidence = serde_json::from_slice(&bytes)
        .context("controller retirement probe evidence is not strict JSON")?;
    match evidence {
        RetirementProbeAuditEvidence::RuntimeAuthorizationRejected {
            schema,
            previous_controller_key_id,
            active_controller_key_id,
            probe_sha256,
            controller_verified_target,
            application_reported_embedded_identity,
        } => {
            if schema != 1
                || !safe_identity_component(&previous_controller_key_id)
                || !safe_identity_component(&active_controller_key_id)
                || !valid_sha256(&probe_sha256)
                || application_reported_embedded_identity.protocol
                    != nazo_operator_protocol::PROTOCOL_VERSION
                || application_reported_embedded_identity.release.is_empty()
                || application_reported_embedded_identity.revision.is_empty()
                || application_reported_embedded_identity.build_id.is_empty()
            {
                bail!("controller retirement probe evidence is invalid")
            }
            match controller_verified_target {
                RuntimeTargetClaim::OciImage {
                    image_ref,
                    image_digest,
                } if !image_ref.is_empty()
                    && image_digest
                        .strip_prefix("sha256:")
                        .is_some_and(valid_sha256) => {}
                RuntimeTargetClaim::HostBinary { path, sha256 }
                    if Path::new(&path).is_absolute() && valid_sha256(&sha256) => {}
                _ => bail!("controller retirement probe target evidence is invalid"),
            }
        }
        RetirementProbeAuditEvidence::NotIssued {
            schema,
            previous_controller_key_id,
            previous_controller_public_sha256,
            reason,
        } => {
            if schema != 1
                || !safe_identity_component(&previous_controller_key_id)
                || !valid_sha256(&previous_controller_public_sha256)
                || reason != "controller-private-unavailable"
            {
                bail!("controller retirement probe non-issuance evidence is invalid")
            }
        }
    }
    Ok(())
}

fn encode_retirement_probe_audit_evidence(
    evidence: &RetirementProbeAuditEvidence,
) -> anyhow::Result<String> {
    Ok(format!(
        "evidence-v1.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(evidence)?)
    ))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    if let Some((controller, audit, break_glass)) = expected_previous
        && (controller != config.operator.controller_key_id
            || audit != config.operator.audit_key_id
            || break_glass != config.operator.break_glass_key_id)
    {
        bail!("controller trust transition chain does not terminate at the active identity");
    }
    Ok(())
}

pub(crate) fn initialize_identity_generation(
    operator_directory: &Path,
    recovery_directory: &Path,
) -> anyhow::Result<()> {
    let active_file = operator_directory.join("active-generation.json");
    let layout = IdentityLayout {
        operator_directory: operator_directory.to_owned(),
        active_file: active_file.clone(),
        generations: operator_directory.join("generations"),
        recovery_generations: recovery_directory.join("generations"),
    };
    if path_present(&active_file)? {
        ensure_static_identity_files(operator_directory)?;
        let active = read_active_identity(&active_file)?;
        validate_generation(&layout, &active)?;
        return Ok(());
    }
    for legacy in [
        operator_directory.join("controller.key"),
        operator_directory.join("controller.pub"),
        operator_directory.join("audit.key"),
        operator_directory.join("audit.pub"),
        recovery_directory.join("break-glass.key"),
        operator_directory.join("break-glass.pub"),
    ] {
        if path_present(&legacy)? {
            bail!(
                "legacy operator identity exists without an active generation; refuse ambiguous fresh install"
            )
        }
    }
    create_private_directory(operator_directory)?;
    create_private_directory(recovery_directory)?;
    repair_uncommitted_receipt_identity(operator_directory)?;
    ensure_static_identity_files(operator_directory)?;
    retire_generation_private_material(
        &layout.generations,
        None,
        &["controller.key", "audit.key"],
    )?;
    retire_generation_private_material(&layout.recovery_generations, None, &["break-glass.key"])?;
    let controller = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let audit = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let break_glass = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let active = new_active_identity(&controller, &audit, &break_glass);
    write_generation(&layout, &active, &controller, &audit, &break_glass)?;
    write_active_identity(&layout, &active)
}

fn repair_uncommitted_receipt_identity(directory: &Path) -> anyhow::Result<()> {
    let paths = [
        directory.join("receipt.key"),
        directory.join("receipt.pub"),
        directory.join("receipt.kid"),
    ];
    let present = paths
        .iter()
        .map(|path| path_present(path))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .filter(|present| *present)
        .count();
    if present == 0 || present == paths.len() {
        return Ok(());
    }
    for path in paths {
        remove_managed_regular_file(&path)?;
    }
    Ok(())
}

pub(crate) fn read_active_identity(path: &Path) -> anyhow::Result<ActiveIdentity> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect active identity record {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("active identity record must be a regular non-symlink file")
    }
    let active: ActiveIdentity = serde_json::from_slice(&fs::read(path)?)?;
    validate_active_identity(&active)?;
    Ok(active)
}

fn identity_layout(config: &UpdateConfig) -> anyhow::Result<IdentityLayout> {
    let active_file = if config.operator.active_identity_file.as_os_str().is_empty() {
        config
            .operator
            .controller_private_key
            .parent()
            .context("operator directory is unavailable")?
            .join("active-generation.json")
    } else {
        config.operator.active_identity_file.clone()
    };
    let operator_directory = active_file
        .parent()
        .context("active identity record has no operator directory")?
        .to_owned();
    let recovery_directory = config
        .operator
        .break_glass_private_key
        .parent()
        .context("recovery private key has no parent directory")?;
    Ok(IdentityLayout {
        generations: if config
            .operator
            .identity_generations_directory
            .as_os_str()
            .is_empty()
        {
            operator_directory.join("generations")
        } else {
            config.operator.identity_generations_directory.clone()
        },
        recovery_generations: if config
            .operator
            .recovery_generations_directory
            .as_os_str()
            .is_empty()
        {
            recovery_directory.join("generations")
        } else {
            config.operator.recovery_generations_directory.clone()
        },
        operator_directory,
        active_file,
    })
}

fn create_private_directory(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    crate::filesystem::set_mode(path, 0o700)
}

fn ensure_static_identity_files(directory: &Path) -> anyhow::Result<()> {
    for (name, private_mode) in [("deployment-id", 0o400), ("secret-revision", 0o400)] {
        let path = directory.join(name);
        if !path_present(&path)? {
            let value = if name == "deployment-id" {
                format!("deployment-{}", encode_hex(&rand::random::<[u8; 16]>()))
            } else {
                format!("secret-{}", encode_hex(&rand::random::<[u8; 16]>()))
            };
            atomic_write(&path, value.as_bytes(), private_mode)?;
        } else if !is_regular_non_symlink(&path)? || read_single_line(&path)?.len() > 128 {
            bail!(
                "static operator identity file is invalid: {}",
                path.display()
            )
        }
    }
    let private = directory.join("receipt.key");
    let public = directory.join("receipt.pub");
    let kid = directory.join("receipt.kid");
    if path_present(&private)? || path_present(&public)? || path_present(&kid)? {
        if !(is_regular_non_symlink(&private)?
            && is_regular_non_symlink(&public)?
            && is_regular_non_symlink(&kid)?)
        {
            bail!("incomplete receipt identity requires review")
        }
        let verifying = read_verifying_key(&public)?;
        let expected_kid = format!(
            "receipt-{}",
            &encode_hex(&Sha256::digest(verifying.to_bytes()))[..16]
        );
        if read_signing_key(&private)?.verifying_key() != verifying
            || read_single_line(&kid)? != expected_kid
        {
            bail!("receipt identity is inconsistent")
        }
        return Ok(());
    }
    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let public_bytes = key.verifying_key().to_bytes();
    let digest = encode_hex(&Sha256::digest(public_bytes));
    atomic_write(
        &private,
        URL_SAFE_NO_PAD.encode(key.to_bytes()).as_bytes(),
        0o400,
    )?;
    atomic_write(
        &public,
        URL_SAFE_NO_PAD.encode(public_bytes).as_bytes(),
        0o444,
    )?;
    atomic_write(&kid, format!("receipt-{}", &digest[..16]).as_bytes(), 0o444)
}

fn new_active_identity(
    controller: &SigningKey,
    audit: &SigningKey,
    break_glass: &SigningKey,
) -> ActiveIdentity {
    let controller_digest = encode_hex(&Sha256::digest(controller.verifying_key().to_bytes()));
    let audit_digest = encode_hex(&Sha256::digest(audit.verifying_key().to_bytes()));
    let break_glass_digest = encode_hex(&Sha256::digest(break_glass.verifying_key().to_bytes()));
    ActiveIdentity {
        schema: 1,
        generation: format!("generation-{}", &controller_digest[..24]),
        controller_key_id: format!("controller-{}", &controller_digest[..16]),
        audit_key_id: format!("audit-{}", &audit_digest[..16]),
        break_glass_key_id: format!("break-glass-{}", &break_glass_digest[..16]),
    }
}

fn validate_active_identity(active: &ActiveIdentity) -> anyhow::Result<()> {
    if active.schema != 1
        || !safe_identity_component(&active.generation)
        || !safe_identity_component(&active.controller_key_id)
        || !safe_identity_component(&active.audit_key_id)
        || !safe_identity_component(&active.break_glass_key_id)
    {
        bail!("active identity record is invalid")
    }
    Ok(())
}

fn safe_identity_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn generation_paths(layout: &IdentityLayout, active: &ActiveIdentity) -> (PathBuf, PathBuf) {
    (
        layout.generations.join(&active.generation),
        layout.recovery_generations.join(&active.generation),
    )
}

fn write_generation(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
    controller: &SigningKey,
    audit: &SigningKey,
    break_glass: &SigningKey,
) -> anyhow::Result<()> {
    validate_active_identity(active)?;
    let (generation, recovery_generation) = generation_paths(layout, active);
    if path_present(&generation)? || path_present(&recovery_generation)? {
        bail!("identity generation already exists")
    }
    create_private_directory(&generation)?;
    create_private_directory(&recovery_generation)?;
    atomic_write(
        &generation.join("controller.key"),
        URL_SAFE_NO_PAD.encode(controller.to_bytes()).as_bytes(),
        0o400,
    )?;
    atomic_write(
        &generation.join("controller.pub"),
        URL_SAFE_NO_PAD
            .encode(controller.verifying_key().to_bytes())
            .as_bytes(),
        0o444,
    )?;
    atomic_write(
        &generation.join("audit.key"),
        URL_SAFE_NO_PAD.encode(audit.to_bytes()).as_bytes(),
        0o400,
    )?;
    atomic_write(
        &generation.join("audit.pub"),
        URL_SAFE_NO_PAD
            .encode(audit.verifying_key().to_bytes())
            .as_bytes(),
        0o444,
    )?;
    atomic_write(
        &recovery_generation.join("break-glass.key"),
        URL_SAFE_NO_PAD.encode(break_glass.to_bytes()).as_bytes(),
        0o400,
    )?;
    atomic_write(
        &generation.join("break-glass.pub"),
        URL_SAFE_NO_PAD
            .encode(break_glass.verifying_key().to_bytes())
            .as_bytes(),
        0o444,
    )?;
    validate_generation(layout, active)
}

fn validate_generation(layout: &IdentityLayout, active: &ActiveIdentity) -> anyhow::Result<()> {
    let (generation, recovery_generation) = generation_paths(layout, active);
    let controller_public = read_verifying_key(&generation.join("controller.pub"))?;
    let audit_public = read_verifying_key(&generation.join("audit.pub"))?;
    let break_glass_public = read_verifying_key(&generation.join("break-glass.pub"))?;
    if read_signing_key(&generation.join("controller.key"))?.verifying_key() != controller_public
        || read_signing_key(&generation.join("audit.key"))?.verifying_key() != audit_public
        || read_signing_key(&recovery_generation.join("break-glass.key"))?.verifying_key()
            != break_glass_public
        || active.controller_key_id
            != format!(
                "controller-{}",
                &encode_hex(&Sha256::digest(controller_public.to_bytes()))[..16]
            )
        || active.audit_key_id
            != format!(
                "audit-{}",
                &encode_hex(&Sha256::digest(audit_public.to_bytes()))[..16]
            )
        || active.break_glass_key_id
            != format!(
                "break-glass-{}",
                &encode_hex(&Sha256::digest(break_glass_public.to_bytes()))[..16]
            )
    {
        bail!("identity generation key material is inconsistent")
    }
    Ok(())
}

/// Recovery needs the public controller identity plus the independently held
/// break-glass signer.  Requiring the very private key that is being recovered
/// would make a real loss unrecoverable.
fn validate_generation_for_break_glass_recovery(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) -> anyhow::Result<()> {
    let (generation, recovery_generation) = generation_paths(layout, active);
    let controller_public = read_verifying_key(&generation.join("controller.pub"))?;
    let audit_public = read_verifying_key(&generation.join("audit.pub"))?;
    let break_glass_public = read_verifying_key(&generation.join("break-glass.pub"))?;
    if read_signing_key(&generation.join("audit.key"))?.verifying_key() != audit_public
        || read_signing_key(&recovery_generation.join("break-glass.key"))?.verifying_key()
            != break_glass_public
        || active.controller_key_id
            != format!(
                "controller-{}",
                &encode_hex(&Sha256::digest(controller_public.to_bytes()))[..16]
            )
        || active.audit_key_id
            != format!(
                "audit-{}",
                &encode_hex(&Sha256::digest(audit_public.to_bytes()))[..16]
            )
        || active.break_glass_key_id
            != format!(
                "break-glass-{}",
                &encode_hex(&Sha256::digest(break_glass_public.to_bytes()))[..16]
            )
    {
        bail!("identity generation recovery material is inconsistent")
    }
    Ok(())
}

fn write_active_identity(layout: &IdentityLayout, active: &ActiveIdentity) -> anyhow::Result<()> {
    validate_generation(layout, active)?;
    atomic_write(
        &layout.active_file,
        &serde_json::to_vec_pretty(active)?,
        0o600,
    )
}

fn apply_active_identity(
    config: &mut UpdateConfig,
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) {
    let (generation, recovery_generation) = generation_paths(layout, active);
    config.operator.controller_key_id = active.controller_key_id.clone();
    config.operator.controller_private_key = generation.join("controller.key");
    config.operator.controller_public_key = generation.join("controller.pub");
    config.operator.audit_key_id = active.audit_key_id.clone();
    config.operator.audit_private_key = generation.join("audit.key");
    config.operator.audit_public_key = generation.join("audit.pub");
    config.operator.break_glass_key_id = active.break_glass_key_id.clone();
    config.operator.break_glass_private_key = recovery_generation.join("break-glass.key");
    config.operator.break_glass_public_key = generation.join("break-glass.pub");
    config.operator.active_identity_file = layout.active_file.clone();
    config.operator.identity_generations_directory = layout.generations.clone();
    config.operator.recovery_generations_directory = layout.recovery_generations.clone();
}

fn adopt_legacy_identity(
    config_path: &Path,
    config: &mut UpdateConfig,
    layout: &IdentityLayout,
) -> anyhow::Result<()> {
    let controller = read_signing_key(&config.operator.controller_private_key)?;
    let controller_public = read_verifying_key(&config.operator.controller_public_key)?;
    let audit = read_signing_key(&config.operator.audit_private_key)?;
    let audit_public = read_verifying_key(&config.operator.audit_public_key)?;
    let break_glass = read_signing_key(&config.operator.break_glass_private_key)?;
    let break_glass_public = read_verifying_key(&config.operator.break_glass_public_key)?;
    if controller.verifying_key() != controller_public
        || audit.verifying_key() != audit_public
        || break_glass.verifying_key() != break_glass_public
    {
        bail!("legacy operator identity is inconsistent; refuse automatic adoption")
    }
    let active = ActiveIdentity {
        schema: 1,
        generation: format!("legacy-{}", config.operator.controller_key_id),
        controller_key_id: config.operator.controller_key_id.clone(),
        audit_key_id: config.operator.audit_key_id.clone(),
        break_glass_key_id: config.operator.break_glass_key_id.clone(),
    };
    validate_active_identity(&active)?;
    let intent_path = layout.operator_directory.join("legacy-adoption.json");
    let intent = LegacyAdoptionIntent {
        schema: 1,
        generation: active.generation.clone(),
        controller_key_id: active.controller_key_id.clone(),
        audit_key_id: active.audit_key_id.clone(),
        break_glass_key_id: active.break_glass_key_id.clone(),
    };
    refuse_ambiguous_legacy_adoption(config, layout, &intent_path, &intent)?;
    if !path_present(&intent_path)? {
        atomic_write(&intent_path, &serde_json::to_vec_pretty(&intent)?, 0o600)?;
    }
    if path_present(&generation_paths(layout, &active).0)?
        || path_present(&generation_paths(layout, &active).1)?
    {
        match validate_generation(layout, &active) {
            Ok(()) => {
                let (generation, recovery_generation) = generation_paths(layout, &active);
                if read_signing_key(&generation.join("controller.key"))?.to_bytes()
                    != controller.to_bytes()
                    || read_signing_key(&generation.join("audit.key"))?.to_bytes()
                        != audit.to_bytes()
                    || read_signing_key(&recovery_generation.join("break-glass.key"))?.to_bytes()
                        != break_glass.to_bytes()
                {
                    bail!("staged legacy adoption conflicts with configured identity")
                }
            }
            Err(_) => {
                remove_uncommitted_generation(layout, &active)?;
                write_generation(layout, &active, &controller, &audit, &break_glass)?;
            }
        }
    } else {
        write_generation(layout, &active, &controller, &audit, &break_glass)?;
    }
    write_active_identity(layout, &active)?;
    apply_active_identity(config, layout, &active);
    atomic_write(config_path, &serde_json::to_vec_pretty(config)?, 0o600)?;
    crate::filesystem::remove_file_durable(&intent_path)
}

fn refuse_ambiguous_legacy_adoption(
    config: &UpdateConfig,
    layout: &IdentityLayout,
    intent_path: &Path,
    expected: &LegacyAdoptionIntent,
) -> anyhow::Result<()> {
    if path_present(&layout.operator_directory.join("rotation-intent.json"))?
        || directory_has_entries(&config.operator.audit_directory.join("trust-transitions"))?
    {
        bail!("legacy identity cannot be adopted from an ambiguous rotation state")
    }
    if path_present(intent_path)? {
        let actual: LegacyAdoptionIntent = serde_json::from_slice(&fs::read(intent_path)?)?;
        if actual.schema != expected.schema
            || actual.generation != expected.generation
            || actual.controller_key_id != expected.controller_key_id
            || actual.audit_key_id != expected.audit_key_id
            || actual.break_glass_key_id != expected.break_glass_key_id
        {
            bail!("legacy identity adoption intent conflicts with configured identity")
        }
        ensure_only_expected_generation(&layout.generations, &expected.generation)?;
        ensure_only_expected_generation(&layout.recovery_generations, &expected.generation)?;
        return Ok(());
    }
    if directory_has_entries(&layout.generations)?
        || directory_has_entries(&layout.recovery_generations)?
    {
        bail!("legacy identity exists with uncommitted generation state")
    }
    Ok(())
}

fn directory_has_entries(path: &Path) -> anyhow::Result<bool> {
    if !path_present(path)? {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("managed identity path must be a regular non-symlink directory")
    }
    Ok(fs::read_dir(path)?.next().transpose()?.is_some())
}

fn ensure_only_expected_generation(directory: &Path, expected: &str) -> anyhow::Result<()> {
    if !path_present(directory)? {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("managed identity path must be a regular non-symlink directory")
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name().to_str() != Some(expected) || !entry.file_type()?.is_dir() {
            bail!("legacy adoption contains an unexpected identity generation")
        }
    }
    Ok(())
}

fn remove_uncommitted_generation(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) -> anyhow::Result<()> {
    let (generation, recovery_generation) = generation_paths(layout, active);
    remove_allowlisted_generation_directory(
        &generation,
        &[
            "controller.key",
            "controller.pub",
            "audit.key",
            "audit.pub",
            "break-glass.pub",
        ],
    )?;
    remove_allowlisted_generation_directory(&recovery_generation, &["break-glass.key"])
}

fn remove_allowlisted_generation_directory(path: &Path, allowed: &[&str]) -> anyhow::Result<()> {
    if !path_present(path)? {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("uncommitted identity generation is not a regular directory")
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("uncommitted identity entry is not UTF-8"))?;
        if !allowed.contains(&name.as_str()) || !entry.file_type()?.is_file() {
            bail!("uncommitted identity generation contains an unexpected entry")
        }
        remove_managed_regular_file(&entry.path())?;
    }
    fs::remove_dir(path).with_context(|| format!("failed to remove {}", path.display()))
}

fn archive_public_key(path: &Path, source: &Path) -> anyhow::Result<()> {
    if path_present(path)? {
        if fs::read(path)? != fs::read(source)? {
            bail!("historical trust public key conflicts with staged generation")
        }
        return Ok(());
    }
    atomic_write(path, fs::read(source)?.as_slice(), 0o444)
}

fn archive_generation_publics(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) -> anyhow::Result<()> {
    let (generation, _) = generation_paths(layout, active);
    archive_public_key(
        &layout
            .operator_directory
            .join("trusted-controllers")
            .join(format!("{}.pub", active.controller_key_id)),
        &generation.join("controller.pub"),
    )?;
    archive_public_key(
        &layout
            .operator_directory
            .join("trusted-audit")
            .join(format!("{}.pub", active.audit_key_id)),
        &generation.join("audit.pub"),
    )?;
    archive_public_key(
        &layout
            .operator_directory
            .join("trusted-break-glass")
            .join(format!("{}.pub", active.break_glass_key_id)),
        &generation.join("break-glass.pub"),
    )
}

fn verify_rotation_intent(
    config: &UpdateConfig,
    active: &ActiveIdentity,
    next: &ActiveIdentity,
    intent: &RotationIntent,
) -> anyhow::Result<()> {
    let active_is_previous = active.controller_key_id == intent.previous_key_id
        && active.audit_key_id == intent.previous_audit_key_id
        && active.break_glass_key_id == intent.previous_break_glass_key_id;
    let active_is_next = active.controller_key_id == next.controller_key_id
        && active.audit_key_id == next.audit_key_id
        && active.break_glass_key_id == next.break_glass_key_id;
    if !active_is_previous && !active_is_next {
        bail!("controller rotation intent does not connect to the active generation")
    }
    let header = protected_header(&intent.compact_transition)?;
    let key = if header.kid == intent.previous_key_id {
        if active_is_previous {
            read_verifying_key(&config.operator.controller_public_key)?
        } else {
            trusted_controller_key(config, &header.kid)?
        }
    } else if header.kid == intent.previous_break_glass_key_id {
        if active_is_previous {
            read_verifying_key(&config.operator.break_glass_public_key)?
        } else {
            trusted_break_glass_key(config, &header.kid)?
        }
    } else {
        bail!("controller rotation intent signer is not active controller or break-glass identity")
    };
    let transition = verify_trust_transition(&intent.compact_transition, &header.kid, &key)?;
    if transition.deployment_id != config.operator.deployment_id
        || transition.previous_key_id != intent.previous_key_id
        || transition.next_key_id != next.controller_key_id
        || transition.previous_audit_key_id != intent.previous_audit_key_id
        || transition.next_audit_key_id != next.audit_key_id
        || transition.previous_break_glass_key_id != intent.previous_break_glass_key_id
        || transition.next_break_glass_key_id != next.break_glass_key_id
    {
        bail!("controller rotation intent transition does not bind the staged generation")
    }
    match transition.authorization {
        TransitionAuthorization::Controller if header.kid == intent.previous_key_id => Ok(()),
        TransitionAuthorization::BreakGlass if header.kid == intent.previous_break_glass_key_id => {
            Ok(())
        }
        _ => bail!("controller rotation intent authorization does not match its signer"),
    }
}

fn retire_non_active_private_material(
    layout: &IdentityLayout,
    active: &ActiveIdentity,
) -> anyhow::Result<()> {
    retire_generation_private_material(
        &layout.generations,
        Some(&active.generation),
        &["controller.key", "audit.key"],
    )?;
    retire_generation_private_material(
        &layout.recovery_generations,
        Some(&active.generation),
        &["break-glass.key"],
    )?;
    for legacy in [
        layout.operator_directory.join("controller.key"),
        layout.operator_directory.join("audit.key"),
        layout
            .recovery_generations
            .parent()
            .context("recovery generation directory has no parent")?
            .join("break-glass.key"),
    ] {
        if path_present(&legacy)? {
            remove_managed_regular_file(&legacy)?;
        }
    }
    Ok(())
}

fn generation_private_material_present(
    directory: &Path,
    active_generation: &str,
    private_names: &[&str],
) -> anyhow::Result<bool> {
    if !path_present(directory)? {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("identity generations path must be a regular non-symlink directory")
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("identity generation name is not UTF-8"))?;
        if !safe_identity_component(&name) || !entry.file_type()?.is_dir() {
            bail!("identity generations directory contains an unsafe entry")
        }
        if name == active_generation {
            continue;
        }
        for private_name in private_names {
            let path = entry.path().join(private_name);
            if managed_regular_file_present(&path)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn managed_regular_file_present(path: &Path) -> anyhow::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "managed identity path is not a regular non-symlink file: {}",
            path.display()
        )
    }
    Ok(true)
}

fn retire_generation_private_material(
    directory: &Path,
    active_generation: Option<&str>,
    private_names: &[&str],
) -> anyhow::Result<()> {
    if !path_present(directory)? {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("identity generations path must be a regular non-symlink directory")
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("identity generation name is not UTF-8"))?;
        if !safe_identity_component(&name) || !entry.file_type()?.is_dir() {
            bail!("identity generations directory contains an unsafe entry")
        }
        if active_generation == Some(name.as_str()) {
            continue;
        }
        for private_name in private_names {
            remove_managed_regular_file(&entry.path().join(private_name))?;
        }
    }
    Ok(())
}

fn remove_managed_regular_file(path: &Path) -> anyhow::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "managed identity path is not a regular non-symlink file: {}",
            path.display()
        )
    }
    crate::filesystem::remove_file_durable(path)
}

fn path_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn is_real_directory_or_missing(path: &Path, description: &str) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => bail!("{description} is not a real directory: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn is_regular_non_symlink(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn retirement_probe(config: &UpdateConfig, old_key: &SigningKey) -> anyhow::Result<String> {
    let now = Utc::now().timestamp();
    let task = TaskEnvelope {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: format!("controller:{}", config.operator.deployment_id),
        aud: format!("runtime:{}", config.operator.deployment_id),
        jti: format!("probe-{}", encode_hex(&rand::random::<[u8; 16]>())),
        iat: now,
        nbf: now,
        exp: now + nazo_operator_protocol::MAX_TASK_LIFETIME_SECONDS,
        deployment_id: config.operator.deployment_id.clone(),
        actor: Actor {
            kind: ActorKind::LocalRoot,
            id: "uid:0".to_owned(),
        },
        target: nazo_operator_protocol::TargetExpectation::HostBinary {
            path: "/nazoauth-retirement-probe".to_owned(),
            sha256: "0".repeat(64),
        },
        embedded: EmbeddedIdentity {
            release: "retirement-probe".to_owned(),
            revision: "retirement-probe".to_owned(),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "retirement-probe".to_owned(),
        },
        config: ConfigBinding {
            manifest_version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
            config_sha256: "0".repeat(64),
            secret_binding: SecretBinding::OpaqueRevision {
                revision: "retirement-probe".to_owned(),
            },
        },
        operation: TaskOperation::KeysValidate,
    };
    Ok(sign_task(
        &task,
        &config.operator.controller_key_id,
        old_key,
    )?)
}

pub(crate) fn verify_retired_controller_probe(
    config: &UpdateConfig,
    rotation: &RotationResult,
    release: &str,
    expected: &ExpectedReleaseTarget,
) -> anyhow::Result<()> {
    verify_retired_controller_probe_with(config, rotation, release, |probe| {
        let operation = TaskOperation::KeysValidate;
        let manifest = canonical_manifest(config, &operation)?;
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let runtime = Runtime::new(config);
        let target = if config.runtime.engine == "host" {
            config.runtime.binary_path.to_string_lossy().into_owned()
        } else {
            runtime.active_image()?
        };
        // This must create and execute the same constrained application task
        // used by public key validation.  A local verifier alone cannot
        // establish the runtime mount/context boundary.
        let prepared = runtime.prepare_app_task(&target, &operation, None, &manifest_bytes)?;
        verify_target_expectation(&prepared.target, expected)?;
        let embedded = runtime.embedded_identity(&target)?;
        if embedded != expected.embedded {
            bail!("runtime embedded build identity does not match the active signed Release")
        }
        prepared.expect_authorization_rejection(probe)?;
        runtime.verify_prepared_target(&prepared.target)?;
        Ok(RetirementProbeExecution {
            controller_verified_target: prepared.target.clone(),
            application_reported_embedded_identity: embedded,
        })
    })
}

fn verify_retired_controller_probe_with<F>(
    config: &UpdateConfig,
    rotation: &RotationResult,
    release: &str,
    runtime_rejection: F,
) -> anyhow::Result<()>
where
    F: FnOnce(&str) -> anyhow::Result<RetirementProbeExecution>,
{
    let Some(probe) = rotation.retirement_probe.as_deref() else {
        let evidence =
            encode_retirement_probe_audit_evidence(&RetirementProbeAuditEvidence::NotIssued {
                schema: 1,
                previous_controller_key_id: rotation.previous_controller_key_id.clone(),
                previous_controller_public_sha256: rotation
                    .previous_controller_public_sha256
                    .clone(),
                reason: "controller-private-unavailable".to_owned(),
            })?;
        append_management_event(config, "controller-retirement-probe", release, &evidence)?;
        println!(
            "retired controller probe not issued: previous={} previous_public_sha256={} release={} category=controller-private-unavailable",
            rotation.previous_controller_key_id,
            rotation.previous_controller_public_sha256,
            release
        );
        return Ok(());
    };
    let execution = runtime_rejection(probe)?;
    let probe_digest = compact_sha256(probe);
    let evidence = encode_retirement_probe_audit_evidence(
        &RetirementProbeAuditEvidence::RuntimeAuthorizationRejected {
            schema: 1,
            previous_controller_key_id: rotation.previous_controller_key_id.clone(),
            active_controller_key_id: config.operator.controller_key_id.clone(),
            probe_sha256: probe_digest,
            controller_verified_target: execution.controller_verified_target,
            application_reported_embedded_identity: execution
                .application_reported_embedded_identity,
        },
    )?;
    append_management_event(config, "controller-retirement-probe", release, &evidence)?;
    println!(
        "retired controller probe rejected: previous={} previous_public_sha256={} release={}",
        rotation.previous_controller_key_id, rotation.previous_controller_public_sha256, release
    );
    Ok(())
}

/// File-provider truthfulness boundary: this observes only the key available to
/// the current root process.  It cannot prove that an attacker did not copy it.
pub(crate) fn report_controller_availability(config: &UpdateConfig) -> anyhow::Result<bool> {
    let available = read_signing_key(&config.operator.controller_private_key)
        .ok()
        .is_some_and(|key| {
            read_verifying_key(&config.operator.controller_public_key)
                .is_ok_and(|public| key.verifying_key() == public)
        });
    println!(
        "controller-key-availability={}; provider=file; copied-key-status=not-provable",
        if available {
            "available"
        } else {
            "unavailable"
        }
    );
    Ok(available)
}

pub(crate) fn rotate_controller(
    config_path: &Path,
    config: &UpdateConfig,
    break_glass: bool,
    reason: &str,
) -> anyhow::Result<RotationResult> {
    rotate_controller_with_access(
        config_path,
        config,
        break_glass,
        reason,
        ControllerSigningAccess::Available,
    )
}

/// This is an actual recovery transition under a simulated unavailable file
/// provider.  The active controller private key is loaded only before the
/// guard is established, solely to construct the post-transition rejection
/// probe; the rotation itself cannot read it.
pub(crate) fn rehearse_controller_loss(
    config_path: &Path,
    config: &UpdateConfig,
) -> anyhow::Result<RotationResult> {
    let probe_key = read_signing_key(&config.operator.controller_private_key)?;
    rotate_controller_with_access(
        config_path,
        config,
        true,
        "simulated-unavailable",
        ControllerSigningAccess::ForbiddenForRehearsal(Box::new(probe_key)),
    )
}

pub(crate) fn recover_controller_without_controller_key(
    config_path: &Path,
    config: &UpdateConfig,
    reason: &str,
) -> anyhow::Result<RotationResult> {
    rotate_controller_with_access(
        config_path,
        config,
        true,
        reason,
        ControllerSigningAccess::Unavailable,
    )
}

fn rotate_controller_with_access(
    config_path: &Path,
    config: &UpdateConfig,
    break_glass: bool,
    reason: &str,
    controller_access: ControllerSigningAccess,
) -> anyhow::Result<RotationResult> {
    let layout = identity_layout(config)?;
    let current = read_active_identity(&layout.active_file)?;
    if break_glass {
        validate_generation_for_break_glass_recovery(&layout, &current)?;
    } else {
        validate_generation(&layout, &current)?;
    }
    let old_controller_public = read_verifying_key(&config.operator.controller_public_key)?;
    let old_controller_digest = encode_hex(&Sha256::digest(old_controller_public.to_bytes()));
    let probe = controller_access
        .controller_for_retirement_probe(&config.operator.controller_private_key)?
        .map(|key| retirement_probe(config, &key))
        .transpose()?;
    let new_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let new_audit_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let next_break_glass = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let next = new_active_identity(&new_key, &new_audit_key, &next_break_glass);
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
            controller_access
                .controller_for_normal_rotation(&config.operator.controller_private_key)?,
        )
    };
    let transition = ControllerTrustTransition {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        deployment_id: config.operator.deployment_id.clone(),
        issued_at: Utc::now().timestamp(),
        authorization,
        previous_key_id: config.operator.controller_key_id.clone(),
        next_key_id: next.controller_key_id.clone(),
        next_public_key_sha256: encode_hex(&Sha256::digest(new_key.verifying_key().to_bytes())),
        previous_audit_key_id: config.operator.audit_key_id.clone(),
        next_audit_key_id: next.audit_key_id.clone(),
        next_audit_public_key_sha256: encode_hex(&Sha256::digest(
            new_audit_key.verifying_key().to_bytes(),
        )),
        previous_break_glass_key_id: config.operator.break_glass_key_id.clone(),
        next_break_glass_key_id: next.break_glass_key_id.clone(),
        next_break_glass_public_key_sha256: encode_hex(&Sha256::digest(
            next_break_glass.verifying_key().to_bytes(),
        )),
        reason: reason.to_owned(),
    };
    let compact = sign_trust_transition(&transition, signer_id, &signer)?;
    let transitions = config.operator.audit_directory.join("trust-transitions");
    fs::create_dir_all(&transitions)?;
    let transition_file = format!(
        "{}-{}-to-{}.jws",
        Utc::now().format("%Y%m%dT%H%M%S%.6fZ"),
        config.operator.controller_key_id,
        next.controller_key_id
    );
    let transition_path = transitions.join(&transition_file);
    write_generation(&layout, &next, &new_key, &new_audit_key, &next_break_glass)?;
    archive_generation_publics(&layout, &current)?;
    archive_generation_publics(&layout, &next)?;
    atomic_write(
        &layout.operator_directory.join("rotation-intent.json"),
        &serde_json::to_vec_pretty(&RotationIntent {
            schema: 1,
            next_generation: next.generation.clone(),
            previous_key_id: config.operator.controller_key_id.clone(),
            next_key_id: next.controller_key_id.clone(),
            previous_audit_key_id: config.operator.audit_key_id.clone(),
            next_audit_key_id: next.audit_key_id.clone(),
            previous_break_glass_key_id: config.operator.break_glass_key_id.clone(),
            next_break_glass_key_id: next.break_glass_key_id.clone(),
            transition_file,
            compact_transition: compact.clone(),
        })?,
        0o600,
    )?;
    atomic_write(&transition_path, compact.as_bytes(), 0o400)?;
    let mut next_config = config.clone();
    write_active_identity(&layout, &next)?;
    apply_active_identity(&mut next_config, &layout, &next);
    atomic_write(
        config_path,
        &serde_json::to_vec_pretty(&next_config)?,
        0o600,
    )?;
    retire_non_active_private_material(&layout, &next)?;
    crate::filesystem::remove_file_durable(
        &layout.operator_directory.join("rotation-intent.json"),
    )?;
    println!(
        "controller/audit identity rotated: previous={} next={} previous_audit={} next_audit={} previous_break_glass={} next_break_glass={} authorization={authorization:?} transition={}",
        config.operator.controller_key_id,
        next.controller_key_id,
        config.operator.audit_key_id,
        next.audit_key_id,
        config.operator.break_glass_key_id,
        next.break_glass_key_id,
        transition_path.display()
    );
    Ok(RotationResult {
        previous_controller_key_id: current.controller_key_id,
        previous_controller_public_sha256: old_controller_digest,
        retirement_probe: probe,
    })
}

/// Inspect whether the identity state needs an explicitly authorized recovery.
/// This function is deliberately read-only: observation commands use it to fail
/// closed instead of completing a rotation, adopting legacy identity, or
/// retiring key material as a side effect of loading configuration.
pub(crate) fn identity_recovery_required(config: &UpdateConfig) -> anyhow::Result<bool> {
    let layout = identity_layout(config)?;
    if !path_present(&layout.active_file)? {
        return Ok(true);
    }
    let active = read_active_identity(&layout.active_file)?;
    validate_generation_for_break_glass_recovery(&layout, &active)?;

    let mut expected = config.clone();
    apply_active_identity(&mut expected, &layout, &active);
    if serde_json::to_vec(&expected)? != serde_json::to_vec(config)? {
        return Ok(true);
    }
    if path_present(&layout.operator_directory.join("legacy-adoption.json"))?
        || path_present(&layout.operator_directory.join("rotation-intent.json"))?
        || generation_private_material_present(
            &layout.generations,
            &active.generation,
            &["controller.key", "audit.key"],
        )?
        || generation_private_material_present(
            &layout.recovery_generations,
            &active.generation,
            &["break-glass.key"],
        )?
    {
        return Ok(true);
    }
    for legacy in [
        layout.operator_directory.join("controller.key"),
        layout.operator_directory.join("audit.key"),
        layout
            .recovery_generations
            .parent()
            .context("recovery generation directory has no parent")?
            .join("break-glass.key"),
    ] {
        if managed_regular_file_present(&legacy)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn recover_pending_rotation(
    config_path: &Path,
    config: &mut UpdateConfig,
) -> anyhow::Result<()> {
    let layout = identity_layout(config)?;
    if !path_present(&layout.active_file)? {
        adopt_legacy_identity(config_path, config, &layout)?;
    }
    let mut active = read_active_identity(&layout.active_file)?;
    validate_generation_for_break_glass_recovery(&layout, &active)?;
    let config_before_repair = serde_json::to_vec(config)?;
    apply_active_identity(config, &layout, &active);
    let adoption_path = layout.operator_directory.join("legacy-adoption.json");
    let adoption_pending = if path_present(&adoption_path)? {
        let adoption: LegacyAdoptionIntent = serde_json::from_slice(&fs::read(&adoption_path)?)?;
        if adoption.schema != 1
            || adoption.generation != active.generation
            || adoption.controller_key_id != active.controller_key_id
            || adoption.audit_key_id != active.audit_key_id
            || adoption.break_glass_key_id != active.break_glass_key_id
        {
            bail!("legacy identity adoption intent conflicts with the active generation")
        }
        true
    } else {
        false
    };
    let intent_path = layout.operator_directory.join("rotation-intent.json");
    if adoption_pending && path_present(&intent_path)? {
        bail!("legacy adoption and controller rotation cannot be pending together")
    }
    if path_present(&intent_path)? {
        let intent: RotationIntent = serde_json::from_slice(&fs::read(&intent_path)?)?;
        if intent.schema != 1
            || !safe_identity_component(&intent.next_generation)
            || intent.transition_file.is_empty()
            || intent.transition_file.starts_with('.')
            || intent.transition_file.contains(['/', '\\'])
        {
            bail!("controller rotation intent is invalid")
        }
        let next = ActiveIdentity {
            schema: 1,
            generation: intent.next_generation.clone(),
            controller_key_id: intent.next_key_id.clone(),
            audit_key_id: intent.next_audit_key_id.clone(),
            break_glass_key_id: intent.next_break_glass_key_id.clone(),
        };
        validate_generation(&layout, &next)?;
        verify_rotation_intent(config, &active, &next, &intent)?;
        archive_generation_publics(&layout, &active)?;
        archive_generation_publics(&layout, &next)?;
        let transition_path = config
            .operator
            .audit_directory
            .join("trust-transitions")
            .join(&intent.transition_file);
        if !path_present(&transition_path)? {
            fs::create_dir_all(
                transition_path
                    .parent()
                    .context("rotation transition path has no parent")?,
            )?;
            atomic_write(
                &transition_path,
                intent.compact_transition.as_bytes(),
                0o400,
            )?;
        }
        if active.generation != next.generation {
            write_active_identity(&layout, &next)?;
            active = next;
        }
        apply_active_identity(config, &layout, &active);
        atomic_write(config_path, &serde_json::to_vec_pretty(config)?, 0o600)?;
    }
    retire_non_active_private_material(&layout, &active)?;
    if serde_json::to_vec(config)? != config_before_repair {
        atomic_write(config_path, &serde_json::to_vec_pretty(config)?, 0o600)?;
    }
    if adoption_pending {
        crate::filesystem::remove_file_durable(&adoption_path)?;
    }
    if path_present(&intent_path)? {
        crate::filesystem::remove_file_durable(&intent_path)?;
    }
    Ok(())
}

fn trusted_controller_key(config: &UpdateConfig, key_id: &str) -> anyhow::Result<VerifyingKey> {
    if key_id == config.operator.controller_key_id {
        return read_verifying_key(&config.operator.controller_public_key);
    }
    let directory = identity_layout(config)?
        .operator_directory
        .join("trusted-controllers");
    read_verifying_key(&directory.join(format!("{key_id}.pub")))
}

fn trusted_audit_key(config: &UpdateConfig, key_id: &str) -> anyhow::Result<VerifyingKey> {
    if key_id == config.operator.audit_key_id {
        return read_verifying_key(&config.operator.audit_public_key);
    }
    let directory = identity_layout(config)?
        .operator_directory
        .join("trusted-audit");
    read_verifying_key(&directory.join(format!("{key_id}.pub")))
}

fn trusted_break_glass_key(config: &UpdateConfig, key_id: &str) -> anyhow::Result<VerifyingKey> {
    if key_id == config.operator.break_glass_key_id {
        return read_verifying_key(&config.operator.break_glass_public_key);
    }
    let directory = identity_layout(config)?
        .operator_directory
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
