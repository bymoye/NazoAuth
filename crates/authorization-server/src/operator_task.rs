//! Privileged task entry point. It accepts only a signed, non-secret envelope on stdin.

use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nazo_operator_protocol::{
    EmbeddedIdentity, RuntimeReceipt, SecretBinding, TaskEnvelope, TaskOperation, TaskOutcome,
    TaskResult, compact_sha256, sign_runtime_receipt, verify_task_signature, verify_task_window,
};
use sha2::{Digest as _, Sha256};

const CONTEXT_PATH: &str = "/run/nazoauth-operator/context.json";
const CONTROLLER_PUBLIC_KEY_PATH: &str = "/run/nazoauth-operator/controller.pub";
const RECEIPT_PRIVATE_KEY_PATH: &str = "/run/nazoauth-operator/receipt.key";
const EXTERNAL_PUBLIC_JWK_PATH: &str = "/run/nazoauth-operator/public.jwk";
const STATE_DIRECTORY: &str = "/var/lib/nazoauth/operator-state";
const CONFIG_MANIFEST_PATH: &str = "/run/nazoauth-operator/config-manifest.json";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskContext {
    controller_key_id: String,
    receipt_key_id: String,
}

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
    let task = verify_task_signature(compact, &context.controller_key_id, &controller_key)
        .context("operator task authorization failed")?;
    validate_embedded_identity(&task)?;
    validate_config_manifest(&task)?;
    let state = configured_path("NAZOAUTH_OPERATOR_STATE_DIRECTORY", STATE_DIRECTORY);
    fs::create_dir_all(&state)?;
    let lock_path = state.join("task.lock");
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)?;
    lock.lock()?;

    let request_sha256 = compact_sha256(compact);
    let request_path = state.join(format!("{}.request.sha256", task.jti));
    claim_request(&request_path, &request_sha256)?;
    let receipt_path = state.join(format!("{}.receipt.jws", task.jti));
    if receipt_path.is_file() {
        let prior = fs::read_to_string(receipt_path)?;
        print!("{prior}");
        return Ok(());
    }
    verify_task_window(&task, Utc::now().timestamp())
        .context("operator task authorization failed")?;

    let started_at = Utc::now().timestamp();
    let outcome = execute(&task.operation).await;
    let completed_at = Utc::now().timestamp();
    let receipt = RuntimeReceipt {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: format!("runtime:{}", task.deployment_id),
        aud: task.iss.clone(),
        jti: task.jti.clone(),
        request_sha256,
        deployment_id: task.deployment_id.clone(),
        actor: task.actor.clone(),
        operation: operation_name(&task.operation).to_owned(),
        started_at,
        completed_at,
        embedded: embedded_identity(),
        config: task.config.clone(),
        outcome,
    };
    let receipt_key = read_signing_key(&configured_path(
        "NAZOAUTH_OPERATOR_RECEIPT_PRIVATE_KEY_FILE",
        RECEIPT_PRIVATE_KEY_PATH,
    ))?;
    let compact_receipt = sign_runtime_receipt(&receipt, &context.receipt_key_id, &receipt_key)?;
    write_receipt_atomic(&receipt_path, compact_receipt.as_bytes())?;
    print!("{compact_receipt}");
    Ok(())
}

async fn execute(operation: &TaskOperation) -> TaskOutcome {
    let result = match operation {
        TaskOperation::MigrateApply => crate::cli::run_migrations()
            .await
            .map(|()| TaskResult::Migration { applied: true }),
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
    let path = configured_path(
        "NAZOAUTH_OPERATOR_CONFIG_MANIFEST_FILE",
        CONFIG_MANIFEST_PATH,
    );
    let bytes = fs::read(path).context("canonical config manifest is unavailable")?;
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
    let server_config = configured_path("NAZOAUTH_SERVER_CONFIG_FILE", "/app/.env.yaml");
    let actual: String = Sha256::digest(fs::read(server_config)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if manifest.entries.get("server_config_sha256") != Some(&actual) {
        bail!("server configuration digest mismatch");
    }
    Ok(())
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

fn embedded_identity() -> EmbeddedIdentity {
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

fn claim_request(path: &Path, digest: &str) -> anyhow::Result<()> {
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
    file.write_all(digest.as_bytes())?;
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
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if fs::read_to_string(path)?.trim() == digest {
                Ok(())
            } else {
                bail!("request identifier was already claimed by a different envelope")
            }
        }
        Err(error) => Err(error.into()),
    }
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
    let temporary = path.with_extension("receipt.jws.tmp");
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn verify_public_jwk(expected_sha256: &str) -> anyhow::Result<PathBuf> {
    let path = configured_path(
        "NAZOAUTH_OPERATOR_PUBLIC_JWK_FILE",
        EXTERNAL_PUBLIC_JWK_PATH,
    );
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

#[cfg(test)]
#[path = "../tests/unit/operator_task.rs"]
mod tests;
