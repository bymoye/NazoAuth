use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{IsTerminal as _, Read as _, Write as _},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use nazo_operator_protocol::TaskOperation;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    backup::Backup,
    cli::{
        BootstrapAdminOptions, Cli, Command, ConformanceLeaseCommand, KeysCommand, UpdateOptions,
    },
    filesystem::{atomic_write, copy_atomic, remove_file_durable, set_mode, symlink_atomic},
    install::{self, PreparedInstall},
    model::{ReleaseManifest, UpdateConfig},
    operator::{self, ExpectedReleaseTarget},
    process::Process,
    release::{VerifiedRelease, commit_release_trust, compare_versions, enforce_release_trust},
    runtime::Runtime,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RollbackState {
    schema: u32,
    from_release: ReleaseManifest,
    to_release: ReleaseManifest,
    previous_runtime: String,
    previous_ui: Option<PathBuf>,
    backup: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum UpdatePhase {
    Prepared,
    WriterStopping,
    WriterStopped,
    BackupCreating,
    BackupCreated,
    MigrationRunning,
    MigrationApplied,
    CandidateActivating,
    CandidateActive,
    UiActivating,
    UiActive,
    HealthChecking,
    HealthVerified,
    StateCommitting,
    StateCommitted,
    TrustCommitting,
    TrustCommitted,
    AuditCommitting,
    AuditCommitted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UpdateJournal {
    schema: u32,
    transaction_id: String,
    started_at: String,
    phase: UpdatePhase,
    from_release: ReleaseManifest,
    to_release: ReleaseManifest,
    previous_runtime: String,
    previous_ui: Option<PathBuf>,
    candidate_runtime: String,
    candidate_ui: PathBuf,
    staged_updater: PathBuf,
    backup: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdateRecoveryAction {
    RestorePrevious,
    ContinueForward,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallCompletion {
    schema: u32,
    version: String,
    backend_commit: String,
    management_event_file: String,
    management_event_sha256: String,
}

const BOOTSTRAP_MOUNT_TARGET: &str = "/var/lib/nazo_oauth/bootstrap";
const BOOTSTRAP_TOKEN_FILE: &str = "initial-admin-token";
const MAX_BOOTSTRAP_CREDENTIAL_BYTES: u64 = 8 * 1024;
const MAX_BOOTSTRAP_TOKEN_BYTES: u64 = 2 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapAdminCredentials {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct BootstrapAdminRequest<'a> {
    request_id: &'a str,
    token: &'a str,
    email: &'a str,
    password: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapAdminResponse {
    request_id: String,
    id: String,
    email: String,
    role: String,
    next: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum BootstrapAdminPendingStatus {
    Intent,
    Succeeded,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapAdminPending {
    schema: u32,
    request_id: String,
    email_hmac_sha256: String,
    recovery_epoch: String,
    status: BootstrapAdminPendingStatus,
    claimed_user_id: Option<String>,
    token_hmac_sha256: Option<String>,
}

#[derive(Debug)]
struct VerifiedBootstrapReceipt {
    claimed_user_id: uuid::Uuid,
    token_hmac_sha256: String,
}

#[derive(Debug)]
struct BootstrapOutcomeUnknown;

impl std::fmt::Display for BootstrapOutcomeUnknown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("initial administrator request outcome is unknown")
    }
}

impl std::error::Error for BootstrapOutcomeUnknown {}

fn conformance_operation(command: ConformanceLeaseCommand) -> anyhow::Result<TaskOperation> {
    Ok(match command {
        ConformanceLeaseCommand::Create {
            profile,
            material,
            ttl_seconds,
            yes,
        } => {
            require_confirmation(yes, "create a temporary conformance lease")?;
            let material_sha256 = crate::filesystem::sha256(&material)?;
            let public_material = if profile == "openid4vc" {
                let metadata = fs::symlink_metadata(&material)
                    .context("failed to inspect OpenID4VC conformance material")?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.len() == 0
                    || metadata.len() > 32 * 1024
                {
                    bail!(
                        "OpenID4VC conformance material must be a regular file from 1 through 32768 bytes"
                    );
                }
                Some(
                    serde_json::from_slice::<nazo_operator_protocol::Openid4vcConformanceTrust>(
                        &fs::read(&material)?,
                    )
                    .context("OpenID4VC conformance material must be strict JSON")?,
                )
            } else {
                None
            };
            TaskOperation::ConformanceLeaseCreate {
                profile,
                material_sha256,
                public_material,
                ttl_seconds,
            }
        }
        ConformanceLeaseCommand::List => TaskOperation::ConformanceLeaseList,
        ConformanceLeaseCommand::Revoke { lease_id, yes } => {
            require_confirmation(
                yes,
                "revoke the conformance lease and deactivate its clients",
            )?;
            TaskOperation::ConformanceLeaseRevoke { lease_id }
        }
        ConformanceLeaseCommand::Cleanup { yes } => {
            require_confirmation(yes, "delete revoked and expired conformance clients")?;
            TaskOperation::ConformanceLeaseCleanup
        }
    })
}

pub(crate) fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Install(options) => install(cli.config, *options),
        Command::Status => {
            let config = load_config(&cli.config)?;
            status(&config)
        }
        Command::Doctor => {
            let config = load_config(&cli.config)?;
            doctor(&config)
        }
        Command::BootstrapAdmin(options) => {
            require_root()?;
            let config = load_config(&cli.config)?;
            require_confirmation(options.yes, "create the first NazoAuth administrator")?;
            bootstrap_admin(&config, options)
        }
        Command::Check(version) => {
            let config = load_config(&cli.config)?;
            update(
                &cli.config,
                &config,
                UpdateOptions {
                    version,
                    plan: true,
                    yes: false,
                    accept_migration_barrier: false,
                },
            )
        }
        Command::Update(options) => {
            require_root()?;
            let config = load_config(&cli.config)?;
            update(&cli.config, &config, options)
        }
        Command::Rollback { yes } => {
            require_root()?;
            let config = load_config(&cli.config)?;
            require_confirmation(
                yes,
                "rollback the application artifact without restoring the database",
            )?;
            public_rollback(&config)
        }
        Command::Recover { yes } => {
            require_root()?;
            let config = load_config(&cli.config)?;
            require_confirmation(
                yes,
                "restore the declared database backup and previous application artifact",
            )?;
            recover_from_backup(&config)
        }
        Command::RecoverUpdate { yes } => {
            require_root()?;
            let config = load_config_unsettled(&cli.config)?;
            if crate::operator::identity_recovery_required(&config)? {
                bail!("identity recovery is pending; run nazoauthctl recover-identity --yes first");
            }
            let journal = load_update_journal(&config)?
                .context("no interrupted update transaction requires recovery")?;
            require_confirmation(
                yes,
                &format!(
                    "recover update transaction {} from phase {:?}",
                    journal.transaction_id, journal.phase
                ),
            )?;
            recover_pending_update(&cli.config, &config)?;
            load_config(&cli.config).map(|_| ())
        }
        Command::RecoverIdentity { yes } => {
            require_root()?;
            let mut config = load_config_unsettled(&cli.config)?;
            ensure_no_pending_update(&config)?;
            if !crate::operator::identity_recovery_required(&config)? {
                bail!("no interrupted identity transition requires recovery");
            }
            require_confirmation(yes, "recover the interrupted identity transition")?;
            crate::operator::recover_pending_rotation(&cli.config, &mut config)?;
            load_config(&cli.config).map(|_| ())
        }
        Command::Migrate { yes } => {
            require_root()?;
            let config = load_config(&cli.config)?;
            require_confirmation(yes, "apply pending database migrations")?;
            app_command(&config, TaskOperation::MigrateApply, None)
        }
        Command::Keys(command) => {
            require_root()?;
            let config = load_config(&cli.config)?;
            let (operation, public_jwk) = match command {
                KeysCommand::List => (TaskOperation::KeysList, None),
                KeysCommand::Validate => (TaskOperation::KeysValidate, None),
                KeysCommand::ExportOpenid4vcTrust { output } => {
                    return export_openid4vc_trust(&config, &output);
                }
                KeysCommand::GenerateLocal { alg, purposes, yes } => {
                    require_confirmation(yes, "mutate the application signing keyset")?;
                    (TaskOperation::KeysGenerateLocal { alg, purposes }, None)
                }
                KeysCommand::RegisterExternal {
                    kid,
                    alg,
                    key_ref,
                    public_jwk,
                    yes,
                } => {
                    require_confirmation(yes, "mutate the application signing keyset")?;
                    let public_jwk_sha256 = crate::filesystem::sha256(&public_jwk)?;
                    (
                        TaskOperation::KeysRegisterExternal {
                            kid,
                            alg,
                            key_ref,
                            public_jwk_sha256,
                        },
                        Some(public_jwk),
                    )
                }
            };
            app_command(&config, operation, public_jwk.as_deref())
        }
        Command::Conformance(command) => {
            require_root()?;
            let config = load_config(&cli.config)?;
            let operation = conformance_operation(command)?;
            app_command(&config, operation, None)
        }
        Command::AuditVerify => {
            let config = load_config(&cli.config)?;
            crate::operator::verify_audit(&config)
        }
        Command::AuditShow { request_id } => {
            let config = load_config(&cli.config)?;
            crate::operator::show_audit(&config, request_id.as_deref())
        }
        Command::IdentityRotate { yes } => {
            require_root()?;
            let config = load_config(&cli.config)?;
            require_confirmation(yes, "rotate the controller identity")?;
            let rotation =
                crate::operator::rotate_controller(&cli.config, &config, false, "normal")?;
            let current = load_config(&cli.config)?;
            let release = load_active_release(&current)?;
            let expected = expected_target(&current, &release)?;
            crate::operator::verify_retired_controller_probe(
                &current,
                &rotation,
                &release.version,
                &expected,
            )
        }
        Command::BreakGlassControllerAvailability => {
            require_root()?;
            let config = load_config(&cli.config)?;
            crate::operator::report_controller_availability(&config).map(|_| ())
        }
        Command::BreakGlassRehearseControllerLoss { yes } => {
            require_root()?;
            let config = load_config(&cli.config)?;
            require_confirmation(
                yes,
                "rehearse controller-key loss with a simulated unavailable file provider",
            )?;
            let rotation = crate::operator::rehearse_controller_loss(&cli.config, &config)?;
            let current = load_config(&cli.config)?;
            let release = load_active_release(&current)?;
            crate::operator::append_management_event(
                &current,
                "break-glass-controller-loss-rehearsal",
                &release.version,
                "simulated-unavailable:file-provider-only:copied-key-status-not-provable",
            )?;
            let expected = expected_target(&current, &release)?;
            crate::operator::verify_retired_controller_probe(
                &current,
                &rotation,
                &release.version,
                &expected,
            )
        }
        Command::BreakGlassRecover { yes, reason } => {
            require_root()?;
            let config = load_config(&cli.config)?;
            require_confirmation(yes, "perform break-glass controller recovery")?;
            let rotation = crate::operator::recover_controller_without_controller_key(
                &cli.config,
                &config,
                &reason,
            )?;
            let current = load_config(&cli.config)?;
            let release = load_active_release(&current)?;
            if reason == "lost" {
                crate::operator::append_management_event(
                    &current,
                    "break-glass-loss-assumption",
                    &release.version,
                    "file-provider-unavailability-not-proven",
                )?;
            } else {
                crate::operator::append_management_event(
                    &current,
                    "break-glass-stolen-assumption",
                    &release.version,
                    "copied-key-risk-assumed:file-provider-cannot-prove-non-copy",
                )?;
            }
            let expected = expected_target(&current, &release)?;
            crate::operator::verify_retired_controller_probe(
                &current,
                &rotation,
                &release.version,
                &expected,
            )
        }
    }
}

const OPENID4VC_CERTIFICATE_BUNDLE: &str = "openid4vc-certificate-bundle.pem";
const OPENID4VC_KEYS_MOUNT: &str = "/var/lib/nazo_oauth/keys";
const MAX_OPENID4VC_CERTIFICATE_BUNDLE_BYTES: usize = 1024 * 1024;

fn export_openid4vc_trust(config: &UpdateConfig, output: &Path) -> anyhow::Result<()> {
    if config.install_profile != "standards-full" {
        bail!("OpenID4VC trust export requires a standards-full managed installation");
    }
    safe_export_destination(output)?;
    let bundle = managed_openid4vc_bundle_path(config)?;
    let metadata = fs::symlink_metadata(&bundle).with_context(|| {
        format!(
            "failed to inspect managed OpenID4VC bundle {}",
            bundle.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("managed OpenID4VC certificate bundle must be a regular non-symlink file");
    }
    let anchors = extract_openid4vc_trust_anchors(&fs::read(&bundle)?)?;
    let release = load_active_release(config)?;
    crate::operator::append_management_event(
        config,
        "keys-export-openid4vc-trust-intent",
        &release.version,
        "public-ca-trust-anchor-export-requested",
    )?;
    atomic_write(output, &anchors, 0o644)?;
    crate::operator::append_management_event(
        config,
        "keys-export-openid4vc-trust-completed",
        &release.version,
        "public-ca-trust-anchor-export-completed",
    )?;
    println!("OpenID4VC trust anchors exported to {}", output.display());
    Ok(())
}

fn managed_openid4vc_bundle_path(config: &UpdateConfig) -> anyhow::Result<PathBuf> {
    let key_directories = if config.runtime.engine == "host" {
        config
            .runtime
            .snapshot_paths
            .iter()
            .filter(|path| path.file_name().is_some_and(|name| name == "keys"))
            .collect::<Vec<_>>()
    } else {
        config
            .runtime
            .mounts
            .iter()
            .filter(|mount| {
                mount.target == Path::new(OPENID4VC_KEYS_MOUNT)
                    && mount.mode.starts_with("rw")
                    && mount.source.file_name().is_some_and(|name| name == "keys")
            })
            .map(|mount| &mount.source)
            .collect::<Vec<_>>()
    };
    if key_directories.len() != 1 {
        bail!("managed installation must expose exactly one writable OpenID4VC key directory");
    }
    let keys = key_directories[0];
    crate::model::safe_absolute(keys)?;
    let metadata = fs::symlink_metadata(keys)
        .with_context(|| format!("failed to inspect managed key directory {}", keys.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("managed OpenID4VC key directory must be a real directory");
    }
    Ok(keys.join(OPENID4VC_CERTIFICATE_BUNDLE))
}

fn safe_export_destination(output: &Path) -> anyhow::Result<()> {
    crate::model::safe_absolute(output)?;
    let parent = output
        .parent()
        .context("OpenID4VC trust export output has no parent directory")?;
    let parent_metadata = fs::symlink_metadata(parent).with_context(|| {
        format!(
            "OpenID4VC trust export parent does not exist: {}",
            parent.display()
        )
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("OpenID4VC trust export parent must be a real directory");
    }
    if fs::canonicalize(parent)?.as_path() != parent {
        bail!("OpenID4VC trust export parent must not traverse a symlink");
    }
    match fs::symlink_metadata(output) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("OpenID4VC trust export output must be a regular non-symlink file when it exists")
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect trust export output {}", output.display())),
    }
}

fn extract_openid4vc_trust_anchors(bundle: &[u8]) -> anyhow::Result<Vec<u8>> {
    if bundle.len() > MAX_OPENID4VC_CERTIFICATE_BUNDLE_BYTES {
        bail!("managed OpenID4VC certificate bundle exceeds 1 MiB");
    }
    let mut remaining = trim_ascii_whitespace(bundle);
    let mut certificate_count = 0;
    let mut ca_count = 0;
    let mut leaf_count = 0;
    let mut output = Vec::new();
    while !remaining.is_empty() {
        if !remaining.starts_with(b"-----BEGIN CERTIFICATE-----") {
            bail!("managed OpenID4VC certificate bundle contains a non-certificate block");
        }
        let (rest, pem) = x509_parser::pem::parse_x509_pem(remaining).map_err(|_| {
            anyhow::anyhow!("managed OpenID4VC certificate bundle is not valid PEM")
        })?;
        if pem.label != "CERTIFICATE" {
            bail!("managed OpenID4VC certificate bundle contains a non-certificate block");
        }
        let (der_remaining, certificate) = x509_parser::parse_x509_certificate(&pem.contents)
            .map_err(|_| {
                anyhow::anyhow!("managed OpenID4VC certificate bundle contains invalid X.509 data")
            })?;
        if !der_remaining.is_empty() {
            bail!("managed OpenID4VC certificate bundle contains trailing X.509 data");
        }
        certificate_count += 1;
        let is_ca = certificate.is_ca();
        if (certificate_count == 1 && is_ca) || (certificate_count == 2 && !is_ca) {
            bail!("managed OpenID4VC certificate bundle must order leaf before CA trust anchor");
        }
        if is_ca {
            ca_count += 1;
            append_pem_certificate(&mut output, &pem.contents);
        } else {
            leaf_count += 1;
        }
        remaining = trim_ascii_whitespace(rest);
    }
    if certificate_count != 2 || ca_count != 1 || leaf_count != 1 {
        bail!(
            "managed OpenID4VC certificate bundle must contain exactly one leaf certificate and one CA trust anchor"
        );
    }
    Ok(output)
}

fn append_pem_certificate(output: &mut Vec<u8>, der: &[u8]) {
    output.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
    let encoded = STANDARD.encode(der);
    for line in encoded.as_bytes().chunks(64) {
        output.extend_from_slice(line);
        output.push(b'\n');
    }
    output.extend_from_slice(b"-----END CERTIFICATE-----\n");
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while let Some((first, rest)) = value.split_first() {
        if !first.is_ascii_whitespace() {
            break;
        }
        value = rest;
    }
    value
}

fn bootstrap_admin(config: &UpdateConfig, options: BootstrapAdminOptions) -> anyhow::Result<()> {
    let credentials = read_bootstrap_admin_credentials(options.credentials_stdin)?;
    let request_id = audited_bootstrap_admin(
        config,
        &credentials,
        std::ffi::OsStr::new("curl"),
        Some(bootstrap_state_owner_uid(config)?),
    )?;
    println!(
        "Initial administrator created (request ID: {request_id}). Continue at {}/ui/auth",
        config.runtime.expected_issuer.trim_end_matches('/'),
    );
    Ok(())
}

fn audited_bootstrap_admin(
    config: &UpdateConfig,
    credentials: &BootstrapAdminCredentials,
    curl_program: &std::ffi::OsStr,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<String> {
    let normalized_email = normalize_bootstrap_admin_email(&credentials.email)?;
    let mut pending = load_or_create_bootstrap_pending(config, &normalized_email)?;
    let request_id = pending.request_id.clone();
    let release = load_active_release(config)?.version;
    let intent_id = format!("{request_id}-intent");
    crate::operator::append_management_event_idempotent(
        config,
        &intent_id,
        "bootstrap-admin-intent",
        &release,
        "single-use-database-claim",
    )?;
    if pending.status == BootstrapAdminPendingStatus::Succeeded {
        crate::operator::append_management_event_idempotent(
            config,
            &format!("{request_id}-succeeded"),
            "bootstrap-admin-succeeded",
            &release,
            "single-use-database-claim",
        )?;
        let token_path = bootstrap_token_path(config, expected_owner_uid)?;
        if token_path.exists() {
            let token = read_bootstrap_token(&token_path, expected_owner_uid)?;
            let expected_token_hmac = pending
                .token_hmac_sha256
                .as_deref()
                .context("bootstrap-admin success state has no token binding")?;
            if bootstrap_state_hmac(config, b"token-v1", token.as_bytes())? != expected_token_hmac {
                bail!(
                    "bootstrap token changed after the recorded success; a database recovery may have reopened initial administration"
                );
            }
            let receipt = claim_bootstrap_admin(
                config,
                credentials,
                &request_id,
                curl_program,
                expected_owner_uid,
            )?;
            let expected_user_id = pending
                .claimed_user_id
                .as_deref()
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
                .context("bootstrap-admin success state has no valid application receipt")?;
            if receipt.claimed_user_id != expected_user_id
                || receipt.token_hmac_sha256 != expected_token_hmac
            {
                bail!("bootstrap application receipt changed after the recorded success");
            }
            remove_file_durable(&token_path)?;
        }
        return Ok(request_id);
    }
    match claim_bootstrap_admin(
        config,
        credentials,
        &request_id,
        curl_program,
        expected_owner_uid,
    ) {
        Ok(receipt) => {
            crate::operator::append_management_event_idempotent(
                config,
                &format!("{request_id}-succeeded"),
                "bootstrap-admin-succeeded",
                &release,
                "single-use-database-claim",
            )
            .with_context(|| {
                format!(
                    "initial administrator was created but audit finalization failed for request ID {request_id}"
                )
            })?;
            pending.status = BootstrapAdminPendingStatus::Succeeded;
            pending.claimed_user_id = Some(receipt.claimed_user_id.to_string());
            pending.token_hmac_sha256 = Some(receipt.token_hmac_sha256);
            atomic_write(
                &bootstrap_pending_path(config),
                &serde_json::to_vec_pretty(&pending)?,
                0o600,
            )?;
            let token_path = bootstrap_token_path(config, expected_owner_uid)?;
            remove_file_durable(&token_path)
                .context("initial administrator was created but token cleanup failed")?;
            Ok(request_id)
        }
        Err(error) => {
            let outcome_unknown = error.is::<BootstrapOutcomeUnknown>();
            let (suffix, operation) = if outcome_unknown {
                ("outcome-unknown", "bootstrap-admin-outcome-unknown")
            } else {
                ("failed", "bootstrap-admin-failed")
            };
            crate::operator::append_management_event_idempotent(
                config,
                &format!("{request_id}-{suffix}"),
                operation,
                &release,
                "single-use-database-claim",
            )
            .with_context(|| {
                format!(
                    "bootstrap-admin failed and its audit outcome could not be recorded for request ID {request_id}; original error: {error:#}"
                )
            })?;
            Err(error).with_context(|| format!("bootstrap-admin request ID {request_id} failed"))
        }
    }
}

fn claim_bootstrap_admin(
    config: &UpdateConfig,
    credentials: &BootstrapAdminCredentials,
    request_id: &str,
    curl_program: &std::ffi::OsStr,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<VerifiedBootstrapReceipt> {
    let normalized_email = normalize_bootstrap_admin_email(&credentials.email)?;
    if !(12..=1024).contains(&credentials.password.chars().count()) {
        bail!("administrator password must contain between 12 and 1024 characters");
    }

    let token_path = bootstrap_token_path(config, expected_owner_uid)?;
    let token = read_bootstrap_token(&token_path, expected_owner_uid)?;
    let token_hmac_sha256 = bootstrap_state_hmac(config, b"token-v1", token.as_bytes())?;
    let endpoint = bootstrap_admin_endpoint(&config.runtime.expected_issuer)?;
    let request = serde_json::to_vec(&BootstrapAdminRequest {
        request_id,
        token: &token,
        email: &normalized_email,
        password: &credentials.password,
    })?;
    let protocol = if endpoint.scheme() == "https" {
        "=https"
    } else {
        "=http"
    };
    let submission = (|| -> anyhow::Result<uuid::Uuid> {
        let output = Process::new(curl_program)
            .args([
                "--silent",
                "--show-error",
                "--fail-with-body",
                "--proto",
                protocol,
                "--connect-timeout",
                "10",
                "--max-time",
                "30",
                "--request",
                "POST",
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
                "--write-out",
                "\n%{http_code}",
            ])
            .arg(endpoint.as_str())
            .stdin_stdout(&request)
            .context("initial administrator request failed")?;
        let (body, status) = output
            .rsplit_once('\n')
            .context("initial administrator response omitted its HTTP status")?;
        if status.trim() != "201" {
            bail!("initial administrator endpoint returned an unexpected HTTP status");
        }
        let response: BootstrapAdminResponse = serde_json::from_str(body)
            .context("initial administrator endpoint returned an invalid response")?;
        let claimed_user_id = uuid::Uuid::parse_str(&response.id)
            .context("initial administrator response has an invalid user ID")?;
        if response.request_id != request_id
            || response.email != normalized_email
            || response.role != "admin"
            || response.next != "/ui/auth"
        {
            bail!("initial administrator endpoint returned an unexpected response contract");
        }
        Ok(claimed_user_id)
    })();
    let claimed_user_id = submission
        .map_err(|error| anyhow::Error::new(BootstrapOutcomeUnknown).context(error.to_string()))?;
    Ok(VerifiedBootstrapReceipt {
        claimed_user_id,
        token_hmac_sha256,
    })
}

fn bootstrap_pending_path(config: &UpdateConfig) -> PathBuf {
    config
        .operator
        .state_directory
        .join("bootstrap-admin-pending.json")
}

fn bootstrap_recovery_epoch_path(config: &UpdateConfig) -> PathBuf {
    config
        .operator
        .state_directory
        .join("bootstrap-recovery-epoch")
}

fn load_or_create_bootstrap_pending(
    config: &UpdateConfig,
    normalized_email: &str,
) -> anyhow::Result<BootstrapAdminPending> {
    let path = bootstrap_pending_path(config);
    let email_hmac_sha256 = bootstrap_email_hmac(config, normalized_email)?;
    let recovery_epoch = current_bootstrap_recovery_epoch(config)?;
    if path.exists() {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("bootstrap-admin pending state is not a regular file");
        }
        let pending: BootstrapAdminPending = serde_json::from_slice(&fs::read(&path)?)
            .context("bootstrap-admin pending state is invalid")?;
        if pending.schema != 2 || !valid_bootstrap_request_id(&pending.request_id) {
            bail!("bootstrap-admin pending state does not match this request");
        }
        if pending.recovery_epoch == recovery_epoch {
            if pending.email_hmac_sha256 != email_hmac_sha256 {
                bail!("bootstrap-admin pending state does not match this request");
            }
            let receipt_is_valid = match pending.status {
                BootstrapAdminPendingStatus::Intent => {
                    pending.claimed_user_id.is_none() && pending.token_hmac_sha256.is_none()
                }
                BootstrapAdminPendingStatus::Succeeded => {
                    pending
                        .claimed_user_id
                        .as_deref()
                        .is_some_and(|value| uuid::Uuid::parse_str(value).is_ok())
                        && pending
                            .token_hmac_sha256
                            .as_deref()
                            .is_some_and(valid_lower_hex_sha256)
                }
            };
            if !receipt_is_valid {
                bail!("bootstrap-admin pending state has an invalid application receipt");
            }
            return Ok(pending);
        }
    }
    fs::create_dir_all(&config.operator.state_directory)?;
    let pending = BootstrapAdminPending {
        schema: 2,
        request_id: format!("bootstrap-admin-{:032x}", rand::random::<u128>()),
        email_hmac_sha256,
        recovery_epoch,
        status: BootstrapAdminPendingStatus::Intent,
        claimed_user_id: None,
        token_hmac_sha256: None,
    };
    atomic_write(&path, &serde_json::to_vec_pretty(&pending)?, 0o600)?;
    Ok(pending)
}

fn bootstrap_email_hmac(config: &UpdateConfig, email: &str) -> anyhow::Result<String> {
    bootstrap_state_hmac(config, b"email-v2", email.as_bytes())
}

fn bootstrap_state_hmac(
    config: &UpdateConfig,
    domain: &[u8],
    value: &[u8],
) -> anyhow::Result<String> {
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::Sha256;

    let key = fs::read(&config.operator.secret_revision_file)
        .context("failed to read deployment secret revision for bootstrap binding")?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(&key)
        .context("deployment secret revision cannot bind bootstrap state")?;
    hmac.update(b"nazoauthctl-bootstrap-admin-v2\0");
    hmac.update(domain);
    hmac.update(b"\0");
    hmac.update(value);
    let bytes = hmac.finalize().into_bytes();
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(encoded)
}

fn valid_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_bootstrap_recovery_epoch(value: &str) -> bool {
    value.len() == 41
        && value.strip_prefix("recovery-").is_some_and(|suffix| {
            suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

fn current_bootstrap_recovery_epoch(config: &UpdateConfig) -> anyhow::Result<String> {
    let path = bootstrap_recovery_epoch_path(config);
    if path.exists() {
        let value = fs::read_to_string(&path)?;
        if !valid_bootstrap_recovery_epoch(&value) {
            bail!("bootstrap recovery epoch is invalid");
        }
        return Ok(value);
    }
    fs::create_dir_all(&config.operator.state_directory)?;
    let value = format!("recovery-{:032x}", rand::random::<u128>());
    atomic_write(&path, value.as_bytes(), 0o400)?;
    Ok(value)
}

fn rotate_bootstrap_recovery_epoch(config: &UpdateConfig) -> anyhow::Result<String> {
    fs::create_dir_all(&config.operator.state_directory)?;
    let value = format!("recovery-{:032x}", rand::random::<u128>());
    atomic_write(
        &bootstrap_recovery_epoch_path(config),
        value.as_bytes(),
        0o400,
    )?;
    Ok(value)
}

fn valid_bootstrap_request_id(request_id: &str) -> bool {
    request_id.len() == 48
        && request_id
            .strip_prefix("bootstrap-admin-")
            .is_some_and(|suffix| {
                suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
}

fn read_bootstrap_admin_credentials(from_stdin: bool) -> anyhow::Result<BootstrapAdminCredentials> {
    if from_stdin {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(MAX_BOOTSTRAP_CREDENTIAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("failed to read administrator credentials from stdin")?;
        return parse_bootstrap_admin_credentials(&bytes);
    }
    if !std::io::stdin().is_terminal() {
        bail!("interactive bootstrap requires a terminal or --credentials-stdin");
    }
    eprint!("Administrator email: ");
    std::io::stderr().flush()?;
    let mut email = String::new();
    std::io::stdin()
        .read_line(&mut email)
        .context("failed to read administrator email")?;
    let password = rpassword::prompt_password("Administrator password: ")
        .context("failed to read administrator password")?;
    validate_bootstrap_admin_credentials(BootstrapAdminCredentials { email, password })
}

fn parse_bootstrap_admin_credentials(bytes: &[u8]) -> anyhow::Result<BootstrapAdminCredentials> {
    if bytes.len() as u64 > MAX_BOOTSTRAP_CREDENTIAL_BYTES {
        bail!("administrator credential input exceeds the allowed size");
    }
    let credentials = serde_json::from_slice(bytes)
        .context("administrator credentials must be strict JSON with email and password")?;
    validate_bootstrap_admin_credentials(credentials)
}

fn validate_bootstrap_admin_credentials(
    credentials: BootstrapAdminCredentials,
) -> anyhow::Result<BootstrapAdminCredentials> {
    normalize_bootstrap_admin_email(&credentials.email)?;
    if !(12..=1024).contains(&credentials.password.chars().count()) {
        bail!("administrator password must contain between 12 and 1024 characters");
    }
    Ok(credentials)
}

fn normalize_bootstrap_admin_email(value: &str) -> anyhow::Result<String> {
    let value = value.trim().to_ascii_lowercase();
    let Some((local, domain)) = value.split_once('@') else {
        bail!("administrator email is invalid");
    };
    if value.len() > 254
        || local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 253
        || domain.contains('@')
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
        || !local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'.' | b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                )
        })
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        || domain.split('.').any(|label| {
            label.is_empty() || label.starts_with('-') || label.ends_with('-') || label.len() > 63
        })
    {
        bail!("administrator email is invalid");
    }
    Ok(value)
}

fn bootstrap_admin_endpoint(issuer: &str) -> anyhow::Result<url::Url> {
    let mut endpoint =
        url::Url::parse(issuer).context("configured issuer is not an HTTP origin")?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || !matches!(endpoint.path(), "" | "/")
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        bail!("configured issuer is not an HTTP origin");
    }
    if endpoint.scheme() == "http"
        && !endpoint.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    {
        bail!("initial administrator bootstrap requires HTTPS outside loopback trial mode");
    }
    endpoint.set_path("/auth/bootstrap-admin");
    Ok(endpoint)
}

fn bootstrap_token_path(
    config: &UpdateConfig,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<PathBuf> {
    let target = Path::new(BOOTSTRAP_MOUNT_TARGET);
    let mut sources = config
        .runtime
        .mounts
        .iter()
        .filter(|mount| mount.target == target)
        .map(|mount| mount.source.clone())
        .collect::<Vec<_>>();
    if config.runtime.engine == "host" && sources.is_empty() {
        sources.extend(
            config
                .runtime
                .snapshot_paths
                .iter()
                .filter(|path| path.file_name().is_some_and(|name| name == "bootstrap"))
                .cloned(),
        );
    }
    if sources.len() != 1 {
        bail!("managed runtime must expose exactly one bootstrap state source");
    }
    let source = &sources[0];
    validate_bootstrap_directory(source, expected_owner_uid)?;
    Ok(source.join(BOOTSTRAP_TOKEN_FILE))
}

fn read_bootstrap_token(path: &Path, expected_owner_uid: Option<u32>) -> anyhow::Result<String> {
    let metadata = fs::symlink_metadata(path)
        .context("initial administrator token is unavailable or already consumed")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("initial administrator token is not a regular file");
    }
    validate_bootstrap_secret_metadata(&metadata, expected_owner_uid)?;
    let file = File::open(path).context("failed to open initial administrator token")?;
    let opened_metadata = file
        .metadata()
        .context("failed to inspect opened initial administrator token")?;
    validate_same_file(&metadata, &opened_metadata)?;
    let mut bytes = Vec::new();
    file.take(MAX_BOOTSTRAP_TOKEN_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("failed to read initial administrator token")?;
    if bytes.len() as u64 > MAX_BOOTSTRAP_TOKEN_BYTES {
        bail!("initial administrator token exceeds the allowed size");
    }
    let token = std::str::from_utf8(&bytes)
        .context("initial administrator token is not valid UTF-8")?
        .trim_end_matches(['\r', '\n']);
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("initial administrator token has an invalid format");
    }
    Ok(token.to_owned())
}

fn bootstrap_state_owner_uid(config: &UpdateConfig) -> anyhow::Result<u32> {
    if config.runtime.engine != "host" {
        return Ok(10_001);
    }
    Process::new("id")
        .args(["-u", config.runtime.service_user.as_str()])
        .stdout()?
        .trim()
        .parse()
        .context("managed host service user has no valid numeric UID")
}

#[cfg(unix)]
fn validate_bootstrap_directory(
    path: &Path,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata =
        fs::symlink_metadata(path).context("managed bootstrap state directory is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("managed bootstrap state source is not a directory");
    }
    if fs::canonicalize(path)? != path {
        bail!("managed bootstrap state source must not traverse symbolic links");
    }
    if expected_owner_uid.is_some_and(|expected| metadata.uid() != expected) {
        bail!("managed bootstrap state source has an unexpected runtime owner");
    }
    if metadata.mode() & 0o077 != 0 {
        bail!("managed bootstrap state source must not be accessible by group or other users");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_bootstrap_directory(
    _path: &Path,
    _expected_owner_uid: Option<u32>,
) -> anyhow::Result<()> {
    bail!("bootstrap-admin is supported only on Unix managed hosts")
}

#[cfg(unix)]
fn validate_bootstrap_secret_metadata(
    metadata: &fs::Metadata,
    expected_owner_uid: Option<u32>,
) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if expected_owner_uid.is_some_and(|expected| metadata.uid() != expected) {
        bail!("initial administrator token has an unexpected runtime owner");
    }
    if metadata.mode() & 0o077 != 0 {
        bail!("initial administrator token must not be accessible by group or other users");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_bootstrap_secret_metadata(
    _metadata: &fs::Metadata,
    _expected_owner_uid: Option<u32>,
) -> anyhow::Result<()> {
    bail!("bootstrap-admin is supported only on Unix managed hosts")
}

#[cfg(unix)]
fn validate_same_file(before: &fs::Metadata, opened: &fs::Metadata) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        bail!("initial administrator token changed while it was being opened");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_file(_before: &fs::Metadata, _opened: &fs::Metadata) -> anyhow::Result<()> {
    Ok(())
}

fn command_is_read_only(command: &Command) -> bool {
    match command {
        Command::Status
        | Command::Doctor
        | Command::Check(_)
        | Command::AuditVerify
        | Command::AuditShow { .. }
        | Command::BreakGlassControllerAvailability => true,
        Command::Update(options) => options.plan,
        _ => false,
    }
}

pub(crate) fn acquire_lock(command: &Command) -> anyhow::Result<File> {
    // Installation, update, identity rotation and break-glass recovery mutate
    // one lifecycle state machine and therefore must share one lock even when
    // a test or operator overrides its location.
    let path = std::env::var_os("NAZOAUTHCTL_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/lock/nazoauthctl.lock"));
    acquire_lock_at(&path, command)
}

fn acquire_lock_at(path: &Path, command: &Command) -> anyhow::Result<File> {
    let read_only = command_is_read_only(command);
    let file = if read_only {
        OpenOptions::new().read(true).open(path).with_context(|| {
            format!(
                "failed to open existing lifecycle lock {} for read-only observation",
                path.display()
            )
        })?
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create lock directory {}", parent.display()))?;
        }
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("failed to open lifecycle lock {}", path.display()))?
    };
    let result = if read_only {
        file.try_lock_shared()
    } else {
        file.try_lock()
    };
    match result {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => {
            bail!("another nazoauthctl lifecycle operation is already running")
        }
        Err(TryLockError::Error(error)) => Err(error).context("failed to acquire lifecycle lock"),
    }
}

fn install(config_path: PathBuf, options: crate::cli::InstallOptions) -> anyhow::Result<()> {
    require_root()?;
    if config_path.exists() {
        let config = load_config(&config_path)?;
        if !config.managed_install {
            bail!("refusing to take ownership of an existing unmanaged deployment");
        }
        if install_is_complete(&config)? {
            if !health_ready(&config) {
                bail!("managed installation is complete but not healthy; run nazoauthctl doctor");
            }
            println!(
                "NazoAuth is already installed and ready; use nazoauthctl update for releases"
            );
            return Ok(());
        }
        println!("Resuming the existing managed installation");
        let resume_version = options.version.or_else(|| {
            load_active_release(&config)
                .ok()
                .map(|release| release.version)
        });
        return install_transaction(&config_path, &config, resume_version.as_deref());
    }
    let requested_version = options.version.clone();
    let PreparedInstall {
        config,
        config_path,
    } = install::prepare(&config_path, options)?;
    let result = install_transaction(&config_path, &config, requested_version.as_deref());
    if let Err(error) = result {
        eprintln!(
            "nazoauthctl: install stopped; persisted data was retained for a safe retry: {error:#}"
        );
        return Err(error);
    }
    Ok(())
}

fn install_transaction(
    config_path: &Path,
    config: &UpdateConfig,
    version: Option<&str>,
) -> anyhow::Result<()> {
    crate::operator::append_management_event(config, "install-intent", "pending", "backup")?;
    install::start_managed_dependencies(config)?;
    let release = VerifiedRelease::fetch(&config.repository, version, config.container_engine())?;
    enforce_release_trust(config, &release.manifest)?;
    let updater = release.artifact("updater", &config.repository)?;
    let _backup = Backup::create(config_path, config, &release.manifest.version)?;

    if config.runtime.engine == "host" {
        let binary = release.artifact("binary", &config.repository)?;
        let candidate = install_host_candidate(config, &release, &binary)?;
        install::install_systemd(config)?;
        execute_release_task(
            config,
            &release,
            candidate.to_string_lossy().as_ref(),
            TaskOperation::MigrateApply,
            None,
        )?;
        bootstrap_profile_keys(config, &release, candidate.to_string_lossy().as_ref())?;
        symlink_atomic(&candidate, &config.runtime.binary_path)?;
        Runtime::new(config).start_service()?;
    } else {
        let runtime = Runtime::new(config);
        let image_ref = release.manifest.image_ref()?;
        runtime.pull_image(&image_ref)?;
        if runtime.image_revision(&image_ref)? != release.manifest.backend_commit {
            bail!("pulled image revision does not match signed manifest");
        }
        execute_release_task(
            config,
            &release,
            &image_ref,
            TaskOperation::MigrateApply,
            None,
        )?;
        bootstrap_profile_keys(config, &release, &image_ref)?;
        if runtime.container_exists() {
            runtime.remove_container()?;
        }
        runtime.start_container(&image_ref)?;
    }
    wait_ready(config)?;
    verify_public(config)?;
    verify_ui(config, &release.manifest)?;
    write_active_release(config, &release.manifest)?;
    commit_release_trust(config, &release.manifest)?;
    copy_atomic(&updater, &config.updater_install_path, 0o755)?;
    write_record(config, &release.manifest, "install-success", None)?;
    let management_event = crate::operator::append_management_event(
        config,
        "install",
        &release.manifest.version,
        "backup",
    )?;
    let management_event_file = management_event
        .file_name()
        .and_then(|name| name.to_str())
        .context("management audit event has no valid file name")?
        .to_owned();
    atomic_write(
        &install_completion_path(config),
        &serde_json::to_vec_pretty(&InstallCompletion {
            schema: 1,
            version: release.manifest.version.clone(),
            backend_commit: release.manifest.backend_commit.clone(),
            management_event_file,
            management_event_sha256: crate::filesystem::sha256(&management_event)?,
        })?,
        0o600,
    )?;
    println!(
        "NazoAuth installed at {} ({})",
        release.manifest.version, release.manifest.backend_commit
    );
    println!(
        "Break-glass recovery key: {} (root-only; copy it to protected offline storage)",
        config.operator.break_glass_private_key.display()
    );
    println!("Create the first administrator with: nazoauthctl bootstrap-admin");
    Ok(())
}

fn bootstrap_profile_keys(
    config: &UpdateConfig,
    release: &VerifiedRelease,
    target: &str,
) -> anyhow::Result<()> {
    if config.install_profile != "standards-full" {
        return Ok(());
    }
    execute_release_task(
        config,
        release,
        target,
        TaskOperation::KeysGenerateLocal {
            alg: "ES256".to_owned(),
            purposes: vec!["credential".to_owned(), "presentation_request".to_owned()],
        },
        None,
    )
    .map(|_| ())
}

fn install_completion_path(config: &UpdateConfig) -> PathBuf {
    config.deployment_root.join("managed-install-complete.json")
}

fn install_is_complete(config: &UpdateConfig) -> anyhow::Result<bool> {
    let path = install_completion_path(config);
    if !path.exists() {
        return Ok(false);
    }
    let completion: InstallCompletion = serde_json::from_slice(&fs::read(&path)?)
        .context("managed installation completion marker is invalid")?;
    if completion.schema != 1 {
        bail!("unsupported managed installation completion marker");
    }
    let active = load_active_release(config)?;
    if completion.version != active.version || completion.backend_commit != active.backend_commit {
        bail!("managed installation completion marker does not match the active Release");
    }
    let event_path = config
        .operator
        .audit_directory
        .join("management")
        .join(&completion.management_event_file);
    if crate::filesystem::sha256(&event_path)? != completion.management_event_sha256 {
        bail!("managed installation completion audit digest mismatch");
    }
    let event = operator::load_management_event(config, &completion.management_event_file)?;
    if event.operation != "install" || event.release != completion.version {
        bail!("managed installation completion audit event is inconsistent");
    }
    Ok(true)
}

fn update(config_path: &Path, config: &UpdateConfig, options: UpdateOptions) -> anyhow::Result<()> {
    let release = VerifiedRelease::fetch(
        &config.repository,
        options.version.as_deref(),
        config.container_engine(),
    )?;
    enforce_release_trust(config, &release.manifest)?;
    let runtime = Runtime::new(config);
    let current = runtime.active_revision()?;
    let active = load_active_release(config)?;
    let minimum = format!("v{}", release.manifest.rollback.minimum_supported_version);
    if compare_versions(&active.version, &minimum)? == std::cmp::Ordering::Less {
        bail!(
            "active Release {} is below the target's minimum supported {}; use an intermediate signed Release",
            active.version,
            minimum
        );
    }
    if options.plan {
        print_update_plan(config, &active.version, &current, &release.manifest)?;
        return Ok(());
    }
    if current == release.manifest.backend_commit {
        println!(
            "NazoAuth is already at {} ({})",
            release.manifest.version, current
        );
        return Ok(());
    }
    require_confirmation(options.yes, "apply the signed Release update")?;
    if release.manifest.rollback.irreversible_migration && !options.accept_migration_barrier {
        bail!(
            "this Release crosses an irreversible migration barrier; inspect update --plan and repeat with --accept-migration-barrier --yes"
        );
    }
    crate::operator::append_management_event(
        config,
        "update-intent",
        &release.manifest.version,
        recovery_boundary_name(release.manifest.rollback.database_restore),
    )?;
    let runtime_artifact = if config.runtime.engine == "host" {
        Some(release.artifact("binary", &config.repository)?)
    } else {
        None
    };
    let updater = release.artifact("updater", &config.repository)?;
    let previous_manifest = load_active_release(config)?;
    let previous_ui = Some(
        config
            .ui
            .releases_root
            .join(&previous_manifest.frontend.artifact.sha256),
    );
    let previous_runtime = if config.runtime.engine == "host" {
        std::fs::canonicalize(&config.runtime.binary_path)
            .context("failed to resolve previous host binary")?
            .to_string_lossy()
            .into_owned()
    } else {
        previous_manifest.image_ref()?
    };

    let candidate = if config.runtime.engine == "host" {
        install_host_candidate(
            config,
            &release,
            runtime_artifact
                .as_deref()
                .context("host Release has no binary artifact")?,
        )?
        .to_string_lossy()
        .into_owned()
    } else {
        let image_ref = release.manifest.image_ref()?;
        runtime.pull_image(&image_ref)?;
        if runtime.image_revision(&image_ref)? != release.manifest.backend_commit {
            bail!("pulled image revision does not match signed manifest");
        }
        image_ref
    };
    let candidate_ui = config
        .ui
        .releases_root
        .join(&release.manifest.frontend.artifact.sha256);
    fs::create_dir_all(&config.deployment_root)?;
    let staged_updater = config.deployment_root.join(format!(
        "candidate-nazoauthctl-{}",
        release.manifest.backend_commit
    ));
    copy_atomic(&updater, &staged_updater, 0o500)?;
    let mut journal = UpdateJournal {
        schema: 1,
        transaction_id: format!("update-{}", encode_transaction_id()),
        started_at: Utc::now().to_rfc3339(),
        phase: UpdatePhase::Prepared,
        from_release: previous_manifest,
        to_release: release.manifest.clone(),
        previous_runtime,
        previous_ui,
        candidate_runtime: candidate,
        candidate_ui,
        staged_updater,
        backup: None,
    };
    write_update_journal(config, &journal)?;
    if let Err(error) = advance_update_transaction(config_path, config, &mut journal) {
        return handle_update_failure(config, &journal, error);
    }
    println!(
        "NazoAuth updated to {} ({})",
        release.manifest.version, release.manifest.backend_commit
    );
    Ok(())
}

fn advance_update_transaction(
    config_path: &Path,
    config: &UpdateConfig,
    journal: &mut UpdateJournal,
) -> anyhow::Result<()> {
    let runtime = Runtime::new(config);
    let resuming_activated_target = journal.phase >= UpdatePhase::CandidateActive;
    if resuming_activated_target {
        activate_candidate(config, &runtime, journal)?;
    }
    if journal.phase >= UpdatePhase::UiActive && !target_ui_is_active(journal) {
        bail!("candidate application did not retain its signed frontend cache");
    }
    if journal.phase >= UpdatePhase::HealthVerified {
        wait_ready(config)?;
        verify_public(config)?;
        verify_ui(config, &journal.to_release)?;
    }
    if journal.phase < UpdatePhase::WriterStopped {
        set_update_phase(config, journal, UpdatePhase::WriterStopping)?;
        stop_active_runtime(config, &runtime)?;
        set_update_phase(config, journal, UpdatePhase::WriterStopped)?;
    }
    if journal.phase < UpdatePhase::BackupCreated {
        set_update_phase(config, journal, UpdatePhase::BackupCreating)?;
        let backup = Backup::create(config_path, config, &journal.to_release.version)?;
        journal.backup = Some(backup.path().to_owned());
        set_update_phase(config, journal, UpdatePhase::BackupCreated)?;
    }
    if journal.phase < UpdatePhase::MigrationApplied {
        set_update_phase(config, journal, UpdatePhase::MigrationRunning)?;
        execute_manifest_task(
            config,
            &journal.to_release,
            &journal.candidate_runtime,
            TaskOperation::MigrateApply,
            None,
        )?;
        install::grant_runtime_database(config)?;
        set_update_phase(config, journal, UpdatePhase::MigrationApplied)?;
    }
    if journal.phase < UpdatePhase::CandidateActive {
        set_update_phase(config, journal, UpdatePhase::CandidateActivating)?;
        activate_candidate(config, &runtime, journal)?;
        set_update_phase(config, journal, UpdatePhase::CandidateActive)?;
    }
    if journal.phase < UpdatePhase::UiActive {
        set_update_phase(config, journal, UpdatePhase::UiActivating)?;
        wait_ready(config)?;
        verify_ui(config, &journal.to_release)?;
        if !target_ui_is_active(journal) {
            bail!("candidate application did not materialize its signed frontend cache");
        }
        set_update_phase(config, journal, UpdatePhase::UiActive)?;
    }
    if journal.phase < UpdatePhase::HealthVerified {
        set_update_phase(config, journal, UpdatePhase::HealthChecking)?;
        wait_ready(config)?;
        verify_public(config)?;
        verify_ui(config, &journal.to_release)?;
        set_update_phase(config, journal, UpdatePhase::HealthVerified)?;
    }
    if journal.phase < UpdatePhase::StateCommitted {
        set_update_phase(config, journal, UpdatePhase::StateCommitting)?;
        let backup = journal_backup(config, journal)?;
        write_active_release(config, &journal.to_release)?;
        copy_atomic(&journal.staged_updater, &config.updater_install_path, 0o755)?;
        write_rollback_state(
            config,
            RollbackState {
                schema: 1,
                from_release: journal.from_release.clone(),
                to_release: journal.to_release.clone(),
                previous_runtime: journal.previous_runtime.clone(),
                previous_ui: journal.previous_ui.clone(),
                backup: backup.path().to_owned(),
            },
        )?;
        write_update_record(config, journal, "deployment-success", Some(backup.path()))?;
        set_update_phase(config, journal, UpdatePhase::StateCommitted)?;
    }
    if journal.phase < UpdatePhase::TrustCommitted {
        set_update_phase(config, journal, UpdatePhase::TrustCommitting)?;
        commit_release_trust(config, &journal.to_release)?;
        set_update_phase(config, journal, UpdatePhase::TrustCommitted)?;
    }
    if journal.phase < UpdatePhase::AuditCommitted {
        set_update_phase(config, journal, UpdatePhase::AuditCommitting)?;
        append_update_management_event(
            config,
            journal,
            "completed",
            "update",
            &journal.to_release.version,
            recovery_boundary_name(journal.to_release.rollback.database_restore),
        )?;
        set_update_phase(config, journal, UpdatePhase::AuditCommitted)?;
    }
    finish_update_journal(config, journal)
}

fn update_journal_path(config: &UpdateConfig) -> PathBuf {
    config.deployment_root.join("update-transaction.json")
}

fn write_update_journal(config: &UpdateConfig, journal: &UpdateJournal) -> anyhow::Result<()> {
    validate_update_journal(config, journal)?;
    atomic_write(
        &update_journal_path(config),
        &serde_json::to_vec_pretty(journal)?,
        0o600,
    )
}

fn set_update_phase(
    config: &UpdateConfig,
    journal: &mut UpdateJournal,
    phase: UpdatePhase,
) -> anyhow::Result<()> {
    if phase < journal.phase {
        bail!("update transaction phase cannot move backwards");
    }
    let previous = journal.phase;
    journal.phase = phase;
    if let Err(error) = write_update_journal(config, journal) {
        journal.phase = previous;
        return Err(error);
    }
    Ok(())
}

fn validate_update_journal(config: &UpdateConfig, journal: &UpdateJournal) -> anyhow::Result<()> {
    if journal.schema != 1
        || journal.transaction_id.is_empty()
        || journal.transaction_id.len() > 96
        || !journal
            .transaction_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        || journal.started_at.is_empty()
        || journal.started_at.len() > 64
        || chrono::DateTime::parse_from_rfc3339(&journal.started_at).is_err()
    {
        bail!("update transaction journal header is invalid");
    }
    for manifest in [&journal.from_release, &journal.to_release] {
        let identity = format!(
            "https://github.com/{}/.github/workflows/release-security.yml@refs/tags/{}",
            config.repository, manifest.version
        );
        manifest.validate(&manifest.version, &identity)?;
    }
    if journal.previous_runtime.is_empty() || journal.candidate_runtime.is_empty() {
        bail!("update transaction journal contains an unsafe candidate path");
    }
    let expected_candidate_ui = config
        .ui
        .releases_root
        .join(&journal.to_release.frontend.artifact.sha256);
    let expected_updater = config.deployment_root.join(format!(
        "candidate-nazoauthctl-{}",
        journal.to_release.backend_commit
    ));
    if journal.candidate_ui != expected_candidate_ui || journal.staged_updater != expected_updater {
        bail!("update transaction candidate artifacts do not match the signed Release");
    }
    if let Some(previous_ui) = &journal.previous_ui {
        let expected_previous_ui = config
            .ui
            .releases_root
            .join(&journal.from_release.frontend.artifact.sha256);
        if previous_ui != &expected_previous_ui {
            bail!("update transaction previous UI does not match the active Release");
        }
    }
    if config.runtime.engine == "host" {
        let expected_previous_runtime = config
            .runtime
            .binary_releases
            .join(&journal.from_release.backend_commit)
            .join("nazoauth");
        let expected_candidate_runtime = config
            .runtime
            .binary_releases
            .join(&journal.to_release.backend_commit)
            .join("nazoauth");
        if Path::new(&journal.previous_runtime) != expected_previous_runtime
            || Path::new(&journal.candidate_runtime) != expected_candidate_runtime
        {
            bail!("update transaction host runtime does not match its signed Release");
        }
    } else if journal.candidate_runtime != journal.to_release.image_ref()?
        || journal.previous_runtime != journal.from_release.image_ref()?
    {
        bail!("update transaction image runtime does not match its signed Release");
    }
    if let Some(backup) = &journal.backup
        && !backup.starts_with(&config.backup_root)
    {
        bail!("update transaction backup is outside the backup root");
    }
    if journal.phase >= UpdatePhase::BackupCreated && journal.backup.is_none() {
        bail!("update transaction lost its committed backup path");
    }
    Ok(())
}

fn load_update_journal(config: &UpdateConfig) -> anyhow::Result<Option<UpdateJournal>> {
    let path = update_journal_path(config);
    if !path.exists() {
        return Ok(None);
    }
    if !path.is_file() || path.is_symlink() {
        bail!("update transaction journal must be a regular non-symlink file");
    }
    let journal: UpdateJournal = serde_json::from_slice(&fs::read(&path)?)
        .context("update transaction journal is invalid")?;
    validate_update_journal(config, &journal)?;
    Ok(Some(journal))
}

fn journal_backup(config: &UpdateConfig, journal: &UpdateJournal) -> anyhow::Result<Backup> {
    Backup::open_existing(
        config,
        journal
            .backup
            .as_deref()
            .context("update transaction has no verified backup")?,
    )
}

fn target_is_active(config: &UpdateConfig, journal: &UpdateJournal) -> bool {
    let runtime = Runtime::new(config);
    if config.runtime.engine != "host" && !runtime.container_exists() {
        return false;
    }
    runtime
        .active_revision()
        .is_ok_and(|revision| revision == journal.to_release.backend_commit)
}

fn recovery_action(journal: &UpdateJournal, target_is_active: bool) -> UpdateRecoveryAction {
    if target_is_active || journal.phase >= UpdatePhase::CandidateActive {
        return UpdateRecoveryAction::ContinueForward;
    }
    if journal.phase < UpdatePhase::MigrationRunning
        || (journal.to_release.rollback.artifact
            && journal.to_release.rollback.schema_compatible
            && !journal.to_release.rollback.irreversible_migration)
    {
        UpdateRecoveryAction::RestorePrevious
    } else {
        UpdateRecoveryAction::ContinueForward
    }
}

fn recover_pending_update(config_path: &Path, config: &UpdateConfig) -> anyhow::Result<()> {
    let Some(mut journal) = load_update_journal(config)? else {
        return Ok(());
    };
    eprintln!(
        "nazoauthctl: recovering update transaction {} at phase {:?}",
        journal.transaction_id, journal.phase
    );
    match recovery_action(&journal, target_is_active(config, &journal)) {
        UpdateRecoveryAction::ContinueForward => {
            advance_update_transaction(config_path, config, &mut journal)?;
            eprintln!(
                "nazoauthctl: update transaction {} completed at {}",
                journal.transaction_id, journal.to_release.version
            );
        }
        UpdateRecoveryAction::RestorePrevious => {
            restore_previous_transaction(config, &journal)?;
            append_update_management_event(
                config,
                &journal,
                "artifact-restored",
                "update-artifact-restored",
                &journal.from_release.version,
                "schema-compatible",
            )?;
            finish_update_journal(config, &journal)?;
            eprintln!(
                "nazoauthctl: interrupted update transaction {} restored {}",
                journal.transaction_id, journal.from_release.version
            );
        }
    }
    Ok(())
}

fn restore_previous_transaction(
    config: &UpdateConfig,
    journal: &UpdateJournal,
) -> anyhow::Result<()> {
    if journal.phase >= UpdatePhase::MigrationRunning {
        let backup = journal_backup(config, journal)?;
        rollback(
            config,
            &journal.previous_runtime,
            journal.previous_ui.as_deref(),
            &backup,
        )?;
    } else {
        let runtime = Runtime::new(config);
        if config.runtime.engine == "host" {
            runtime.stop_service().ok();
        } else if runtime.container_exists() {
            runtime.remove_container()?;
        }
        if config.runtime.engine == "host" {
            symlink_atomic(
                Path::new(&journal.previous_runtime),
                &config.runtime.binary_path,
            )?;
            runtime.start_service()?;
        } else {
            runtime.start_container(&journal.previous_runtime)?;
        }
        wait_ready(config)?;
    }
    verify_public(config)?;
    verify_ui(config, &journal.from_release)?;
    write_active_release(config, &journal.from_release)
}

fn handle_update_failure(
    config: &UpdateConfig,
    journal: &UpdateJournal,
    error: anyhow::Error,
) -> anyhow::Result<()> {
    if recovery_action(journal, target_is_active(config, journal))
        == UpdateRecoveryAction::ContinueForward
        && (!journal.to_release.rollback.schema_compatible
            || journal.to_release.rollback.irreversible_migration)
    {
        write_record(
            config,
            &journal.to_release,
            "recovery-required-after-update-failure",
            journal.backup.as_deref(),
        )
        .ok();
        append_update_management_event(
            config,
            journal,
            "recovery-required",
            "update-failed-recovery-required",
            &journal.to_release.version,
            recovery_boundary_name(journal.to_release.rollback.database_restore),
        )?;
        bail!(
            "update failed across a schema rollback barrier at phase {:?}: {error:#}; run nazoauthctl recover-update --yes to continue the persisted transaction; database recovery boundary={:?}; backup={}",
            journal.phase,
            journal.to_release.rollback.database_restore,
            journal.backup.as_deref().map_or_else(
                || "unavailable".to_owned(),
                |path| path.display().to_string()
            )
        );
    }
    let recovery = restore_previous_transaction(config, journal);
    if let Err(recovery_error) = recovery {
        append_update_management_event(
            config,
            journal,
            "rollback-failed",
            "update-failed-rollback-failed",
            &journal.to_release.version,
            "persisted-recovery-required",
        )?;
        bail!(
            "update failed at phase {:?}: {error:#}; persisted recovery also failed: {recovery_error:#}; run nazoauthctl recover-update --yes",
            journal.phase
        );
    }
    append_update_management_event(
        config,
        journal,
        "artifact-restored",
        "update-artifact-restored",
        &journal.from_release.version,
        "schema-compatible",
    )?;
    finish_update_journal(config, journal)?;
    bail!(
        "update failed at phase {:?} and the previous runtime was restored: {error:#}",
        journal.phase
    )
}

fn activate_candidate(
    config: &UpdateConfig,
    runtime: &Runtime<'_>,
    journal: &UpdateJournal,
) -> anyhow::Result<()> {
    if target_is_active(config, journal) {
        if config.runtime.engine == "host" {
            runtime.start_service()?;
        } else {
            runtime.restart()?;
        }
        return Ok(());
    }
    if config.runtime.engine == "host" {
        runtime.stop_service().ok();
        symlink_atomic(
            Path::new(&journal.candidate_runtime),
            &config.runtime.binary_path,
        )?;
        runtime.start_service()
    } else {
        if runtime.container_exists() {
            runtime.remove_container()?;
        }
        runtime.start_container(&journal.candidate_runtime)
    }
}

fn frontend_cache_matches(candidate_ui: &Path, release: &ReleaseManifest) -> bool {
    fn regular_file(path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
    }

    if !matches!(
        fs::symlink_metadata(candidate_ui),
        Ok(metadata) if metadata.is_dir()
    ) || !regular_file(&candidate_ui.join("index.html"))
    {
        return false;
    }
    let marker = candidate_ui.join(".nazoauth-ui.json");
    if !regular_file(&marker) {
        return false;
    }
    let Ok(actual) = fs::read(&marker).and_then(|bytes| {
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    }) else {
        return false;
    };
    actual
        == json!({
            "schema": 1,
            "repository": release.frontend.repository,
            "version": release.frontend.version,
            "commit": release.frontend.commit,
            "release_identity": release.frontend.release_identity,
            "artifact": release.frontend.artifact,
        })
}

fn target_ui_is_active(journal: &UpdateJournal) -> bool {
    frontend_cache_matches(&journal.candidate_ui, &journal.to_release)
}

fn finish_update_journal(config: &UpdateConfig, journal: &UpdateJournal) -> anyhow::Result<()> {
    remove_file_durable(&journal.staged_updater)?;
    remove_file_durable(&update_journal_path(config))
}

fn append_update_management_event(
    config: &UpdateConfig,
    journal: &UpdateJournal,
    event: &str,
    operation: &str,
    release: &str,
    recovery_boundary: &str,
) -> anyhow::Result<PathBuf> {
    operator::append_management_event_idempotent(
        config,
        &format!("request-{}-{event}", journal.transaction_id),
        operation,
        release,
        recovery_boundary,
    )
}

fn encode_transaction_id() -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(32);
    for byte in rand::random::<[u8; 16]>() {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn stop_active_runtime(config: &UpdateConfig, runtime: &Runtime<'_>) -> anyhow::Result<()> {
    if config.runtime.engine == "host" {
        runtime.stop_service()
    } else if runtime.container_exists() {
        runtime.remove_container()
    } else {
        bail!("active application container is unavailable")
    }
}

fn rollback(
    config: &UpdateConfig,
    previous_runtime: &str,
    previous_ui: Option<&Path>,
    backup: &Backup,
) -> anyhow::Result<()> {
    let runtime = Runtime::new(config);
    if config.runtime.engine == "host" {
        runtime.stop_service().ok();
    } else if runtime.container_exists() {
        runtime.remove_container().ok();
    }
    let _ = previous_ui;
    backup.restore_snapshots()?;
    if config.runtime.engine == "host" {
        symlink_atomic(Path::new(previous_runtime), &config.runtime.binary_path)?;
        runtime.start_service()?;
    } else {
        runtime.start_container(previous_runtime)?;
    }
    wait_ready(config)
}

fn rollback_state_path(config: &UpdateConfig) -> PathBuf {
    config.deployment_root.join("rollback-state.json")
}

fn write_rollback_state(config: &UpdateConfig, state: RollbackState) -> anyhow::Result<()> {
    atomic_write(
        &rollback_state_path(config),
        &serde_json::to_vec_pretty(&state)?,
        0o600,
    )
}

fn public_rollback(config: &UpdateConfig) -> anyhow::Result<()> {
    let state: RollbackState = serde_json::from_slice(&fs::read(rollback_state_path(config))?)
        .context("rollback state is invalid")?;
    if state.schema != 1 {
        bail!("unsupported rollback state");
    }
    let active = load_active_release(config)?;
    if active.version != state.to_release.version
        || !active.rollback.schema_compatible
        || active.rollback.irreversible_migration
    {
        bail!(
            "artifact rollback is not schema compatible; database recovery must use the declared {:?} boundary",
            active.rollback.database_restore
        );
    }
    let backup = Backup::open_existing(config, &state.backup)?;
    crate::operator::append_management_event(
        config,
        "artifact-rollback-intent",
        &state.from_release.version,
        "schema-compatible",
    )?;
    rollback(
        config,
        &state.previous_runtime,
        state.previous_ui.as_deref(),
        &backup,
    )?;
    verify_public(config)?;
    verify_ui(config, &state.from_release)?;
    write_active_release(config, &state.from_release)?;
    crate::operator::append_management_event(
        config,
        "artifact-rollback",
        &state.from_release.version,
        "schema-compatible",
    )?;
    println!(
        "artifact rollback completed to {}; database was not restored; schema compatibility was verified from the signed Release policy",
        state.from_release.version
    );
    Ok(())
}

fn recover_from_backup(config: &UpdateConfig) -> anyhow::Result<()> {
    let state: RollbackState = serde_json::from_slice(&fs::read(rollback_state_path(config))?)
        .context("recovery state is invalid")?;
    if state.schema != 1
        || state.to_release.rollback.database_restore != crate::model::DatabaseRestore::Backup
    {
        bail!("the signed Release does not declare backup-based database recovery");
    }
    let backup = Backup::open_existing(config, &state.backup)?;
    crate::operator::append_management_event(
        config,
        "backup-recovery-intent",
        &state.from_release.version,
        "database-backup",
    )?;
    rotate_bootstrap_recovery_epoch(config)
        .context("failed to invalidate bootstrap receipts before database recovery")?;
    let runtime = Runtime::new(config);
    if config.runtime.engine == "host" {
        runtime.stop_service()?;
    } else if runtime.container_exists() {
        runtime.remove_container()?;
    }
    backup.restore_databases(config)?;
    backup.restore_snapshots()?;
    install::grant_runtime_database(config)?;
    if config.runtime.engine == "host" {
        symlink_atomic(
            Path::new(&state.previous_runtime),
            &config.runtime.binary_path,
        )?;
        runtime.start_service()?;
    } else {
        runtime.start_container(&state.previous_runtime)?;
    }
    wait_ready(config)?;
    verify_public(config)?;
    verify_ui(config, &state.from_release)?;
    write_active_release(config, &state.from_release)?;
    crate::operator::append_management_event(
        config,
        "backup-recovery",
        &state.from_release.version,
        "database-backup",
    )?;
    println!(
        "backup recovery completed from {}; application={} database=restored valkey=restored",
        state.backup.display(),
        state.from_release.version
    );
    Ok(())
}

fn print_update_plan(
    config: &UpdateConfig,
    current_version: &str,
    current_revision: &str,
    target: &ReleaseManifest,
) -> anyhow::Result<()> {
    let value = json!({
        "current_version": current_version,
        "current_revision": current_revision,
        "target_version": target.version,
        "target_revision": target.backend_commit,
        "target_oci_digest": target.image_oci_digest(),
        "artifact_rollback": target.rollback.artifact
            && target.rollback.schema_compatible
            && !target.rollback.irreversible_migration,
        "schema_compatible_rollback": target.rollback.schema_compatible,
        "database_recovery": match (config.dependencies.mode.as_str(), target.rollback.database_restore) {
            ("managed", crate::model::DatabaseRestore::Backup) => "verified managed backup restore via nazoauthctl recover --yes",
            ("external", crate::model::DatabaseRestore::Backup) => "external provider backup restore; nazoauthctl will not modify the provider database",
            (_, crate::model::DatabaseRestore::Backup) => "invalid dependency recovery owner",
            (_, crate::model::DatabaseRestore::Pitr) => "external provider PITR procedure required; nazoauthctl does not claim automatic PITR",
            (_, crate::model::DatabaseRestore::None) => "unavailable",
        },
        "database_recovery_owner": if config.dependencies.mode == "managed"
            && target.rollback.database_restore == crate::model::DatabaseRestore::Backup {
            "nazoauthctl"
        } else {
            "external-operator"
        },
        "database_auto_rollback": false,
        "backup_consistency": if config.dependencies.mode == "managed" {
            "single managed application writer is stopped before PostgreSQL and Valkey backup; cross-store recovery may invalidate ephemeral Valkey state"
        } else {
            "this application instance is stopped, but the external operator must quiesce every other writer and provide the declared database recovery procedure"
        },
        "irreversible_migration_barrier": target.rollback.irreversible_migration,
        "migration_floor": target.rollback.migration_floor,
        "minimum_supported_version": target.rollback.minimum_supported_version,
        "backup_will_be_created_at": config.backup_root,
        "rationale": target.rollback.rationale,
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn recovery_boundary_name(boundary: crate::model::DatabaseRestore) -> &'static str {
    match boundary {
        crate::model::DatabaseRestore::Backup => "database-backup",
        crate::model::DatabaseRestore::Pitr => "database-pitr",
        crate::model::DatabaseRestore::None => "database-unavailable",
    }
}

fn app_command(
    config: &UpdateConfig,
    operation: TaskOperation,
    public_jwk: Option<&Path>,
) -> anyhow::Result<()> {
    let migration = matches!(operation, TaskOperation::MigrateApply);
    let runtime = Runtime::new(config);
    let target = if config.runtime.engine == "host" {
        config.runtime.binary_path.to_string_lossy().into_owned()
    } else {
        runtime.active_image()?
    };
    let release = load_active_release(config)?;
    let result = execute_manifest_task(config, &release, &target, operation, public_jwk)?;
    if migration {
        install::grant_runtime_database(config)?;
    }
    println!("{}", operation_result_json(&result)?);
    Ok(())
}

fn operation_result_json(result: &operator::OperationResult) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&serde_json::json!({
        "request_id": result.request_id,
        "receipt": result.final_receipt,
        "result": result.result,
    }))?)
}

fn execute_release_task(
    config: &UpdateConfig,
    release: &VerifiedRelease,
    target: &str,
    operation: TaskOperation,
    public_jwk: Option<&Path>,
) -> anyhow::Result<operator::OperationResult> {
    let migration = matches!(operation, TaskOperation::MigrateApply);
    let result = execute_manifest_task(config, &release.manifest, target, operation, public_jwk)?;
    if migration {
        install::grant_runtime_database(config)?;
    }
    Ok(result)
}

fn execute_manifest_task(
    config: &UpdateConfig,
    manifest: &ReleaseManifest,
    target: &str,
    operation: TaskOperation,
    public_jwk: Option<&Path>,
) -> anyhow::Result<operator::OperationResult> {
    let expected = expected_target(config, manifest)?;
    operator::execute(config, target, &expected, operation, public_jwk)
}

fn expected_target(
    config: &UpdateConfig,
    manifest: &ReleaseManifest,
) -> anyhow::Result<ExpectedReleaseTarget> {
    operator::expected_release_target(
        config,
        manifest.embedded.clone(),
        if config.runtime.engine == "host" {
            manifest.image_oci_digest()
        } else {
            manifest.runtime_oci_digest()?
        }
        .to_owned(),
        manifest
            .artifacts
            .get("binary")
            .context("Release manifest has no binary artifact")?
            .sha256
            .clone(),
    )
}

fn active_release_path(config: &UpdateConfig) -> PathBuf {
    config.deployment_root.join("active-release.json")
}

fn write_active_release(config: &UpdateConfig, manifest: &ReleaseManifest) -> anyhow::Result<()> {
    atomic_write(
        &active_release_path(config),
        &serde_json::to_vec_pretty(manifest)?,
        0o600,
    )
}

fn load_active_release(config: &UpdateConfig) -> anyhow::Result<ReleaseManifest> {
    let manifest: ReleaseManifest =
        serde_json::from_slice(&fs::read(active_release_path(config))?)?;
    let identity = format!(
        "https://github.com/{}/.github/workflows/release-security.yml@refs/tags/{}",
        config.repository, manifest.version
    );
    manifest.validate(&manifest.version, &identity)?;
    Ok(manifest)
}

fn load_config_unsettled(path: &Path) -> anyhow::Result<UpdateConfig> {
    if !path.is_file() || path.is_symlink() {
        bail!(
            "update config must be a regular non-symlink file: {}",
            path.display()
        );
    }
    validate_config_permissions(path)?;
    UpdateConfig::parse(
        &fs::read(path).with_context(|| format!("failed to read {}", path.display()))?,
    )
}

fn ensure_no_pending_update(config: &UpdateConfig) -> anyhow::Result<()> {
    if let Some(journal) = load_update_journal(config)? {
        bail!(
            "update transaction {} is pending at phase {:?}; run nazoauthctl recover-update --yes",
            journal.transaction_id,
            journal.phase
        )
    }
    Ok(())
}

fn load_config(path: &Path) -> anyhow::Result<UpdateConfig> {
    let config = load_config_unsettled(path)?;
    if crate::operator::identity_recovery_required(&config)? {
        bail!("identity recovery is pending; run nazoauthctl recover-identity --yes")
    }
    ensure_no_pending_update(&config)?;
    Ok(config)
}

#[cfg(unix)]
fn validate_config_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if cfg!(test) || test_mode() {
        return Ok(());
    }
    let metadata = fs::metadata(path)?;
    if !config_permissions_are_safe(metadata.uid(), metadata.mode()) {
        bail!("update config must be root-owned and not group/world writable");
    }
    Ok(())
}

#[cfg(unix)]
fn config_permissions_are_safe(owner_uid: u32, mode: u32) -> bool {
    owner_uid == 0 && mode & 0o022 == 0
}

#[cfg(not(unix))]
fn validate_config_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn status(config: &UpdateConfig) -> anyhow::Result<()> {
    let runtime = Runtime::new(config);
    let revision = runtime.active_revision()?;
    let release = load_active_release(config)?;
    let (target, runtime_name) = if config.runtime.engine == "host" {
        let path = fs::canonicalize(&config.runtime.binary_path)?;
        let target = json!({
            "kind": "host-binary",
            "path": path,
            "sha256": crate::filesystem::sha256(&config.runtime.binary_path)?,
        });
        (target, path.display().to_string())
    } else {
        let image = runtime.active_image()?;
        let image_digest = runtime.image_digest(&image)?;
        (
            json!({
                "kind": "oci-image",
                "image_ref": image,
                "image_digest": image_digest,
            }),
            image,
        )
    };
    let actual_embedded = runtime.embedded_identity(&runtime_name)?;
    let embedded_identity_matches_release = actual_embedded == release.embedded;
    let value = json!({
        "engine": config.runtime.engine,
        "revision": revision,
        "release": release.version,
        "release_identity": release.release_identity,
        "runtime_target": target,
        "embedded_build_identity": actual_embedded,
        "embedded_identity_matches_release": embedded_identity_matches_release,
        "health_url": config.runtime.health_url,
        "ready": health_ready(config),
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn doctor(config: &UpdateConfig) -> anyhow::Result<()> {
    let runtime = Runtime::new(config);
    let release = load_active_release(config)?;
    let target = if config.runtime.engine == "host" {
        nazo_operator_protocol::RuntimeTargetClaim::HostBinary {
            path: fs::canonicalize(&config.runtime.binary_path)?
                .display()
                .to_string(),
            sha256: crate::filesystem::sha256(&config.runtime.binary_path)?,
        }
    } else {
        let image = runtime.active_image()?;
        nazo_operator_protocol::RuntimeTargetClaim::OciImage {
            image_digest: runtime.image_digest(&image)?,
            image_ref: image,
        }
    };
    let expected = expected_target(config, &release)?;
    let runtime_name = match &target {
        nazo_operator_protocol::RuntimeTargetClaim::OciImage { image_ref, .. } => image_ref,
        nazo_operator_protocol::RuntimeTargetClaim::HostBinary { path, .. } => path,
    };
    if runtime.embedded_identity(runtime_name)? != release.embedded {
        bail!("doctor: runtime embedded build identity differs from the signed Release");
    }
    match &target {
        nazo_operator_protocol::RuntimeTargetClaim::OciImage { image_digest, .. }
            if image_digest != &expected.image_digest =>
        {
            bail!("doctor: active OCI digest differs from the signed Release")
        }
        nazo_operator_protocol::RuntimeTargetClaim::HostBinary { sha256, .. }
            if sha256 != &expected.binary_digest =>
        {
            bail!("doctor: active host binary digest differs from the signed Release")
        }
        _ => {}
    }
    if !health_ready(config) {
        bail!("doctor: readiness endpoint is not healthy");
    }
    crate::operator::verify_audit(config)?;
    install::verify_runtime_no_ddl(config)?;
    println!(
        "doctor: ok; release={}; revision={}; target={target:?}",
        release.version, release.backend_commit
    );
    Ok(())
}

fn wait_ready(config: &UpdateConfig) -> anyhow::Result<()> {
    for _ in 0..config.runtime.readiness_attempts {
        if health_ready(config) {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(
            config.runtime.readiness_interval_seconds,
        ));
    }
    bail!(
        "NazoAuth did not become ready at {}",
        config.runtime.health_url
    )
}

fn health_ready(config: &UpdateConfig) -> bool {
    Process::new("curl")
        .timeout(Duration::from_secs(10))
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=http,https",
            "--max-time",
            "5",
            config.runtime.health_url.as_str(),
        ])
        .succeeds()
}

fn verify_public(config: &UpdateConfig) -> anyhow::Result<()> {
    let response = Process::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https,http",
            "--max-time",
            "10",
            config.runtime.public_discovery_url.as_str(),
        ])
        .stdout()?;
    let value: serde_json::Value =
        serde_json::from_str(&response).context("Discovery response is not valid JSON")?;
    if value.get("issuer").and_then(serde_json::Value::as_str)
        != Some(config.runtime.expected_issuer.as_str())
    {
        bail!("public Discovery issuer does not match configured issuer");
    }
    Ok(())
}

const MAX_UI_INDEX_BYTES: u64 = 1024 * 1024;

fn signed_ui_index(config: &UpdateConfig, release: &ReleaseManifest) -> anyhow::Result<Vec<u8>> {
    let cache = config
        .ui
        .releases_root
        .join(&release.frontend.artifact.sha256);
    if !frontend_cache_matches(&cache, release) {
        bail!("runtime frontend cache does not match the signed Release descriptor");
    }
    let index = cache.join("index.html");
    let metadata = fs::metadata(&index)?;
    if metadata.len() == 0 || metadata.len() > MAX_UI_INDEX_BYTES {
        bail!("runtime frontend index is empty or exceeds the verification boundary");
    }
    let content = fs::read(index)?;
    if content.len() as u64 != metadata.len() {
        bail!("runtime frontend index changed during verification");
    }
    Ok(content)
}

fn verify_ui_binding(
    config: &UpdateConfig,
    release: &ReleaseManifest,
    served: &[u8],
) -> anyhow::Result<()> {
    let expected = signed_ui_index(config, release)?;
    if served != expected {
        bail!("served frontend does not match the signed runtime cache");
    }
    Ok(())
}

fn verify_ui(config: &UpdateConfig, release: &ReleaseManifest) -> anyhow::Result<()> {
    let expected = signed_ui_index(config, release)?;
    let url = format!(
        "{}/ui/",
        config.runtime.expected_issuer.trim_end_matches('/')
    );
    let output = Process::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https,http",
            "--proto-redir",
            "=https",
            "--max-redirs",
            "5",
            "--max-time",
            "10",
        ])
        .arg("--max-filesize")
        .arg(expected.len().to_string())
        .arg(&url)
        .output()?;
    if !output.status.success() {
        bail!("public frontend verification request failed");
    }
    verify_ui_binding(config, release, &output.stdout)
}

fn install_host_candidate(
    config: &UpdateConfig,
    release: &VerifiedRelease,
    binary: &Path,
) -> anyhow::Result<PathBuf> {
    let directory = config
        .runtime
        .binary_releases
        .join(&release.manifest.backend_commit);
    fs::create_dir_all(&directory)?;
    set_mode(&directory, 0o755)?;
    let target = directory.join("nazoauth");
    if target.exists() {
        if crate::filesystem::sha256(&target)? != crate::filesystem::sha256(binary)? {
            bail!("existing host binary differs from the signed artifact");
        }
    } else {
        copy_atomic(binary, &target, 0o755)?;
    }
    let binary_parent = config
        .runtime
        .binary_path
        .parent()
        .context("host binary path has no parent")?;
    fs::create_dir_all(binary_parent)?;
    set_mode(binary_parent, 0o755)?;
    Process::new(&target).arg("--help").run_quiet()?;
    Ok(target)
}

fn write_record(
    config: &UpdateConfig,
    release: &ReleaseManifest,
    status: &str,
    backup: Option<&Path>,
) -> anyhow::Result<()> {
    fs::create_dir_all(&config.deployment_root)?;
    let stamp = Utc::now().format("%Y%m%dT%H%M%S%.6fZ");
    let value = json!({
        "status": status,
        "version": release.version,
        "backend_commit": release.backend_commit,
        "frontend_commit": release.frontend_commit(),
        "frontend_version": release.frontend.version,
        "frontend_artifact_sha256": release.frontend.artifact.sha256,
        "engine": config.runtime.engine,
        "backup": backup.map(|path| path.display().to_string()),
        "recorded_at": Utc::now().to_rfc3339(),
    });
    atomic_write(
        &config
            .deployment_root
            .join(format!("{}-{}.json", release.version, stamp)),
        &(serde_json::to_vec_pretty(&value)?),
        0o600,
    )
}

fn write_update_record(
    config: &UpdateConfig,
    journal: &UpdateJournal,
    status: &str,
    backup: Option<&Path>,
) -> anyhow::Result<()> {
    fs::create_dir_all(&config.deployment_root)?;
    let value = json!({
        "status": status,
        "transaction_id": journal.transaction_id,
        "version": journal.to_release.version,
        "backend_commit": journal.to_release.backend_commit,
        "frontend_commit": journal.to_release.frontend_commit(),
        "frontend_version": journal.to_release.frontend.version,
        "frontend_artifact_sha256": journal.to_release.frontend.artifact.sha256,
        "engine": config.runtime.engine,
        "backup": backup.map(|path| path.display().to_string()),
        "recorded_at": journal.started_at,
    });
    atomic_write(
        &config
            .deployment_root
            .join(format!("update-{}.json", journal.transaction_id)),
        &serde_json::to_vec_pretty(&value)?,
        0o600,
    )
}

fn require_root() -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if Process::new("id").arg("-u").stdout()?.trim() != "0" {
        bail!("this command requires root");
    }
    Ok(())
}

fn test_mode() -> bool {
    #[cfg(debug_assertions)]
    return std::env::var_os("NAZOAUTHCTL_TESTING").is_some();
    #[cfg(not(debug_assertions))]
    false
}

fn require_confirmation(yes: bool, action: &str) -> anyhow::Result<()> {
    use std::io::{IsTerminal as _, Write as _};

    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!("{action} requires --yes in non-interactive mode");
    }
    eprint!("Confirm: {action} [y/N]: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        bail!("operation cancelled")
    }
}

#[cfg(test)]
#[path = "../tests/unit/controller.rs"]
mod tests;
