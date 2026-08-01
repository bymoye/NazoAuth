use std::{
    fs::{self, File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anyhow::{Context, bail};
use chrono::Utc;
use nazo_operator_protocol::TaskOperation;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    backup::Backup,
    cli::{Cli, Command, KeysCommand, UpdateOptions},
    filesystem::{
        atomic_write, copy_atomic, directory_digests, extract_ui, set_mode, symlink_atomic,
    },
    install::{self, PreparedInstall},
    model::{ReleaseManifest, UpdateConfig},
    operator::{self, ExpectedReleaseTarget},
    process::Process,
    release::{VerifiedRelease, commit_release_trust, compare_versions, enforce_release_trust},
    runtime::Runtime,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RollbackState {
    schema: u32,
    from_release: ReleaseManifest,
    to_release: ReleaseManifest,
    previous_runtime: String,
    previous_ui: Option<PathBuf>,
    backup: PathBuf,
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

pub(crate) fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Install(options) => install(cli.config, options),
        Command::Status => {
            let config = load_config(&cli.config)?;
            status(&config)
        }
        Command::Doctor => {
            let config = load_config(&cli.config)?;
            doctor(&config)
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
            require_confirmation(
                yes,
                "rollback the application artifact without restoring the database",
            )?;
            let config = load_config(&cli.config)?;
            public_rollback(&config)
        }
        Command::Recover { yes } => {
            require_root()?;
            require_confirmation(
                yes,
                "restore the declared database backup and previous application artifact",
            )?;
            let config = load_config(&cli.config)?;
            recover_from_backup(&config)
        }
        Command::Migrate { yes } => {
            require_root()?;
            require_confirmation(yes, "apply pending database migrations")?;
            let config = load_config(&cli.config)?;
            app_command(&config, TaskOperation::MigrateApply, None)
        }
        Command::Keys(command) => {
            require_root()?;
            let config = load_config(&cli.config)?;
            let (operation, public_jwk) = match command {
                KeysCommand::List => (TaskOperation::KeysList, None),
                KeysCommand::Validate => (TaskOperation::KeysValidate, None),
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
            require_confirmation(yes, "rotate the controller identity")?;
            let config = load_config(&cli.config)?;
            crate::operator::rotate_controller(&cli.config, &config, false, "normal")
        }
        Command::BreakGlassRecover { yes, reason } => {
            require_root()?;
            require_confirmation(yes, "perform break-glass controller recovery")?;
            let config = load_config(&cli.config)?;
            crate::operator::rotate_controller(&cli.config, &config, true, &reason)
        }
    }
}

pub(crate) fn acquire_lock(install: bool) -> anyhow::Result<File> {
    let override_name = if install {
        "NAZOAUTHCTL_INSTALL_LOCK"
    } else {
        "NAZOAUTHCTL_LOCK"
    };
    let path = std::env::var_os(override_name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/lock/nazoauthctl.lock"));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create lock directory {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("failed to open lifecycle lock {}", path.display()))?;
    match file.try_lock() {
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
    let ui_archive = release.artifact("ui", &config.repository)?;
    let updater = release.artifact("updater", &config.repository)?;
    let ui_release = prepare_ui(config, &release, &ui_archive)?;
    symlink_atomic(&ui_release, &config.ui.active_path)?;
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
        let image = release.artifact("image", &config.repository)?;
        let runtime = Runtime::new(config);
        runtime.load_image(&image)?;
        if runtime.image_revision(&release.manifest.image_ref)? != release.manifest.backend_commit {
            bail!("loaded image revision does not match signed manifest");
        }
        execute_release_task(
            config,
            &release,
            &release.manifest.image_ref,
            TaskOperation::MigrateApply,
            None,
        )?;
        bootstrap_profile_keys(config, &release, &release.manifest.image_ref)?;
        if runtime.container_exists() {
            runtime.remove_container()?;
        }
        runtime.start_container(&release.manifest.image_ref)?;
    }
    wait_ready(config)?;
    verify_public(config)?;
    verify_ui(config)?;
    write_active_release(config, &release.manifest)?;
    commit_release_trust(config, &release.manifest)?;
    copy_atomic(&updater, &config.updater_install_path, 0o755)?;
    write_record(config, &release, "install-success", None)?;
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
        release.artifact("binary", &config.repository)?
    } else {
        release.artifact("image", &config.repository)?
    };
    let ui_archive = release.artifact("ui", &config.repository)?;
    let updater = release.artifact("updater", &config.repository)?;
    let previous_ui = current_symlink(&config.ui.active_path)?;
    let previous_manifest = load_active_release(config)?;
    let previous_runtime = if config.runtime.engine == "host" {
        std::fs::canonicalize(&config.runtime.binary_path)
            .context("failed to resolve previous host binary")?
            .to_string_lossy()
            .into_owned()
    } else {
        runtime.active_image_id()?
    };

    let candidate = if config.runtime.engine == "host" {
        install_host_candidate(config, &release, &runtime_artifact)?
            .to_string_lossy()
            .into_owned()
    } else {
        runtime.load_image(&runtime_artifact)?;
        if runtime.image_revision(&release.manifest.image_ref)? != release.manifest.backend_commit {
            bail!("loaded image revision does not match signed manifest");
        }
        release.manifest.image_ref.clone()
    };

    stop_active_runtime(config, &runtime)?;
    let backup = match Backup::create(config_path, config, &release.manifest.version) {
        Ok(backup) => backup,
        Err(error) => {
            let restart = start_previous_runtime(config, &runtime, &previous_runtime);
            crate::operator::append_management_event(
                config,
                "update-backup-failed",
                &previous_manifest.version,
                "previous-runtime-restored",
            )?;
            if let Err(restart_error) = restart {
                bail!(
                    "update backup failed before migration: {error:#}; previous runtime restart also failed: {restart_error:#}"
                );
            }
            bail!(
                "update backup failed before migration; previous runtime was restored: {error:#}"
            );
        }
    };
    let result = update_mutation(config, &release, &candidate, &ui_archive, &updater)
        .and_then(|()| write_record(config, &release, "deployment-success", Some(backup.path())))
        .and_then(|()| {
            write_rollback_state(
                config,
                RollbackState {
                    schema: 1,
                    from_release: previous_manifest.clone(),
                    to_release: release.manifest.clone(),
                    previous_runtime: previous_runtime.clone(),
                    previous_ui: previous_ui.clone(),
                    backup: backup.path().to_owned(),
                },
            )
        });
    if let Err(error) = result {
        if !release.manifest.rollback.artifact
            || release.manifest.rollback.irreversible_migration
            || !release.manifest.rollback.schema_compatible
        {
            write_record(
                config,
                &release,
                "recovery-required-after-update-failure",
                Some(backup.path()),
            )
            .ok();
            crate::operator::append_management_event(
                config,
                "update-failed-recovery-required",
                &release.manifest.version,
                recovery_boundary_name(release.manifest.rollback.database_restore),
            )?;
            bail!(
                "update failed across a schema rollback barrier: {error:#}; application artifact rollback is unsafe; database recovery boundary={:?}; backup={}",
                release.manifest.rollback.database_restore,
                backup.path().display()
            );
        }
        let recovery = rollback(config, &previous_runtime, previous_ui.as_deref(), &backup);
        write_active_release(config, &previous_manifest).ok();
        write_record(
            config,
            &release,
            "rollback-after-update-failure",
            Some(backup.path()),
        )
        .ok();
        if let Err(recovery_error) = recovery {
            crate::operator::append_management_event(
                config,
                "update-failed-rollback-failed",
                &release.manifest.version,
                "manual-recovery-required",
            )?;
            bail!(
                "update failed: {error:#}; automatic recovery also failed: {recovery_error:#}; backup={}",
                backup.path().display()
            );
        }
        crate::operator::append_management_event(
            config,
            "update-failed-artifact-restored",
            &previous_manifest.version,
            "schema-compatible",
        )?;
        bail!(
            "update failed and the previous runtime was restored: {error:#}; backup={}",
            backup.path().display()
        );
    }
    commit_release_trust(config, &release.manifest)?;
    crate::operator::append_management_event(
        config,
        "update",
        &release.manifest.version,
        recovery_boundary_name(release.manifest.rollback.database_restore),
    )?;
    println!(
        "NazoAuth updated to {} ({})",
        release.manifest.version, release.manifest.backend_commit
    );
    Ok(())
}

fn update_mutation(
    config: &UpdateConfig,
    release: &VerifiedRelease,
    candidate: &str,
    ui_archive: &Path,
    updater: &Path,
) -> anyhow::Result<()> {
    let runtime = Runtime::new(config);
    execute_release_task(
        config,
        release,
        candidate,
        TaskOperation::MigrateApply,
        None,
    )?;
    if config.runtime.engine == "host" {
        symlink_atomic(Path::new(candidate), &config.runtime.binary_path)?;
        runtime.start_service()?;
    } else {
        runtime.start_container(candidate)?;
    }
    wait_ready(config)?;
    verify_public(config)?;

    let ui_release = prepare_ui(config, release, ui_archive)?;
    symlink_atomic(&ui_release, &config.ui.active_path)?;
    if config.ui.serve_from_application {
        runtime.restart()?;
        wait_ready(config)?;
    }
    verify_public(config)?;
    verify_ui(config)?;
    write_active_release(config, &release.manifest)?;
    copy_atomic(updater, &config.updater_install_path, 0o755)
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

fn start_previous_runtime(
    config: &UpdateConfig,
    runtime: &Runtime<'_>,
    previous_runtime: &str,
) -> anyhow::Result<()> {
    if config.runtime.engine == "host" {
        runtime.start_service()
    } else {
        runtime.start_container(previous_runtime)
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
    if let Some(ui) = previous_ui {
        symlink_atomic(ui, &config.ui.active_path)?;
    }
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
    let runtime = Runtime::new(config);
    if config.runtime.engine == "host" {
        runtime.stop_service()?;
    } else if runtime.container_exists() {
        runtime.remove_container()?;
    }
    backup.restore_databases(config)?;
    backup.restore_snapshots()?;
    if let Some(ui) = state.previous_ui.as_deref() {
        symlink_atomic(ui, &config.ui.active_path)?;
    }
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
    verify_ui(config)?;
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
        "target_oci_digest": target.image_oci_digest,
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
    println!(
        "request_id={} receipt={} result={:?}",
        result.request_id,
        result.final_receipt.display(),
        result.result
    );
    Ok(())
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
        manifest.image_oci_digest.clone(),
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

fn load_config(path: &Path) -> anyhow::Result<UpdateConfig> {
    if !path.is_file() || path.is_symlink() {
        bail!(
            "update config must be a regular non-symlink file: {}",
            path.display()
        );
    }
    validate_config_permissions(path)?;
    let mut config = UpdateConfig::parse(
        &fs::read(path).with_context(|| format!("failed to read {}", path.display()))?,
    )?;
    crate::operator::recover_pending_rotation(path, &mut config)?;
    Ok(config)
}

#[cfg(unix)]
fn validate_config_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if test_mode() {
        return Ok(());
    }
    let metadata = fs::metadata(path)?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("update config must be root-owned and not group/world writable");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_config_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn status(config: &UpdateConfig) -> anyhow::Result<()> {
    let runtime = Runtime::new(config);
    let revision = runtime.active_revision()?;
    let release = load_active_release(config)?;
    let target = if config.runtime.engine == "host" {
        json!({
            "kind": "host-binary",
            "path": fs::canonicalize(&config.runtime.binary_path)?,
            "sha256": crate::filesystem::sha256(&config.runtime.binary_path)?,
        })
    } else {
        let image = runtime.active_image()?;
        let image_digest = runtime.image_digest(&image)?;
        json!({
            "kind": "oci-image",
            "image_ref": image,
            "image_digest": image_digest,
        })
    };
    let value = json!({
        "engine": config.runtime.engine,
        "revision": revision,
        "release": release.version,
        "release_identity": release.release_identity,
        "runtime_target": target,
        "embedded_build_identity": release.embedded,
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

fn verify_ui(config: &UpdateConfig) -> anyhow::Result<()> {
    if !config.ui.serve_from_application {
        return Ok(());
    }
    let url = format!(
        "{}/ui/",
        config.runtime.expected_issuer.trim_end_matches('/')
    );
    Process::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https,http",
            "--max-time",
            "10",
            &url,
        ])
        .run_quiet()
}

fn prepare_ui(
    config: &UpdateConfig,
    release: &VerifiedRelease,
    archive: &Path,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(&config.ui.releases_root)?;
    let target = config
        .ui
        .releases_root
        .join(&release.manifest.frontend_commit);
    let temporary = config.ui.releases_root.join(format!(
        ".{}.tmp-{}",
        release.manifest.frontend_commit,
        std::process::id()
    ));
    if temporary.exists() {
        bail!(
            "stale UI release staging directory requires review: {}",
            temporary.display()
        );
    }
    fs::create_dir(&temporary)?;
    extract_ui(archive, &temporary)?;
    if target.exists() {
        if directory_digests(&target)? != directory_digests(&temporary)? {
            bail!(
                "existing UI release differs from the signed artifact: {}",
                target.display()
            );
        }
        fs::remove_dir_all(&temporary)?;
        return Ok(target);
    }
    fs::rename(&temporary, &target)?;
    Ok(target)
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

fn current_symlink(path: &Path) -> anyhow::Result<Option<PathBuf>> {
    if path.is_symlink() {
        return Ok(Some(fs::read_link(path)?));
    }
    if path.exists() {
        bail!(
            "active path must be a symlink or absent: {}",
            path.display()
        );
    }
    Ok(None)
}

fn write_record(
    config: &UpdateConfig,
    release: &VerifiedRelease,
    status: &str,
    backup: Option<&Path>,
) -> anyhow::Result<()> {
    fs::create_dir_all(&config.deployment_root)?;
    let stamp = Utc::now().format("%Y%m%dT%H%M%S%.6fZ");
    let value = json!({
        "status": status,
        "version": release.manifest.version,
        "backend_commit": release.manifest.backend_commit,
        "frontend_commit": release.manifest.frontend_commit,
        "engine": config.runtime.engine,
        "backup": backup.map(|path| path.display().to_string()),
        "recorded_at": Utc::now().to_rfc3339(),
    });
    atomic_write(
        &config
            .deployment_root
            .join(format!("{}-{}.json", release.manifest.version, stamp)),
        &(serde_json::to_vec_pretty(&value)?),
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
