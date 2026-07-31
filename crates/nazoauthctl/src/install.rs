use std::{
    collections::BTreeMap,
    env, fs,
    io::Read as _,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{
    cli::InstallOptions,
    filesystem::{atomic_write, generate_secret, set_mode},
    model::{
        Dependencies, Mount, Operator, Postgres, Runtime, Ui, UpdateConfig, Valkey, safe_absolute,
    },
    process::{Process, command_exists},
    secret_provider::PostgresProvider,
};

pub(crate) const POSTGRES_IMAGE: &str = "docker.io/library/postgres:18@sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a";
pub(crate) const VALKEY_IMAGE: &str = "docker.io/valkey/valkey:8-alpine@sha256:a038175878d66b9d274fbf8be73c0305e93798b83917647f167e18cef3c71eec";
const STANDARDS_PROFILE_SECRET_NAMES: &[&str] = &[
    "dynamic-registration-token",
    "ciba-decision-token",
    "openid4vc-data-encryption-key",
    "openid4vci-management-token",
    "openid4vp-management-token",
];

pub(crate) struct PreparedInstall {
    pub(crate) config: UpdateConfig,
    pub(crate) config_path: PathBuf,
}

pub(crate) fn prepare(
    config_path: &Path,
    mut options: InstallOptions,
) -> anyhow::Result<PreparedInstall> {
    require_linux()?;
    require_root()?;
    safe_absolute(config_path)?;
    safe_absolute(&options.data_root)?;
    validate_public_url(&options.public_url)?;
    normalize_external_dependencies(&mut options)?;
    let (runtime_engine, dependency_engine) = select_runtime(&options)?;
    let trusted_proxy_cidr = if options.profile == "standards-full" {
        if runtime_engine == "host" {
            Some("127.0.0.1/32".to_owned())
        } else {
            ensure_network(&runtime_engine, "nazo_oauth_net")?;
            Some(host_cidr(network_gateway(
                &runtime_engine,
                "nazo_oauth_net",
            )?))
        }
    } else {
        None
    };
    let config_dir = config_path
        .parent()
        .context("update config path has no parent")?;
    let secrets_dir = config_dir.join("secrets");
    let app_root = options.data_root.join("app");
    create_directory(config_dir, 0o755)?;
    create_directory(&options.data_root, 0o755)?;
    create_directory(&secrets_dir, 0o700)?;
    for path in [
        options.data_root.join("backups"),
        options.data_root.join("deployments"),
        options.data_root.join("ui-releases"),
    ] {
        create_directory(&path, 0o755)?;
    }
    for path in [
        app_root.join("keys"),
        app_root.join("avatars"),
        app_root.join("secrets"),
        app_root.join("bootstrap"),
        app_root.join("operator-state"),
    ] {
        create_directory(&path, 0o700)?;
    }
    let operator_dir = config_dir.join("operator");
    create_directory(&operator_dir, 0o700)?;
    create_directory(&options.data_root.join("audit"), 0o700)?;
    write_operator_identities(&operator_dir)?;
    let profile = write_install_profile(config_dir, &app_root, &options)?;

    let dependency_mode = if options.database_url.is_some() {
        write_external_urls(&secrets_dir, &options)?
    } else {
        write_managed_secrets(&secrets_dir)?
    };
    write_server_config(
        config_dir,
        &options,
        &runtime_engine,
        &options.data_root,
        trusted_proxy_cidr.as_deref(),
        profile.as_deref(),
    )?;
    let config = build_config(
        config_path,
        &options,
        &runtime_engine,
        &dependency_engine,
        &dependency_mode,
    )?;
    configure_runtime_permissions(&config)?;
    atomic_write(config_path, &(serde_json::to_vec_pretty(&config)?), 0o600)?;
    Ok(PreparedInstall {
        config,
        config_path: config_path.to_owned(),
    })
}

fn configure_runtime_permissions(config: &UpdateConfig) -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if config.runtime.engine == "host" {
        return Ok(());
    }
    let app_root = config
        .runtime
        .snapshot_paths
        .first()
        .and_then(|path| path.parent())
        .context("application data root is unavailable")?;
    Process::new("chown")
        .args(["-R", "10001:10001"])
        .arg(app_root)
        .run_quiet()?;
    let config_file = config
        .runtime
        .mounts
        .iter()
        .find(|mount| mount.target == Path::new("/app/.env.yaml"))
        .context("server configuration mount is unavailable")?
        .source
        .clone();
    let mut readable = vec![
        config_file,
        config.dependencies.database_url_file.clone(),
        config.dependencies.migration_database_url_file.clone(),
        config.dependencies.valkey_url_file.clone(),
        config.operator.receipt_private_key.clone(),
    ];
    for name in STANDARDS_PROFILE_SECRET_NAMES {
        readable.push(
            config
                .dependencies
                .database_url_file
                .parent()
                .context("secret directory is unavailable")?
                .join(name),
        );
    }
    readable.retain(|path| path.exists());
    for path in readable {
        Process::new("chown")
            .arg("root:10001")
            .arg(&path)
            .run_quiet()?;
        set_mode(&path, 0o440)?;
    }
    Ok(())
}

pub(crate) fn start_managed_dependencies(config: &UpdateConfig) -> anyhow::Result<()> {
    if config.dependencies.mode != "managed" {
        return Ok(());
    }
    let engine = config
        .container_engine()
        .context("managed dependencies require Podman or Docker")?;
    ensure_network(engine, &config.runtime.network)?;
    for volume in ["nazo_oauth_postgres", "nazo_oauth_valkey"] {
        ensure_volume(engine, volume)?;
    }
    let secrets = config
        .dependencies
        .database_url_file
        .parent()
        .context("dependency secret path has no parent")?
        .join("dependencies");
    ensure_dependency_container(
        engine,
        &config.postgres.container_name,
        Process::new(engine)
            .args([
                "run",
                "-d",
                "--name",
                config.postgres.container_name.as_str(),
            ])
            .args([
                "--label",
                "io.nazoauth.managed=true",
                "--restart",
                "unless-stopped",
                "--network",
                config.runtime.network.as_str(),
                "-e",
                "POSTGRES_DB=oauth",
                "-e",
                "POSTGRES_USER=nazoauth_migrator",
                "-e",
                "POSTGRES_PASSWORD_FILE=/run/nazoauth-secrets/postgres-password",
                "-v",
                "nazo_oauth_postgres:/var/lib/postgresql",
                "-v",
            ])
            .arg(format!(
                "{}:/run/nazoauth-secrets/postgres-password:ro,Z",
                secrets.join("postgres-password").display()
            ))
            .arg(&config.postgres.image),
    )?;
    ensure_dependency_container(
        engine,
        &config.valkey.container_name,
        Process::new(engine)
            .args(["run", "-d", "--name", config.valkey.container_name.as_str()])
            .args([
                "--label",
                "io.nazoauth.managed=true",
                "--restart",
                "unless-stopped",
                "--network",
                config.runtime.network.as_str(),
                "-v",
                "nazo_oauth_valkey:/data",
                "-v",
            ])
            .arg(format!(
                "{}:/run/nazoauth-secrets/valkey-password:ro,Z",
                secrets.join("valkey-password").display()
            ))
            .arg("-v")
            .arg(format!(
                "{}:/run/nazoauth-secrets/valkey.acl:ro,Z",
                secrets.join("valkey.acl").display()
            ))
            .arg(&config.valkey.image)
            .args([
                "valkey-server",
                "--aclfile",
                "/run/nazoauth-secrets/valkey.acl",
                "--appendonly",
                "yes",
                "--dir",
                "/data",
            ]),
    )?;
    wait_dependencies(config)?;
    configure_managed_database_roles(config)
}

pub(crate) fn install_systemd(config: &UpdateConfig) -> anyhow::Result<()> {
    if config.runtime.engine != "host" {
        return Ok(());
    }
    if !Process::new("id")
        .args(["-u", config.runtime.service_user.as_str()])
        .succeeds()
    {
        Process::new("useradd")
            .args([
                "--system",
                "--home",
                config.runtime.working_directory.to_string_lossy().as_ref(),
                "--shell",
                "/usr/sbin/nologin",
                config.runtime.service_user.as_str(),
            ])
            .run_quiet()?;
    }
    let config_dir = &config.runtime.working_directory;
    let secrets_dir = config_dir.join("secrets");
    Process::new("chown")
        .arg(format!("root:{}", config.runtime.service_user))
        .arg(config_dir)
        .arg(config_dir.join(".env.yaml"))
        .arg(&secrets_dir)
        .run_quiet()?;
    set_mode(config_dir, 0o750)?;
    set_mode(&secrets_dir, 0o750)?;
    set_mode(&config_dir.join(".env.yaml"), 0o440)?;
    let operator_dir = config
        .operator
        .controller_public_key
        .parent()
        .context("operator directory is unavailable")?;
    Process::new("chown")
        .arg(format!("root:{}", config.runtime.service_user))
        .arg(operator_dir)
        .run_quiet()?;
    set_mode(operator_dir, 0o750)?;
    for entry in fs::read_dir(&secrets_dir)? {
        let path = entry?.path();
        if path.file_name().is_some_and(|name| name == "dependencies") {
            Process::new("chown")
                .arg("root:root")
                .arg(&path)
                .run_quiet()?;
            set_mode(&path, 0o700)?;
            continue;
        }
        Process::new("chown")
            .arg(format!("root:{}", config.runtime.service_user))
            .arg(&path)
            .run_quiet()?;
        let runtime_readable =
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    matches!(name, "database-url" | "valkey-url")
                        || STANDARDS_PROFILE_SECRET_NAMES.contains(&name)
                });
        if !runtime_readable {
            Process::new("chown")
                .arg("root:root")
                .arg(&path)
                .run_quiet()?;
        }
        set_mode(&path, if runtime_readable { 0o440 } else { 0o600 })?;
    }
    Process::new("chown")
        .arg("root:root")
        .arg(&config.operator.receipt_private_key)
        .run_quiet()?;
    set_mode(&config.operator.receipt_private_key, 0o600)?;
    if let Some(app_root) = config
        .runtime
        .snapshot_paths
        .first()
        .and_then(|path| path.parent())
    {
        Process::new("chown")
            .arg("-R")
            .arg(format!(
                "{}:{}",
                config.runtime.service_user, config.runtime.service_user
            ))
            .arg(app_root)
            .run_quiet()?;
    }
    let unit_dir = env::var_os("NAZOAUTH_SYSTEMD_UNIT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"));
    safe_absolute(&unit_dir)?;
    create_directory(&unit_dir, 0o755)?;
    let unit_path = unit_dir.join(&config.runtime.service_name);
    if unit_path.exists() {
        let current = fs::read_to_string(&unit_path)?;
        if !current.starts_with("# Managed by nazoauthctl\n") {
            bail!(
                "refusing to replace an unmanaged systemd unit: {}",
                unit_path.display()
            );
        }
    }
    let app_root = config
        .runtime
        .snapshot_paths
        .first()
        .and_then(|path| path.parent())
        .context("host runtime has no application data root")?;
    let data_root = app_root
        .parent()
        .context("host runtime has no deployment data root")?;
    let operator_dir = config
        .operator
        .controller_public_key
        .parent()
        .context("host runtime has no operator directory")?;
    let unit = HostSystemdUnit {
        user: &config.runtime.service_user,
        working: &config.runtime.working_directory,
        binary: &config.runtime.binary_path,
        app_root,
        ui_releases: &data_root.join("ui-releases"),
        operator_state: &config.operator.state_directory,
        operator_dir,
        migration_url: &config.dependencies.migration_database_url_file,
    }
    .render();
    atomic_write(&unit_path, unit.as_bytes(), 0o644)?;
    Process::new("systemctl").arg("daemon-reload").run_quiet()?;
    Process::new("systemctl")
        .args(["enable", config.runtime.service_name.as_str()])
        .run_quiet()
}

struct HostSystemdUnit<'a> {
    user: &'a str,
    working: &'a Path,
    binary: &'a Path,
    app_root: &'a Path,
    ui_releases: &'a Path,
    operator_state: &'a Path,
    operator_dir: &'a Path,
    migration_url: &'a Path,
}

impl HostSystemdUnit<'_> {
    fn render(&self) -> String {
        format!(
            "# Managed by nazoauthctl\n\
         [Unit]\n\
         Description=NazoAuth authorization server\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         Group={user}\n\
         WorkingDirectory={working}\n\
         ExecStart={binary} server\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         NoNewPrivileges=true\n\
         PrivateTmp=true\n\
         PrivateDevices=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectControlGroups=true\n\
         RestrictSUIDSGID=true\n\
         LockPersonality=true\n\
         CapabilityBoundingSet=\n\
         AmbientCapabilities=\n\
         ReadWritePaths={keys} {avatars} {secrets} {bootstrap}\n\
         ReadOnlyPaths={ui_releases}\n\
         InaccessiblePaths={operator_state} {operator_dir} {migration_url}\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
            user = self.user,
            working = self.working.display(),
            binary = self.binary.display(),
            keys = self.app_root.join("keys").display(),
            avatars = self.app_root.join("avatars").display(),
            secrets = self.app_root.join("secrets").display(),
            bootstrap = self.app_root.join("bootstrap").display(),
            ui_releases = self.ui_releases.display(),
            operator_state = self.operator_state.display(),
            operator_dir = self.operator_dir.display(),
            migration_url = self.migration_url.display(),
        )
    }
}

fn normalize_external_dependencies(options: &mut InstallOptions) -> anyhow::Result<()> {
    if !options.external_dependencies && (options.secrets_stdin || options.secret_fd.is_some()) {
        bail!("secure dependency secret input requires --external-dependencies");
    }
    if options.secrets_stdin && options.secret_fd.is_some() {
        bail!("choose exactly one of --secrets-stdin or --secret-fd");
    }
    if options.external_dependencies {
        if options.secrets_stdin {
            read_external_dependency_secrets(options, std::io::stdin().lock())?;
        } else if options.secret_fd.is_some() {
            #[cfg(unix)]
            {
                let fd = options.secret_fd.context("secret FD is unavailable")?;
                let file = fs::File::open(format!("/proc/self/fd/{fd}"))?;
                read_external_dependency_secrets(options, file)?;
            }
            #[cfg(not(unix))]
            bail!("--secret-fd requires Linux");
        } else {
            options.database_url = Some(rpassword::prompt_password("PostgreSQL runtime URL: ")?);
            options.migration_database_url =
                Some(rpassword::prompt_password("PostgreSQL migration URL: ")?);
            options.valkey_url = Some(rpassword::prompt_password("Valkey URL: ")?);
        }
    }
    if (options.database_url.is_some()
        || options.migration_database_url.is_some()
        || options.valkey_url.is_some())
        && (options.database_url.is_none()
            || options.migration_database_url.is_none()
            || options.valkey_url.is_none())
    {
        bail!(
            "external dependencies require runtime PostgreSQL, migration PostgreSQL, and Valkey URLs"
        );
    }
    if let Some(database) = &options.database_url {
        validate_dependency_url(database, &["postgres", "postgresql"], "PostgreSQL")?;
        validate_dependency_url(
            options
                .migration_database_url
                .as_deref()
                .unwrap_or_default(),
            &["postgres", "postgresql"],
            "PostgreSQL migration",
        )?;
        validate_dependency_url(
            options.valkey_url.as_deref().unwrap_or_default(),
            &["redis", "rediss"],
            "Valkey",
        )?;
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalDependencySecrets {
    database_url: String,
    migration_database_url: String,
    valkey_url: String,
}

fn read_external_dependency_secrets(
    options: &mut InstallOptions,
    mut source: impl std::io::Read,
) -> anyhow::Result<()> {
    let mut bytes = Vec::new();
    source
        .by_ref()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        bail!("dependency secret input exceeds 64 KiB");
    }
    let secrets: ExternalDependencySecrets =
        serde_json::from_slice(&bytes).context("dependency secret input must be strict JSON")?;
    options.database_url = Some(secrets.database_url);
    options.migration_database_url = Some(secrets.migration_database_url);
    options.valkey_url = Some(secrets.valkey_url);
    Ok(())
}

fn select_runtime(options: &InstallOptions) -> anyhow::Result<(String, String)> {
    let runtime = match options.runtime.as_str() {
        "auto" => {
            if command_exists("podman") {
                "podman"
            } else if command_exists("docker") {
                "docker"
            } else {
                bail!("auto runtime requires Podman or Docker");
            }
        }
        explicit => explicit,
    }
    .to_owned();
    if matches!(runtime.as_str(), "podman" | "docker") {
        if !command_exists(&runtime) {
            bail!("required command is missing: {runtime}");
        }
        return Ok((runtime.clone(), runtime));
    }
    for command in ["systemctl", "systemd-run", "systemd"] {
        if !command_exists(command) {
            bail!("required command is missing: {command}");
        }
    }
    if !test_mode() {
        let version = parse_systemd_version(&Process::new("systemd").arg("--version").stdout()?)?;
        if version < 247 {
            bail!("host runtime requires systemd 247 or newer for transient credentials");
        }
    }
    if options.database_url.is_some() {
        return Ok((runtime, String::new()));
    }
    let engine = if command_exists("podman") {
        "podman"
    } else if command_exists("docker") {
        "docker"
    } else {
        bail!("host runtime requires Podman or Docker for managed dependencies");
    };
    Ok((runtime, engine.to_owned()))
}

fn write_external_urls(secrets: &Path, options: &InstallOptions) -> anyhow::Result<String> {
    atomic_write(
        &secrets.join("database-migration-url"),
        options
            .migration_database_url
            .as_deref()
            .context("missing PostgreSQL migration URL")?
            .as_bytes(),
        0o440,
    )?;
    atomic_write(
        &secrets.join("database-url"),
        options
            .database_url
            .as_deref()
            .context("missing PostgreSQL URL")?
            .as_bytes(),
        0o440,
    )?;
    atomic_write(
        &secrets.join("valkey-url"),
        options
            .valkey_url
            .as_deref()
            .context("missing Valkey URL")?
            .as_bytes(),
        0o440,
    )?;
    Ok("external".to_owned())
}

fn write_managed_secrets(secrets: &Path) -> anyhow::Result<String> {
    let dependencies = secrets.join("dependencies");
    create_directory(&dependencies, 0o700)?;
    let postgres = generate_secret(&dependencies.join("postgres-password"))?;
    let runtime_postgres = generate_secret(&dependencies.join("postgres-runtime-password"))?;
    let valkey = generate_secret(&dependencies.join("valkey-password"))?;
    // Dependency containers use fixed internal UIDs unrelated to host groups.
    // The dependency-only parent remains root-owned 0700, and these bind mounts
    // are read-only in their containers, so runtime users cannot traverse to them.
    set_mode(&dependencies.join("postgres-password"), 0o444)?;
    set_mode(&dependencies.join("valkey-password"), 0o444)?;
    atomic_write(
        &secrets.join("database-url"),
        format!("postgresql://nazoauth_runtime:{runtime_postgres}@nazo-oauth-postgres:5432/oauth")
            .as_bytes(),
        0o440,
    )?;
    atomic_write(
        &secrets.join("database-migration-url"),
        format!("postgresql://nazoauth_migrator:{postgres}@nazo-oauth-postgres:5432/oauth")
            .as_bytes(),
        0o440,
    )?;
    atomic_write(
        &secrets.join("valkey-url"),
        format!("redis://default:{valkey}@nazo-oauth-valkey:6379/0").as_bytes(),
        0o440,
    )?;
    atomic_write(
        &dependencies.join("valkey.acl"),
        format!("user default on >{valkey} ~* &* +@all\n").as_bytes(),
        0o444,
    )?;
    Ok("managed".to_owned())
}

fn write_server_config(
    config_dir: &Path,
    options: &InstallOptions,
    runtime: &str,
    data_root: &Path,
    trusted_proxy_cidr: Option<&str>,
    profile: Option<&str>,
) -> anyhow::Result<()> {
    let target = config_dir.join(".env.yaml");
    if target.exists() {
        if !target.is_file() || target.is_symlink() || fs::metadata(&target)?.len() == 0 {
            bail!(
                "existing server configuration is invalid: {}",
                target.display()
            );
        }
        return Ok(());
    }
    let (bind, data_dir, ui_dir, dependency_files) = if runtime == "host" {
        (
            format!("127.0.0.1:{}", options.port),
            data_root.join("app").display().to_string(),
            data_root.join("ui-releases/current").display().to_string(),
            format!(
                "DATABASE_URL_FILE: \"{}\"\nVALKEY_URL_FILE: \"{}\"\n",
                config_dir.join("secrets/database-url").display(),
                config_dir.join("secrets/valkey-url").display()
            ),
        )
    } else {
        (
            "0.0.0.0:8000".to_owned(),
            "/var/lib/nazo_oauth".to_owned(),
            "/var/lib/nazo_oauth/ui-releases/current".to_owned(),
            String::new(),
        )
    };
    let profile_secret_root = if runtime == "host" {
        config_dir.join("secrets").display().to_string()
    } else {
        "/run/nazoauth-secrets".to_owned()
    };
    let profile_app_root = if runtime == "host" {
        data_root.join("app").display().to_string()
    } else {
        "/var/lib/nazo_oauth".to_owned()
    };
    let content = format!(
        "# Generated by nazoauthctl install. Explicit operator overrides are preserved.\n\
         BIND: \"{bind}\"\n\
         PUBLIC_BASE_URL: \"{public_url}\"\n\
         DATABASE_MAX_CONNECTIONS: 32\n\
         DATA_DIR: \"{data_dir}\"\n\
         UI_STATIC_DIR: \"{ui_dir}\"\n\
         RUST_LOG: \"info\"\n\
         {dependency_files}{profile}",
        public_url = options.public_url,
        profile = profile
            .unwrap_or_default()
            .replace(
                "${TRUSTED_PROXY_CIDR}",
                trusted_proxy_cidr.unwrap_or_default(),
            )
            .replace("${PROFILE_SECRET_ROOT}", &profile_secret_root,)
            .replace("${PROFILE_APP_ROOT}", &profile_app_root),
    );
    atomic_write(&target, content.as_bytes(), 0o640)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StandardsFullProfileMaterial {
    client_attestation_issuer: String,
    client_attestation_jwks: serde_json::Value,
    key_attestation_jwks: serde_json::Value,
    credential_configurations: serde_json::Value,
    wallet_authorization_origins: Vec<String>,
    ciba_notification_private_origins: Vec<String>,
    backchannel_logout_private_origins: Vec<String>,
    trust_anchors_pem: String,
}

fn write_install_profile(
    config_dir: &Path,
    app_root: &Path,
    options: &InstallOptions,
) -> anyhow::Result<Option<String>> {
    if options.profile == "baseline" {
        return Ok(None);
    }
    let source = options
        .profile_material
        .as_deref()
        .context("standards-full profile material is unavailable")?;
    safe_absolute(source)?;
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("failed to inspect profile material {}", source.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 256 * 1024 {
        bail!("profile material must be a regular file no larger than 256 KiB");
    }
    let material: StandardsFullProfileMaterial = serde_json::from_slice(&fs::read(source)?)
        .context("standards-full profile material must be strict JSON")?;
    validate_https_origin(
        &material.client_attestation_issuer,
        "client attestation issuer",
    )?;
    validate_public_jwks(&material.client_attestation_jwks, "client attestation JWKS")?;
    validate_public_jwks(&material.key_attestation_jwks, "key attestation JWKS")?;
    let credential_configurations = material
        .credential_configurations
        .as_object()
        .filter(|value| !value.is_empty())
        .context("credential configurations must be a non-empty object")?;
    if credential_configurations
        .keys()
        .any(|key| key.trim().is_empty())
    {
        bail!("credential configuration identifiers must not be empty");
    }
    for (name, origins) in [
        (
            "wallet authorization",
            &material.wallet_authorization_origins,
        ),
        (
            "CIBA notification",
            &material.ciba_notification_private_origins,
        ),
        (
            "back-channel logout",
            &material.backchannel_logout_private_origins,
        ),
    ] {
        if origins.is_empty() {
            bail!("{name} origins must not be empty");
        }
        for origin in origins {
            validate_https_origin(origin, &format!("{name} origin"))?;
        }
    }
    for (name, pem) in [("trust anchors", &material.trust_anchors_pem)] {
        if !pem.contains("-----BEGIN CERTIFICATE-----")
            || !pem.contains("-----END CERTIFICATE-----")
            || pem.contains("PRIVATE KEY")
        {
            bail!("{name} must contain certificates and no private key material");
        }
    }

    let keys = app_root.join("keys");
    atomic_write(
        &keys.join("openid4vc-trust-anchors.pem"),
        material.trust_anchors_pem.as_bytes(),
        0o440,
    )?;
    let secrets = config_dir.join("secrets");
    for name in [
        "dynamic-registration-token",
        "ciba-decision-token",
        "openid4vci-management-token",
        "openid4vp-management-token",
    ] {
        generate_secret(&secrets.join(name))?;
    }
    let encryption_key_path = secrets.join("openid4vc-data-encryption-key");
    if !encryption_key_path.exists() {
        let value = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        atomic_write(&encryption_key_path, value.as_bytes(), 0o440)?;
    }
    let encryption_key = fs::read_to_string(&encryption_key_path)?;
    if encryption_key.contains(['\n', '\r'])
        || URL_SAFE_NO_PAD
            .decode(&encryption_key)
            .ok()
            .is_none_or(|decoded| decoded.len() != 32)
    {
        bail!("persisted OpenID4VC data encryption key is invalid");
    }

    let scalar = |value: &str| serde_json::to_string(value).expect("serialize YAML scalar");
    let lines = [
        "ENABLE_REQUEST_OBJECT: true".to_owned(),
        "ENABLE_PAR_REQUEST_OBJECT: true".to_owned(),
        "ENABLE_AUTHORIZATION_DETAILS: true".to_owned(),
        "ENABLE_DEVICE_AUTHORIZATION_GRANT: true".to_owned(),
        "ENABLE_DYNAMIC_CLIENT_REGISTRATION: true".to_owned(),
        "ENABLE_CIBA: true".to_owned(),
        "ENABLE_FRONTCHANNEL_LOGOUT: true".to_owned(),
        "ENABLE_SESSION_MANAGEMENT: true".to_owned(),
        "ENABLE_NATIVE_SSO: true".to_owned(),
        "ENABLE_OPENID4VCI_ISSUER: true".to_owned(),
        "ENABLE_OPENID4VP_VERIFIER: true".to_owned(),
        format!(
            "MTLS_ENDPOINT_BASE_URL: {}",
            scalar(options.public_url.trim_end_matches('/'))
        ),
        "TRUSTED_PROXY_CIDRS: \"${TRUSTED_PROXY_CIDR}\"".to_owned(),
        "MTLS_CERTIFICATE_SOURCE: \"legacy-verified-headers\"".to_owned(),
        "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/dynamic-registration-token\"".to_owned(),
        "CIBA_AUTOMATED_DECISION_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/ciba-decision-token\"".to_owned(),
        "OPENID4VC_DATA_ENCRYPTION_KEY_FILE: \"${PROFILE_SECRET_ROOT}/openid4vc-data-encryption-key\"".to_owned(),
        "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/openid4vci-management-token\"".to_owned(),
        "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN_FILE: \"${PROFILE_SECRET_ROOT}/openid4vp-management-token\"".to_owned(),
        "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE: \"${PROFILE_APP_ROOT}/keys/openid4vc-signing-chain.pem\"".to_owned(),
        "OPENID4VC_TRUST_ANCHORS_FILE: \"${PROFILE_APP_ROOT}/keys/openid4vc-trust-anchors.pem\"".to_owned(),
        format!(
            "OPENID4VC_CLIENT_ATTESTATION_ISSUER: {}",
            scalar(&material.client_attestation_issuer)
        ),
        format!(
            "OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON: {}",
            scalar(&serde_json::to_string(&material.client_attestation_jwks)?)
        ),
        format!(
            "OPENID4VC_KEY_ATTESTATION_JWKS_JSON: {}",
            scalar(&serde_json::to_string(&material.key_attestation_jwks)?)
        ),
        format!(
            "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON: {}",
            scalar(&serde_json::to_string(&material.credential_configurations)?)
        ),
        format!(
            "OPENID4VP_WALLET_AUTHORIZATION_ORIGINS: {}",
            scalar(&material.wallet_authorization_origins.join(","))
        ),
        format!(
            "CIBA_NOTIFICATION_PRIVATE_ORIGINS: {}",
            scalar(&material.ciba_notification_private_origins.join(","))
        ),
        format!(
            "BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS: {}",
            scalar(&material.backchannel_logout_private_origins.join(","))
        ),
    ];
    Ok(Some(format!("{}\n", lines.join("\n"))))
}

fn validate_https_origin(value: &str, label: &str) -> anyhow::Result<()> {
    let parsed = Url::parse(value).with_context(|| format!("invalid {label}"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || parsed.path() != "/"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("{label} must be an HTTPS origin without credentials, path, query or fragment");
    }
    Ok(())
}

fn validate_public_jwks(value: &serde_json::Value, label: &str) -> anyhow::Result<()> {
    let keys = value
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .filter(|keys| !keys.is_empty())
        .with_context(|| format!("{label} must contain a non-empty keys array"))?;
    const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if keys.iter().any(|key| {
        key.as_object().is_none_or(|object| {
            PRIVATE_MEMBERS
                .iter()
                .any(|name| object.contains_key(*name))
        })
    }) {
        bail!("{label} must contain public asymmetric keys only");
    }
    Ok(())
}

fn network_gateway(engine: &str, network: &str) -> anyhow::Result<std::net::IpAddr> {
    let document: serde_json::Value = serde_json::from_str(
        &Process::new(engine)
            .args(["network", "inspect", network])
            .stdout()?,
    )
    .context("container network inspection is not valid JSON")?;
    fn find(value: &serde_json::Value) -> Option<std::net::IpAddr> {
        match value {
            serde_json::Value::Object(object) => object.iter().find_map(|(key, value)| {
                if key.eq_ignore_ascii_case("gateway") {
                    value.as_str().and_then(|value| value.parse().ok())
                } else {
                    find(value)
                }
            }),
            serde_json::Value::Array(values) => values.iter().find_map(find),
            _ => None,
        }
    }
    find(&document).context("container network has no inspectable gateway")
}

fn host_cidr(address: std::net::IpAddr) -> String {
    match address {
        std::net::IpAddr::V4(address) => format!("{address}/32"),
        std::net::IpAddr::V6(address) => format!("{address}/128"),
    }
}

fn build_config(
    config_path: &Path,
    options: &InstallOptions,
    runtime_engine: &str,
    dependency_engine: &str,
    dependency_mode: &str,
) -> anyhow::Result<UpdateConfig> {
    let config_dir = config_path.parent().context("config has no parent")?;
    let secrets = config_dir.join("secrets");
    let app = options.data_root.join("app");
    let updater = env::var_os("NAZOAUTH_UPDATER_INSTALL_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/sbin/nazoauthctl"));
    let binary = env::var_os("NAZOAUTH_BINARY_INSTALL_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin/nazoauth"));
    let releases = env::var_os("NAZOAUTH_BINARY_RELEASES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/opt/nazoauth/releases"));
    let container = runtime_engine != "host";
    let mut mounts = if container {
        vec![
            mount(config_dir.join(".env.yaml"), "/app/.env.yaml", "ro,Z"),
            mount(app.join("keys"), "/var/lib/nazo_oauth/keys", "rw,Z"),
            mount(app.join("avatars"), "/var/lib/nazo_oauth/avatars", "rw,Z"),
            mount(app.join("secrets"), "/var/lib/nazo_oauth/secrets", "rw,Z"),
            mount(
                app.join("bootstrap"),
                "/var/lib/nazo_oauth/bootstrap",
                "rw,Z",
            ),
            mount(
                options.data_root.join("ui-releases"),
                "/var/lib/nazo_oauth/ui-releases",
                "ro,Z",
            ),
            mount(
                secrets.join("database-url"),
                "/run/nazoauth-secrets/database-url",
                "ro,Z",
            ),
            mount(
                secrets.join("valkey-url"),
                "/run/nazoauth-secrets/valkey-url",
                "ro,Z",
            ),
        ]
    } else {
        Vec::new()
    };
    if container && options.profile == "standards-full" {
        mounts.extend(STANDARDS_PROFILE_SECRET_NAMES.iter().map(|name| {
            mount(
                secrets.join(name),
                &format!("/run/nazoauth-secrets/{name}"),
                "ro,Z",
            )
        }));
    }
    let environment = if container {
        BTreeMap::from([
            (
                "DATABASE_URL_FILE".to_owned(),
                "/run/nazoauth-secrets/database-url".to_owned(),
            ),
            (
                "VALKEY_URL_FILE".to_owned(),
                "/run/nazoauth-secrets/valkey-url".to_owned(),
            ),
        ])
    } else {
        BTreeMap::new()
    };
    let publish_address = if container {
        format!("127.0.0.1:{}:8000", options.port)
    } else {
        String::new()
    };
    let (service_name, service_user, binary_path, binary_releases, working_directory) = if container
    {
        (
            String::new(),
            String::new(),
            PathBuf::new(),
            PathBuf::new(),
            PathBuf::new(),
        )
    } else {
        (
            "nazoauth.service".to_owned(),
            "nazoauth".to_owned(),
            binary,
            releases,
            config_dir.to_owned(),
        )
    };
    let valkey_password_file = if dependency_mode == "managed" {
        PathBuf::from("/run/nazoauth-secrets/valkey-password")
    } else {
        PathBuf::new()
    };
    let config = UpdateConfig {
        schema: 2,
        managed_install: true,
        install_profile: options.profile.clone(),
        repository: "nazozero/NazoAuth".to_owned(),
        updater_install_path: updater,
        backup_root: options.data_root.join("backups"),
        deployment_root: options.data_root.join("deployments"),
        operator: operator_config(config_dir, &options.data_root)?,
        dependencies: Dependencies {
            mode: dependency_mode.to_owned(),
            database_url_file: secrets.join("database-url"),
            migration_database_url_file: secrets.join("database-migration-url"),
            valkey_url_file: secrets.join("valkey-url"),
        },
        runtime: Runtime {
            engine: runtime_engine.to_owned(),
            dependency_engine: dependency_engine.to_owned(),
            container_name: "nazo-oauth-server".to_owned(),
            network: "nazo_oauth_net".to_owned(),
            ip_address: String::new(),
            publish_address,
            health_url: format!("http://127.0.0.1:{}/ready", options.port),
            readiness_attempts: 60,
            readiness_interval_seconds: 1,
            public_discovery_url: format!(
                "{}/.well-known/openid-configuration",
                options.public_url.trim_end_matches('/')
            ),
            expected_issuer: options.public_url.trim_end_matches('/').to_owned(),
            mounts,
            snapshot_paths: vec![app.join("keys"), app.join("secrets"), app.join("bootstrap")],
            environment,
            service_name,
            service_user,
            binary_path,
            binary_releases,
            working_directory,
        },
        postgres: Postgres {
            container_name: "nazo-oauth-postgres".to_owned(),
            database: "oauth".to_owned(),
            user: "nazoauth_migrator".to_owned(),
            image: POSTGRES_IMAGE.to_owned(),
            validation_image: POSTGRES_IMAGE.to_owned(),
        },
        valkey: Valkey {
            container_name: "nazo-oauth-valkey".to_owned(),
            image: VALKEY_IMAGE.to_owned(),
            rdb_path: "/data/dump.rdb".to_owned(),
            password_file: valkey_password_file,
        },
        ui: Ui {
            active_path: options.data_root.join("ui-releases/current"),
            releases_root: options.data_root.join("ui-releases"),
            serve_from_application: true,
        },
    };
    config.validate()?;
    Ok(config)
}

fn operator_config(config_dir: &Path, data_root: &Path) -> anyhow::Result<Operator> {
    let directory = config_dir.join("operator");
    let deployment_id = fs::read_to_string(directory.join("deployment-id"))?;
    let controller_key_id = fs::read_to_string(directory.join("controller.kid"))?;
    let receipt_key_id = fs::read_to_string(directory.join("receipt.kid"))?;
    let audit_key_id = fs::read_to_string(directory.join("audit.kid"))?;
    let break_glass_key_id = fs::read_to_string(directory.join("break-glass.kid"))?;
    Ok(Operator {
        deployment_id,
        controller_key_id,
        controller_private_key: directory.join("controller.key"),
        controller_public_key: directory.join("controller.pub"),
        receipt_key_id,
        receipt_private_key: directory.join("receipt.key"),
        receipt_public_key: directory.join("receipt.pub"),
        audit_key_id,
        audit_private_key: directory.join("audit.key"),
        audit_public_key: directory.join("audit.pub"),
        break_glass_key_id,
        break_glass_private_key: directory.join("break-glass.key"),
        break_glass_public_key: directory.join("break-glass.pub"),
        secret_revision_file: directory.join("secret-revision"),
        state_directory: data_root.join("app/operator-state"),
        audit_directory: data_root.join("audit"),
        trust_state_file: directory.join("release-trust.json"),
    })
}

fn write_operator_identities(directory: &Path) -> anyhow::Result<()> {
    let deployment_path = directory.join("deployment-id");
    if !deployment_path.exists() {
        atomic_write(
            &deployment_path,
            format!("deployment-{}", encode_hex(&rand::random::<[u8; 16]>())).as_bytes(),
            0o400,
        )?;
    }
    let secret_revision = directory.join("secret-revision");
    if !secret_revision.exists() {
        atomic_write(
            &secret_revision,
            format!("secret-{}", encode_hex(&rand::random::<[u8; 16]>())).as_bytes(),
            0o400,
        )?;
    }
    for name in ["controller", "receipt", "audit", "break-glass"] {
        write_operator_keypair(directory, name)?;
    }
    Ok(())
}

fn write_operator_keypair(directory: &Path, name: &str) -> anyhow::Result<()> {
    let private_path = directory.join(format!("{name}.key"));
    let public_path = directory.join(format!("{name}.pub"));
    let kid_path = directory.join(format!("{name}.kid"));
    if private_path.exists() || public_path.exists() || kid_path.exists() {
        if private_path.is_file() && public_path.is_file() && kid_path.is_file() {
            return Ok(());
        }
        bail!("incomplete operator keypair requires review: {name}");
    }
    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let public = key.verifying_key().to_bytes();
    let digest = Sha256::digest(public);
    let kid = format!("{name}-{}", encode_hex(&digest[..8]));
    atomic_write(
        &private_path,
        URL_SAFE_NO_PAD.encode(key.to_bytes()).as_bytes(),
        0o400,
    )?;
    atomic_write(
        &public_path,
        URL_SAFE_NO_PAD.encode(public).as_bytes(),
        0o444,
    )?;
    atomic_write(&kid_path, kid.as_bytes(), 0o444)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn mount(source: PathBuf, target: &str, mode: &str) -> Mount {
    Mount {
        source,
        target: PathBuf::from(target),
        mode: mode.to_owned(),
    }
}

fn ensure_network(engine: &str, name: &str) -> anyhow::Result<()> {
    if Process::new(engine)
        .args(["network", "inspect", name])
        .succeeds()
    {
        assert_managed_label(engine, &["network", "inspect", name])?;
        return Ok(());
    }
    Process::new(engine)
        .args([
            "network",
            "create",
            "--label",
            "io.nazoauth.managed=true",
            name,
        ])
        .run_quiet()
}

fn ensure_volume(engine: &str, name: &str) -> anyhow::Result<()> {
    if Process::new(engine)
        .args(["volume", "inspect", name])
        .succeeds()
    {
        assert_managed_label(engine, &["volume", "inspect", name])?;
        return Ok(());
    }
    Process::new(engine)
        .args([
            "volume",
            "create",
            "--label",
            "io.nazoauth.managed=true",
            name,
        ])
        .run_quiet()
}

fn assert_managed_label(engine: &str, prefix: &[&str]) -> anyhow::Result<()> {
    for format in [
        "{{index .Config.Labels \"io.nazoauth.managed\"}}",
        "{{index .Labels \"io.nazoauth.managed\"}}",
    ] {
        let value = Process::new(engine)
            .args(prefix)
            .args(["--format", format])
            .stdout();
        if value.is_ok_and(|value| value.trim() == "true") {
            return Ok(());
        }
    }
    bail!("refusing to manage an unlabelled existing runtime object")
}

fn ensure_dependency_container(engine: &str, name: &str, create: Process) -> anyhow::Result<()> {
    if Process::new(engine).args(["inspect", name]).succeeds() {
        assert_managed_label(engine, &["inspect", name])?;
        return Process::new(engine).args(["start", name]).run_quiet();
    }
    create.run_quiet()
}

fn wait_dependencies(config: &UpdateConfig) -> anyhow::Result<()> {
    let engine = config
        .container_engine()
        .context("managed dependencies require a container engine")?;
    for _ in 0..60 {
        let postgres = Process::new(engine)
            .args([
                "exec",
                config.postgres.container_name.as_str(),
                "pg_isready",
                "-U",
                config.postgres.user.as_str(),
                "-d",
                config.postgres.database.as_str(),
            ])
            .succeeds();
        let valkey = Process::new(engine)
            .args([
                "exec",
                config.valkey.container_name.as_str(),
                "sh",
                "-eu",
                "-c",
                "cat /run/nazoauth-secrets/valkey-password | valkey-cli --askpass PING",
            ])
            .succeeds();
        if postgres && valkey {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    bail!("managed PostgreSQL or Valkey did not become ready")
}

fn configure_managed_database_roles(config: &UpdateConfig) -> anyhow::Result<()> {
    let engine = config
        .container_engine()
        .context("managed PostgreSQL requires a container engine")?;
    let password_path = config
        .dependencies
        .database_url_file
        .parent()
        .context("managed PostgreSQL secret directory is unavailable")?
        .join("dependencies")
        .join("postgres-runtime-password");
    let password = fs::read_to_string(password_path)?;
    if password.is_empty()
        || !password
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        bail!("managed PostgreSQL runtime password is invalid");
    }
    let sql = format!(
        "DO $$ BEGIN\n\
         IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nazoauth_runtime') THEN\n\
           CREATE ROLE nazoauth_runtime LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;\n\
         ELSE\n\
           ALTER ROLE nazoauth_runtime PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;\n\
         END IF;\n\
         END $$;\n\
         REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n\
         REVOKE TEMPORARY ON DATABASE oauth FROM PUBLIC;\n"
    );
    Process::new(engine)
        .args([
            "exec",
            "-i",
            config.postgres.container_name.as_str(),
            "psql",
            "--no-psqlrc",
            "--set",
            "ON_ERROR_STOP=1",
            "-U",
            config.postgres.user.as_str(),
            "-d",
            config.postgres.database.as_str(),
        ])
        .stdin_stdout(sql.as_bytes())?;
    Ok(())
}

pub(crate) fn grant_runtime_database(config: &UpdateConfig) -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if config.dependencies.mode != "managed" {
        return Ok(());
    }
    let engine = config
        .container_engine()
        .context("managed PostgreSQL requires a container engine")?;
    let sql = b"GRANT CONNECT ON DATABASE oauth TO nazoauth_runtime;\n\
        GRANT USAGE ON SCHEMA public TO nazoauth_runtime;\n\
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nazoauth_runtime;\n\
        GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO nazoauth_runtime;\n\
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO nazoauth_runtime;\n\
        ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nazoauth_runtime;\n\
        ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO nazoauth_runtime;\n\
        ALTER DEFAULT PRIVILEGES FOR ROLE nazoauth_migrator IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO nazoauth_runtime;\n";
    Process::new(engine)
        .args([
            "exec",
            "-i",
            config.postgres.container_name.as_str(),
            "psql",
            "--no-psqlrc",
            "--set",
            "ON_ERROR_STOP=1",
            "-U",
            config.postgres.user.as_str(),
            "-d",
            config.postgres.database.as_str(),
        ])
        .stdin_stdout(sql)?;
    Ok(())
}

pub(crate) fn verify_runtime_no_ddl(config: &UpdateConfig) -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if config.dependencies.mode != "managed" {
        eprintln!(
            "doctor: external PostgreSQL privileges are operator-owned and were not modified"
        );
        return Ok(());
    }
    let engine = config
        .container_engine()
        .context("managed PostgreSQL requires a container engine")?;
    let postgres = PostgresProvider::from_url_file(&config.dependencies.database_url_file)?;
    Process::new(engine)
        .args([
            "run",
            "--rm",
            "--network",
            config.runtime.network.as_str(),
            "-e",
            "PGSERVICEFILE=/run/nazoauth-secrets/pg_service.conf",
            "-e",
            "PGPASSFILE=/run/nazoauth-secrets/pgpass",
            "-v",
        ])
        .arg(format!(
            "{}:/run/nazoauth-secrets/pg_service.conf:ro,Z",
            postgres.service_file().display()
        ))
        .arg("-v")
        .arg(format!(
            "{}:/run/nazoauth-secrets/pgpass:ro,Z",
            postgres.password_file().display()
        ))
        .arg(&config.postgres.validation_image)
        .args([
            "sh",
            "-eu",
            "-c",
            "if psql --no-psqlrc --dbname='service=nazoauth' --set ON_ERROR_STOP=1 --command='BEGIN; CREATE TABLE nazoauth_runtime_ddl_probe(id integer); ROLLBACK;'; then echo 'runtime role unexpectedly has persistent DDL permission' >&2; exit 1; fi; if psql --no-psqlrc --dbname='service=nazoauth' --set ON_ERROR_STOP=1 --command='BEGIN; CREATE TEMPORARY TABLE nazoauth_runtime_temp_probe(id integer); ROLLBACK;'; then echo 'runtime role unexpectedly has temporary DDL permission' >&2; exit 1; fi; exit 0",
        ])
        .run_quiet()
}

fn validate_public_url(value: &str) -> anyhow::Result<()> {
    let url = Url::parse(value).context("--public-url must be an absolute HTTP(S) origin")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || (url.path() != "" && url.path() != "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("--public-url must be an absolute HTTP(S) origin");
    }
    Ok(())
}

fn validate_dependency_url(value: &str, schemes: &[&str], name: &str) -> anyhow::Result<()> {
    let parsed = Url::parse(value).with_context(|| format!("{name} URL is invalid"))?;
    if !schemes.contains(&parsed.scheme()) || parsed.host_str().is_none() {
        bail!("{name} URL has an unsupported scheme or no host");
    }
    Ok(())
}

fn parse_systemd_version(output: &str) -> anyhow::Result<u32> {
    let mut fields = output.lines().next().unwrap_or_default().split_whitespace();
    if fields.next() != Some("systemd") {
        bail!("systemd returned an invalid version banner");
    }
    fields
        .next()
        .context("systemd version is unavailable")?
        .parse()
        .context("systemd version is invalid")
}

fn create_directory(path: &Path, mode: u32) -> anyhow::Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create directory {}", path.display()))?;
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!(
            "managed directory must not be a symlink: {}",
            path.display()
        );
    }
    set_mode(path, mode)
}

fn require_linux() -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if std::env::consts::OS != "linux" || std::env::consts::ARCH != "x86_64" {
        bail!("standalone installation currently supports Linux x86_64");
    }
    Ok(())
}

fn require_root() -> anyhow::Result<()> {
    if test_mode() {
        return Ok(());
    }
    if Process::new("id").arg("-u").stdout()?.trim() != "0" {
        bail!("install and update require root");
    }
    Ok(())
}

fn test_mode() -> bool {
    #[cfg(debug_assertions)]
    return env::var_os("NAZOAUTHCTL_TESTING").is_some();
    #[cfg(not(debug_assertions))]
    false
}

#[cfg(test)]
#[path = "../tests/unit/install.rs"]
mod tests;
