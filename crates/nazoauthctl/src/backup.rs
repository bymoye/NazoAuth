use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anyhow::{Context, bail};

const AUTHENTICATED_VALKEY_COMMAND: &str =
    "password_file=\"$1\"; shift; cat \"$password_file\" | valkey-cli --askpass \"$@\"";
use chrono::Utc;
use tar::{Archive, Builder};

use crate::{
    filesystem::{set_mode, sha256},
    model::UpdateConfig,
    process::{Process, command_exists},
    secret_provider::{PostgresProvider, ValkeyProvider},
};

pub(crate) struct Backup {
    path: PathBuf,
}

impl Backup {
    pub(crate) fn open_existing(config: &UpdateConfig, path: &Path) -> anyhow::Result<Self> {
        let root = fs::canonicalize(&config.backup_root)
            .context("failed to resolve configured backup root")?;
        let path = fs::canonicalize(path).context("failed to resolve rollback backup")?;
        if path.parent() != Some(root.as_path()) || !path.is_dir() || path.is_symlink() {
            bail!("rollback backup is outside the configured backup root");
        }
        let backup = Self { path };
        backup.verify_checksums()?;
        Ok(backup)
    }
    pub(crate) fn create(
        config_path: &Path,
        config: &UpdateConfig,
        version: &str,
    ) -> anyhow::Result<Self> {
        fs::create_dir_all(&config.backup_root)
            .with_context(|| format!("failed to create {}", config.backup_root.display()))?;
        let path = allocate_backup_dir(&config.backup_root, version)?;
        let backup = Self { path };
        if config.dependencies.mode == "external" {
            backup.external_dependencies(config)?;
        } else {
            backup.managed_dependencies(config)?;
        }
        fs::copy(config_path, backup.path.join("update-config.json"))
            .context("failed to back up update configuration")?;
        backup.snapshots(config)?;
        backup.write_checksums()?;
        Ok(backup)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn restore_snapshots(&self) -> anyhow::Result<()> {
        let mut index = 0;
        loop {
            let path_file = self.path.join(format!("snapshot-{index}.path"));
            if !path_file.exists() {
                break;
            }
            let target = PathBuf::from(
                fs::read_to_string(&path_file)
                    .with_context(|| format!("failed to read {}", path_file.display()))?
                    .trim(),
            );
            let parent = target
                .parent()
                .context("snapshot target has no parent directory")?;
            let quarantine = parent.join(format!(
                ".{}.failed-{}",
                target
                    .file_name()
                    .context("snapshot target has no file name")?
                    .to_string_lossy(),
                std::process::id()
            ));
            if quarantine.exists() {
                bail!(
                    "snapshot recovery quarantine already exists: {}",
                    quarantine.display()
                );
            }
            if target.exists() {
                fs::rename(&target, &quarantine).with_context(|| {
                    format!("failed to quarantine snapshot target {}", target.display())
                })?;
            }
            let archive_path = self.path.join(format!("snapshot-{index}.tar"));
            let restore = (|| -> anyhow::Result<()> {
                let file = File::open(&archive_path)
                    .with_context(|| format!("failed to open {}", archive_path.display()))?;
                let mut archive = Archive::new(file);
                archive.set_preserve_ownerships(true);
                archive
                    .unpack(parent)
                    .with_context(|| format!("failed to restore {}", target.display()))
            })();
            if restore.is_err() && quarantine.exists() {
                if target.exists() {
                    fs::remove_dir_all(&target).ok();
                }
                fs::rename(&quarantine, &target).ok();
            }
            restore?;
            if quarantine.exists() {
                fs::remove_dir_all(&quarantine).with_context(|| {
                    format!(
                        "failed to remove recovery quarantine {}",
                        quarantine.display()
                    )
                })?;
            }
            index += 1;
        }
        Ok(())
    }

    pub(crate) fn restore_databases(&self, config: &UpdateConfig) -> anyhow::Result<()> {
        self.verify_checksums()?;
        if config.dependencies.mode != "managed" {
            bail!(
                "automatic external database recovery is unavailable; use the provider's documented PostgreSQL and Valkey recovery procedures"
            );
        }
        let engine = config
            .container_engine()
            .context("managed recovery requires a container engine")?;
        let postgres =
            PostgresProvider::from_url_file(&config.dependencies.migration_database_url_file)?;
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
            .arg(format!("{}:/backup:ro,Z", self.path.display()))
            .arg("-v")
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
                "pg_restore",
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-privileges",
                "--dbname=service=nazoauth",
                "/backup/postgresql.dump",
            ])
            .run_quiet()?;
        Process::new(engine)
            .args(["stop", config.valkey.container_name.as_str()])
            .run_quiet()?;
        let restore = Process::new(engine)
            .args(["run", "--rm", "-v", "nazo_oauth_valkey:/data", "-v"])
            .arg(format!("{}:/backup:ro,Z", self.path.display()))
            .arg(&config.valkey.image)
            .args([
                "sh",
                "-eu",
                "-c",
                "test -s /backup/valkey-dump.rdb; rm -rf -- /data/appendonlydir; install -m 600 /backup/valkey-dump.rdb /data/dump.rdb",
            ])
            .run_quiet();
        let restart = Process::new(engine)
            .args(["start", config.valkey.container_name.as_str()])
            .run_quiet();
        restore?;
        restart
    }

    fn external_dependencies(&self, config: &UpdateConfig) -> anyhow::Result<()> {
        for command in ["pg_dump", "pg_restore", "valkey-cli"] {
            if !command_exists(command) {
                bail!("required command is missing: {command}");
            }
        }
        validate_secret(&config.dependencies.database_url_file)?;
        validate_secret(&config.dependencies.valkey_url_file)?;
        let postgres = self.path.join("postgresql.dump");
        let postgres_provider =
            PostgresProvider::from_url_file(&config.dependencies.database_url_file)?;
        Process::new("pg_dump")
            .env("PGSERVICEFILE", postgres_provider.service_file())
            .env("PGPASSFILE", postgres_provider.password_file())
            .args([
                "--dbname=service=nazoauth",
                "--format=custom",
                "--no-owner",
                "--no-privileges",
            ])
            .stdout_file(&postgres)?;
        Process::new("pg_restore")
            .arg("--list")
            .arg(&postgres)
            .run_quiet()?;
        let valkey = self.path.join("valkey-dump.rdb");
        let valkey_provider = ValkeyProvider::from_url_file(&config.dependencies.valkey_url_file)?;
        let mut command = Process::new("valkey-cli")
            .args(["--no-auth-warning", "--askpass", "-h"])
            .arg(&valkey_provider.host)
            .arg("-p")
            .arg(valkey_provider.port.to_string())
            .arg("-n")
            .arg(valkey_provider.database.to_string());
        if let Some(username) = &valkey_provider.username {
            command = command.arg("--user").arg(username);
        }
        if valkey_provider.tls {
            command = command.arg("--tls");
        }
        command = command.arg("--rdb").arg(&valkey);
        command.stdin_stdout(&valkey_provider.password_stdin())?;
        if fs::metadata(&valkey).map_or(true, |metadata| metadata.len() == 0) {
            bail!("external Valkey RDB export is empty");
        }
        Ok(())
    }

    fn managed_dependencies(&self, config: &UpdateConfig) -> anyhow::Result<()> {
        let engine = config
            .container_engine()
            .context("managed dependencies require a container engine")?;
        let postgres = self.path.join("postgresql.dump");
        Process::new(engine)
            .args(["exec", config.postgres.container_name.as_str(), "pg_dump"])
            .args([
                "--format=custom",
                "--no-owner",
                "--no-privileges",
                "-U",
                config.postgres.user.as_str(),
                config.postgres.database.as_str(),
            ])
            .stdout_file(&postgres)?;
        Process::new(engine)
            .args(["run", "--rm", "-v"])
            .arg(format!("{}:/backup:ro", self.path.display()))
            .arg(&config.postgres.validation_image)
            .args(["pg_restore", "--list", "/backup/postgresql.dump"])
            .run_quiet()?;

        let last_save = valkey(config, &["LASTSAVE"])?
            .trim()
            .parse::<u64>()
            .context("Valkey LASTSAVE is not numeric")?;
        valkey(config, &["BGSAVE"])?;
        let mut completed = false;
        for _ in 0..60 {
            let next = valkey(config, &["LASTSAVE"])?
                .trim()
                .parse::<u64>()
                .context("Valkey LASTSAVE is not numeric")?;
            if next > last_save {
                completed = true;
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        if !completed {
            bail!("Valkey BGSAVE did not complete");
        }
        Process::new(engine)
            .args(["cp"])
            .arg(format!(
                "{}:{}",
                config.valkey.container_name, config.valkey.rdb_path
            ))
            .arg(self.path.join("valkey-dump.rdb"))
            .run_quiet()
    }

    fn snapshots(&self, config: &UpdateConfig) -> anyhow::Result<()> {
        for (index, path) in config.runtime.snapshot_paths.iter().enumerate() {
            if !path.is_dir() || path.is_symlink() {
                bail!("snapshot path is not a real directory: {}", path.display());
            }
            let name = path.file_name().context("snapshot path has no file name")?;
            let file = File::create(self.path.join(format!("snapshot-{index}.tar")))
                .context("failed to create snapshot archive")?;
            let mut archive = Builder::new(file);
            archive
                .append_dir_all(name, path)
                .with_context(|| format!("failed to snapshot {}", path.display()))?;
            archive
                .finish()
                .context("failed to finish snapshot archive")?;
            fs::write(
                self.path.join(format!("snapshot-{index}.path")),
                format!("{}\n", path.display()),
            )
            .context("failed to write snapshot path")?;
        }
        Ok(())
    }

    fn write_checksums(&self) -> anyhow::Result<()> {
        let mut entries = fs::read_dir(&self.path)
            .context("failed to enumerate backup")?
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let mut file =
            File::create(self.path.join("SHA256SUMS")).context("failed to create checksums")?;
        for entry in entries {
            if entry.file_type()?.is_file() && entry.file_name() != "SHA256SUMS" {
                writeln!(
                    file,
                    "{}  {}",
                    sha256(&entry.path())?,
                    entry.file_name().to_string_lossy()
                )?;
            }
        }
        file.sync_all()
            .context("failed to persist backup checksums")
    }

    fn verify_checksums(&self) -> anyhow::Result<()> {
        let content = fs::read_to_string(self.path.join("SHA256SUMS"))?;
        if content.is_empty() {
            bail!("backup checksum manifest is empty");
        }
        for line in content.lines() {
            let (expected, name) = line
                .split_once("  ")
                .context("backup checksum entry is invalid")?;
            if name.is_empty()
                || name.starts_with('.')
                || name.contains(['/', '\\'])
                || expected.len() != 64
            {
                bail!("backup checksum entry is unsafe");
            }
            if sha256(&self.path.join(name))? != expected {
                bail!("backup checksum mismatch: {name}");
            }
        }
        Ok(())
    }
}

fn allocate_backup_dir(root: &Path, version: &str) -> anyhow::Result<PathBuf> {
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    for _ in 0..32 {
        let suffix = format!("{:08x}", rand::random::<u32>());
        let path = root.join(format!("{stamp}-before-{version}.{suffix}"));
        match fs::create_dir(&path) {
            Ok(()) => {
                set_mode(&path, 0o700)?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("failed to create backup directory"),
        }
    }
    bail!("failed to allocate a unique backup directory")
}

fn validate_secret(path: &Path) -> anyhow::Result<()> {
    let value = fs::read_to_string(path)
        .with_context(|| format!("failed to read secret {}", path.display()))?;
    if value.is_empty() || value.contains(['\n', '\r']) {
        bail!("secret file is empty or multiline: {}", path.display());
    }
    Ok(())
}

fn valkey(config: &UpdateConfig, arguments: &[&str]) -> anyhow::Result<String> {
    let engine = config
        .container_engine()
        .context("managed dependencies require a container engine")?;
    if config.valkey.password_file.as_os_str().is_empty() {
        return Process::new(engine)
            .args(["exec", config.valkey.container_name.as_str(), "valkey-cli"])
            .args(arguments)
            .stdout();
    }
    let mut command = Process::new(engine)
        .args([
            "exec",
            config.valkey.container_name.as_str(),
            "sh",
            "-eu",
            "-c",
            AUTHENTICATED_VALKEY_COMMAND,
            "_",
        ])
        .arg(&config.valkey.password_file);
    command = command.args(arguments);
    command.stdout()
}

#[cfg(all(test, unix))]
#[path = "../tests/unit/backup.rs"]
mod tests;
