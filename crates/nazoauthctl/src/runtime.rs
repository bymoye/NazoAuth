use std::{ffi::OsString, fs, path::Path, time::Duration};

use anyhow::{Context, bail};
use nazo_operator_protocol::{RuntimeTargetClaim, TaskOperation};

use crate::{
    filesystem::{atomic_write, sha256},
    model::{Mount, UpdateConfig},
    process::Process,
};

#[derive(Debug)]
pub(crate) struct PreparedAppTask {
    process: Process,
    pub(crate) target: RuntimeTargetClaim,
    cleanup: TaskCleanup,
}

#[derive(Debug)]
enum TaskCleanup {
    Container { engine: String, name: String },
    SystemdUnit(String),
}

impl PreparedAppTask {
    pub(crate) fn execute(&self, compact_envelope: &str) -> anyhow::Result<String> {
        let result = self.process.stdin_stdout(compact_envelope.as_bytes());
        if result.is_err() {
            self.cleanup();
        }
        result
    }

    fn cleanup(&self) {
        match &self.cleanup {
            TaskCleanup::Container { engine, name } => {
                Process::new(engine)
                    .args(["rm", "-f", name])
                    .timeout(Duration::from_secs(30))
                    .run_quiet()
                    .ok();
            }
            TaskCleanup::SystemdUnit(unit) => {
                Process::new("systemctl")
                    .args(["stop", unit])
                    .timeout(Duration::from_secs(30))
                    .run_quiet()
                    .ok();
            }
        }
    }
}

pub(crate) struct Runtime<'a> {
    config: &'a UpdateConfig,
}

impl<'a> Runtime<'a> {
    pub(crate) fn new(config: &'a UpdateConfig) -> Self {
        Self { config }
    }

    pub(crate) fn active_revision(&self) -> anyhow::Result<String> {
        if self.config.runtime.engine == "host" {
            let target = std::fs::canonicalize(&self.config.runtime.binary_path)
                .context("failed to resolve active host binary")?;
            return target
                .parent()
                .and_then(Path::file_name)
                .map(|name| name.to_string_lossy().into_owned())
                .context("active host binary does not have a release directory");
        }
        self.inspect_container("{{index .Config.Labels \"org.opencontainers.image.revision\"}}")
    }

    pub(crate) fn active_image(&self) -> anyhow::Result<String> {
        if self.config.runtime.engine == "host" {
            bail!("host runtime does not have an active image");
        }
        let format = if self.config.runtime.engine == "docker" {
            "{{.Config.Image}}"
        } else {
            "{{.ImageName}}"
        };
        self.inspect_container(format)
    }

    fn inspect_container(&self, format: &str) -> anyhow::Result<String> {
        let engine = self
            .config
            .container_engine()
            .context("container engine is unavailable")?;
        Ok(Process::new(engine)
            .args([
                OsString::from("inspect"),
                self.config.runtime.container_name.clone().into(),
                OsString::from("--format"),
                OsString::from(format),
            ])
            .stdout()?
            .trim()
            .to_owned())
    }

    pub(crate) fn prepare_app_task(
        &self,
        image_or_binary: &str,
        operation: &TaskOperation,
        public_jwk: Option<&Path>,
        config_manifest: &[u8],
    ) -> anyhow::Result<PreparedAppTask> {
        self.write_task_context(config_manifest)?;
        if self.config.runtime.engine == "host" {
            let unit = format!("nazoauth-operator-task-{}", std::process::id());
            let target =
                fs::canonicalize(image_or_binary).context("failed to resolve host task binary")?;
            let digest = sha256(&target)?;
            let key_directory = self
                .config
                .runtime
                .snapshot_paths
                .first()
                .context("application key state directory is unavailable")?;
            let app_root = key_directory
                .parent()
                .context("application data root is unavailable")?;
            let ui_releases = app_root
                .parent()
                .context("deployment data root is unavailable")?
                .join("ui-releases");
            let mut command = Process::new("systemd-run")
                .timeout(Duration::from_secs(300))
                .current_dir(&self.config.runtime.working_directory)
                .args([
                    "--quiet",
                    "--wait",
                    "--pipe",
                    "--collect",
                    "--service-type=exec",
                ])
                .arg(format!("--unit={unit}"))
                .arg(format!("--uid={}", self.config.runtime.service_user))
                .arg(format!("--gid={}", self.config.runtime.service_user))
                .arg(format!(
                    "--working-directory={}",
                    self.config.runtime.working_directory.display()
                ))
                .args([
                    "--property=NoNewPrivileges=yes",
                    "--property=PrivateTmp=yes",
                    "--property=PrivateDevices=yes",
                    "--property=PrivateMounts=yes",
                    "--property=ProtectSystem=strict",
                    "--property=ProtectHome=yes",
                    "--property=ProtectKernelTunables=yes",
                    "--property=ProtectKernelModules=yes",
                    "--property=ProtectControlGroups=yes",
                    "--property=RestrictSUIDSGID=yes",
                    "--property=LockPersonality=yes",
                    "--property=CapabilityBoundingSet=",
                    "--property=AmbientCapabilities=",
                ])
                .arg(format!(
                    "--property=ReadWritePaths={}",
                    self.config.operator.state_directory.display()
                ))
                .arg(format!(
                    "--setenv=NAZOAUTH_OPERATOR_CONTEXT_FILE={}",
                    self.config
                        .operator
                        .controller_public_key
                        .parent()
                        .context("operator directory is unavailable")?
                        .join("context.json")
                        .display()
                ))
                .arg(format!(
                    "--setenv=NAZOAUTH_OPERATOR_CONTROLLER_PUBLIC_KEY_FILE={}",
                    self.config.operator.controller_public_key.display()
                ))
                .arg(format!(
                    "--property=LoadCredential=operator-receipt-key:{}",
                    self.config.operator.receipt_private_key.display()
                ))
                .arg("--setenv=NAZOAUTH_OPERATOR_RECEIPT_PRIVATE_KEY_FILE=%d/operator-receipt-key")
                .arg(format!(
                    "--setenv=NAZOAUTH_OPERATOR_STATE_DIRECTORY={}",
                    self.config.operator.state_directory.display()
                ))
                .arg(format!(
                    "--setenv=NAZOAUTH_OPERATOR_CONFIG_MANIFEST_FILE={}",
                    self.config
                        .operator
                        .controller_public_key
                        .parent()
                        .context("operator directory is unavailable")?
                        .join("config-manifest.json")
                        .display()
                ))
                .arg(format!(
                    "--setenv=NAZOAUTH_SERVER_CONFIG_FILE={}",
                    self.config
                        .runtime
                        .working_directory
                        .join(".env.yaml")
                        .display()
                ));
            command = if matches!(operation, TaskOperation::MigrateApply) {
                command
                    .arg("--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6")
                    .arg(format!(
                        "--property=LoadCredential=migration-database-url:{}",
                        self.config
                            .dependencies
                            .migration_database_url_file
                            .display()
                    ))
                    .arg(format!(
                        "--property=InaccessiblePaths={}",
                        key_directory.display()
                    ))
                    .arg(format!(
                        "--property=InaccessiblePaths={} {} {} {}",
                        app_root.join("avatars").display(),
                        app_root.join("secrets").display(),
                        app_root.join("bootstrap").display(),
                        ui_releases.display()
                    ))
                    .arg("--setenv=DATABASE_URL_FILE=%d/migration-database-url")
            } else {
                let mut command = command
                    .arg("--property=RestrictAddressFamilies=AF_UNIX")
                    .arg(format!(
                        "--property=ReadWritePaths={}",
                        key_directory.display()
                    ))
                    .arg(format!(
                        "--property=InaccessiblePaths={} {} {} {} {}",
                        self.config
                            .dependencies
                            .migration_database_url_file
                            .parent()
                            .context("dependency secret directory is unavailable")?
                            .display(),
                        app_root.join("avatars").display(),
                        app_root.join("secrets").display(),
                        app_root.join("bootstrap").display(),
                        ui_releases.display()
                    ));
                if let Some(path) = public_jwk {
                    command = command
                        .arg(format!("--property=ReadOnlyPaths={}", path.display()))
                        .arg(format!(
                            "--setenv=NAZOAUTH_OPERATOR_PUBLIC_JWK_FILE={}",
                            path.display()
                        ));
                }
                command
            };
            command = command.arg(target.as_os_str()).arg("operator-task");
            return Ok(PreparedAppTask {
                process: command,
                target: RuntimeTargetClaim::HostBinary {
                    path: target.display().to_string(),
                    sha256: digest,
                },
                cleanup: TaskCleanup::SystemdUnit(unit),
            });
        }
        let engine = self
            .config
            .container_engine()
            .context("container engine is unavailable")?;
        let task_name = format!(
            "{}-task-{}",
            self.config.runtime.container_name,
            std::process::id()
        );
        let mut command = Process::new(engine)
            .timeout(Duration::from_secs(300))
            .args(["run", "--rm"])
            .arg("--name")
            .arg(&task_name)
            .args([
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--read-only",
                "--pids-limit",
                "128",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m",
            ]);
        command = if matches!(operation, TaskOperation::MigrateApply) {
            command.arg("--network").arg(&self.config.runtime.network)
        } else {
            command.args(["--network", "none"])
        };
        command = self.append_task_mounts(command, operation, public_jwk)?;
        command = command
            .arg(image_or_binary)
            .args(["nazoauth", "operator-task"]);
        let digest = self.image_digest(image_or_binary)?;
        Ok(PreparedAppTask {
            process: command,
            target: RuntimeTargetClaim::OciImage {
                image_ref: image_or_binary.to_owned(),
                image_digest: digest,
            },
            cleanup: TaskCleanup::Container {
                engine: engine.to_owned(),
                name: task_name,
            },
        })
    }

    pub(crate) fn start_container(&self, image: &str) -> anyhow::Result<()> {
        let engine = self
            .config
            .container_engine()
            .context("container engine is unavailable")?;
        let mut command = Process::new(engine)
            .args(["run", "-d", "--name"])
            .arg(&self.config.runtime.container_name)
            .args([
                "--label",
                "io.nazoauth.managed=true",
                "--restart",
                "unless-stopped",
            ])
            .args([
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--read-only",
                "--pids-limit",
                "512",
                "--memory",
                "1g",
                "--cpus",
                "2",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=64m",
            ])
            .arg("--network")
            .arg(&self.config.runtime.network);
        if !self.config.runtime.ip_address.is_empty() {
            command = command.args(["--ip", self.config.runtime.ip_address.as_str()]);
        }
        if !self.config.runtime.publish_address.is_empty() {
            command = command.args(["-p", self.config.runtime.publish_address.as_str()]);
        }
        command = self.append_environment_and_mounts(command);
        command.arg(image).args(["nazoauth", "server"]).run_quiet()
    }

    pub(crate) fn remove_container(&self) -> anyhow::Result<()> {
        let engine = self
            .config
            .container_engine()
            .context("container engine is unavailable")?;
        if self.config.managed_install && !self.container_has_managed_label() {
            bail!("refusing to replace an unlabelled application container");
        }
        Process::new(engine)
            .args(["rm", "-f", self.config.runtime.container_name.as_str()])
            .run_quiet()
    }

    pub(crate) fn container_exists(&self) -> bool {
        if self.config.runtime.engine == "host" {
            return false;
        }
        self.config.container_engine().is_some_and(|engine| {
            Process::new(engine)
                .args(["inspect", self.config.runtime.container_name.as_str()])
                .succeeds()
        })
    }

    pub(crate) fn restart(&self) -> anyhow::Result<()> {
        if self.config.runtime.engine == "host" {
            return Process::new("systemctl")
                .args(["restart", self.config.runtime.service_name.as_str()])
                .run_quiet();
        }
        Process::new(
            self.config
                .container_engine()
                .context("container engine is unavailable")?,
        )
        .args(["restart", self.config.runtime.container_name.as_str()])
        .run_quiet()
    }

    pub(crate) fn start_service(&self) -> anyhow::Result<()> {
        Process::new("systemctl")
            .args(["start", self.config.runtime.service_name.as_str()])
            .run_quiet()
    }

    pub(crate) fn stop_service(&self) -> anyhow::Result<()> {
        Process::new("systemctl")
            .args(["stop", self.config.runtime.service_name.as_str()])
            .run_quiet()
    }

    pub(crate) fn pull_image(&self, image: &str) -> anyhow::Result<()> {
        Process::new(
            self.config
                .container_engine()
                .context("container engine is unavailable")?,
        )
        .args(["pull", image])
        .run_quiet()
    }

    pub(crate) fn image_revision(&self, image: &str) -> anyhow::Result<String> {
        let format = if self.config.runtime.engine == "docker" {
            "{{index .Config.Labels \"org.opencontainers.image.revision\"}}"
        } else {
            "{{index .Labels \"org.opencontainers.image.revision\"}}"
        };
        Ok(Process::new(
            self.config
                .container_engine()
                .context("container engine is unavailable")?,
        )
        .args(["image", "inspect", image, "--format", format])
        .stdout()?
        .trim()
        .to_owned())
    }

    pub(crate) fn image_digest(&self, image: &str) -> anyhow::Result<String> {
        let (_, expected_digest) = image
            .rsplit_once('@')
            .context("managed OCI image reference is not pinned by digest")?;
        let normalized = expected_digest.strip_prefix("sha256:").unwrap_or("");
        if normalized.len() != 64
            || !normalized
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            bail!("managed OCI image reference has an invalid digest");
        }
        let engine = self
            .config
            .container_engine()
            .context("container engine is unavailable")?;
        let repo_digests = Process::new(engine)
            .args([
                "image",
                "inspect",
                image,
                "--format",
                "{{json .RepoDigests}}",
            ])
            .stdout()?;
        let repo_digests = serde_json::from_str::<Vec<String>>(repo_digests.trim());
        if repo_digests.is_ok_and(|values| {
            values.iter().any(|value| {
                value
                    .rsplit_once('@')
                    .is_some_and(|(_, digest)| digest == expected_digest)
            })
        }) {
            return Ok(expected_digest.to_ascii_lowercase());
        }
        if self.config.runtime.engine == "podman" {
            let digest = Process::new(engine)
                .args(["image", "inspect", image, "--format", "{{.Digest}}"])
                .stdout()?;
            if digest.trim() == expected_digest {
                return Ok(expected_digest.to_ascii_lowercase());
            }
        }
        bail!("container engine did not retain the signed OCI digest")
    }

    pub(crate) fn embedded_identity(
        &self,
        image_or_binary: &str,
    ) -> anyhow::Result<nazo_operator_protocol::EmbeddedIdentity> {
        let output = if self.config.runtime.engine == "host" {
            Process::new(image_or_binary)
                .arg("build-identity")
                .stdout()?
        } else {
            Process::new(
                self.config
                    .container_engine()
                    .context("container engine is unavailable")?,
            )
            .args([
                "run",
                "--rm",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--read-only",
                "--pids-limit",
                "32",
            ])
            .arg(image_or_binary)
            .args(["nazoauth", "build-identity"])
            .stdout()?
        };
        serde_json::from_str(&output).context("runtime embedded build identity is invalid")
    }

    pub(crate) fn verify_prepared_target(
        &self,
        expected: &RuntimeTargetClaim,
    ) -> anyhow::Result<()> {
        let actual = match expected {
            RuntimeTargetClaim::OciImage { image_ref, .. } => RuntimeTargetClaim::OciImage {
                image_ref: image_ref.clone(),
                image_digest: self.image_digest(image_ref)?,
            },
            RuntimeTargetClaim::HostBinary { path, .. } => RuntimeTargetClaim::HostBinary {
                path: path.clone(),
                sha256: sha256(Path::new(path))?,
            },
        };
        if &actual != expected {
            bail!("runtime target changed during privileged task execution");
        }
        Ok(())
    }

    fn write_task_context(&self, config_manifest: &[u8]) -> anyhow::Result<()> {
        let directory = self
            .config
            .operator
            .controller_public_key
            .parent()
            .context("operator directory is unavailable")?;
        atomic_write(
            &directory.join("context.json"),
            &serde_json::to_vec(&serde_json::json!({
                "controller_key_id": self.config.operator.controller_key_id,
                "receipt_key_id": self.config.operator.receipt_key_id,
            }))?,
            0o444,
        )?;
        atomic_write(
            &directory.join("config-manifest.json"),
            config_manifest,
            0o444,
        )
    }

    fn append_task_mounts(
        &self,
        mut command: Process,
        operation: &TaskOperation,
        public_jwk: Option<&Path>,
    ) -> anyhow::Result<Process> {
        let config_mount = self.required_mount("/app/.env.yaml")?;
        command = append_mount(command, config_mount);
        match operation {
            TaskOperation::MigrateApply => {
                command = command
                    .args(["-e", "DATABASE_URL_FILE=/run/nazoauth-secrets/database-url"])
                    .arg("-v")
                    .arg(mount_argument(
                        &self.config.dependencies.migration_database_url_file,
                        Path::new("/run/nazoauth-secrets/database-url"),
                        "ro,Z",
                    ));
            }
            TaskOperation::KeysList
            | TaskOperation::KeysValidate
            | TaskOperation::KeysGenerateLocal { .. }
            | TaskOperation::KeysRegisterExternal { .. } => {
                command = append_mount(command, self.required_mount("/var/lib/nazo_oauth/keys")?);
            }
        }
        for (source, target, mode) in [
            (
                &self.config.operator.controller_public_key,
                "/run/nazoauth-operator/controller.pub",
                "ro,Z",
            ),
            (
                &self
                    .config
                    .operator
                    .controller_public_key
                    .parent()
                    .context("operator directory is unavailable")?
                    .join("config-manifest.json"),
                "/run/nazoauth-operator/config-manifest.json",
                "ro,Z",
            ),
            (
                &self.config.operator.receipt_private_key,
                "/run/nazoauth-operator/receipt.key",
                "ro,Z",
            ),
            (
                &self
                    .config
                    .operator
                    .controller_public_key
                    .parent()
                    .context("operator directory is unavailable")?
                    .join("context.json"),
                "/run/nazoauth-operator/context.json",
                "ro,Z",
            ),
            (
                &self.config.operator.state_directory,
                "/var/lib/nazoauth/operator-state",
                "rw,Z",
            ),
        ] {
            command = command
                .arg("-v")
                .arg(mount_argument(source, Path::new(target), mode));
        }
        if let Some(path) = public_jwk {
            command = command.arg("-v").arg(mount_argument(
                path,
                Path::new("/run/nazoauth-operator/public.jwk"),
                "ro,Z",
            ));
        }
        Ok(command)
    }

    fn required_mount(&self, target: &str) -> anyhow::Result<&Mount> {
        self.config
            .runtime
            .mounts
            .iter()
            .find(|mount| mount.target == Path::new(target))
            .with_context(|| format!("runtime mount {target} is unavailable"))
    }

    fn append_environment_and_mounts(&self, mut command: Process) -> Process {
        for (key, value) in &self.config.runtime.environment {
            command = command.args(["-e", &format!("{key}={value}")]);
        }
        for mount in &self.config.runtime.mounts {
            command =
                command
                    .arg("-v")
                    .arg(mount_argument(&mount.source, &mount.target, &mount.mode));
        }
        command
    }

    fn container_has_managed_label(&self) -> bool {
        let Some(engine) = self.config.container_engine() else {
            return false;
        };
        for format in [
            "{{index .Config.Labels \"io.nazoauth.managed\"}}",
            "{{index .Labels \"io.nazoauth.managed\"}}",
        ] {
            let value = Process::new(engine)
                .args([
                    "inspect",
                    self.config.runtime.container_name.as_str(),
                    "--format",
                    format,
                ])
                .stdout();
            if value.is_ok_and(|value| value.trim() == "true") {
                return true;
            }
        }
        false
    }
}

fn mount_argument(source: &Path, target: &Path, mode: &str) -> OsString {
    let mut value = source.as_os_str().to_os_string();
    value.push(":");
    value.push(target);
    value.push(":");
    value.push(mode);
    value
}

fn append_mount(command: Process, mount: &Mount) -> Process {
    command
        .arg("-v")
        .arg(mount_argument(&mount.source, &mount.target, &mount.mode))
}

#[cfg(test)]
#[path = "../tests/unit/runtime.rs"]
mod tests;
