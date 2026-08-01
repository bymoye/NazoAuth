use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateConfig {
    pub(crate) schema: u32,
    #[serde(default)]
    pub(crate) managed_install: bool,
    #[serde(default = "baseline_install_profile")]
    pub(crate) install_profile: String,
    pub(crate) repository: String,
    pub(crate) updater_install_path: PathBuf,
    pub(crate) backup_root: PathBuf,
    pub(crate) deployment_root: PathBuf,
    pub(crate) operator: Operator,
    #[serde(default)]
    pub(crate) dependencies: Dependencies,
    pub(crate) runtime: Runtime,
    pub(crate) postgres: Postgres,
    pub(crate) valkey: Valkey,
    pub(crate) ui: Ui,
}

fn baseline_install_profile() -> String {
    "baseline".to_owned()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Operator {
    pub(crate) deployment_id: String,
    pub(crate) controller_key_id: String,
    pub(crate) controller_private_key: PathBuf,
    pub(crate) controller_public_key: PathBuf,
    pub(crate) receipt_key_id: String,
    pub(crate) receipt_private_key: PathBuf,
    pub(crate) receipt_public_key: PathBuf,
    pub(crate) audit_key_id: String,
    pub(crate) audit_private_key: PathBuf,
    pub(crate) audit_public_key: PathBuf,
    pub(crate) break_glass_key_id: String,
    pub(crate) break_glass_private_key: PathBuf,
    pub(crate) break_glass_public_key: PathBuf,
    pub(crate) secret_revision_file: PathBuf,
    pub(crate) state_directory: PathBuf,
    pub(crate) audit_directory: PathBuf,
    pub(crate) trust_state_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Dependencies {
    #[serde(default = "default_dependency_mode")]
    pub(crate) mode: String,
    #[serde(default)]
    pub(crate) database_url_file: PathBuf,
    #[serde(default)]
    pub(crate) migration_database_url_file: PathBuf,
    #[serde(default)]
    pub(crate) valkey_url_file: PathBuf,
}

fn default_dependency_mode() -> String {
    "managed".to_owned()
}

impl Default for Dependencies {
    fn default() -> Self {
        Self {
            mode: default_dependency_mode(),
            database_url_file: PathBuf::new(),
            migration_database_url_file: PathBuf::new(),
            valkey_url_file: PathBuf::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Runtime {
    pub(crate) engine: String,
    #[serde(default)]
    pub(crate) dependency_engine: String,
    pub(crate) container_name: String,
    pub(crate) network: String,
    #[serde(default)]
    pub(crate) ip_address: String,
    #[serde(default)]
    pub(crate) publish_address: String,
    pub(crate) health_url: String,
    pub(crate) readiness_attempts: u32,
    pub(crate) readiness_interval_seconds: u64,
    pub(crate) public_discovery_url: String,
    pub(crate) expected_issuer: String,
    #[serde(default)]
    pub(crate) mounts: Vec<Mount>,
    #[serde(default)]
    pub(crate) snapshot_paths: Vec<PathBuf>,
    #[serde(default)]
    pub(crate) environment: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) service_name: String,
    #[serde(default)]
    pub(crate) service_user: String,
    #[serde(default)]
    pub(crate) binary_path: PathBuf,
    #[serde(default)]
    pub(crate) binary_releases: PathBuf,
    #[serde(default)]
    pub(crate) working_directory: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mount {
    pub(crate) source: PathBuf,
    pub(crate) target: PathBuf,
    pub(crate) mode: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Postgres {
    pub(crate) container_name: String,
    pub(crate) database: String,
    pub(crate) user: String,
    #[serde(default)]
    pub(crate) image: String,
    pub(crate) validation_image: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Valkey {
    pub(crate) container_name: String,
    #[serde(default)]
    pub(crate) image: String,
    pub(crate) rdb_path: String,
    #[serde(default)]
    pub(crate) password_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ui {
    pub(crate) active_path: PathBuf,
    pub(crate) releases_root: PathBuf,
    #[serde(default)]
    pub(crate) serve_from_application: bool,
}

impl UpdateConfig {
    pub(crate) fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let config: Self =
            serde_json::from_slice(bytes).context("update configuration is not valid JSON")?;
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.schema != 2 {
            bail!("unsupported update config schema");
        }
        if !matches!(self.install_profile.as_str(), "baseline" | "standards-full") {
            bail!("unsupported install profile {}", self.install_profile);
        }
        let repository_parts = self.repository.split('/').collect::<Vec<_>>();
        if repository_parts.len() != 2 || repository_parts.iter().any(|part| !safe_identifier(part))
        {
            bail!("repository must be a safe owner/name pair");
        }
        if !matches!(self.runtime.engine.as_str(), "podman" | "docker" | "host") {
            bail!("runtime engine must be podman, docker, or host");
        }
        if !matches!(self.dependencies.mode.as_str(), "managed" | "external") {
            bail!("dependency mode must be managed or external");
        }
        for name in [
            &self.runtime.container_name,
            &self.runtime.network,
            &self.postgres.container_name,
            &self.valkey.container_name,
        ] {
            if !safe_identifier(name) {
                bail!("runtime object name is unsafe: {name}");
            }
        }
        for path in [
            &self.updater_install_path,
            &self.backup_root,
            &self.deployment_root,
            &self.ui.active_path,
            &self.ui.releases_root,
            &self.operator.controller_private_key,
            &self.operator.controller_public_key,
            &self.operator.receipt_private_key,
            &self.operator.receipt_public_key,
            &self.operator.audit_private_key,
            &self.operator.audit_public_key,
            &self.operator.break_glass_private_key,
            &self.operator.break_glass_public_key,
            &self.operator.secret_revision_file,
            &self.operator.state_directory,
            &self.operator.audit_directory,
            &self.operator.trust_state_file,
        ] {
            safe_absolute(path)?;
        }
        for identifier in [
            &self.operator.deployment_id,
            &self.operator.controller_key_id,
            &self.operator.receipt_key_id,
            &self.operator.audit_key_id,
            &self.operator.break_glass_key_id,
        ] {
            if !safe_identifier(identifier) {
                bail!("operator identity is unsafe");
            }
        }
        if self.runtime.engine == "host" {
            for path in [
                &self.runtime.binary_path,
                &self.runtime.binary_releases,
                &self.runtime.working_directory,
            ] {
                safe_absolute(path)?;
            }
            if self.runtime.service_name.is_empty() || self.runtime.service_user.is_empty() {
                bail!("host runtime requires service_name and service_user");
            }
            if !safe_identifier(&self.runtime.service_name)
                || !safe_identifier(&self.runtime.service_user)
            {
                bail!("host service name or user is unsafe");
            }
        }
        if self.dependencies.mode == "external" {
            safe_absolute(&self.dependencies.database_url_file)?;
            safe_absolute(&self.dependencies.migration_database_url_file)?;
            safe_absolute(&self.dependencies.valkey_url_file)?;
        }
        if self.runtime.readiness_attempts == 0 {
            bail!("readiness_attempts must be positive");
        }
        for mount in &self.runtime.mounts {
            safe_absolute(&mount.source)?;
            safe_absolute(&mount.target)?;
            if !matches!(
                mount.mode.as_str(),
                "ro" | "rw" | "ro,z" | "rw,z" | "ro,Z" | "rw,Z"
            ) {
                bail!("unsupported mount mode {}", mount.mode);
            }
        }
        for path in &self.runtime.snapshot_paths {
            safe_absolute(path)?;
        }
        for (key, value) in &self.runtime.environment {
            if !valid_environment_key(key) || !key.ends_with("_FILE") {
                bail!("runtime environment is limited to non-secret *_FILE locators");
            }
            safe_absolute(std::path::Path::new(value))?;
        }
        Ok(())
    }

    pub(crate) fn container_engine(&self) -> Option<&str> {
        if self.runtime.engine == "host" {
            (!self.runtime.dependency_engine.is_empty())
                .then_some(self.runtime.dependency_engine.as_str())
        } else {
            Some(self.runtime.engine.as_str())
        }
    }
}

pub(crate) fn safe_absolute(path: &std::path::Path) -> anyhow::Result<()> {
    if !path.is_absolute() || path.parent().is_none() {
        bail!(
            "path must be absolute and must not be the filesystem root: {}",
            path.display()
        );
    }
    Ok(())
}

fn valid_environment_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some('A'..='Z' | '_'))
        && chars.all(|character| matches!(character, 'A'..='Z' | '0'..='9' | '_'))
}

fn safe_identifier(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn safe_protocol_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_/@+-".contains(character))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseManifest {
    pub(crate) schema: u32,
    pub(crate) version: String,
    pub(crate) backend_commit: String,
    pub(crate) frontend_commit: String,
    pub(crate) image_ref: String,
    pub(crate) release_identity: String,
    pub(crate) image_oci_digest: String,
    pub(crate) embedded: nazo_operator_protocol::EmbeddedIdentity,
    pub(crate) artifacts: BTreeMap<String, Artifact>,
    pub(crate) rollback: Rollback,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub(crate) name: String,
    pub(crate) sha256: String,
    pub(crate) size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rollback {
    pub(crate) artifact: bool,
    pub(crate) schema_compatible: bool,
    pub(crate) database_restore: DatabaseRestore,
    pub(crate) irreversible_migration: bool,
    pub(crate) minimum_supported_version: String,
    pub(crate) migration_floor: String,
    pub(crate) rationale: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DatabaseRestore {
    Backup,
    Pitr,
    None,
}

impl ReleaseManifest {
    pub(crate) fn validate(&self, version: &str, expected_identity: &str) -> anyhow::Result<()> {
        if self.schema != 3
            || self.version != version
            || self.release_identity != expected_identity
            || self.embedded.release != self.version
            || self.embedded.revision != self.backend_commit
            || self.embedded.protocol != nazo_operator_protocol::PROTOCOL_VERSION
            || !safe_protocol_identifier(&self.embedded.build_id)
            || !self.image_oci_digest.starts_with("sha256:")
            || !is_lower_hex(&self.image_oci_digest[7..], 64)
            || !is_lower_hex(&self.backend_commit, 40)
            || !is_lower_hex(&self.frontend_commit, 40)
            || !self.image_ref.starts_with("localhost/nazo-oauth-server:v")
        {
            bail!("signed release manifest failed policy validation");
        }
        if self.rollback.rationale.trim().is_empty()
            || !semantic_tag(&format!("v{}", self.rollback.minimum_supported_version))
            || !self
                .rollback
                .migration_floor
                .chars()
                .all(|character| character.is_ascii_digit())
        {
            bail!("signed release manifest has invalid recovery policy");
        }
        if self.rollback.irreversible_migration && self.rollback.schema_compatible {
            bail!("irreversible migrations cannot claim schema-compatible rollback");
        }
        if self.rollback.schema_compatible && !self.rollback.artifact {
            bail!("schema-compatible rollback requires a retained artifact");
        }
        let expected = BTreeSet::from([
            "binary".to_owned(),
            "bootstrap".to_owned(),
            "image".to_owned(),
            "sbom".to_owned(),
            "ui".to_owned(),
            "updater".to_owned(),
            "updater_sbom".to_owned(),
        ]);
        if self.artifacts.keys().cloned().collect::<BTreeSet<_>>() != expected {
            bail!("signed release manifest has an unexpected artifact set");
        }
        for artifact in self.artifacts.values() {
            if artifact.size == 0
                || !safe_artifact_name(&artifact.name)
                || !is_lower_hex(&artifact.sha256, 64)
            {
                bail!("signed release manifest contains an invalid artifact");
            }
        }
        Ok(())
    }
}

pub(crate) fn semantic_tag(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('v') else {
        return false;
    };
    semver::Version::parse(rest).is_ok_and(|parsed| parsed.to_string() == rest)
}

fn safe_artifact_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('.')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

#[cfg(test)]
#[path = "../tests/unit/model.rs"]
mod tests;
