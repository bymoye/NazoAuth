//! Local identity anchors for the one-shot operator (E04 step 5).
//!
//! Three independent fences run after signature verification and before
//! journal acceptance:
//!
//! 1. embedded build identity equality (J1): the signed `target.embedded`
//!    must equal the build identity of *this* executing binary, so an
//!    operation authorized for artifact A can never execute on runtime B;
//! 2. deployment binding: the signed `deployment_id` must match the local
//!    authoritative anchors (server config, persisted instance identity, and
//!    the operator state anchor);
//! 3. config_revision fencing: the signed opaque revision must equal the
//!    local revision marker, constant-time compared through the frozen
//!    [`nazo_operator_protocol::config_revision_matches`] helper.
//!
//! The old TaskEnvelope-era secret-binding HMAC checks and canonical config
//! manifest validation are gone with that envelope: `config_revision` is the
//! only revision fence in the frozen contract.

use std::{io::Cursor, path::Path};

use anyhow::{Context as _, bail};
use sha2::{Digest as _, Sha256};
use yaml_serde::Value as YamlValue;

use super::*;
use crate::adapters::security::constant_time_eq;
use crate::control_discovery::read_identifier;
use nazo_operator_protocol::ControlOperationPayload;

const OCI_IMAGE_DIGEST_ENVIRONMENT: &str = "NAZOAUTH_OPERATOR_OCI_IMAGE_DIGEST";

/// J1: the operation must name exactly this executing binary's build.
///
/// The frozen contract expresses build identity as
/// [`nazo_operator_protocol::ControlBuildIdentity`] `{product, version,
/// commit}`; this runtime maps it onto the same build environment as the
/// runtime build identity: `product` is the fixed workspace product name
/// (`CONTROL_DISCOVERY_PRODUCT`), `version` comes from
/// `NAZOAUTH_BUILD_RELEASE`, and `commit` from `NAZOAUTH_BUILD_REVISION`.
/// ctl must construct `target.embedded` from exactly these values (see the
/// E04 report's ctl-contract notes).
pub(super) fn validate_embedded_target_identity(
    target: &nazo_operator_protocol::ControlTarget,
) -> anyhow::Result<()> {
    let executable = env::current_exe()
        .context("failed to resolve the executing binary for artifact identity validation")?;
    let oci_image_digest = match target {
        nazo_operator_protocol::ControlTarget::OciImage { .. } => Some(
            env::var(OCI_IMAGE_DIGEST_ENVIRONMENT)
                .context("operator OCI image digest authority is unavailable")?,
        ),
        nazo_operator_protocol::ControlTarget::HostBinary { .. } => None,
    };
    validate_embedded_target_identity_at(target, &executable, oci_image_digest.as_deref())
}

pub(super) fn validate_embedded_target_identity_at(
    target: &nazo_operator_protocol::ControlTarget,
    executable: &Path,
    oci_image_digest: Option<&str>,
) -> anyhow::Result<()> {
    let actual = control_build_identity();
    if *target.embedded() != actual {
        bail!("embedded build identity does not match the executing runtime");
    }
    match target {
        nazo_operator_protocol::ControlTarget::HostBinary { sha256, .. } => {
            let executable = fs::read(executable)
                .context("failed to measure the executing host binary artifact")?;
            let actual: String = Sha256::digest(executable)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            if !constant_time_eq(actual.as_bytes(), sha256.as_bytes()) {
                bail!("host binary artifact digest does not match the executing runtime");
            }
        }
        nazo_operator_protocol::ControlTarget::OciImage { image_digest, .. } => {
            let actual =
                oci_image_digest.context("operator OCI image digest authority is unavailable")?;
            nazo_operator_protocol::validate_oci_image_digest(actual)
                .context("operator OCI image digest authority is invalid")?;
            if !constant_time_eq(actual.as_bytes(), image_digest.as_bytes()) {
                bail!("OCI image artifact digest does not match the executing runtime");
            }
        }
    }
    Ok(())
}

/// This binary's build identity in the frozen contract's shape.
pub(crate) fn control_build_identity() -> nazo_operator_protocol::ControlBuildIdentity {
    nazo_operator_protocol::ControlBuildIdentity {
        product: nazo_operator_protocol::CONTROL_DISCOVERY_PRODUCT.to_owned(),
        version: option_env!("NAZOAUTH_BUILD_RELEASE")
            .unwrap_or("development")
            .to_owned(),
        commit: option_env!("NAZOAUTH_BUILD_REVISION")
            .unwrap_or("development")
            .to_owned(),
    }
}

pub(super) fn validate_config_revision(operation: &ControlOperation) -> anyhow::Result<()> {
    let revision_path = configured_path(
        "NAZOAUTH_OPERATOR_CONFIG_REVISION_FILE",
        CONFIG_REVISION_PATH,
    );
    validate_config_revision_at(operation, &revision_path)
}

pub(super) fn validate_config_revision_at(
    operation: &ControlOperation,
    revision_path: &Path,
) -> anyhow::Result<()> {
    let local_revision = fs::read_to_string(revision_path).with_context(|| {
        format!(
            "operator configuration revision authority is unavailable: {}",
            revision_path.display()
        )
    })?;
    let local_revision = local_revision.trim();
    if local_revision.is_empty() {
        bail!("operator configuration revision authority is empty");
    }
    if !nazo_operator_protocol::config_revision_matches(operation, local_revision.as_bytes()) {
        bail!("operator configuration revision binding mismatch");
    }
    Ok(())
}

/// Bind the signed operation to the deployment identity that is local to this
/// runtime.  The controller signature is necessary but not sufficient: a
/// stale or forged envelope for another deployment must never execute here.
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
pub(super) fn validate_local_operation_identity(
    operation: &ControlOperationPayload,
) -> anyhow::Result<String> {
    let server_config_path = configured_path("NAZOAUTH_SERVER_CONFIG_FILE", "/app/.env.yaml");
    let explicit_identity_path =
        env::var_os("NAZOAUTH_OPERATOR_DEPLOYMENT_ID_FILE").map(PathBuf::from);
    let state_directory = configured_path("NAZOAUTH_OPERATOR_STATE_DIRECTORY", STATE_DIRECTORY);
    validate_local_operation_identity_at(
        operation,
        &server_config_path,
        explicit_identity_path.as_deref(),
        Some(&state_directory),
    )
}

pub(super) fn validate_local_operation_identity_at(
    operation: &ControlOperationPayload,
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
    let bootstrap_operation = matches!(operation, ControlOperationPayload::MigrateApply);
    if state_deployment_id.is_none() && !bootstrap_operation {
        bail!(
            "operator state deployment identity is unavailable for a non-bootstrap operator task"
        );
    }
    if let Some(state) = state_deployment_id {
        return Ok(state);
    }
    if let Some(persisted) = persisted_deployment_id {
        return Ok(persisted);
    }
    if let Some(configured) = configured_deployment_id {
        if !bootstrap_operation {
            bail!("persisted deployment identity is unavailable for a non-bootstrap operator task");
        }
        return Ok(configured);
    }
    bail!("no local deployment identity is available");
}

pub(super) fn persist_operator_state_identity(
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
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o400);
    }
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

pub(super) fn yaml_mapping_scalar(
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

pub(crate) fn embedded_identity() -> nazo_operator_protocol::EmbeddedIdentity {
    nazo_operator_protocol::EmbeddedIdentity {
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
