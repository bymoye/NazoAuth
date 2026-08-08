use super::*;

use crate::adapters::security::constant_time_eq;

pub(super) fn validate_embedded_identity(task: &TaskEnvelope) -> anyhow::Result<()> {
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

pub(super) fn validate_secret_binding(task: &TaskEnvelope) -> anyhow::Result<()> {
    let revision_path = configured_path(
        "NAZOAUTH_OPERATOR_SECRET_REVISION_FILE",
        SECRET_REVISION_PATH,
    );
    validate_secret_binding_at(task, &revision_path)
}

pub(super) fn validate_secret_binding_at(
    task: &TaskEnvelope,
    revision_path: &Path,
) -> anyhow::Result<()> {
    let SecretBinding::OpaqueRevision { revision } = &task.config.secret_binding else {
        // The v1 controller emits OpaqueRevision from the single
        // secret-revision authority.  HMAC bindings require a separately
        // provisioned deployment key/provider, which this runtime does not
        // have; accepting one without recomputing it would be fail-open.
        bail!("operator task HMAC secret binding has no local provider");
    };
    let local_revision = read_identifier(revision_path).with_context(|| {
        format!(
            "operator task secret revision authority is unavailable: {}",
            revision_path.display()
        )
    })?;
    if !constant_time_eq(local_revision.as_bytes(), revision.as_bytes()) {
        bail!("operator task secret revision binding mismatch");
    }
    Ok(())
}

pub(super) fn validate_config_manifest(task: &TaskEnvelope) -> anyhow::Result<()> {
    let manifest_path = configured_path(
        "NAZOAUTH_OPERATOR_CONFIG_MANIFEST_FILE",
        CONFIG_MANIFEST_PATH,
    );
    let server_config_path = configured_path("NAZOAUTH_SERVER_CONFIG_FILE", "/app/.env.yaml");
    validate_config_manifest_at(task, &manifest_path, &server_config_path)
}

pub(super) fn validate_config_manifest_at(
    task: &TaskEnvelope,
    manifest_path: &Path,
    server_config_path: &Path,
) -> anyhow::Result<()> {
    let bytes = fs::read(manifest_path).context("canonical config manifest is unavailable")?;
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
    let actual: String = Sha256::digest(fs::read(server_config_path)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if manifest.entries.get("server_config_sha256") != Some(&actual) {
        bail!("server configuration digest mismatch");
    }
    Ok(())
}

/// Bind the signed task to the deployment identity that is local to this
/// runtime.  The controller signature is necessary but not sufficient: a
/// stale controller mount can carry a valid envelope for another deployment.
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
pub(super) fn validate_local_task_identity(task: &TaskEnvelope) -> anyhow::Result<String> {
    let server_config_path = configured_path("NAZOAUTH_SERVER_CONFIG_FILE", "/app/.env.yaml");
    let explicit_identity_path =
        env::var_os("NAZOAUTH_OPERATOR_DEPLOYMENT_ID_FILE").map(PathBuf::from);
    let state_directory = configured_path("NAZOAUTH_OPERATOR_STATE_DIRECTORY", STATE_DIRECTORY);
    validate_local_task_identity_at(
        task,
        &server_config_path,
        explicit_identity_path.as_deref(),
        Some(&state_directory),
    )
}

pub(super) fn validate_local_task_identity_at(
    task: &TaskEnvelope,
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
    if state_deployment_id.is_none() && !matches!(&task.operation, TaskOperation::MigrateApply) {
        bail!(
            "operator state deployment identity is unavailable for a non-bootstrap operator task"
        );
    }
    let expected = if let Some(state) = state_deployment_id {
        state
    } else if let Some(persisted) = persisted_deployment_id {
        persisted
    } else if let Some(configured) = configured_deployment_id {
        if !matches!(&task.operation, TaskOperation::MigrateApply) {
            bail!("persisted deployment identity is unavailable for a non-bootstrap operator task");
        }
        configured
    } else {
        bail!("no local deployment identity is available");
    };
    validate_task_deployment_binding(task, &expected).map_err(|error| {
        anyhow::anyhow!("operator task deployment identity is not local: {error}")
    })?;
    Ok(expected)
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
    options.mode(0o400);
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

pub(super) fn operation_name(operation: &TaskOperation) -> &'static str {
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

pub(crate) fn embedded_identity() -> EmbeddedIdentity {
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
