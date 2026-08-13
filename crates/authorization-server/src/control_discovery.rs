use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::Path,
    sync::Arc,
};

use actix_web::{HttpResponse, web};
use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use nazo_operator_protocol::{
    CONTROL_DISCOVERY_PRODUCT, CONTROL_DISCOVERY_SCHEMA, DeploymentStatement, DiscoveryRequest,
    DiscoveryResponse, DiscoveryStatement, PROTOCOL_VERSION, decode_instance_public_key,
    encode_instance_public_key, instance_key_id, sign_deployment_statement,
    sign_discovery_statement, validate_discovery_request, verify_deployment_statement,
};

use crate::{config::read_or_create_instance_identity_key, operator_task::embedded_identity};

const INSTANCE_DIRECTORY: &str = "instance";
const IDENTITY_KEY_FILE: &str = "identity.key";
const IDENTITY_PUBLIC_FILE: &str = "identity.pub";
const DEPLOYMENT_ID_FILE: &str = "deployment-id";
const RUNTIME_INSTANCE_ID_FILE: &str = "runtime-instance-id";
const DEPLOYMENT_STATEMENT_FILE: &str = "deployment-statement.jws";
const DISCOVERY_RESPONSE_SECONDS: i64 = 60;

#[derive(Clone)]
pub(crate) struct ControlDiscoveryEndpoint {
    identity: Arc<InstanceIdentity>,
}

struct InstanceIdentity {
    signing_key: SigningKey,
    key_id: String,
    public_key: String,
    deployment: DeploymentStatement,
}

impl ControlDiscoveryEndpoint {
    pub(crate) fn initialize(
        data_dir: &Path,
        identity_dir: Option<&Path>,
        configured_deployment_id: Option<&str>,
        configured_runtime_instance_id: Option<&str>,
        issuer: &str,
    ) -> anyhow::Result<Self> {
        let shared_identity_dir = data_dir.join(INSTANCE_DIRECTORY);
        fs::create_dir_all(&shared_identity_dir).with_context(|| {
            format!(
                "failed to create deployment identity directory {}",
                shared_identity_dir.display()
            )
        })?;
        let deployment_id = stable_identifier(
            &shared_identity_dir.join(DEPLOYMENT_ID_FILE),
            configured_deployment_id,
        )?;
        let identity_dir = identity_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| shared_identity_dir.clone());
        fs::create_dir_all(&identity_dir).with_context(|| {
            format!(
                "failed to create runtime instance identity directory {}",
                identity_dir.display()
            )
        })?;
        let runtime_instance_id = stable_identifier(
            &identity_dir.join(RUNTIME_INSTANCE_ID_FILE),
            configured_runtime_instance_id,
        )?;
        let (_, encoded_private_key) =
            read_or_create_instance_identity_key(&identity_dir, IDENTITY_KEY_FILE)?;
        let private_key = URL_SAFE_NO_PAD
            .decode(encoded_private_key)
            .context("instance identity key is not valid base64url")?;
        let private_key: [u8; 32] = private_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("instance identity key must contain 32 bytes"))?;
        let signing_key = SigningKey::from_bytes(&private_key);
        let public_key = encode_instance_public_key(&signing_key.verifying_key());
        publish_public_key(&identity_dir.join(IDENTITY_PUBLIC_FILE), &public_key)?;
        let key_id = instance_key_id(&signing_key.verifying_key());
        let embedded = embedded_identity();
        let deployment = DeploymentStatement {
            schema: CONTROL_DISCOVERY_SCHEMA,
            product: CONTROL_DISCOVERY_PRODUCT.to_owned(),
            deployment_id,
            runtime_instance_id,
            issuer: issuer.to_owned(),
            release: embedded.release,
            revision: embedded.revision,
            build_id: embedded.build_id,
            control_protocol_versions: vec![CONTROL_DISCOVERY_SCHEMA],
            operator_protocol_versions: vec![PROTOCOL_VERSION],
            instance_key_id: key_id.clone(),
            issued_at: Utc::now().timestamp(),
        };
        publish_deployment_statement(
            &identity_dir.join(DEPLOYMENT_STATEMENT_FILE),
            &deployment,
            &key_id,
            &signing_key,
        )?;
        Ok(Self {
            identity: Arc::new(InstanceIdentity {
                signing_key,
                key_id,
                public_key,
                deployment,
            }),
        })
    }

    pub(crate) fn runtime_instance_id(&self) -> &str {
        &self.identity.deployment.runtime_instance_id
    }

    fn respond(&self, request: DiscoveryRequest) -> anyhow::Result<DiscoveryResponse> {
        validate_discovery_request(&request)?;
        let issued_at = Utc::now().timestamp();
        let deployment = &self.identity.deployment;
        let statement = DiscoveryStatement {
            schema: deployment.schema,
            product: deployment.product.clone(),
            deployment_id: deployment.deployment_id.clone(),
            runtime_instance_id: deployment.runtime_instance_id.clone(),
            issuer: deployment.issuer.clone(),
            release: deployment.release.clone(),
            revision: deployment.revision.clone(),
            build_id: deployment.build_id.clone(),
            control_protocol_versions: deployment.control_protocol_versions.clone(),
            operator_protocol_versions: deployment.operator_protocol_versions.clone(),
            instance_key_id: deployment.instance_key_id.clone(),
            nonce: request.nonce,
            issued_at,
            expires_at: issued_at + DISCOVERY_RESPONSE_SECONDS,
        };
        Ok(DiscoveryResponse {
            statement: sign_discovery_statement(
                &statement,
                &self.identity.key_id,
                &self.identity.signing_key,
            )?,
            instance_public_key: self.identity.public_key.clone(),
        })
    }
}

pub(crate) async fn control_discovery(
    endpoint: web::Data<ControlDiscoveryEndpoint>,
    request: web::Json<DiscoveryRequest>,
) -> HttpResponse {
    match endpoint.respond(request.into_inner()) {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(error) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_control_discovery_request",
            "error_description": error.to_string(),
        })),
    }
}

fn stable_identifier(path: &Path, configured: Option<&str>) -> anyhow::Result<String> {
    if let Some(configured) = configured.map(str::trim).filter(|value| !value.is_empty()) {
        nazo_operator_protocol::validate_file_identifier_value(configured)?;
        if path.exists() {
            let persisted = read_identifier(path)?;
            if persisted != configured {
                bail!(
                    "configured identity does not match persisted identity at {}; refusing to change deployment identity",
                    path.display()
                );
            }
            return Ok(persisted);
        }
        publish_new_file(path, configured.as_bytes())?;
        return Ok(configured.to_owned());
    }
    if path.exists() {
        return read_identifier(path);
    }
    let generated = uuid::Uuid::now_v7().to_string();
    match publish_new_file(path, generated.as_bytes()) {
        Ok(()) => Ok(generated),
        Err(error) if path.exists() => read_identifier(path).or(Err(error)),
        Err(error) => Err(error),
    }
}

pub(crate) fn read_identifier(path: &Path) -> anyhow::Result<String> {
    let value = fs::read_to_string(path)
        .with_context(|| format!("failed to read identity {}", path.display()))?;
    let value = value.trim().to_owned();
    nazo_operator_protocol::validate_file_identifier_value(&value)?;
    Ok(value)
}

fn publish_public_key(path: &Path, public_key: &str) -> anyhow::Result<()> {
    let parsed = decode_instance_public_key(public_key)?;
    if path.exists() {
        let existing = fs::read_to_string(path)
            .with_context(|| format!("failed to read instance public key {}", path.display()))?;
        let existing = decode_instance_public_key(existing.trim())?;
        if existing != parsed {
            bail!(
                "instance public key at {} does not match identity.key; restore the identity as one unit",
                path.display()
            );
        }
        return Ok(());
    }
    publish_new_file(path, public_key.as_bytes())
}

fn publish_deployment_statement(
    path: &Path,
    statement: &DeploymentStatement,
    key_id: &str,
    signing_key: &SigningKey,
) -> anyhow::Result<()> {
    if path.exists() {
        let existing = fs::read_to_string(path)
            .with_context(|| format!("failed to read deployment statement {}", path.display()))?;
        let existing =
            verify_deployment_statement(existing.trim(), key_id, &signing_key.verifying_key())?;
        if deployment_identity_matches(&existing, statement) {
            return Ok(());
        }
    }
    let compact = sign_deployment_statement(statement, key_id, signing_key)?;
    publish_replaceable_file(path, compact.as_bytes())
}

fn deployment_identity_matches(left: &DeploymentStatement, right: &DeploymentStatement) -> bool {
    left.schema == right.schema
        && left.product == right.product
        && left.deployment_id == right.deployment_id
        && left.runtime_instance_id == right.runtime_instance_id
        && left.issuer == right.issuer
        && left.release == right.release
        && left.revision == right.revision
        && left.build_id == right.build_id
        && left.control_protocol_versions == right.control_protocol_versions
        && left.operator_protocol_versions == right.operator_protocol_versions
        && left.instance_key_id == right.instance_key_id
}

fn publish_new_file(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("identity path has no parent"))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("identity"),
        URL_SAFE_NO_PAD.encode(rand::random::<[u8; 12]>())
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to persist {}", temporary.display()))?;
    drop(file);
    let result = match fs::hard_link(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (|| {
            let metadata = fs::symlink_metadata(path).with_context(|| {
                format!(
                    "failed to inspect concurrently published identity {}",
                    path.display()
                )
            })?;
            if !metadata.file_type().is_file() {
                bail!(
                    "refusing concurrently published identity at {} because it is not a regular file",
                    path.display()
                );
            }
            let existing = fs::read(path).with_context(|| {
                format!(
                    "failed to read concurrently published identity {}",
                    path.display()
                )
            })?;
            if existing == contents {
                Ok(())
            } else {
                Err(error).with_context(|| {
                    format!(
                        "refusing concurrently published identity with different contents at {}",
                        path.display()
                    )
                })
            }
        })(),
        Err(error) => Err(error).with_context(|| format!("failed to publish {}", path.display())),
    };
    let _ = fs::remove_file(&temporary);
    result
}

fn publish_replaceable_file(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("deployment statement path has no parent"))?;
    let temporary = parent.join(format!(
        ".deployment-statement.{}.tmp",
        URL_SAFE_NO_PAD.encode(rand::random::<[u8; 12]>())
    ));
    publish_new_file(&temporary, contents)?;
    if path.exists() {
        let previous = parent.join("deployment-statement.previous.jws");
        if previous.exists() {
            fs::remove_file(&previous).with_context(|| {
                format!("failed to remove stale statement {}", previous.display())
            })?;
        }
        fs::rename(path, &previous)
            .with_context(|| format!("failed to preserve previous statement {}", path.display()))?;
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::rename(&previous, path);
            let _ = fs::remove_file(&temporary);
            return Err(error).with_context(|| {
                format!("failed to activate deployment statement {}", path.display())
            });
        }
        return Ok(());
    }
    fs::rename(&temporary, path)
        .with_context(|| format!("failed to activate deployment statement {}", path.display()))
}

#[cfg(test)]
#[path = "../tests/unit/control_discovery.rs"]
mod tests;
