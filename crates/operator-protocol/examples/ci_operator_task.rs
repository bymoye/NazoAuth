use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use nazo_operator_protocol::{
    Actor, ActorKind, CanonicalConfigManifest, ConfigBinding, EmbeddedIdentity, SecretBinding,
    TargetExpectation, TaskEnvelope, TaskOperation, TaskOutcome, canonical_config_sha256,
    compact_sha256, sign_task, verify_runtime_receipt,
};
use sha2::{Digest as _, Sha256};

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("prepare") => prepare(parse_options(args)?)?,
        Some("verify") => verify(parse_options(args)?)?,
        _ => anyhow::bail!("usage: ci_operator_task <prepare|verify> --name value ..."),
    }
    Ok(())
}

fn prepare(options: BTreeMap<String, String>) -> anyhow::Result<()> {
    let config = required_path(&options, "--config")?;
    let output = required_path(&options, "--output")?;
    let image_ref = required(&options, "--image-ref")?;
    let image_digest = required(&options, "--image-digest")?;
    fs::create_dir(&output)?;
    fs::create_dir(output.join("state"))?;
    let controller = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let receipt = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let controller_public = controller.verifying_key().to_bytes();
    let receipt_public = receipt.verifying_key().to_bytes();
    let controller_kid = format!(
        "ci-controller-{}",
        &hex(&Sha256::digest(controller_public))[..16]
    );
    let receipt_kid = format!("ci-receipt-{}", &hex(&Sha256::digest(receipt_public))[..16]);
    write(
        &output.join("controller.pub"),
        &URL_SAFE_NO_PAD.encode(controller_public),
    )?;
    write_private(
        &output.join("receipt.key"),
        &URL_SAFE_NO_PAD.encode(receipt.to_bytes()),
    )?;
    write(
        &output.join("receipt.pub"),
        &URL_SAFE_NO_PAD.encode(receipt_public),
    )?;
    write(
        &output.join("context.json"),
        &serde_json::to_string(&serde_json::json!({
            "controller_key_id": controller_kid,
            "receipt_key_id": receipt_kid,
        }))?,
    )?;
    let manifest = CanonicalConfigManifest {
        version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
        entries: BTreeMap::from([
            ("deployment_id".to_owned(), "deployment-ci".to_owned()),
            ("operation".to_owned(), "migrate-apply".to_owned()),
            ("server_config_sha256".to_owned(), file_sha256(&config)?),
        ]),
    };
    write(
        &output.join("config-manifest.json"),
        &serde_json::to_string(&manifest)?,
    )?;
    let now = Utc::now().timestamp();
    let task = TaskEnvelope {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: "controller:deployment-ci".to_owned(),
        aud: "runtime:deployment-ci".to_owned(),
        jti: format!("request-ci-{}", hex(&rand::random::<[u8; 16]>())),
        iat: now,
        nbf: now,
        exp: now + nazo_operator_protocol::MAX_TASK_LIFETIME_SECONDS,
        deployment_id: "deployment-ci".to_owned(),
        actor: Actor {
            kind: ActorKind::Automation,
            id: "github-actions".to_owned(),
        },
        target: TargetExpectation::OciImage {
            image_ref: image_ref.to_owned(),
            image_digest: image_digest.to_owned(),
        },
        embedded: EmbeddedIdentity {
            release: "development".to_owned(),
            revision: "development".to_owned(),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "local:development".to_owned(),
        },
        config: ConfigBinding {
            manifest_version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
            config_sha256: canonical_config_sha256(&manifest)?,
            secret_binding: SecretBinding::OpaqueRevision {
                revision: "ci-secret-revision".to_owned(),
            },
        },
        operation: TaskOperation::MigrateApply,
    };
    let compact = sign_task(&task, &controller_kid, &controller)?;
    write(&output.join("envelope.jws"), &compact)?;
    write(&output.join("request.sha256"), &compact_sha256(&compact))
}

fn verify(options: BTreeMap<String, String>) -> anyhow::Result<()> {
    let receipt_path = required_path(&options, "--receipt")?;
    let public_path = required_path(&options, "--public-key")?;
    let request_path = required_path(&options, "--request-sha256")?;
    let compact = fs::read_to_string(receipt_path)?;
    let header = nazo_operator_protocol::protected_header(compact.trim())?;
    let public = URL_SAFE_NO_PAD.decode(fs::read_to_string(public_path)?.trim())?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid receipt key"))?;
    let receipt = verify_runtime_receipt(
        compact.trim(),
        &header.kid,
        &ed25519_dalek::VerifyingKey::from_bytes(&public)?,
    )?;
    if receipt.request_sha256 != fs::read_to_string(request_path)?.trim()
        || !matches!(receipt.outcome, TaskOutcome::Succeeded { .. })
    {
        anyhow::bail!("runtime receipt is not bound to the successful CI request");
    }
    Ok(())
}

fn parse_options(args: impl Iterator<Item = String>) -> anyhow::Result<BTreeMap<String, String>> {
    let values = args.collect::<Vec<_>>();
    if values.len() % 2 != 0 {
        anyhow::bail!("each option requires one value");
    }
    let mut options = BTreeMap::new();
    for pair in values.chunks_exact(2) {
        if !pair[0].starts_with("--") || options.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            anyhow::bail!("invalid or duplicate option");
        }
    }
    Ok(options)
}

fn required<'a>(options: &'a BTreeMap<String, String>, name: &str) -> anyhow::Result<&'a str> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing {name}"))
}

fn required_path(options: &BTreeMap<String, String>, name: &str) -> anyhow::Result<PathBuf> {
    Ok(PathBuf::from(required(options, name)?))
}

fn write(path: &Path, value: &str) -> anyhow::Result<()> {
    fs::write(path, value)?;
    Ok(())
}

fn write_private(path: &Path, value: &str) -> anyhow::Result<()> {
    fs::write(path, value)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    }
    Ok(())
}

fn file_sha256(path: &Path) -> anyhow::Result<String> {
    Ok(hex(&Sha256::digest(fs::read(path)?)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
