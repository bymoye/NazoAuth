//! Typed signing-key operations reachable only through the signed operator-task protocol.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use nazo_auth::SigningPurpose;
use nazo_key_management::signing_algorithm_from_name;
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::PKey,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, KeyUsage},
    },
};
use tokio::io::AsyncWriteExt as _;

use crate::{config::ConfigSource, settings::key_settings_from_config};

fn load_key_task_config() -> anyhow::Result<(nazo_key_management::KeySettings, Option<PathBuf>)> {
    let config = ConfigSource::load_without_secret_values()?;
    Ok((
        key_settings_from_config(&config)?,
        config
            .optional_string("OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE")
            .map(PathBuf::from),
    ))
}

#[derive(Debug)]
struct GenerateLocalKeyOptions {
    alg: jsonwebtoken::Algorithm,
    purposes: BTreeSet<SigningPurpose>,
}

pub(crate) async fn operator_list() -> anyhow::Result<String> {
    let (settings, _) = load_key_task_config()?;
    let _ = nazo_key_management::KeyManager::list_keys(&settings).await?;
    keyset_revision_from(&settings).await
}

pub(crate) async fn operator_validate() -> anyhow::Result<String> {
    let (settings, _) = load_key_task_config()?;
    nazo_key_management::KeyManager::validate(&settings).await?;
    keyset_revision_from(&settings).await
}

pub(crate) async fn operator_generate_local(
    algorithm: &str,
    purposes: &[String],
) -> anyhow::Result<(String, String)> {
    let options = parse_generate_local(algorithm, purposes)?;
    let (settings, certificate_path) = load_key_task_config()?;
    generate_local_with_key_settings(&settings, certificate_path.as_deref(), options).await
}

async fn generate_local_with_key_settings(
    key_settings: &nazo_key_management::KeySettings,
    certificate_path: Option<&Path>,
    options: GenerateLocalKeyOptions,
) -> anyhow::Result<(String, String)> {
    let create_certificate = options.purposes.contains(&SigningPurpose::Credential);
    nazo_key_management::KeyManager::load_or_create(key_settings.clone()).await?;
    let kid = nazo_key_management::KeyManager::register_local(
        key_settings,
        nazo_key_management::LocalKeyRegistration {
            algorithm: options.alg,
            purposes: options.purposes,
        },
    )
    .await?;
    if create_certificate && certificate_path.is_some() {
        ensure_openid4vc_certificate(key_settings, &kid, certificate_path).await?;
    }
    Ok((kid, keyset_revision_from(key_settings).await?))
}

pub(crate) async fn operator_register_external(
    kid: &str,
    algorithm: &str,
    key_ref: &str,
    public_jwk_file: PathBuf,
) -> anyhow::Result<String> {
    let alg = signing_algorithm_from_name(algorithm)
        .ok_or_else(|| anyhow::anyhow!("unsupported signing alg {algorithm}"))?;
    let (settings, _) = load_key_task_config()?;
    nazo_key_management::KeyManager::register_external(
        &settings,
        nazo_key_management::ExternalKeyRegistration {
            kid: kid.to_owned(),
            algorithm: alg,
            key_ref: key_ref.to_owned(),
            public_jwk_file,
        },
    )
    .await?;
    keyset_revision_from(&settings).await
}

async fn ensure_openid4vc_certificate(
    settings: &nazo_key_management::KeySettings,
    kid: &str,
    certificate_path: Option<&Path>,
) -> anyhow::Result<()> {
    let certificate_path = certificate_path
        .context("credential signing requires OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE")?;
    let record = nazo_key_management::KeyManager::list_keys(settings)
        .await?
        .into_iter()
        .find(|record| record.kid == kid)
        .context("generated credential signing key is missing from the keyset")?;
    if record.backend != "local-pem" || record.locator.is_empty() {
        bail!("credential signing certificate requires a local private key");
    }
    let key_path = settings.keys_dir.join(record.locator);
    let private_key =
        PKey::private_key_from_pem(&tokio::fs::read(&key_path).await?).with_context(|| {
            format!(
                "failed to load credential signing key {}",
                key_path.display()
            )
        })?;
    if certificate_path.exists() {
        let certificate =
            X509::from_pem(&tokio::fs::read(certificate_path).await?).with_context(|| {
                format!(
                    "invalid OpenID4VC certificate {}",
                    certificate_path.display()
                )
            })?;
        if certificate.public_key()?.public_eq(&private_key) {
            return Ok(());
        }
        bail!("OpenID4VC certificate does not match the credential signing key");
    }
    let parent = certificate_path
        .parent()
        .context("OpenID4VC certificate path has no parent")?;
    tokio::fs::create_dir_all(parent).await?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "NazoAuth OpenID4VC Credential Signer")?;
    let name = name.build();
    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::ONE, false)?;
    let serial = serial.to_asn1_integer()?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(3650)?;
    let mut certificate = X509::builder()?;
    certificate.set_version(2)?;
    certificate.set_serial_number(&serial)?;
    certificate.set_subject_name(&name)?;
    certificate.set_issuer_name(&name)?;
    certificate.set_pubkey(&private_key)?;
    certificate.set_not_before(&not_before)?;
    certificate.set_not_after(&not_after)?;
    certificate.append_extension(BasicConstraints::new().critical().build()?)?;
    certificate.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
    certificate.sign(&private_key, MessageDigest::sha256())?;
    let pem = certificate.build().to_pem()?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        certificate_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("OpenID4VC certificate name is invalid")?,
        uuid::Uuid::now_v7()
    ));
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .await?;
    file.write_all(&pem).await?;
    file.sync_all().await?;
    drop(file);
    if let Err(error) = tokio::fs::rename(&temporary, certificate_path).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error).with_context(|| {
            format!(
                "failed to activate OpenID4VC certificate {}",
                certificate_path.display()
            )
        });
    }
    Ok(())
}

fn parse_generate_local(
    algorithm: &str,
    purposes: &[String],
) -> anyhow::Result<GenerateLocalKeyOptions> {
    let alg = signing_algorithm_from_name(algorithm)
        .ok_or_else(|| anyhow::anyhow!("unsupported signing alg {algorithm}"))?;
    let mut parsed = BTreeSet::new();
    for name in purposes {
        let purpose = SigningPurpose::from_name(name)
            .ok_or_else(|| anyhow::anyhow!("unsupported signing purpose {name}"))?;
        if !parsed.insert(purpose) {
            bail!("duplicate signing purpose {name}");
        }
    }
    if parsed.is_empty() {
        bail!("generate-local requires non-empty purposes");
    }
    if parsed.iter().any(|purpose| {
        !matches!(
            purpose,
            SigningPurpose::Credential | SigningPurpose::PresentationRequest
        )
    }) {
        bail!("generate-local purposes are restricted to credential,presentation_request");
    }
    Ok(GenerateLocalKeyOptions {
        alg,
        purposes: parsed,
    })
}

async fn keyset_revision_from(
    settings: &nazo_key_management::KeySettings,
) -> anyhow::Result<String> {
    use sha2::{Digest as _, Sha256};

    let path = settings.keys_dir.join("keyset.json");
    let bytes = tokio::fs::read(&path).await?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
#[path = "../tests/unit/keyctl.rs"]
mod tests;
