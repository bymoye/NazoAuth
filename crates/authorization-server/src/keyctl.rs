//! Typed signing-key operations reachable only through the signed operator-task protocol.

use std::{collections::BTreeSet, path::PathBuf};

use anyhow::bail;
use nazo_auth::SigningPurpose;
use nazo_key_management::signing_algorithm_from_name;

use crate::{config::ConfigSource, settings::Settings};

fn load_settings() -> anyhow::Result<Settings> {
    let config = ConfigSource::load()?;
    Settings::from_config(&config)
}

#[derive(Debug)]
struct GenerateLocalKeyOptions {
    alg: jsonwebtoken::Algorithm,
    purposes: BTreeSet<SigningPurpose>,
}

pub(crate) async fn operator_list() -> anyhow::Result<String> {
    let settings = load_settings()?;
    list_with_settings(&settings).await
}

async fn list_with_settings(settings: &Settings) -> anyhow::Result<String> {
    let _ = nazo_key_management::KeyManager::list_keys(&settings.key_settings()).await?;
    keyset_revision(settings).await
}

pub(crate) async fn operator_validate() -> anyhow::Result<String> {
    let settings = load_settings()?;
    validate_with_settings(&settings).await
}

async fn validate_with_settings(settings: &Settings) -> anyhow::Result<String> {
    nazo_key_management::KeyManager::validate(&settings.key_settings()).await?;
    keyset_revision(settings).await
}

pub(crate) async fn operator_generate_local(
    algorithm: &str,
    purposes: &[String],
) -> anyhow::Result<(String, String)> {
    let options = parse_generate_local(algorithm, purposes)?;
    let settings = load_settings()?;
    generate_local_with_settings(&settings, options).await
}

async fn generate_local_with_settings(
    settings: &Settings,
    options: GenerateLocalKeyOptions,
) -> anyhow::Result<(String, String)> {
    let key_settings = settings.key_settings();
    nazo_key_management::KeyManager::load_or_create(key_settings.clone()).await?;
    let kid = nazo_key_management::KeyManager::register_local(
        &key_settings,
        nazo_key_management::LocalKeyRegistration {
            algorithm: options.alg,
            purposes: options.purposes,
        },
    )
    .await?;
    Ok((kid, keyset_revision(settings).await?))
}

pub(crate) async fn operator_register_external(
    kid: &str,
    algorithm: &str,
    key_ref: &str,
    public_jwk_file: PathBuf,
) -> anyhow::Result<String> {
    let alg = signing_algorithm_from_name(algorithm)
        .ok_or_else(|| anyhow::anyhow!("unsupported signing alg {algorithm}"))?;
    let settings = load_settings()?;
    register_external_with_settings(&settings, kid, alg, key_ref, public_jwk_file).await
}

async fn register_external_with_settings(
    settings: &Settings,
    kid: &str,
    algorithm: jsonwebtoken::Algorithm,
    key_ref: &str,
    public_jwk_file: PathBuf,
) -> anyhow::Result<String> {
    nazo_key_management::KeyManager::register_external(
        &settings.key_settings(),
        nazo_key_management::ExternalKeyRegistration {
            kid: kid.to_owned(),
            algorithm,
            key_ref: key_ref.to_owned(),
            public_jwk_file,
        },
    )
    .await?;
    keyset_revision(settings).await
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

async fn keyset_revision(settings: &Settings) -> anyhow::Result<String> {
    use sha2::{Digest as _, Sha256};

    let path = settings.key_settings().keys_dir.join("keyset.json");
    let bytes = tokio::fs::read(&path).await?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
#[path = "../tests/unit/keyctl.rs"]
mod tests;
