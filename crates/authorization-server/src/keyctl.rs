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
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, KeyUsage, SubjectAlternativeName},
    },
};
use tokio::io::AsyncWriteExt as _;
use url::{Host, Url};

use crate::{config::ConfigSource, settings::key_settings_from_config};

#[derive(Debug)]
struct Openid4vcCertificatePaths {
    chain: PathBuf,
    anchors: PathBuf,
    hostname: String,
}

fn load_key_task_config() -> anyhow::Result<(
    nazo_key_management::KeySettings,
    Option<Openid4vcCertificatePaths>,
)> {
    let config = ConfigSource::load_without_secret_values()?;
    key_task_config_from(&config)
}

fn key_task_config_from(
    config: &ConfigSource,
) -> anyhow::Result<(
    nazo_key_management::KeySettings,
    Option<Openid4vcCertificatePaths>,
)> {
    let chain = config
        .optional_string("OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE")
        .map(PathBuf::from);
    let anchors = config
        .optional_string("OPENID4VC_TRUST_ANCHORS_FILE")
        .map(PathBuf::from);
    let certificate_paths = match (chain, anchors) {
        (None, None) => None,
        (Some(chain), Some(anchors)) => {
            let issuer = config
                .optional_string("ISSUER")
                .unwrap_or_else(|| config.string("PUBLIC_BASE_URL", "http://127.0.0.1:8000"));
            let issuer =
                Url::parse(&issuer).context("OpenID4VC certificate issuer must be absolute")?;
            if issuer.scheme() != "https" {
                bail!("OpenID4VC certificate issuer must use HTTPS");
            }
            let Host::Domain(hostname) = issuer
                .host()
                .context("OpenID4VC certificate issuer must include a DNS hostname")?
            else {
                bail!("OpenID4VC certificate issuer must include a DNS hostname");
            };
            Some(Openid4vcCertificatePaths {
                chain,
                anchors,
                hostname: hostname.to_owned(),
            })
        }
        _ => bail!(
            "OpenID4VC certificate generation requires both OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE and OPENID4VC_TRUST_ANCHORS_FILE"
        ),
    };
    Ok((key_settings_from_config(config)?, certificate_paths))
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
    let (settings, certificate_paths) = load_key_task_config()?;
    generate_local_with_key_settings(&settings, certificate_paths.as_ref(), options).await
}

async fn generate_local_with_key_settings(
    key_settings: &nazo_key_management::KeySettings,
    certificate_paths: Option<&Openid4vcCertificatePaths>,
    options: GenerateLocalKeyOptions,
) -> anyhow::Result<(String, String)> {
    let openid4vc_purposes = [
        SigningPurpose::Credential,
        SigningPurpose::PresentationRequest,
    ]
    .into_iter()
    .collect();
    if certificate_paths.is_some() && options.purposes != openid4vc_purposes {
        bail!(
            "OpenID4VC certificate generation requires one ES256 key scoped to both credential and presentation_request"
        );
    }
    nazo_key_management::KeyManager::load_or_create(key_settings.clone()).await?;
    let kid = nazo_key_management::KeyManager::register_local(
        key_settings,
        nazo_key_management::LocalKeyRegistration {
            algorithm: options.alg,
            purposes: options.purposes,
        },
    )
    .await?;
    if let Some(certificate_paths) = certificate_paths {
        ensure_openid4vc_certificates(key_settings, &kid, certificate_paths).await?;
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

async fn ensure_openid4vc_certificates(
    settings: &nazo_key_management::KeySettings,
    kid: &str,
    paths: &Openid4vcCertificatePaths,
) -> anyhow::Result<()> {
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
    if existing_openid4vc_bundle_matches(paths, &private_key).await? {
        return Ok(());
    }

    let bundle = build_openid4vc_certificate_bundle(&private_key, &paths.hostname)?;
    activate_openid4vc_certificate_bundle(paths, &bundle).await
}

async fn existing_openid4vc_bundle_matches(
    paths: &Openid4vcCertificatePaths,
    private_key: &PKey<openssl::pkey::Private>,
) -> anyhow::Result<bool> {
    if paths.chain != paths.anchors {
        bail!(
            "OpenID4VC signing certificate chain and trust anchors must reference one atomic certificate bundle"
        );
    }
    let chain = match tokio::fs::read(&paths.chain).await {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", paths.chain.display()));
        }
    };
    let Ok(certificates) = X509::stack_from_pem(&chain) else {
        return Ok(false);
    };
    if certificates.len() != 2 {
        return Ok(false);
    }
    let leaf = &certificates[0];
    let ca = &certificates[1];
    let ca_public_key = ca.public_key()?;
    if !leaf.public_key()?.public_eq(private_key)
        || leaf.to_der()? == ca.to_der()?
        || is_ca_certificate(leaf)?
        || !is_ca_certificate(ca)?
        || ca.subject_name().to_der()? != ca.issuer_name().to_der()?
        || leaf.issuer_name().to_der()? != ca.subject_name().to_der()?
        || !ca.verify(&ca_public_key)?
        || !leaf.verify(&ca_public_key)?
    {
        return Ok(false);
    }
    let Some(subject_alt_names) = leaf.subject_alt_names() else {
        return Ok(false);
    };
    Ok(subject_alt_names.len() == 1
        && subject_alt_names[0].dnsname() == Some(paths.hostname.as_str()))
}

fn build_openid4vc_certificate_bundle(
    signing_key: &PKey<openssl::pkey::Private>,
    hostname: &str,
) -> anyhow::Result<Vec<u8>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ca_key = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "NazoAuth OpenID4VC Local CA")?;
    let ca_name = name.build();
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(3650)?;

    let mut ca = X509::builder()?;
    ca.set_version(2)?;
    let ca_serial = random_serial()?;
    ca.set_serial_number(&ca_serial)?;
    ca.set_subject_name(&ca_name)?;
    ca.set_issuer_name(&ca_name)?;
    ca.set_pubkey(&ca_key)?;
    ca.set_not_before(&not_before)?;
    ca.set_not_after(&not_after)?;
    ca.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    ca.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;
    ca.sign(&ca_key, MessageDigest::sha256())?;
    let ca = ca.build();

    let mut leaf_name = X509NameBuilder::new()?;
    leaf_name.append_entry_by_text("CN", hostname)?;
    let leaf_name = leaf_name.build();
    let mut leaf = X509::builder()?;
    leaf.set_version(2)?;
    let leaf_serial = random_serial()?;
    leaf.set_serial_number(&leaf_serial)?;
    leaf.set_subject_name(&leaf_name)?;
    leaf.set_issuer_name(ca.subject_name())?;
    leaf.set_pubkey(signing_key)?;
    leaf.set_not_before(&not_before)?;
    leaf.set_not_after(&not_after)?;
    leaf.append_extension(BasicConstraints::new().critical().build()?)?;
    leaf.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
    let san = SubjectAlternativeName::new()
        .dns(hostname)
        .build(&leaf.x509v3_context(Some(&ca), None))?;
    leaf.append_extension(san)?;
    leaf.sign(&ca_key, MessageDigest::sha256())?;
    let leaf = leaf.build();

    let mut chain = leaf.to_pem()?;
    chain.extend(ca.to_pem()?);
    Ok(chain)
}

fn random_serial() -> anyhow::Result<openssl::asn1::Asn1Integer> {
    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::ONE, false)?;
    Ok(serial.to_asn1_integer()?)
}

fn is_ca_certificate(certificate: &X509) -> anyhow::Result<bool> {
    let der = certificate.to_der()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der)
        .map_err(|error| anyhow::anyhow!("failed to parse X.509 certificate: {error}"))?;
    Ok(parsed.is_ca())
}

async fn activate_openid4vc_certificate_bundle(
    paths: &Openid4vcCertificatePaths,
    bundle: &[u8],
) -> anyhow::Result<()> {
    if paths.chain != paths.anchors {
        bail!(
            "OpenID4VC signing certificate chain and trust anchors must reference one atomic certificate bundle"
        );
    }
    let parent = paths
        .chain
        .parent()
        .context("OpenID4VC certificate bundle path has no parent")?;
    tokio::fs::create_dir_all(parent).await?;
    match tokio::fs::symlink_metadata(&paths.chain).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!(
                "OpenID4VC certificate bundle must be a regular file: {}",
                paths.chain.display()
            );
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", paths.chain.display()));
        }
    }
    let temporary = parent.join(format!(
        ".openid4vc-certificate-bundle-{}",
        uuid::Uuid::now_v7()
    ));
    write_openid4vc_file(&temporary, bundle).await?;
    if let Err(error) = tokio::fs::rename(&temporary, &paths.chain).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error).with_context(|| {
            format!(
                "failed to atomically activate OpenID4VC certificate bundle {}",
                paths.chain.display()
            )
        });
    }
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

async fn write_openid4vc_file(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await?;
    file.write_all(contents).await?;
    file.sync_all().await?;
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
