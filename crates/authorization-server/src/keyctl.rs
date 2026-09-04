//! Typed signing-key operations reachable only through the signed operator-task protocol.

use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context, bail};
use nazo_auth::SigningPurpose;
use nazo_key_management::signing_algorithm_from_name;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData, SerialNumber,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use url::{Host, Url};

use crate::{
    config::ConfigSource,
    settings::{Settings, key_settings_from_config},
};

#[derive(Debug)]
struct Openid4vcCertificatePaths {
    chain: PathBuf,
    anchors: PathBuf,
    revocation_snapshot: Option<PathBuf>,
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
                revocation_snapshot: config
                    .optional_string("OPENID4VC_REVOCATION_SNAPSHOT_FILE")
                    .map(PathBuf::from),
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

pub(crate) async fn operator_generate_local_for_tenant(
    binding: &nazo_identity::TenantDirectoryBinding,
    algorithm: &str,
    purposes: &[String],
) -> anyhow::Result<(String, String, String)> {
    let options = parse_generate_local(algorithm, purposes)?;
    let config = ConfigSource::load()?;
    let settings = Settings::from_directory_binding(&config, binding)?;
    let chain = settings
        .openid4vc
        .signing_certificate_chain_file
        .clone()
        .context("tenant-local certificate generation requires OpenID4VC to be enabled")?;
    let anchors = settings
        .openid4vc
        .trust_anchors_file
        .clone()
        .context("tenant-local certificate generation requires OpenID4VC trust storage")?;
    let issuer = Url::parse(&binding.issuer)?;
    let Host::Domain(hostname) = issuer
        .host()
        .context("tenant issuer must include a DNS hostname")?
    else {
        bail!("tenant issuer must include a DNS hostname");
    };
    let certificate_paths = Openid4vcCertificatePaths {
        chain: chain.clone(),
        anchors,
        revocation_snapshot: settings.openid4vc.revocation_snapshot_file.clone(),
        hostname: hostname.to_owned(),
    };
    let key_settings = settings.key_settings();
    nazo_key_management::KeyManager::load_or_create(key_settings.clone()).await?;
    for record in nazo_key_management::KeyManager::list_keys(&key_settings).await? {
        if record.status != nazo_key_management::KeyRecordStatus::PurposeScoped
            || record.algorithm != "ES256"
            || record.backend != "local-pem"
            || record.locator.is_empty()
        {
            continue;
        }
        let private_key_pem =
            tokio::fs::read_to_string(key_settings.keys_dir.join(&record.locator)).await?;
        let private_key = KeyPair::from_pem(&private_key_pem)?;
        if existing_openid4vc_bundle_matches(&certificate_paths, &private_key).await? {
            ensure_openid4vc_revocation_snapshot(&certificate_paths).await?;
            let certificate_chain = tokio::fs::read_to_string(&chain).await?;
            return Ok((
                record.kid,
                keyset_revision_from(&key_settings).await?,
                certificate_chain,
            ));
        }
    }
    let (kid, revision) =
        generate_local_with_key_settings(&key_settings, Some(&certificate_paths), options).await?;
    let certificate_chain = tokio::fs::read_to_string(&chain).await.with_context(|| {
        format!(
            "failed to read generated certificate chain {}",
            chain.display()
        )
    })?;
    Ok((kid, revision, certificate_chain))
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
    public_jwk_bytes: &[u8],
) -> anyhow::Result<String> {
    let alg = signing_algorithm_from_name(algorithm)
        .ok_or_else(|| anyhow::anyhow!("unsupported signing alg {algorithm}"))?;
    let public_jwk = serde_json::from_slice(public_jwk_bytes)
        .context("failed to parse mounted external public JWK")?;
    let (settings, _) = load_key_task_config()?;
    nazo_key_management::KeyManager::register_external(
        &settings,
        nazo_key_management::ExternalKeyRegistration {
            kid: kid.to_owned(),
            algorithm: alg,
            key_ref: key_ref.to_owned(),
            public_jwk,
        },
    )
    .await?;
    keyset_revision_from(&settings).await
}

pub(crate) async fn remove_tenant_material(
    tenant_id: nazo_identity::TenantId,
) -> anyhow::Result<()> {
    let config = ConfigSource::load_without_secret_values()?;
    let data_dir = config.persistent_path("DATA_DIR", Some(crate::config::DEFAULT_DATA_DIR))?;
    let tenants_dir = data_dir.join("tenants");
    let tenant_dir = tenants_dir.join(tenant_id.as_uuid().to_string());
    match tokio::fs::symlink_metadata(&tenant_dir).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("tenant material path must be a real directory")
        }
        Ok(_) => tokio::fs::remove_dir_all(&tenant_dir)
            .await
            .with_context(|| format!("failed to remove tenant material {}", tenant_dir.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect tenant material {}", tenant_dir.display())),
    }
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
    let private_key_pem = tokio::fs::read_to_string(&key_path)
        .await
        .with_context(|| {
            format!(
                "failed to load credential signing key {}",
                key_path.display()
            )
        })?;
    let private_key = KeyPair::from_pem(&private_key_pem)
        .context("failed to parse credential signing key as PKCS#8 PEM")?;
    if existing_openid4vc_bundle_matches(paths, &private_key).await? {
        ensure_openid4vc_revocation_snapshot(paths).await?;
        return Ok(());
    }

    let bundle = build_openid4vc_certificate_bundle(&private_key, &paths.hostname)?;
    activate_openid4vc_certificate_bundle(paths, &bundle).await?;
    ensure_openid4vc_revocation_snapshot(paths).await
}

async fn ensure_openid4vc_revocation_snapshot(
    paths: &Openid4vcCertificatePaths,
) -> anyhow::Result<()> {
    let Some(path) = paths.revocation_snapshot.as_ref() else {
        return Ok(());
    };
    let now = chrono::Utc::now();
    let snapshot = nazo_digital_credentials::CertificateRevocationSnapshot {
        version: nazo_digital_credentials::CertificateRevocationSnapshot::VERSION,
        this_update: now - chrono::Duration::minutes(1),
        next_update: now + chrono::Duration::hours(24),
        entries: Vec::new(),
    };
    let contents = serde_json::to_vec(&snapshot)?;
    let parent = path
        .parent()
        .context("OpenID4VC revocation snapshot path has no parent")?;
    tokio::fs::create_dir_all(parent).await?;
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!(
                "OpenID4VC revocation snapshot must be a regular file: {}",
                path.display()
            );
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }
    let destination = path.clone();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::Write as _;

        atomicwrites::AtomicFile::new(&destination, atomicwrites::AllowOverwrite)
            .write(|file| file.write_all(&contents))
            .map_err(std::io::Error::from)
    })
    .await
    .context("OpenID4VC revocation snapshot writer task failed")?
    .with_context(|| {
        format!(
            "failed to atomically activate OpenID4VC revocation snapshot {}",
            path.display()
        )
    })
}

async fn existing_openid4vc_bundle_matches(
    paths: &Openid4vcCertificatePaths,
    private_key: &KeyPair,
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
    let Ok(certificates) = CertificateDer::pem_slice_iter(&chain).collect::<Result<Vec<_>, _>>()
    else {
        return Ok(false);
    };
    if certificates.len() != 2 {
        return Ok(false);
    }
    let (_, leaf) = x509_parser::parse_x509_certificate(certificates[0].as_ref())
        .map_err(|error| anyhow::anyhow!("failed to parse OpenID4VC leaf certificate: {error}"))?;
    let (_, ca) = x509_parser::parse_x509_certificate(certificates[1].as_ref())
        .map_err(|error| anyhow::anyhow!("failed to parse OpenID4VC CA certificate: {error}"))?;
    if leaf.public_key().subject_public_key.data.as_ref() != private_key.der_bytes()
        || certificates[0] == certificates[1]
        || leaf.is_ca()
        || !ca.is_ca()
        || ca.subject() != ca.issuer()
        || leaf.issuer() != ca.subject()
        || !leaf.validity().is_valid()
        || !ca.validity().is_valid()
        || ca.verify_signature(Some(ca.public_key())).is_err()
        || leaf.verify_signature(Some(ca.public_key())).is_err()
    {
        return Ok(false);
    }
    let Ok(Some(subject_alt_names)) = leaf.subject_alternative_name() else {
        return Ok(false);
    };
    Ok(subject_alt_names.value.general_names.len() == 1
        && matches!(
            &subject_alt_names.value.general_names[0],
            x509_parser::extensions::GeneralName::DNSName(name) if *name == paths.hostname
        ))
}

fn build_openid4vc_certificate_bundle(
    signing_key: &KeyPair,
    hostname: &str,
) -> anyhow::Result<Vec<u8>> {
    let now = time::OffsetDateTime::now_utc();
    let not_after = now + time::Duration::days(3650);
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "NazoAuth OpenID4VC Local CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = now;
    ca_params.not_after = not_after;
    ca_params.serial_number = Some(SerialNumber::from(rand::random::<[u8; 20]>().to_vec()));
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key)?;

    let mut leaf_params = CertificateParams::new(vec![hostname.to_owned()])?;
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, hostname);
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = now;
    leaf_params.not_after = not_after;
    leaf_params.serial_number = Some(SerialNumber::from(rand::random::<[u8; 20]>().to_vec()));
    let leaf = leaf_params.signed_by(signing_key, &ca)?;

    Ok(format!("{}{}", leaf.pem(), ca.pem()).into_bytes())
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
    let destination = paths.chain.clone();
    let contents = bundle.to_vec();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::Write as _;

        atomicwrites::AtomicFile::new(&destination, atomicwrites::AllowOverwrite)
            .write(|file| file.write_all(&contents))
            .map_err(std::io::Error::from)
    })
    .await
    .context("OpenID4VC certificate bundle writer task failed")?
    .with_context(|| {
        format!(
            "failed to atomically activate OpenID4VC certificate bundle {}",
            paths.chain.display()
        )
    })
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
