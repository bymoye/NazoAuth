//! Signing-key lifecycle plus the local mdoc certificate and CRL material it owns.

use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context, bail};
use nazo_auth::SigningPurpose;
use nazo_key_management::signing_algorithm_from_name;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
    CustomExtension, DistinguishedName, DnType, IsCa, Issuer, KeyIdMethod, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData, RevokedCertParams, SerialNumber,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use url::{Host, Url};
use yasna::{Tag, models::ObjectIdentifier};

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
    mdoc_profile: Option<MdocCertificateProfile>,
}

#[derive(Clone, Debug)]
struct MdocCertificateProfile {
    issuing_country: String,
    issuer_contact_uri: String,
    crl_distribution_uri: String,
}

struct Openid4vcCertificateBundle {
    contents: Vec<u8>,
    mdoc_material: Option<MdocCertificateMaterial>,
}

struct MdocCertificateMaterial {
    leaf_der: Vec<u8>,
    ca_der: Vec<u8>,
    issuer_material_pem: String,
}

#[derive(Clone)]
pub(crate) struct MdocCrlSource {
    certificate_bundle: PathBuf,
    revocation_snapshot: PathBuf,
    issuer_contact_uri: String,
}

impl MdocCrlSource {
    pub(crate) fn from_settings(settings: &crate::settings::Settings) -> Option<Self> {
        let certificate_bundle = settings.openid4vc.signing_certificate_chain_file.clone()?;
        let revocation_snapshot = settings.openid4vc.revocation_snapshot_file.clone()?;
        let issuer_contact_uri = settings
            .endpoint
            .issuer
            .as_str()
            .trim_end_matches('/')
            .to_owned();
        Some(Self {
            certificate_bundle,
            revocation_snapshot,
            issuer_contact_uri,
        })
    }
}

pub(crate) async fn signed_mdoc_crl(
    source: &MdocCrlSource,
    issuer_id: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    if issuer_id.len() != 64
        || !issuer_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(None);
    }
    let key_path = source
        .certificate_bundle
        .parent()
        .context("OpenID4VC certificate bundle path has no parent")?
        .join("iaca-keys")
        .join(format!("{issuer_id}.pem"));
    let issuer_material = match tokio::fs::read_to_string(&key_path).await {
        Ok(material) => material,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("failed to read mdoc issuer material"),
    };
    let snapshot = crate::bootstrap::read_revocation_snapshot(&source.revocation_snapshot)
        .await
        .with_context(|| {
            format!(
                "failed to load mdoc revocation snapshot {}",
                source.revocation_snapshot.display()
            )
        })?;
    let certificates = CertificateDer::pem_slice_iter(issuer_material.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse OpenID4VC certificate bundle")?;
    if certificates.len() != 2 {
        bail!("OpenID4VC certificate bundle must contain a DS and IACA");
    }
    let (_, leaf) = x509_parser::parse_x509_certificate(certificates[0].as_ref())
        .map_err(|error| anyhow::anyhow!("failed to parse OpenID4VC DS certificate: {error}"))?;
    let (_, ca) = x509_parser::parse_x509_certificate(certificates[1].as_ref())
        .map_err(|error| anyhow::anyhow!("failed to parse OpenID4VC IACA certificate: {error}"))?;
    if sha256_hex(certificates[1].as_ref()) != issuer_id {
        bail!("mdoc issuer material does not match requested IACA fingerprint");
    }
    if !is_mdoc_document_signing_certificate(&leaf) {
        return Ok(None);
    }
    let identity = nazo_digital_credentials::certificate_identity(certificates[0].as_ref());
    let status = snapshot
        .entries
        .iter()
        .find(|entry| entry.issuer == source.issuer_contact_uri && entry.certificate == identity)
        .map(|entry| entry.status)
        .context("mdoc revocation snapshot has no status for the current DS certificate")?;
    let private_key = KeyPair::from_pem(&issuer_material)
        .context("failed to parse IACA private key as PKCS#8 PEM")?;
    if private_key.public_key_raw() != ca.public_key().subject_public_key.data.as_ref() {
        bail!("IACA private key does not match current certificate bundle");
    }
    let issuer = Issuer::from_ca_cert_der(&certificates[1], private_key)
        .context("failed to build CRL issuer from IACA certificate")?;
    let this_update = time::OffsetDateTime::from_unix_timestamp(snapshot.this_update.timestamp())
        .context("mdoc revocation snapshot this_update is out of range")?;
    let next_update = time::OffsetDateTime::from_unix_timestamp(snapshot.next_update.timestamp())
        .context("mdoc revocation snapshot next_update is out of range")?;
    let revoked_certs = match status {
        nazo_digital_credentials::CertificateRevocationStatus::Good => Vec::new(),
        nazo_digital_credentials::CertificateRevocationStatus::Revoked => vec![RevokedCertParams {
            serial_number: SerialNumber::from(leaf.raw_serial().to_vec()),
            revocation_time: this_update,
            reason_code: None,
            invalidity_date: None,
        }],
    };
    let crl = CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from(
            u64::try_from(snapshot.this_update.timestamp_micros())
                .context("mdoc revocation snapshot this_update precedes the Unix epoch")?,
        ),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::PreSpecified(subject_key_identifier(issuer.key())),
    }
    .signed_by(&issuer)
    .context("failed to sign mdoc CRL")?;
    Ok(Some(crl.der().to_vec()))
}

fn is_mdoc_document_signing_certificate(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
) -> bool {
    certificate.extensions().iter().any(|extension| {
        extension.critical
            && matches!(
                &extension.parsed_extension(),
                x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(usage)
                    if usage.other.iter().any(|oid| oid.to_id_string() == "2.23.136.1.1.1")
            )
    })
}

fn load_key_settings() -> anyhow::Result<nazo_key_management::KeySettings> {
    key_settings_from_config(&ConfigSource::load_without_secret_values()?)
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
            let issuer = certificate_issuer(config)?;
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
                mdoc_profile: None,
            })
        }
        _ => bail!(
            "OpenID4VC certificate generation requires both OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE and OPENID4VC_TRUST_ANCHORS_FILE"
        ),
    };
    Ok((key_settings_from_config(config)?, certificate_paths))
}

fn certificate_issuer(config: &ConfigSource) -> anyhow::Result<Url> {
    let issuer = config
        .optional_string("ISSUER")
        .unwrap_or_else(|| config.string("PUBLIC_BASE_URL", "http://127.0.0.1:8000"));
    Url::parse(&issuer).context("OpenID4VC certificate issuer must be absolute")
}

fn mdoc_certificate_profile(
    config: &ConfigSource,
    issuer: &Url,
) -> anyhow::Result<Option<MdocCertificateProfile>> {
    let configurations = crate::settings::credential_configurations_from_config(config)?;
    let Some(issuing_country) =
        crate::settings::mdoc_issuing_country_from_config(config, &configurations)?
    else {
        return Ok(None);
    };
    let issuer_contact_uri = issuer.as_str().trim_end_matches('/').to_owned();
    Ok(Some(MdocCertificateProfile {
        issuing_country,
        crl_distribution_uri: format!("{issuer_contact_uri}/.well-known/mdoc"),
        issuer_contact_uri,
    }))
}

#[derive(Debug)]
struct GenerateLocalKeyOptions {
    alg: jsonwebtoken::Algorithm,
    purposes: BTreeSet<SigningPurpose>,
}

pub(crate) async fn operator_list() -> anyhow::Result<String> {
    let settings = load_key_settings()?;
    let _ = nazo_key_management::KeyManager::list_keys(&settings).await?;
    keyset_revision_from(&settings).await
}

pub(crate) async fn operator_validate() -> anyhow::Result<String> {
    let settings = load_key_settings()?;
    nazo_key_management::KeyManager::validate(&settings).await?;
    keyset_revision_from(&settings).await
}

pub(crate) async fn operator_generate_local(
    algorithm: &str,
    purposes: &[String],
) -> anyhow::Result<(String, String)> {
    let options = parse_generate_local(algorithm, purposes)?;
    let config = ConfigSource::load_without_secret_values()?;
    let (settings, mut certificate_paths) = key_task_config_from(&config)?;
    if options.purposes.contains(&SigningPurpose::Credential)
        && let Some(paths) = certificate_paths.as_mut()
    {
        paths.mdoc_profile = mdoc_certificate_profile(&config, &certificate_issuer(&config)?)?;
    }
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
        mdoc_profile: options
            .purposes
            .contains(&SigningPurpose::Credential)
            .then(|| mdoc_certificate_profile(&config, &issuer))
            .transpose()?
            .flatten(),
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
            if certificate_paths.mdoc_profile.is_none() {
                ensure_openid4vc_revocation_snapshot(&certificate_paths).await?;
            }
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
    let settings = load_key_settings()?;
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
        if paths.mdoc_profile.is_none() {
            ensure_openid4vc_revocation_snapshot(paths).await?;
        }
        return Ok(());
    }

    let bundle = build_openid4vc_certificate_bundle(
        &private_key,
        &paths.hostname,
        paths.mdoc_profile.as_ref(),
    )?;
    activate_openid4vc_certificate_bundle(paths, &bundle).await?;
    if let Some(material) = bundle.mdoc_material.as_ref() {
        initialize_mdoc_revocation_snapshot(paths, material).await
    } else {
        ensure_openid4vc_revocation_snapshot(paths).await
    }
}

async fn ensure_openid4vc_revocation_snapshot(
    paths: &Openid4vcCertificatePaths,
) -> anyhow::Result<()> {
    let Some(path) = paths.revocation_snapshot.as_ref() else {
        return Ok(());
    };
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
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }
    let now = chrono::Utc::now();
    let snapshot = nazo_digital_credentials::CertificateRevocationSnapshot {
        version: nazo_digital_credentials::CertificateRevocationSnapshot::VERSION,
        this_update: now - chrono::Duration::minutes(1),
        next_update: now + chrono::Duration::hours(24),
        entries: Vec::new(),
    };
    let contents = serde_json::to_vec(&snapshot)?;
    atomic_write(path, &contents, atomicwrites::AllowOverwrite).await
}

async fn initialize_mdoc_revocation_snapshot(
    paths: &Openid4vcCertificatePaths,
    material: &MdocCertificateMaterial,
) -> anyhow::Result<()> {
    let Some(path) = paths.revocation_snapshot.as_ref() else {
        return Ok(());
    };
    let parent = path
        .parent()
        .context("OpenID4VC revocation snapshot path has no parent")?;
    tokio::fs::create_dir_all(parent).await?;
    let issuer = paths
        .mdoc_profile
        .as_ref()
        .expect("mdoc material requires profile")
        .issuer_contact_uri
        .clone();
    let certificate = nazo_digital_credentials::certificate_identity(&material.leaf_der);
    let mut snapshot = match tokio::fs::read(path).await {
        Ok(bytes) => nazo_digital_credentials::CertificateRevocationSnapshot::from_json(&bytes)
            .map_err(|error| anyhow::anyhow!(error))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let now = chrono::Utc::now();
            nazo_digital_credentials::CertificateRevocationSnapshot {
                version: nazo_digital_credentials::CertificateRevocationSnapshot::VERSION,
                this_update: now - chrono::Duration::minutes(1),
                next_update: now + chrono::Duration::hours(24),
                entries: Vec::new(),
            }
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read OpenID4VC revocation snapshot {}",
                    path.display()
                )
            });
        }
    };
    if !snapshot
        .entries
        .iter()
        .any(|entry| entry.issuer == issuer && entry.certificate == certificate)
    {
        snapshot.this_update = chrono::Utc::now();
        snapshot
            .entries
            .push(nazo_digital_credentials::CertificateRevocationEntry {
                issuer,
                certificate,
                status: nazo_digital_credentials::CertificateRevocationStatus::Good,
            });
        let contents = serde_json::to_vec(&snapshot)?;
        atomic_write(path, &contents, atomicwrites::AllowOverwrite).await?;
    }
    Ok(())
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
    if let Some(profile) = paths.mdoc_profile.as_ref()
        && (!mdoc_certificate_profile_matches(&leaf, &ca, profile)
            || !iaca_private_key_matches(paths, certificates[1].as_ref(), &ca).await?)
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

fn mdoc_certificate_profile_matches(
    leaf: &x509_parser::certificate::X509Certificate<'_>,
    ca: &x509_parser::certificate::X509Certificate<'_>,
    profile: &MdocCertificateProfile,
) -> bool {
    let country_matches = |certificate: &x509_parser::certificate::X509Certificate<'_>| {
        certificate
            .subject()
            .iter_country()
            .map(|country| country.as_str().ok())
            .eq([Some(profile.issuing_country.as_str())])
    };
    let has_ian = |certificate: &x509_parser::certificate::X509Certificate<'_>| {
        certificate.extensions().iter().any(|extension| {
            matches!(
                &extension.parsed_extension(),
                x509_parser::extensions::ParsedExtension::IssuerAlternativeName(names)
                    if names.general_names.iter().any(|name| matches!(name, x509_parser::extensions::GeneralName::URI(uri) if *uri == profile.issuer_contact_uri))
            )
        })
    };
    let has_crldp = leaf.extensions().iter().any(|extension| {
        let x509_parser::extensions::ParsedExtension::CRLDistributionPoints(points) =
            &extension.parsed_extension()
        else {
            return false;
        };
        points.points.iter().any(|point| {
            let Some(x509_parser::extensions::DistributionPointName::FullName(names)) =
                &point.distribution_point
            else {
                return false;
            };
            names.iter().any(|name| {
                matches!(
                    name,
                    x509_parser::extensions::GeneralName::URI(uri)
                        if *uri == format!("{}/{}.crl", profile.crl_distribution_uri, sha256_hex(ca.as_ref()))
                )
            })
        })
    });
    let has_document_signing_eku = is_mdoc_document_signing_certificate(leaf);
    let leaf_ski =
        subject_key_identifier_from_public_key(leaf.public_key().subject_public_key.data.as_ref());
    let ca_ski =
        subject_key_identifier_from_public_key(ca.public_key().subject_public_key.data.as_ref());
    let has_ski = |certificate: &x509_parser::certificate::X509Certificate<'_>, expected: &[u8]| {
        certificate.extensions().iter().any(|extension| {
            matches!(
                &extension.parsed_extension(),
                x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(identifier)
                    if identifier.0 == expected
            )
        })
    };
    let has_aki = leaf.extensions().iter().any(|extension| {
        matches!(
            &extension.parsed_extension(),
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(identifier)
                if identifier.key_identifier.as_ref().is_some_and(|value| value.0 == ca_ski)
        )
    });
    let ca_path_len_is_zero = ca
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|constraint| {
            constraint.value.ca && constraint.value.path_len_constraint == Some(0)
        });
    let validity_seconds =
        leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp();
    country_matches(leaf)
        && country_matches(ca)
        && has_ian(leaf)
        && has_ian(ca)
        && has_crldp
        && has_document_signing_eku
        && has_ski(leaf, &leaf_ski)
        && has_ski(ca, &ca_ski)
        && has_aki
        && ca_path_len_is_zero
        && leaf.raw_serial().len() <= 20
        && validity_seconds <= 457 * 24 * 60 * 60
}

fn subject_key_identifier_from_public_key(public_key: &[u8]) -> Vec<u8> {
    Sha1::digest(public_key).to_vec()
}

async fn iaca_private_key_matches(
    paths: &Openid4vcCertificatePaths,
    ca_der: &[u8],
    ca: &x509_parser::certificate::X509Certificate<'_>,
) -> anyhow::Result<bool> {
    let key_path = iaca_private_key_path(&paths.chain, ca_der)?;
    let private_key_pem = match tokio::fs::read_to_string(&key_path).await {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", key_path.display()));
        }
    };
    let private_key = match KeyPair::from_pem(&private_key_pem) {
        Ok(key) => key,
        Err(_) => return Ok(false),
    };
    Ok(private_key.public_key_raw() == ca.public_key().subject_public_key.data.as_ref())
}

fn build_openid4vc_certificate_bundle(
    signing_key: &KeyPair,
    hostname: &str,
    mdoc_profile: Option<&MdocCertificateProfile>,
) -> anyhow::Result<Openid4vcCertificateBundle> {
    let now = time::OffsetDateTime::now_utc();
    let ca_not_after = now + time::Duration::days(3650);
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "NazoAuth OpenID4VC Local CA");
    if let Some(profile) = mdoc_profile {
        ca_params
            .distinguished_name
            .push(DnType::CountryName, &profile.issuing_country);
        ca_params
            .custom_extensions
            .push(issuer_alternative_name(&profile.issuer_contact_uri));
    }
    ca_params.is_ca = IsCa::Ca(if mdoc_profile.is_some() {
        BasicConstraints::Constrained(0)
    } else {
        BasicConstraints::Unconstrained
    });
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = now;
    ca_params.not_after = ca_not_after;
    ca_params.serial_number = Some(SerialNumber::from(rand::random::<[u8; 19]>().to_vec()));
    if mdoc_profile.is_some() {
        ca_params.key_identifier_method =
            KeyIdMethod::PreSpecified(subject_key_identifier(&ca_key));
    }
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key)?;

    let mut leaf_params = CertificateParams::new(vec![hostname.to_owned()])?;
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, hostname);
    if let Some(profile) = mdoc_profile {
        leaf_params
            .distinguished_name
            .push(DnType::CountryName, &profile.issuing_country);
        leaf_params
            .custom_extensions
            .push(document_signing_extended_key_usage());
        leaf_params
            .custom_extensions
            .push(issuer_alternative_name(&profile.issuer_contact_uri));
        leaf_params
            .crl_distribution_points
            .push(rcgen::CrlDistributionPoint {
                uris: vec![format!(
                    "{}/{}.crl",
                    profile.crl_distribution_uri,
                    sha256_hex(ca.der())
                )],
            });
    }
    leaf_params.is_ca = if mdoc_profile.is_some() {
        IsCa::ExplicitNoCa
    } else {
        IsCa::NoCa
    };
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = now;
    leaf_params.not_after = if mdoc_profile.is_some() {
        now + time::Duration::days(457)
    } else {
        ca_not_after
    };
    leaf_params.serial_number = Some(SerialNumber::from(rand::random::<[u8; 19]>().to_vec()));
    if mdoc_profile.is_some() {
        leaf_params.key_identifier_method =
            KeyIdMethod::PreSpecified(subject_key_identifier(signing_key));
    }
    leaf_params.use_authority_key_identifier_extension = mdoc_profile.is_some();
    let leaf = leaf_params.signed_by(signing_key, &ca)?;

    Ok(Openid4vcCertificateBundle {
        contents: format!("{}{}", leaf.pem(), ca.pem()).into_bytes(),
        mdoc_material: mdoc_profile.map(|_| MdocCertificateMaterial {
            leaf_der: leaf.der().to_vec(),
            ca_der: ca.der().to_vec(),
            // One immutable IACA record owns its key and sole DS. Retaining it
            // keeps the certificate's CRL address valid across key rotation.
            issuer_material_pem: format!("{}{}{}", ca.key().serialize_pem(), leaf.pem(), ca.pem()),
        }),
    })
}

fn subject_key_identifier(key: &KeyPair) -> Vec<u8> {
    subject_key_identifier_from_public_key(key.public_key_raw())
}

fn document_signing_extended_key_usage() -> CustomExtension {
    let content = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer
                .next()
                .write_oid(&ObjectIdentifier::from_slice(&[2, 23, 136, 1, 1, 1]));
        });
    });
    let mut extension = CustomExtension::from_oid_content(&[2, 5, 29, 37], content);
    extension.set_criticality(true);
    extension
}

fn issuer_alternative_name(uri: &str) -> CustomExtension {
    let content = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer
                .next()
                .write_tagged_implicit(Tag::context(6), |writer| writer.write_ia5_string(uri));
        });
    });
    CustomExtension::from_oid_content(&[2, 5, 29, 18], content)
}

async fn activate_openid4vc_certificate_bundle(
    paths: &Openid4vcCertificatePaths,
    bundle: &Openid4vcCertificateBundle,
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
    if let Some(material) = bundle.mdoc_material.as_ref() {
        persist_iaca_private_key(paths, material).await?;
    }
    atomic_write(&paths.chain, &bundle.contents, atomicwrites::AllowOverwrite).await
}

async fn atomic_write(
    path: &std::path::Path,
    contents: &[u8],
    overwrite: atomicwrites::OverwriteBehavior,
) -> anyhow::Result<()> {
    let destination = path.to_owned();
    let contents = contents.to_vec();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::Write as _;

        atomicwrites::AtomicFile::new(&destination, overwrite)
            .write(|file| file.write_all(&contents))
            .map_err(std::io::Error::from)
    })
    .await
    .context("OpenID4VC atomic writer task failed")?
    .with_context(|| {
        format!(
            "failed to atomically write OpenID4VC material {}",
            path.display()
        )
    })
}

pub(crate) fn iaca_private_key_path(
    certificate_bundle: &std::path::Path,
    ca_der: &[u8],
) -> anyhow::Result<PathBuf> {
    let parent = certificate_bundle
        .parent()
        .context("OpenID4VC certificate bundle path has no parent")?;
    Ok(parent
        .join("iaca-keys")
        .join(format!("{}.pem", sha256_hex(ca_der))))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn persist_iaca_private_key(
    paths: &Openid4vcCertificatePaths,
    material: &MdocCertificateMaterial,
) -> anyhow::Result<()> {
    let key_path = iaca_private_key_path(&paths.chain, &material.ca_der)?;
    let key_directory = key_path.parent().expect("IACA key path has parent");
    tokio::fs::create_dir_all(key_directory).await?;
    restrict_iaca_key_directory_permissions(key_directory)?;
    match tokio::fs::symlink_metadata(key_directory).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!(
                "OpenID4VC IACA key directory must be a real directory: {}",
                key_directory.display()
            );
        }
        Ok(_) => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", key_directory.display()));
        }
    }
    match tokio::fs::symlink_metadata(&key_path).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!(
                "OpenID4VC IACA private key must be a regular file: {}",
                key_path.display()
            );
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", key_path.display()));
        }
    }
    let written = match tokio::fs::read_to_string(&key_path).await {
        Ok(existing) => {
            let existing_key = KeyPair::from_pem(&existing)
                .context("failed to parse existing IACA private key")?;
            let (_, ca) =
                x509_parser::parse_x509_certificate(&material.ca_der).map_err(|error| {
                    anyhow::anyhow!("failed to parse generated IACA certificate: {error}")
                })?;
            if existing_key.public_key_raw() != ca.public_key().subject_public_key.data.as_ref() {
                bail!(
                    "existing IACA private key does not match certificate {}",
                    key_path.display()
                );
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic_write_private(&key_path, material.issuer_material_pem.as_bytes()).await
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to read IACA private key {}", key_path.display())),
    };
    written?;
    restrict_iaca_private_key_permissions(&key_path)
}

async fn atomic_write_private(path: &std::path::Path, contents: &[u8]) -> anyhow::Result<()> {
    let destination = path.to_owned();
    let contents = contents.to_vec();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::Write as _;

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        atomicwrites::AtomicFile::new(&destination, atomicwrites::DisallowOverwrite)
            .write_with_options(|file| file.write_all(&contents), options)
            .map_err(std::io::Error::from)
    })
    .await
    .context("OpenID4VC IACA private-key writer task failed")?
    .with_context(|| {
        format!(
            "failed to atomically write IACA private key {}",
            path.display()
        )
    })
}

#[cfg(unix)]
fn restrict_iaca_key_directory_permissions(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to restrict IACA key directory {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_iaca_key_directory_permissions(_path: &std::path::Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_iaca_private_key_permissions(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict IACA private key {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_iaca_private_key_permissions(_path: &std::path::Path) -> anyhow::Result<()> {
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
