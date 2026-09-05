//! Tenant signing keys and their atomically persisted OpenID4VC authority material.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use nazo_auth::SigningPurpose;
use nazo_key_management::{
    KeyManager, Openid4vcMaterial, Openid4vcPublicMaterial, signing_algorithm_from_name,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
    CustomExtension, DistinguishedName, DnType, DnValue, IsCa, Issuer, KeyIdMethod, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, RevokedCertParams, SerialNumber,
    string::PrintableString,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use url::{Host, Url};
use yasna::{Tag, models::ObjectIdentifier};

use crate::{config::ConfigSource, settings::Settings};

#[derive(Debug)]
struct Openid4vcCertificateProfile {
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
    keyset: KeyManager,
    issuer_contact_uri: String,
}

impl MdocCrlSource {
    pub(crate) fn from_settings(settings: &Settings, keyset: KeyManager) -> Option<Self> {
        (settings.modules.enable_openid4vci_issuer || settings.modules.enable_openid4vp_verifier)
            .then(|| Self {
                keyset,
                issuer_contact_uri: settings
                    .endpoint
                    .issuer
                    .as_str()
                    .trim_end_matches('/')
                    .to_owned(),
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
    // Revocation facts are read from the authority, not an instance-local cache.
    let state = source.keyset.database_openid4vc_state().await?;
    let Some(material) = state.material else {
        return Ok(None);
    };
    let Some(issuer_material) = material.iaca_private_materials.get(issuer_id) else {
        return Ok(None);
    };
    let snapshot = material
        .public
        .revocation_snapshot
        .context("mdoc authority has no revocation state")?;
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
    let entry = snapshot
        .entries
        .iter()
        .find(|entry| entry.issuer == source.issuer_contact_uri && entry.certificate == identity)
        .context("mdoc revocation snapshot has no status for the current DS certificate")?;
    let private_key = KeyPair::from_pem(issuer_material)
        .context("failed to parse IACA private key as PKCS#8 PEM")?;
    if private_key.public_key_raw() != ca.public_key().subject_public_key.data.as_ref() {
        bail!("IACA private key does not match current certificate bundle");
    }
    let issuer = Issuer::from_ca_cert_der(&certificates[1], private_key)
        .context("failed to build CRL issuer from IACA certificate")?;
    let this_update = time::OffsetDateTime::now_utc();
    let next_update = this_update + time::Duration::hours(24);
    let revoked_certs = match entry.status {
        nazo_digital_credentials::CertificateRevocationStatus::Good => Vec::new(),
        nazo_digital_credentials::CertificateRevocationStatus::Revoked => vec![RevokedCertParams {
            serial_number: SerialNumber::from(leaf.raw_serial().to_vec()),
            revocation_time: time::OffsetDateTime::from_unix_timestamp(
                entry
                    .revoked_at
                    .context("revoked DS has no recorded revocation time")?
                    .timestamp(),
            )
            .context("DS revocation time is out of range")?,
            reason_code: None,
            invalidity_date: None,
        }],
    };
    let crl = CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from(
            u64::try_from(this_update.unix_timestamp_nanos() / 1_000)
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
                    if usage.other.iter().any(|oid| matches!(
                        oid.to_id_string().as_str(),
                        "1.0.18013.5.1.2" | "2.23.136.1.1.1"
                    ))
            )
    })
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
        ca_params.distinguished_name.push(
            DnType::CountryName,
            printable_country_name(&profile.issuing_country)?,
        );
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
        leaf_params.distinguished_name.push(
            DnType::CountryName,
            printable_country_name(&profile.issuing_country)?,
        );
        leaf_params
            .custom_extensions
            .push(document_signing_extended_key_usage());
        leaf_params
            .custom_extensions
            .push(subject_key_identifier_extension(signing_key));
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
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = now;
    leaf_params.not_after = if mdoc_profile.is_some() {
        now + time::Duration::days(457)
    } else {
        ca_not_after
    };
    leaf_params.serial_number = Some(SerialNumber::from(rand::random::<[u8; 19]>().to_vec()));
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

fn subject_key_identifier_extension(key: &KeyPair) -> CustomExtension {
    let content = yasna::construct_der(|writer| writer.write_bytes(&subject_key_identifier(key)));
    CustomExtension::from_oid_content(&[2, 5, 29, 14], content)
}

fn printable_country_name(country: &str) -> anyhow::Result<DnValue> {
    Ok(DnValue::PrintableString(
        PrintableString::try_from(country)
            .context("mDoc issuing country is not PrintableString")?,
    ))
}

fn document_signing_extended_key_usage() -> CustomExtension {
    let content = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer
                .next()
                .write_oid(&ObjectIdentifier::from_slice(&[1, 0, 18013, 5, 1, 2]));
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

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

async fn database_key_manager_for_tenant(
    config: &ConfigSource,
    settings: nazo_key_management::KeySettings,
    tenant_id: nazo_identity::TenantId,
    persistence: &dyn crate::operator_task::OperatorPersistence,
) -> anyhow::Result<nazo_key_management::KeyManager> {
    nazo_key_management::KeyManager::load_or_create_database(
        settings,
        tenant_id.as_uuid(),
        persistence.signing_key_repository(tenant_id.as_uuid()),
        crate::settings::signing_key_wrapping_key_ring(config)?,
    )
    .await
}

pub(crate) async fn operator_import_legacy_file_keyset(
    config: &ConfigSource,
    binding: &nazo_identity::TenantDirectoryBinding,
    persistence: &dyn crate::operator_task::OperatorPersistence,
    source_directory: PathBuf,
) -> anyhow::Result<String> {
    let mut source_settings = Settings::from_directory_binding(config, binding)?.key_settings();
    source_settings.keys_dir = source_directory;
    let manager = nazo_key_management::KeyManager::import_legacy_file_keyset(
        source_settings,
        binding.tenant.tenant_id.as_uuid(),
        persistence.signing_key_repository(binding.tenant.tenant_id.as_uuid()),
        crate::settings::signing_key_wrapping_key_ring(config)?,
    )
    .await?;
    manager.database_validate().await?;
    manager.database_revision().await
}

pub(crate) async fn operator_list_database_for_tenant(
    config: &ConfigSource,
    binding: &nazo_identity::TenantDirectoryBinding,
    persistence: &dyn crate::operator_task::OperatorPersistence,
) -> anyhow::Result<String> {
    let settings = Settings::from_directory_binding(config, binding)?;
    let manager = database_key_manager_for_tenant(
        config,
        settings.key_settings(),
        binding.tenant.tenant_id,
        persistence,
    )
    .await?;
    let _ = manager.database_list_keys().await?;
    manager.database_revision().await
}

pub(crate) async fn operator_validate_database_for_tenant(
    config: &ConfigSource,
    binding: &nazo_identity::TenantDirectoryBinding,
    persistence: &dyn crate::operator_task::OperatorPersistence,
) -> anyhow::Result<String> {
    let settings = Settings::from_directory_binding(config, binding)?;
    let manager = database_key_manager_for_tenant(
        config,
        settings.key_settings(),
        binding.tenant.tenant_id,
        persistence,
    )
    .await?;
    manager.database_validate().await?;
    manager.database_revision().await
}

pub(crate) async fn operator_register_external_database_for_tenant(
    config: &ConfigSource,
    binding: &nazo_identity::TenantDirectoryBinding,
    persistence: &dyn crate::operator_task::OperatorPersistence,
    kid: &str,
    algorithm: &str,
    key_ref: &str,
    public_jwk_bytes: &[u8],
) -> anyhow::Result<String> {
    let algorithm = signing_algorithm_from_name(algorithm)
        .ok_or_else(|| anyhow::anyhow!("unsupported signing alg {algorithm}"))?;
    let public_jwk = serde_json::from_slice(public_jwk_bytes)
        .context("failed to parse mounted external public JWK")?;
    let settings = Settings::from_directory_binding(config, binding)?;
    let manager = database_key_manager_for_tenant(
        config,
        settings.key_settings(),
        binding.tenant.tenant_id,
        persistence,
    )
    .await?;
    manager
        .database_register_external(nazo_key_management::ExternalKeyRegistration {
            kid: kid.to_owned(),
            algorithm,
            key_ref: key_ref.to_owned(),
            public_jwk,
        })
        .await?;
    manager.database_revision().await
}

pub(crate) async fn operator_generate_local_database_for_tenant(
    config: &ConfigSource,
    binding: &nazo_identity::TenantDirectoryBinding,
    persistence: &dyn crate::operator_task::OperatorPersistence,
    algorithm: &str,
    purposes: &[String],
) -> anyhow::Result<(String, String, Option<String>)> {
    let options = parse_generate_local(algorithm, purposes)?;
    let settings = Settings::from_directory_binding(config, binding)?;
    let key_settings = settings.key_settings();
    let manager = database_key_manager_for_tenant(
        config,
        key_settings,
        binding.tenant.tenant_id,
        persistence,
    )
    .await?;
    let profile = database_certificate_profile(binding, config, &options)?;
    let kid = generate_local_with_database_manager(&manager, profile.as_ref(), options).await?;
    let state = manager.database_openid4vc_state().await?;
    Ok((
        kid,
        state.revision.to_string(),
        state
            .material
            .map(|material| material.public.certificate_chain_pem),
    ))
}

fn database_certificate_profile(
    binding: &nazo_identity::TenantDirectoryBinding,
    config: &ConfigSource,
    options: &GenerateLocalKeyOptions,
) -> anyhow::Result<Option<Openid4vcCertificateProfile>> {
    let both = [
        SigningPurpose::Credential,
        SigningPurpose::PresentationRequest,
    ]
    .into_iter()
    .collect();
    if options.purposes != both {
        return Ok(None);
    }
    if options.alg != jsonwebtoken::Algorithm::ES256 {
        bail!("OpenID4VC certificates require ES256");
    }
    let issuer = Url::parse(&binding.issuer)?;
    let Host::Domain(hostname) = issuer
        .host()
        .context("tenant issuer must include a DNS hostname")?
    else {
        bail!("tenant issuer must include a DNS hostname");
    };
    Ok(Some(Openid4vcCertificateProfile {
        hostname: hostname.to_owned(),
        mdoc_profile: mdoc_certificate_profile(config, &issuer)?,
    }))
}

async fn generate_local_with_database_manager(
    manager: &KeyManager,
    profile: Option<&Openid4vcCertificateProfile>,
    options: GenerateLocalKeyOptions,
) -> anyhow::Result<String> {
    let Some(profile) = profile else {
        return manager
            .database_register_local(nazo_key_management::LocalKeyRegistration {
                algorithm: options.alg,
                purposes: options.purposes,
            })
            .await;
    };
    let state = manager.database_openid4vc_state().await?;
    if let Some(material) = state.material {
        validate_managed_profile(&material, profile)?;
        return Ok(material.public.signing_kid);
    }
    if manager
        .snapshot()
        .signing_verification_key(SigningPurpose::Credential, jsonwebtoken::Algorithm::ES256)
        .is_some()
        || manager
            .snapshot()
            .signing_verification_key(
                SigningPurpose::PresentationRequest,
                jsonwebtoken::Algorithm::ES256,
            )
            .is_some()
    {
        bail!("existing OpenID4VC key requires explicit mdoc-import before use");
    }
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let material = build_managed_material(&signing_key, profile, None)?;
    let kid = material.public.signing_kid.clone();
    match manager
        .database_commit_openid4vc(state.revision, material, Some(signing_key.serialize_pem()))
        .await
    {
        Ok(()) => Ok(kid),
        Err(error) => {
            // Concurrent bootstrap may already have committed a complete generation.
            let winner = manager.database_openid4vc_state().await?;
            if winner.revision != state.revision
                && let Some(material) = winner.material
            {
                validate_managed_profile(&material, profile)?;
                manager.refresh().await?;
                return Ok(material.public.signing_kid);
            }
            Err(error)
        }
    }
}

fn build_managed_material(
    signing_key: &KeyPair,
    profile: &Openid4vcCertificateProfile,
    previous: Option<Openid4vcMaterial>,
) -> anyhow::Result<Openid4vcMaterial> {
    let bundle = build_openid4vc_certificate_bundle(
        signing_key,
        &profile.hostname,
        profile.mdoc_profile.as_ref(),
    )?;
    let chain = String::from_utf8(bundle.contents)?;
    let (mut anchors, mut iacas, mut revocation_snapshot) = match previous {
        Some(previous) => (
            previous.public.trust_anchors_pem,
            previous.iaca_private_materials,
            previous.public.revocation_snapshot,
        ),
        None => (String::new(), BTreeMap::new(), None),
    };
    // Historical roots and IACA keys are needed by credentials already issued.
    let certificates =
        CertificateDer::pem_slice_iter(chain.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let ca_pem = pem_certificate(certificates[1].as_ref());
    if !anchors.contains(&ca_pem) {
        anchors.push_str(&ca_pem);
    }
    let now = chrono::Utc::now();
    let snapshot = revocation_snapshot.get_or_insert_with(|| {
        nazo_digital_credentials::CertificateRevocationSnapshot {
            version: nazo_digital_credentials::CertificateRevocationSnapshot::VERSION,
            this_update: now,
            next_update: now + chrono::Duration::hours(24),
            entries: Vec::new(),
        }
    });
    snapshot.this_update = now;
    snapshot.next_update = now + chrono::Duration::hours(24);
    if let Some(material) = bundle.mdoc_material {
        iacas.insert(sha256_hex(&material.ca_der), material.issuer_material_pem);
        snapshot
            .entries
            .push(nazo_digital_credentials::CertificateRevocationEntry {
                issuer: profile
                    .mdoc_profile
                    .as_ref()
                    .expect("mdoc profile")
                    .issuer_contact_uri
                    .clone(),
                certificate: nazo_digital_credentials::certificate_identity(&material.leaf_der),
                status: nazo_digital_credentials::CertificateRevocationStatus::Good,
                revoked_at: None,
            });
    }
    Ok(Openid4vcMaterial {
        public: Openid4vcPublicMaterial {
            signing_kid: format!("es256-{}", uuid::Uuid::now_v7()),
            certificate_chain_pem: chain,
            trust_anchors_pem: anchors,
            revocation_snapshot,
        },
        iaca_private_materials: iacas,
    })
}

fn pem_certificate(der: &[u8]) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn validate_managed_profile(
    material: &Openid4vcMaterial,
    profile: &Openid4vcCertificateProfile,
) -> anyhow::Result<()> {
    let certificates =
        CertificateDer::pem_slice_iter(material.public.certificate_chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;
    if certificates.len() != 2 {
        bail!("managed OpenID4VC chain must contain DS and CA");
    }
    let (_, leaf) = x509_parser::parse_x509_certificate(certificates[0].as_ref())
        .map_err(|e| anyhow::anyhow!("invalid signing certificate: {e}"))?;
    let (_, ca) = x509_parser::parse_x509_certificate(certificates[1].as_ref())
        .map_err(|e| anyhow::anyhow!("invalid CA certificate: {e}"))?;
    let dns_matches = leaf.subject_alternative_name()?.is_some_and(|san| san.value.general_names.iter().any(|name| matches!(name, x509_parser::extensions::GeneralName::DNSName(dns) if *dns == profile.hostname)));
    if !dns_matches
        || leaf.is_ca()
        || !ca.is_ca()
        || leaf.issuer() != ca.subject()
        || ca.subject() != ca.issuer()
        || ca.verify_signature(Some(ca.public_key())).is_err()
        || leaf.verify_signature(Some(ca.public_key())).is_err()
        || !leaf.validity().is_valid()
        || !ca.validity().is_valid()
        || profile
            .mdoc_profile
            .as_ref()
            .is_some_and(|p| !mdoc_certificate_profile_matches(&leaf, &ca, p))
    {
        bail!(
            "managed certificate no longer matches tenant profile; explicit mdoc rotation is required"
        );
    }
    Ok(())
}

/// One-time administrator import. Runtime startup never reads this directory.
async fn import_mdoc_directory(
    manager: &KeyManager,
    profile: &Openid4vcCertificateProfile,
    source: &Path,
) -> anyhow::Result<String> {
    let state = manager.database_openid4vc_state().await?;
    if state.material.is_some() {
        bail!("managed OpenID4VC material already exists; import cannot overwrite it");
    }
    let snapshot = manager.snapshot();
    let key = snapshot
        .signing_verification_key(SigningPurpose::Credential, jsonwebtoken::Algorithm::ES256)
        .context("import requires the existing credential signing key in the database")?;
    let chain = tokio::fs::read_to_string(source.join("certificate-bundle.pem"))
        .await
        .context("failed to read import certificate-bundle.pem")?;
    let mut anchors = String::new();
    let mut iacas = BTreeMap::new();
    let revocation_snapshot = if let Some(mdoc_profile) = &profile.mdoc_profile {
        let bytes = tokio::fs::read(source.join("revocation-snapshot.json"))
            .await
            .context("failed to read import revocation-snapshot.json")?;
        let mut snapshot =
            nazo_digital_credentials::CertificateRevocationSnapshot::from_json(&bytes)
                .map_err(|e| anyhow::anyhow!("invalid imported revocation state: {e}"))?;
        for entry in &mut snapshot.entries {
            if entry.status == nazo_digital_credentials::CertificateRevocationStatus::Revoked
                && entry.revoked_at.is_none()
            {
                entry.revoked_at = Some(snapshot.this_update);
            }
        }
        let mut owned_certificates = BTreeSet::new();
        let mut directory = tokio::fs::read_dir(source.join("iaca-keys"))
            .await
            .context("failed to read import iaca-keys directory")?;
        while let Some(entry) = directory.next_entry().await? {
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "pem")
            {
                continue;
            }
            let pem = tokio::fs::read_to_string(entry.path()).await?;
            let certificates =
                CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
            if certificates.len() != 2 {
                bail!("imported IACA record must contain its DS and IACA certificates");
            }
            let (_, leaf) = x509_parser::parse_x509_certificate(certificates[0].as_ref())
                .map_err(|e| anyhow::anyhow!("invalid imported DS: {e}"))?;
            let (_, ca) = x509_parser::parse_x509_certificate(certificates[1].as_ref())
                .map_err(|e| anyhow::anyhow!("invalid imported IACA: {e}"))?;
            let private_key = KeyPair::from_pem(&pem)?;
            if !ca.is_ca()
                || ca.subject() != ca.issuer()
                || leaf.issuer() != ca.subject()
                || private_key.public_key_raw() != ca.public_key().subject_public_key.data.as_ref()
                || ca.verify_signature(Some(ca.public_key())).is_err()
                || leaf.verify_signature(Some(ca.public_key())).is_err()
                || !is_mdoc_document_signing_certificate(&leaf)
            {
                bail!("imported IACA key and certificate chain do not match");
            }
            let id = sha256_hex(certificates[1].as_ref());
            if entry.file_name().to_str() != Some(format!("{id}.pem").as_str()) {
                bail!("imported IACA filename does not match its certificate fingerprint");
            }
            let issuer = &mdoc_profile.issuer_contact_uri;
            let identity = nazo_digital_credentials::certificate_identity(certificates[0].as_ref());
            if !snapshot
                .entries
                .iter()
                .any(|entry| entry.issuer == *issuer && entry.certificate == identity)
            {
                bail!("imported revocation state is missing an IACA's DS status");
            }
            owned_certificates.insert((issuer.clone(), identity));
            anchors.push_str(&pem_certificate(certificates[1].as_ref()));
            iacas.insert(id, pem);
        }
        if iacas.is_empty() {
            bail!("mdoc import requires IACA private material");
        }
        if snapshot.entries.iter().any(|entry| {
            !owned_certificates.contains(&(entry.issuer.clone(), entry.certificate.clone()))
        }) {
            bail!("mdoc import accepts revocation facts only for its owned IACA records");
        }
        Some(snapshot)
    } else {
        let now = chrono::Utc::now();
        Some(nazo_digital_credentials::CertificateRevocationSnapshot {
            version: nazo_digital_credentials::CertificateRevocationSnapshot::VERSION,
            this_update: now,
            next_update: now + chrono::Duration::hours(24),
            entries: Vec::new(),
        })
    };
    let certificates =
        CertificateDer::pem_slice_iter(chain.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    if certificates.len() != 2 {
        bail!("imported signing chain must contain DS and CA");
    }
    let active_ca = pem_certificate(certificates[1].as_ref());
    if profile.mdoc_profile.is_some() && !iacas.contains_key(&sha256_hex(certificates[1].as_ref()))
    {
        bail!("import is missing the active IACA private material");
    }
    if let Some(iaca) = iacas.get(&sha256_hex(certificates[1].as_ref())) {
        let owned_chain =
            CertificateDer::pem_slice_iter(iaca.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        if owned_chain[0] != certificates[0] {
            bail!("active signing certificate does not match its IACA record's DS certificate");
        }
    }
    if !anchors.contains(&active_ca) {
        anchors.push_str(&active_ca);
    }
    let material = Openid4vcMaterial {
        public: Openid4vcPublicMaterial {
            signing_kid: key.kid.clone(),
            certificate_chain_pem: chain,
            trust_anchors_pem: anchors,
            revocation_snapshot,
        },
        iaca_private_materials: iacas,
    };
    validate_managed_profile(&material, profile)?;
    manager
        .database_commit_openid4vc(state.revision, material, None)
        .await?;
    manager.database_revision().await
}

async fn rotate_managed_material(
    manager: &KeyManager,
    profile: &Openid4vcCertificateProfile,
) -> anyhow::Result<String> {
    let state = manager.database_openid4vc_state().await?;
    let previous = state
        .material
        .context("rotation requires initialized OpenID4VC material")?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let material = build_managed_material(&key, profile, Some(previous))?;
    manager
        .database_commit_openid4vc(state.revision, material, Some(key.serialize_pem()))
        .await?;
    manager.database_revision().await
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum MdocManagementAction {
    Import(PathBuf),
    Rotate,
    Revoke { issuer_id: String },
}

pub(crate) async fn operator_manage_mdoc(
    config: &ConfigSource,
    binding: &nazo_identity::TenantDirectoryBinding,
    persistence: &dyn crate::operator_task::OperatorPersistence,
    action: MdocManagementAction,
) -> anyhow::Result<String> {
    let settings = Settings::from_directory_binding(config, binding)?;
    let manager = database_key_manager_for_tenant(
        config,
        settings.key_settings(),
        binding.tenant.tenant_id,
        persistence,
    )
    .await?;
    let options = parse_generate_local(
        "ES256",
        &["credential".into(), "presentation_request".into()],
    )?;
    let profile =
        database_certificate_profile(binding, config, &options)?.expect("OpenID4VC purposes");
    match action {
        MdocManagementAction::Import(source) => {
            import_mdoc_directory(&manager, &profile, &source).await
        }
        MdocManagementAction::Rotate => rotate_managed_material(&manager, &profile).await,
        MdocManagementAction::Revoke { issuer_id } => {
            let state = manager.database_openid4vc_state().await?;
            let mut material = state
                .material
                .context("revocation requires initialized mdoc material")?;
            let pem = material
                .iaca_private_materials
                .get(&issuer_id)
                .context("unknown IACA fingerprint")?;
            let certificates =
                CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
            let identity = nazo_digital_credentials::certificate_identity(
                certificates
                    .first()
                    .context("IACA record has no DS certificate")?
                    .as_ref(),
            );
            let snapshot = material
                .public
                .revocation_snapshot
                .as_mut()
                .context("mdoc revocation state is missing")?;
            let issuer = profile
                .mdoc_profile
                .as_ref()
                .context("mdoc profile is not configured")?
                .issuer_contact_uri
                .as_str();
            let entry = snapshot
                .entries
                .iter_mut()
                .find(|entry| entry.issuer == issuer && entry.certificate == identity)
                .context("DS revocation status is missing")?;
            if entry.status == nazo_digital_credentials::CertificateRevocationStatus::Revoked {
                return Ok(state.revision.to_string());
            }
            entry.status = nazo_digital_credentials::CertificateRevocationStatus::Revoked;
            entry.revoked_at = Some(chrono::Utc::now());
            snapshot.this_update = chrono::Utc::now();
            snapshot.next_update = snapshot.this_update + chrono::Duration::hours(24);
            manager
                .database_commit_openid4vc(state.revision, material, None)
                .await?;
            manager.database_revision().await
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/keyctl.rs"]
mod tests;
