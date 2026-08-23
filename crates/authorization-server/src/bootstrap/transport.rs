use std::{
    fmt,
    io::Read as _,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use arc_swap::ArcSwap;
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{ClientHello, NoServerSessionStorage, ResolvesServerCert, WebPkiClientVerifier},
    sign::CertifiedKey,
};
use sha2::{Digest as _, Sha256};

use crate::{
    config::ConfigSource,
    settings::{Settings, TransportMode},
};

const MAX_TLS_MATERIAL_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_TLS_RELOAD_INTERVAL_SECONDS: u64 = 5;
const MAX_TLS_RELOAD_INTERVAL_SECONDS: u64 = 3_600;

pub(super) struct DirectTlsListeners {
    pub(super) public: ServerConfig,
    pub(super) mtls_bind: SocketAddr,
    pub(super) mtls: ServerConfig,
    pub(super) snapshots: Arc<DirectTlsSnapshotStore>,
    pub(super) reload_interval: Duration,
}

#[derive(Clone, Debug)]
struct DirectTlsMaterialPaths {
    certificate: PathBuf,
    private_key: PathBuf,
}

struct DirectTlsGeneration {
    revision: u64,
    material_sha256: [u8; 32],
    server_key: Arc<CertifiedKey>,
}

impl fmt::Debug for DirectTlsGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectTlsGeneration")
            .field("revision", &self.revision)
            .field("material_sha256", &hex_digest(&self.material_sha256))
            .finish_non_exhaustive()
    }
}

pub(super) struct DirectTlsSnapshotStore {
    current: ArcSwap<DirectTlsGeneration>,
    paths: DirectTlsMaterialPaths,
    endpoint_names: Arc<[String]>,
    allow_missing_sni: bool,
}

impl fmt::Debug for DirectTlsSnapshotStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let current = self.current.load();
        formatter
            .debug_struct("DirectTlsSnapshotStore")
            .field("revision", &current.revision)
            .field("material_sha256", &hex_digest(&current.material_sha256))
            .field("endpoint_names", &self.endpoint_names)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DirectTlsReload {
    Unchanged { revision: u64 },
    Published { previous: u64, current: u64 },
}

impl DirectTlsSnapshotStore {
    fn initialize(
        paths: DirectTlsMaterialPaths,
        endpoint_names: Arc<[String]>,
    ) -> anyhow::Result<Arc<Self>> {
        let initial = load_generation(&paths, &endpoint_names, 1)?;
        let allow_missing_sni = endpoint_names
            .iter()
            .any(|name| name.parse::<IpAddr>().is_ok());
        Ok(Arc::new(Self {
            current: ArcSwap::from_pointee(initial),
            paths,
            endpoint_names,
            allow_missing_sni,
        }))
    }

    pub(super) fn revision(&self) -> u64 {
        self.current.load().revision
    }

    pub(super) fn material_sha256(&self) -> [u8; 32] {
        self.current.load().material_sha256
    }

    pub(super) fn reload(&self) -> anyhow::Result<DirectTlsReload> {
        let current = self.current.load_full();
        let candidate = load_generation(&self.paths, &self.endpoint_names, current.revision + 1)?;
        if candidate.material_sha256 == current.material_sha256 {
            return Ok(DirectTlsReload::Unchanged {
                revision: current.revision,
            });
        }

        let candidate_revision = candidate.revision;
        let previous = self.current.compare_and_swap(&current, Arc::new(candidate));
        if Arc::ptr_eq(&previous, &current) {
            Ok(DirectTlsReload::Published {
                previous: current.revision,
                current: candidate_revision,
            })
        } else {
            anyhow::bail!(
                "direct TLS generation changed concurrently (expected {}, current {})",
                current.revision,
                previous.revision
            )
        }
    }

    pub(super) fn server_key_for(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let accepted = match server_name {
            Some(server_name) => self
                .endpoint_names
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(server_name)),
            None => self.allow_missing_sni,
        };
        accepted.then(|| Arc::clone(&self.current.load().server_key))
    }
}

#[derive(Debug)]
struct DynamicServerCertificate {
    snapshots: Arc<DirectTlsSnapshotStore>,
}

impl ResolvesServerCert for DynamicServerCertificate {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.snapshots.server_key_for(client_hello.server_name())
    }
}

pub(super) fn direct_tls_listeners(
    config: &ConfigSource,
    settings: &Settings,
) -> anyhow::Result<Option<DirectTlsListeners>> {
    if settings.endpoint.transport_mode != TransportMode::DirectTls {
        return Ok(None);
    }
    let required = |key: &str| {
        config
            .optional_string(key)
            .ok_or_else(|| anyhow::anyhow!("{key} is required for direct-tls transport"))
    };
    let public_bind: SocketAddr = config.string("BIND", "0.0.0.0:8000").parse()?;
    let mtls_bind: SocketAddr = required("TLS_BIND")?.parse()?;
    if public_bind == mtls_bind && public_bind.port() != 0 {
        anyhow::bail!("BIND and TLS_BIND must use different listener addresses");
    }
    let paths = DirectTlsMaterialPaths {
        certificate: required("TLS_CERTIFICATE_FILE")?.into(),
        private_key: required("TLS_PRIVATE_KEY_FILE")?.into(),
    };
    let client_ca: PathBuf = required("TLS_CLIENT_CA_FILE")?.into();
    let endpoint_names = endpoint_server_names(settings)?.into();
    let snapshots = DirectTlsSnapshotStore::initialize(paths, endpoint_names)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_verifier = load_client_verifier(&client_ca, Arc::clone(&provider))?;
    let resolver = Arc::new(DynamicServerCertificate {
        snapshots: Arc::clone(&snapshots),
    });

    let mut public = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .context("failed to configure TLS protocol versions")?
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    let mut mtls = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .context("failed to configure TLS protocol versions")?
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(resolver);
    // A resumed handshake can bypass the active server identity generation.
    // Disable server-side resumption so every new connection selects the
    // currently published certificate and private key.
    public.session_storage = Arc::new(NoServerSessionStorage {});
    mtls.session_storage = Arc::new(NoServerSessionStorage {});

    let reload_interval_seconds = config.parse(
        "TLS_RELOAD_INTERVAL_SECONDS",
        DEFAULT_TLS_RELOAD_INTERVAL_SECONDS,
    )?;
    if !(1..=MAX_TLS_RELOAD_INTERVAL_SECONDS).contains(&reload_interval_seconds) {
        anyhow::bail!(
            "TLS_RELOAD_INTERVAL_SECONDS must be between 1 and {MAX_TLS_RELOAD_INTERVAL_SECONDS}"
        );
    }

    Ok(Some(DirectTlsListeners {
        public,
        mtls_bind,
        mtls,
        snapshots,
        reload_interval: Duration::from_secs(reload_interval_seconds),
    }))
}

pub(super) fn spawn_direct_tls_reloader(
    snapshots: Arc<DirectTlsSnapshotStore>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match snapshots.reload() {
                Ok(DirectTlsReload::Unchanged { .. }) => {}
                Ok(DirectTlsReload::Published { previous, current }) => tracing::info!(
                    target: "transport.tls",
                    previous_revision = previous,
                    current_revision = current,
                    material_sha256 = %hex_digest(&snapshots.material_sha256()),
                    "published direct TLS identity generation"
                ),
                Err(error) => tracing::warn!(
                    target: "transport.tls",
                    current_revision = snapshots.revision(),
                    %error,
                    "rejected direct TLS identity candidate; retaining last-known-good generation"
                ),
            }
        }
    })
}

fn load_generation(
    paths: &DirectTlsMaterialPaths,
    endpoint_names: &[String],
    revision: u64,
) -> anyhow::Result<DirectTlsGeneration> {
    let first = read_material_snapshot(paths)?;
    let second = read_material_snapshot(paths)?;
    if first != second {
        anyhow::bail!("direct TLS material changed while the candidate generation was being read");
    }
    let [certificate_bytes, private_key_bytes] = second;

    let certificates = CertificateDer::pem_slice_iter(&certificate_bytes)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed to parse TLS certificate chain {}",
                paths.certificate.display()
            )
        })?;
    if certificates.is_empty() {
        anyhow::bail!(
            "TLS certificate chain {} contains no certificates",
            paths.certificate.display()
        );
    }
    let leaf = parse_tls_certificate(&certificates[0], &paths.certificate, "leaf")?;
    if leaf.is_ca() || !leaf.validity().is_valid() {
        anyhow::bail!(
            "TLS leaf certificate {} is not currently valid or is not an end-entity certificate",
            paths.certificate.display()
        );
    }
    validate_tls_server_chain(&certificates, &paths.certificate)?;
    validate_tls_server_names(
        &certificates[0],
        &paths.certificate,
        endpoint_names.iter().map(String::as_str),
    )?;

    let private_key = PrivateKeyDer::from_pem_slice(&private_key_bytes).with_context(|| {
        format!(
            "failed to parse TLS private key {}",
            paths.private_key.display()
        )
    })?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server_key = Arc::new(
        CertifiedKey::from_der(certificates, private_key, &provider)
            .context("TLS certificate chain does not match the configured private key")?,
    );

    Ok(DirectTlsGeneration {
        revision,
        material_sha256: material_digest(&[
            ("certificate", &certificate_bytes),
            ("private-key", &private_key_bytes),
        ]),
        server_key,
    })
}

fn parse_tls_certificate<'a>(
    certificate: &'a CertificateDer<'_>,
    path: &Path,
    description: &str,
) -> anyhow::Result<x509_parser::certificate::X509Certificate<'a>> {
    let (remainder, certificate) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to parse TLS {description} certificate {}: {error}",
                path.display()
            )
        })?;
    if !remainder.is_empty() {
        anyhow::bail!(
            "TLS {description} certificate {} contains trailing DER data",
            path.display()
        );
    }
    Ok(certificate)
}

fn validate_tls_server_chain(
    certificates: &[CertificateDer<'_>],
    path: &Path,
) -> anyhow::Result<()> {
    for (index, pair) in certificates.windows(2).enumerate() {
        let child = parse_tls_certificate(&pair[0], path, "chain child")?;
        let issuer = parse_tls_certificate(&pair[1], path, "chain issuer")?;
        if !issuer.is_ca()
            || !issuer.validity().is_valid()
            || child.issuer() != issuer.subject()
            || child.verify_signature(Some(issuer.public_key())).is_err()
        {
            anyhow::bail!(
                "TLS certificate chain {} is invalid between certificates {} and {}",
                path.display(),
                index + 1,
                index + 2
            );
        }
    }
    Ok(())
}

fn load_client_verifier(
    client_ca: &Path,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> anyhow::Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let client_ca_bytes = read_bounded(client_ca, "TLS client CA bundle", false)?;
    let mut client_roots = RootCertStore::empty();
    let client_ca_certificates = CertificateDer::pem_slice_iter(&client_ca_bytes)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed to parse TLS client CA bundle {}",
                client_ca.display()
            )
        })?;
    if client_ca_certificates.is_empty() {
        anyhow::bail!(
            "TLS client CA bundle {} contains no certificates",
            client_ca.display()
        );
    }
    for certificate in client_ca_certificates {
        client_roots.add(certificate).with_context(|| {
            format!(
                "TLS client CA bundle {} contains an invalid certificate",
                client_ca.display()
            )
        })?;
    }
    WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider)
        .build()
        .context("failed to build mutual TLS client certificate verifier")
}

fn read_material_snapshot(paths: &DirectTlsMaterialPaths) -> anyhow::Result<[Vec<u8>; 2]> {
    Ok([
        read_bounded(&paths.certificate, "TLS certificate chain", false)?,
        read_bounded(&paths.private_key, "TLS private key", true)?,
    ])
}

fn endpoint_server_names(settings: &Settings) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    for endpoint in [
        &settings.endpoint.issuer,
        &settings.endpoint.mtls_endpoint_base_url,
    ] {
        let name = url::Url::parse(endpoint)
            .with_context(|| format!("invalid TLS endpoint URL {endpoint}"))?
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("TLS endpoint URL {endpoint} has no host"))?
            .to_ascii_lowercase();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(names)
}

fn validate_tls_server_names<'a>(
    certificate: &'a CertificateDer<'a>,
    certificate_path: &Path,
    names: impl IntoIterator<Item = &'a str>,
) -> anyhow::Result<()> {
    let certificate = webpki::EndEntityCert::try_from(certificate).map_err(|error| {
        anyhow::anyhow!(
            "invalid TLS leaf certificate {}: {error}",
            certificate_path.display()
        )
    })?;
    for host in names {
        let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|error| anyhow::anyhow!("invalid TLS endpoint host {host}: {error}"))?;
        certificate
            .verify_is_valid_for_subject_name(&server_name)
            .map_err(|error| {
                anyhow::anyhow!(
                    "TLS leaf certificate {} is not valid for endpoint host {host}: {error}",
                    certificate_path.display()
                )
            })?;
    }
    Ok(())
}

fn read_bounded(
    path: &Path,
    label: &str,
    require_private_permissions: bool,
) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("{label} {} is not a regular file", path.display());
    }
    if metadata.len() > MAX_TLS_MATERIAL_BYTES {
        anyhow::bail!(
            "{label} {} exceeds {MAX_TLS_MATERIAL_BYTES} bytes",
            path.display()
        );
    }
    #[cfg(unix)]
    if require_private_permissions {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{label} {} must not be accessible by group or other users (mode {:o})",
                path.display(),
                mode & 0o777
            );
        }
    }
    #[cfg(not(unix))]
    let _ = require_private_permissions;

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_TLS_MATERIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    if bytes.len() as u64 > MAX_TLS_MATERIAL_BYTES {
        anyhow::bail!(
            "{label} {} exceeds {MAX_TLS_MATERIAL_BYTES} bytes",
            path.display()
        );
    }
    Ok(bytes)
}

fn material_digest(material: &[(&str, &[u8])]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"nazoauth-direct-tls-generation-v1\0");
    for (label, bytes) in material {
        digest.update((label.len() as u64).to_be_bytes());
        digest.update(label.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    digest.finalize().into()
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
