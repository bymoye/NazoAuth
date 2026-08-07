use std::{
    collections::BTreeSet,
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use x509_parser::extensions::GeneralName;

use crate::{CredentialFormat, CredentialPayload};

pub type CredentialFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialSignInput {
    pub payload: CredentialPayload,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: Option<Value>,
}

pub trait CredentialSignerPort: Send + Sync {
    fn sign<'a>(
        &'a self,
        input: &'a CredentialSignInput,
    ) -> CredentialFuture<'a, Result<String, CredentialTrustError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentedCredential {
    pub format: CredentialFormat,
    pub encoded: String,
    pub expected_nonce: String,
    pub expected_audience: String,
    pub response_uri: String,
    pub mdoc_session_transcript: Option<Vec<u8>>,
    pub additional_trust_anchors: Vec<Vec<u8>>,
}

/// Return the stable identity used by a revocation snapshot for an X.509
/// certificate.  The DER bytes are hashed rather than a mutable field such as
/// the serial number so that a snapshot cannot accidentally match a different
/// certificate issued by the same authority.
#[must_use]
pub fn certificate_identity(certificate_der: &[u8]) -> String {
    format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(certificate_der))
    )
}

/// A status entry from an operator-provisioned certificate revocation
/// snapshot.  Entries are deliberately explicit: a required policy rejects a
/// certificate that is absent from the snapshot instead of treating absence
/// as proof of validity.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateRevocationEntry {
    /// Issuer URL for SD-JWT credentials, or an operator-defined authority
    /// identity for formats without an issuer URL (for example mdoc).
    pub issuer: String,
    /// The `certificate_identity` value of the certificate being assessed.
    pub certificate: String,
    pub status: CertificateRevocationStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateRevocationStatus {
    Good,
    Revoked,
}

/// An immutable, operator-supplied view of certificate status.
///
/// The verifier never fetches an issuer, CRL, or OCSP endpoint while handling
/// a presentation.  A new snapshot is loaded and validated out of band, then
/// shared by all request handlers.  `next_update` is a hard deadline: once it
/// is reached, a required policy fails closed even if every individual entry
/// says `good`.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateRevocationSnapshot {
    pub version: u32,
    pub this_update: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub entries: Vec<CertificateRevocationEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CertificateRevocationSnapshotError {
    #[error("unsupported certificate revocation snapshot version")]
    UnsupportedVersion,
    #[error("certificate revocation snapshot has an invalid update interval")]
    InvalidUpdateInterval,
    #[error("certificate revocation snapshot is not yet valid")]
    NotYetValid,
    #[error("certificate revocation snapshot is expired")]
    Expired,
    #[error("certificate revocation snapshot contains an invalid entry")]
    InvalidEntry,
    #[error("certificate revocation snapshot contains duplicate entries")]
    DuplicateEntry,
}

impl CertificateRevocationSnapshot {
    pub const VERSION: u32 = 1;

    /// Parse and structurally validate a JSON snapshot.  This method does not
    /// perform I/O and is therefore safe to call during bootstrap or tests.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CertificateRevocationSnapshotError> {
        let snapshot = serde_json::from_slice::<Self>(bytes)
            .map_err(|_| CertificateRevocationSnapshotError::InvalidEntry)?;
        snapshot.validate_structure()?;
        Ok(snapshot)
    }

    pub fn validate_structure(&self) -> Result<(), CertificateRevocationSnapshotError> {
        if self.version != Self::VERSION {
            return Err(CertificateRevocationSnapshotError::UnsupportedVersion);
        }
        if self.this_update >= self.next_update {
            return Err(CertificateRevocationSnapshotError::InvalidUpdateInterval);
        }
        let mut identities = BTreeSet::new();
        for entry in &self.entries {
            if entry.issuer.is_empty()
                || entry.issuer.len() > 2048
                || !valid_certificate_identity(&entry.certificate)
                || !identities.insert((entry.issuer.as_str(), entry.certificate.as_str()))
            {
                return Err(
                    if entry.issuer.is_empty()
                        || entry.issuer.len() > 2048
                        || !valid_certificate_identity(&entry.certificate)
                    {
                        CertificateRevocationSnapshotError::InvalidEntry
                    } else {
                        CertificateRevocationSnapshotError::DuplicateEntry
                    },
                );
            }
        }
        Ok(())
    }

    pub fn validate_freshness_at(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), CertificateRevocationSnapshotError> {
        self.validate_structure()?;
        if now < self.this_update {
            return Err(CertificateRevocationSnapshotError::NotYetValid);
        }
        if now >= self.next_update {
            return Err(CertificateRevocationSnapshotError::Expired);
        }
        Ok(())
    }

    fn status_for(
        &self,
        issuer: Option<&str>,
        certificate: &str,
    ) -> Option<CertificateRevocationStatus> {
        let mut statuses = self.entries.iter().filter_map(|entry| {
            (entry.certificate == certificate && issuer.is_none_or(|issuer| entry.issuer == issuer))
                .then_some(entry.status)
        });
        let first = statuses.next()?;
        statuses.all(|status| status == first).then_some(first)
    }
}

/// Controls whether a verifier requires a fresh status for every certificate
/// in a presented chain.  The policy contains no HTTP client or URL fetching
/// capability by design.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CertificateRevocationMode {
    Disabled,
    Optional,
    Required,
}

struct CertificateRevocationPolicyState {
    snapshot: RwLock<Option<Arc<CertificateRevocationSnapshot>>>,
    mode: CertificateRevocationMode,
}

/// A cloneable handle to an atomically replaceable revocation snapshot.
/// Writers (normally an operator-controlled background loader) validate a new
/// snapshot before publishing it.  Readers take a short synchronous lock and
/// then perform all checks against the immutable `Arc`, so request handling
/// never performs network or filesystem I/O and never waits for async work.
#[derive(Clone)]
pub struct CertificateRevocationPolicy {
    state: Arc<CertificateRevocationPolicyState>,
}

impl Default for CertificateRevocationPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

impl CertificateRevocationPolicy {
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            state: Arc::new(CertificateRevocationPolicyState {
                snapshot: RwLock::new(None),
                mode: CertificateRevocationMode::Disabled,
            }),
        }
    }

    #[must_use]
    pub fn optional(snapshot: Arc<CertificateRevocationSnapshot>) -> Self {
        Self {
            state: Arc::new(CertificateRevocationPolicyState {
                snapshot: RwLock::new(Some(snapshot)),
                mode: CertificateRevocationMode::Optional,
            }),
        }
    }

    #[must_use]
    pub fn required(snapshot: Arc<CertificateRevocationSnapshot>) -> Self {
        Self {
            state: Arc::new(CertificateRevocationPolicyState {
                snapshot: RwLock::new(Some(snapshot)),
                mode: CertificateRevocationMode::Required,
            }),
        }
    }

    #[must_use]
    pub fn required_without_snapshot() -> Self {
        Self {
            state: Arc::new(CertificateRevocationPolicyState {
                snapshot: RwLock::new(None),
                mode: CertificateRevocationMode::Required,
            }),
        }
    }

    #[must_use]
    pub fn is_required(&self) -> bool {
        matches!(self.state.mode, CertificateRevocationMode::Required)
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !matches!(self.state.mode, CertificateRevocationMode::Disabled)
    }

    /// Publish a validated snapshot for subsequent requests.  A failed
    /// validation leaves the previous snapshot untouched, allowing a still-
    /// fresh snapshot to continue serving until its own deadline.
    pub fn replace_snapshot(
        &self,
        snapshot: Arc<CertificateRevocationSnapshot>,
        now: DateTime<Utc>,
    ) -> Result<(), CertificateRevocationSnapshotError> {
        snapshot.validate_freshness_at(now)?;
        let mut current = self
            .state
            .snapshot
            .write()
            .map_err(|_| CertificateRevocationSnapshotError::InvalidEntry)?;
        *current = Some(snapshot);
        Ok(())
    }

    /// Parse and publish a JSON snapshot in one operation.  Parsing and
    /// freshness validation happen before the write, so malformed or stale
    /// reloads cannot displace the previously published snapshot.
    pub fn replace_snapshot_json(
        &self,
        bytes: &[u8],
        now: DateTime<Utc>,
    ) -> Result<(), CertificateRevocationSnapshotError> {
        let snapshot = Arc::new(CertificateRevocationSnapshot::from_json(bytes)?);
        self.replace_snapshot(snapshot, now)
    }

    #[must_use]
    pub fn snapshot(&self) -> Option<Arc<CertificateRevocationSnapshot>> {
        self.state
            .snapshot
            .read()
            .ok()
            .and_then(|snapshot| snapshot.clone())
    }

    /// Check every supplied certificate against the already-loaded snapshot.
    /// `issuer` is the SD-JWT issuer claim; pass `None` for mdoc, where the
    /// certificate identity is globally unique in the snapshot.
    pub fn check_chain(
        &self,
        issuer: Option<&str>,
        certificates: &[Vec<u8>],
        now: DateTime<Utc>,
    ) -> Result<(), CredentialTrustError> {
        self.check_chain_inner(issuer, certificates, now, false)
    }

    /// Check a chain that has already been authenticated against an explicit
    /// short-lived conformance trust anchor.  The normal required policy
    /// remains fail-closed for every certificate; only the lease-scoped
    /// conformance source may supply an out-of-band status for its ephemeral
    /// certificates.  Callers must verify the chain against that anchor before
    /// invoking this method.
    pub fn check_chain_with_conformance_trust(
        &self,
        issuer: Option<&str>,
        certificates: &[Vec<u8>],
        now: DateTime<Utc>,
        conformance_trust_anchors: &[Vec<u8>],
    ) -> Result<(), CredentialTrustError> {
        self.check_chain_inner(
            issuer,
            certificates,
            now,
            !conformance_trust_anchors.is_empty(),
        )
    }

    fn check_chain_inner(
        &self,
        issuer: Option<&str>,
        certificates: &[Vec<u8>],
        now: DateTime<Utc>,
        conformance_trust_loaded: bool,
    ) -> Result<(), CredentialTrustError> {
        if matches!(self.state.mode, CertificateRevocationMode::Disabled) {
            return Ok(());
        }
        let snapshot = self
            .state
            .snapshot
            .read()
            .map_err(|_| CredentialTrustError::RevocationSnapshotUnavailable)?
            .clone();
        let Some(snapshot) = snapshot else {
            return if self.is_required() {
                Err(CredentialTrustError::RevocationSnapshotUnavailable)
            } else {
                Ok(())
            };
        };
        snapshot
            .validate_freshness_at(now)
            .map_err(|error| match error {
                CertificateRevocationSnapshotError::NotYetValid
                | CertificateRevocationSnapshotError::Expired => {
                    CredentialTrustError::RevocationSnapshotStale
                }
                _ => CredentialTrustError::RevocationSnapshotUnavailable,
            })?;
        for certificate in certificates {
            let identity = certificate_identity(certificate);
            match snapshot.status_for(issuer, &identity) {
                Some(CertificateRevocationStatus::Revoked) => {
                    return Err(CredentialTrustError::RevokedCertificate);
                }
                Some(CertificateRevocationStatus::Good) => {}
                None if self.is_required() && !conformance_trust_loaded => {
                    return Err(CredentialTrustError::RevocationStatusUnknown);
                }
                None => {}
            }
        }
        Ok(())
    }
}

/// The trust decision that binds an SD-JWT VC issuer claim to the signer
/// certificate that was authenticated by the JOSE layer.
///
/// A certificate chain terminating in a trusted CA is not, by itself, an
/// issuer identity.  This policy therefore requires the issuer URL host to
/// appear in the leaf certificate's DNS SAN, or the complete issuer URL to
/// appear in a URI SAN.  An optional issuer allowlist can further restrict
/// which issuer URLs are accepted (for example when a deployment has several
/// tenants on one certificate).  Multiple issuer paths on the same DNS name
/// remain valid, while a different issuer host under the same CA is rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VcIssuerTrustPolicy {
    allowed_issuers: Option<BTreeSet<String>>,
}

impl Default for VcIssuerTrustPolicy {
    fn default() -> Self {
        Self::san_bound()
    }
}

impl VcIssuerTrustPolicy {
    /// Construct the default fail-closed policy: HTTPS issuer URLs must bind
    /// to a DNS SAN or an exact URI SAN on the authenticated leaf certificate.
    #[must_use]
    pub const fn san_bound() -> Self {
        Self {
            allowed_issuers: None,
        }
    }

    /// Construct a policy that accepts only the supplied issuer URLs and also
    /// requires each URL's identity to bind to the leaf certificate's SAN.
    ///
    /// The set is intentionally allowed to be empty: that is a valid
    /// fail-closed configuration and rejects every issuer.
    #[must_use]
    pub fn allowlisted<I, S>(issuers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed_issuers: Some(issuers.into_iter().map(Into::into).collect()),
        }
    }

    /// Validate the issuer claim against the authenticated leaf certificate.
    pub fn validate(&self, issuer: &str, leaf_der: &[u8]) -> Result<(), CredentialTrustError> {
        let issuer_url = Url::parse(issuer).map_err(|_| CredentialTrustError::UntrustedIssuer)?;
        if issuer_url.scheme() != "https"
            || issuer_url.host_str().is_none()
            || !issuer_url.username().is_empty()
            || issuer_url.password().is_some()
            || issuer_url.query().is_some()
            || issuer_url.fragment().is_some()
        {
            return Err(CredentialTrustError::UntrustedIssuer);
        }

        if self
            .allowed_issuers
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(issuer))
        {
            return Err(CredentialTrustError::UntrustedIssuer);
        }

        let host = issuer_url
            .host_str()
            .ok_or(CredentialTrustError::UntrustedIssuer)?;
        let (_, certificate) = x509_parser::parse_x509_certificate(leaf_der)
            .map_err(|_| CredentialTrustError::UntrustedIssuer)?;
        let issuer_san_matches = certificate
            .subject_alternative_name()
            .map_err(|_| CredentialTrustError::UntrustedIssuer)?
            .into_iter()
            .flat_map(|extension| extension.value.general_names.iter())
            .any(|name| match name {
                GeneralName::DNSName(value) => {
                    !value.starts_with("*.") && value.eq_ignore_ascii_case(host)
                }
                GeneralName::URI(value) => *value == issuer,
                _ => false,
            });
        if !issuer_san_matches {
            return Err(CredentialTrustError::UntrustedIssuer);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct VerifiedCredential {
    pub format: CredentialFormat,
    pub issuer: String,
    pub credential_type: String,
    pub claims: Value,
    pub holder_key: Option<Value>,
    pub issued_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: Option<Value>,
}

pub trait CredentialVerifierPort: Send + Sync {
    fn verify<'a>(
        &'a self,
        presentation: &'a PresentedCredential,
    ) -> CredentialFuture<'a, Result<VerifiedCredential, CredentialTrustError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CredentialTrustError {
    #[error("credential signature is invalid")]
    InvalidSignature,
    #[error("credential issuer is not trusted")]
    UntrustedIssuer,
    #[error("credential is expired or not yet valid")]
    InvalidValidity,
    #[error("credential status is invalid")]
    InvalidStatus,
    #[error("credential holder binding is invalid")]
    InvalidHolderBinding,
    #[error("credential encoding is invalid")]
    InvalidEncoding,
    #[error("credential cryptographic operation is unavailable")]
    Unavailable,
    #[error("credential signing certificate is revoked")]
    RevokedCertificate,
    #[error("credential certificate revocation snapshot is stale")]
    RevocationSnapshotStale,
    #[error("credential certificate revocation status is unknown")]
    RevocationStatusUnknown,
    #[error("credential certificate revocation snapshot is unavailable")]
    RevocationSnapshotUnavailable,
}

fn valid_certificate_identity(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("sha256:") else {
        return false;
    };
    URL_SAFE_NO_PAD
        .decode(encoded)
        .is_ok_and(|decoded| decoded.len() == 32 && URL_SAFE_NO_PAD.encode(decoded) == encoded)
}
