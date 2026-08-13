//! Shared, transport-independent contracts for OpenID digital credentials.
//!
//! This crate owns credential-format identifiers, trust decisions, selective
//! disclosure policy, and cryptographic ports. It deliberately contains no
//! HTTP framework, database driver, or OAuth server implementation.

mod dcql;
mod format;
mod jose;
mod jwe;
mod trust;

pub use dcql::{
    ClaimPath, ClaimPathSegment, ClaimsQuery, CredentialQuery, CredentialSetOption,
    CredentialSetQuery, DcqlError, DcqlQuery, TrustedAuthority,
};
pub use format::{CredentialFormat, CredentialFormatError, CredentialPayload, HolderBinding};
pub use jose::{
    CompactJwe, CompactJwt, JoseError, JwtHeader, decode_compact_jwt, parse_compact_jwe,
};
pub use jwe::{
    EphemeralEncryptionKey, JweError, encrypt_ecdh_es, encrypt_ecdh_es_a128,
    encrypt_ecdh_es_deflate,
};
pub use trust::{
    CertificateRevocationEntry, CertificateRevocationPolicy, CertificateRevocationSnapshot,
    CertificateRevocationSnapshotError, CertificateRevocationStatus, CredentialFuture,
    CredentialSignInput, CredentialSignerPort, CredentialTrustError, CredentialVerifierPort,
    PresentedCredential, VcIssuerTrustPolicy, VerifiedCredential, certificate_identity,
};

pub const SD_JWT_VC_MEDIA_TYPE: &str = "dc+sd-jwt";
pub const MDOC_MEDIA_TYPE: &str = "mso_mdoc";
