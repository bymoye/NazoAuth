use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use jsonwebtoken::Algorithm;
use nazo_auth::SigningPurpose;
use nazo_digital_credentials::{
    CertificateRevocationPolicy, CredentialTrustError, VcIssuerTrustPolicy,
};
use nazo_key_management::KeyManager;
use p256::PublicKey;
use sha2::{Digest, Sha256};

use super::super::crypto_helpers::{
    p256_public_key_from_jwk, parse_pem_certificates, parse_x509, verify_openid4vc_chain,
};
use super::Openid4vcCredentialCrypto;

pub(crate) fn parse_conformance_credential_trust_anchor(pem: &str) -> anyhow::Result<Vec<u8>> {
    let certificates = parse_pem_certificates(pem.as_bytes())?;
    if certificates.len() != 1 {
        anyhow::bail!(
            "OpenID4VC conformance credential trust must contain exactly one certificate"
        );
    }
    let der = certificates[0].clone();
    let (remainder, parsed) = x509_parser::parse_x509_certificate(&der).map_err(|error| {
        anyhow::anyhow!("failed to parse OpenID4VC conformance credential trust anchor: {error}")
    })?;
    if !remainder.is_empty() || !parsed.is_ca() || !parsed.validity().is_valid() {
        anyhow::bail!(
            "OpenID4VC conformance credential trust anchor must be a currently valid CA certificate"
        );
    }
    Ok(der)
}

impl Openid4vcCredentialCrypto {
    pub(crate) fn new_with_policies(
        keyset: KeyManager,
        certificate_chain_pem: &[u8],
        trust_anchors_pem: &[u8],
        issuer_trust_policy: VcIssuerTrustPolicy,
        revocation_policy: CertificateRevocationPolicy,
    ) -> anyhow::Result<Self> {
        let certificates = parse_pem_certificates(certificate_chain_pem)?;
        let leaf_der = certificates
            .first()
            .ok_or_else(|| anyhow::anyhow!("OpenID4VC signing certificate chain is empty"))?;
        let (_, leaf) = parse_x509(leaf_der, "OpenID4VC signing leaf")?;
        let mut trust_anchors = Vec::new();
        for der in parse_pem_certificates(trust_anchors_pem)? {
            let (_, parsed) = parse_x509(&der, "OpenID4VC trust certificate")?;
            if parsed.is_ca() {
                trust_anchors.push(der);
            }
        }
        if trust_anchors.is_empty() {
            anyhow::bail!("OpenID4VC trust anchor set must not be empty");
        }
        let x5c_der = certificates
            .iter()
            .filter(|certificate| !trust_anchors.contains(certificate))
            .cloned()
            .collect::<Vec<_>>();
        if x5c_der.is_empty() {
            anyhow::bail!("OpenID4VC x5c chain must contain a non-anchor leaf certificate");
        }
        let x5c = x5c_der
            .into_iter()
            .map(|certificate| STANDARD.encode(certificate))
            .collect();
        verify_openid4vc_chain(&certificates, &trust_anchors)?;
        let snapshot = keyset.snapshot();
        let leaf_key =
            PublicKey::from_sec1_bytes(leaf.public_key().subject_public_key.data.as_ref())?;
        let credential_key =
            snapshot.signing_verification_key(SigningPurpose::Credential, Algorithm::ES256);
        let presentation_key = snapshot
            .signing_verification_key(SigningPurpose::PresentationRequest, Algorithm::ES256);
        let key_matches = credential_key.zip(presentation_key).is_some_and(
            |(credential_key, presentation_key)| {
                credential_key.kid == presentation_key.kid
                    && p256_public_key_from_jwk(&credential_key.public_jwk)
                        .is_ok_and(|candidate| candidate == leaf_key)
            },
        );
        if !key_matches {
            anyhow::bail!(
                "OpenID4VC signing certificate does not match a credential and presentation-request scoped ES256 managed key"
            );
        }
        Ok(Self {
            keyset,
            x5c: Arc::new(x5c),
            leaf_der: Arc::new(leaf_der.clone()),
            trust_anchors: Arc::new(trust_anchors),
            issuer_trust_policy,
            revocation_policy,
        })
    }

    pub(crate) fn x509_hash_client_id(&self) -> String {
        format!(
            "x509_hash:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(self.leaf_der.as_slice()))
        )
    }

    pub(crate) fn x509_san_dns_client_id(&self) -> anyhow::Result<String> {
        let (_, certificate) = parse_x509(self.leaf_der.as_slice(), "OpenID4VC signing leaf")?;
        let dns_name = certificate
            .subject_alternative_name()?
            .into_iter()
            .flat_map(|extension| extension.value.general_names.iter())
            .find_map(|name| match name {
                x509_parser::extensions::GeneralName::DNSName(name) => Some((*name).to_owned()),
                _ => None,
            })
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("OpenID4VP signing certificate has no DNS SAN"))?;
        Ok(format!("x509_san_dns:{dns_name}"))
    }

    pub(super) fn combined_trust_anchors(
        &self,
        additional: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, CredentialTrustError> {
        let mut anchors = self.trust_anchors.as_ref().clone();
        for anchor in additional {
            let (_, certificate) = x509_parser::parse_x509_certificate(anchor)
                .map_err(|_| CredentialTrustError::InvalidEncoding)?;
            if !certificate.is_ca() {
                return Err(CredentialTrustError::UntrustedIssuer);
            }
            if !anchors.contains(anchor) {
                anchors.push(anchor.clone());
            }
        }
        Ok(anchors)
    }
}
