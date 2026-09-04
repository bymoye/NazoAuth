use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_digital_credentials::{
    CertificateRevocationPolicy, CredentialTrustError, VcIssuerTrustPolicy,
};
use nazo_key_management::{KeyManager, Openid4vcPublicMaterial, Openid4vcSigningLease};
use sha2::{Digest, Sha256};

use super::super::crypto_helpers::{parse_pem_certificates, parse_x509, verify_openid4vc_chain};
use super::Openid4vcCredentialCrypto;

const MAX_SCOPED_CREDENTIAL_TRUST_ANCHORS: usize = 4;

pub(crate) fn parse_scoped_credential_trust_anchors(pem: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let certificates = parse_pem_certificates(pem.as_bytes())?;
    if certificates.is_empty() || certificates.len() > MAX_SCOPED_CREDENTIAL_TRUST_ANCHORS {
        anyhow::bail!(
            "OpenID4VC scoped credential trust must contain 1 through {MAX_SCOPED_CREDENTIAL_TRUST_ANCHORS} certificates"
        );
    }
    let mut anchors = Vec::with_capacity(certificates.len());
    for der in certificates {
        let (remainder, parsed) = x509_parser::parse_x509_certificate(&der).map_err(|error| {
            anyhow::anyhow!("failed to parse OpenID4VC scoped credential trust anchor: {error}")
        })?;
        if !remainder.is_empty() || !parsed.is_ca() || !parsed.validity().is_valid() {
            anyhow::bail!(
                "OpenID4VC scoped credential trust anchors must be currently valid CA certificates"
            );
        }
        if anchors.contains(&der) {
            anyhow::bail!("OpenID4VC scoped credential trust anchors must be unique");
        }
        anchors.push(der);
    }
    Ok(anchors)
}

pub(super) struct Openid4vcSigningMaterial {
    pub(super) x5c: Vec<String>,
    pub(super) leaf_der: Vec<u8>,
}

impl Openid4vcCredentialCrypto {
    pub(crate) fn new_with_policies(
        keyset: KeyManager,
        issuer_trust_policy: VcIssuerTrustPolicy,
        revocation_policy: crate::settings::Openid4vcRevocationPolicy,
    ) -> anyhow::Result<Self> {
        let material = keyset.openid4vc_public_material().ok_or_else(|| {
            anyhow::anyhow!("OpenID4VC managed certificate material is unavailable")
        })?;
        validate_public_material(&material)?;
        Ok(Self {
            keyset,
            issuer_trust_policy,
            revocation_policy,
        })
    }

    pub(crate) fn prepare_signing(&self) -> anyhow::Result<Openid4vcSigningLease> {
        self.keyset.prepare_openid4vc_signing()
    }

    pub(super) fn signing_material(
        &self,
        lease: &Openid4vcSigningLease,
    ) -> anyhow::Result<Openid4vcSigningMaterial> {
        signing_material(lease)
    }

    pub(crate) fn x509_hash_client_id(
        &self,
        lease: &Openid4vcSigningLease,
    ) -> anyhow::Result<String> {
        Ok(format!(
            "x509_hash:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(signing_material(lease)?.leaf_der))
        ))
    }

    pub(crate) fn x509_san_dns_client_id(
        &self,
        lease: &Openid4vcSigningLease,
    ) -> anyhow::Result<String> {
        let leaf_der = signing_material(lease)?.leaf_der;
        let (_, certificate) = parse_x509(&leaf_der, "OpenID4VC signing leaf")?;
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
        let material = self
            .keyset
            .openid4vc_public_material()
            .ok_or(CredentialTrustError::UntrustedIssuer)?;
        let mut anchors =
            parse_trust_anchors(&material).map_err(|_| CredentialTrustError::UntrustedIssuer)?;
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

    pub(super) fn current_revocation_policy(&self) -> CertificateRevocationPolicy {
        match self.revocation_policy {
            crate::settings::Openid4vcRevocationPolicy::Disabled => {
                CertificateRevocationPolicy::disabled()
            }
            mode => self
                .keyset
                .openid4vc_public_material()
                .and_then(|material| material.revocation_snapshot.clone())
                .map(Arc::new)
                .map(|snapshot| match mode {
                    crate::settings::Openid4vcRevocationPolicy::Optional => {
                        CertificateRevocationPolicy::optional(snapshot)
                    }
                    crate::settings::Openid4vcRevocationPolicy::Required => {
                        CertificateRevocationPolicy::required(snapshot)
                    }
                    crate::settings::Openid4vcRevocationPolicy::Disabled => unreachable!(),
                })
                .unwrap_or_else(CertificateRevocationPolicy::required_without_snapshot),
        }
    }
}

fn signing_material(lease: &Openid4vcSigningLease) -> anyhow::Result<Openid4vcSigningMaterial> {
    let certificates = parse_pem_certificates(lease.material().certificate_chain_pem.as_bytes())?;
    let leaf_der = certificates
        .first()
        .ok_or_else(|| anyhow::anyhow!("OpenID4VC signing certificate chain is empty"))?
        .clone();
    let trust_anchors = parse_trust_anchors(lease.material())?;
    verify_openid4vc_chain(&certificates, &trust_anchors)?;
    let x5c_der = certificates
        .iter()
        .filter(|certificate| !trust_anchors.contains(certificate))
        .cloned()
        .collect::<Vec<_>>();
    if x5c_der.is_empty() {
        anyhow::bail!("OpenID4VC x5c chain must contain a non-anchor leaf certificate");
    }
    Ok(Openid4vcSigningMaterial {
        x5c: x5c_der
            .into_iter()
            .map(|certificate| STANDARD.encode(certificate))
            .collect(),
        leaf_der,
    })
}

fn validate_public_material(material: &Openid4vcPublicMaterial) -> anyhow::Result<()> {
    let certificates = parse_pem_certificates(material.certificate_chain_pem.as_bytes())?;
    let anchors = parse_trust_anchors(material)?;
    verify_openid4vc_chain(&certificates, &anchors)
}

fn parse_trust_anchors(material: &Openid4vcPublicMaterial) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut anchors = Vec::new();
    for der in parse_pem_certificates(material.trust_anchors_pem.as_bytes())? {
        let (_, parsed) = parse_x509(&der, "OpenID4VC trust certificate")?;
        if parsed.is_ca() && !anchors.contains(&der) {
            anchors.push(der);
        }
    }
    if anchors.is_empty() {
        anyhow::bail!("OpenID4VC trust anchor set must not be empty");
    }
    Ok(anchors)
}
