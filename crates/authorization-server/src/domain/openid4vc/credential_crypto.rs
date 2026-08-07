use std::sync::Arc;

#[cfg(test)]
use coset::CborSerializable;
use nazo_digital_credentials::{
    CertificateRevocationPolicy, CredentialFormat, CredentialFuture, CredentialTrustError,
    CredentialVerifierPort, PresentedCredential, VcIssuerTrustPolicy, VerifiedCredential,
};
use nazo_key_management::KeyManager;

mod certificates;
mod mdoc;
mod sd_jwt;
mod signer;

pub(crate) use certificates::parse_conformance_credential_trust_anchor;
#[cfg(test)]
pub(crate) use mdoc::{
    mdoc_failed_assessments_accepted, mdoc_holder_key, standard_device_authentication_bytes,
};

#[cfg(test)]
use mdoc::{AsyncCoseSigner, mdoc_assessments_accepted, verify_certificate_chain_at};

#[derive(Clone)]
pub(crate) struct Openid4vcCredentialCrypto {
    keyset: KeyManager,
    x5c: Arc<Vec<String>>,
    leaf_der: Arc<Vec<u8>>,
    trust_anchors: Arc<Vec<Vec<u8>>>,
    issuer_trust_policy: VcIssuerTrustPolicy,
    revocation_policy: CertificateRevocationPolicy,
}

impl CredentialVerifierPort for Openid4vcCredentialCrypto {
    fn verify<'a>(
        &'a self,
        presentation: &'a PresentedCredential,
    ) -> CredentialFuture<'a, Result<VerifiedCredential, CredentialTrustError>> {
        Box::pin(async move {
            match presentation.format {
                CredentialFormat::SdJwtVc => sd_jwt::verify(self, presentation),
                CredentialFormat::MsoMdoc => mdoc::verify(self, presentation),
            }
        })
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/domain/openid4vc_credential_crypto.rs"]
mod tests;
