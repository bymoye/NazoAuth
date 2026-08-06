mod client_attestation;
mod credential_crypto;
mod crypto_helpers;
mod proof_validator;

pub(crate) use client_attestation::Openid4vcClientAttestationValidator;
pub(crate) use credential_crypto::{
    Openid4vcCredentialCrypto, parse_conformance_credential_trust_anchor,
};
pub(crate) use proof_validator::Openid4vcProofValidator;

#[cfg(test)]
#[path = "../../tests/unit/domain/openid4vc.rs"]
mod tests;
