use std::{future::Future, pin::Pin};

use serde_json::Value;

use crate::{ProofTypeMetadata, Proofs};

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedProof {
    pub proof_type: String,
    pub holder_binding: Value,
    pub nonce: String,
    pub key_attestation: Option<Value>,
}

pub trait ProofValidatorPort: Send + Sync {
    fn validate<'a>(
        &'a self,
        proofs: &'a Proofs,
        client_id: &'a str,
        expected_issuer: &'a str,
        expected_nonce: &'a str,
        metadata: &'a ProofTypeMetadata,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ValidatedProof>, ProofError>> + Send + 'a>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProofError {
    #[error("credential proof is missing")]
    Missing,
    #[error("credential proof type is unsupported")]
    UnsupportedType,
    #[error("credential proof signature is invalid")]
    InvalidSignature,
    #[error("credential proof nonce is invalid")]
    InvalidNonce,
    #[error("credential proof audience is invalid")]
    InvalidAudience,
    #[error("credential proof key attestation is invalid")]
    InvalidKeyAttestation,
    #[error("credential proof service is unavailable")]
    Unavailable,
}
