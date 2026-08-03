use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use serde_json::Value;

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
}
