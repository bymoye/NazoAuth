use std::{error::Error, fmt, future::Future};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SigningPurpose {
    AccessToken,
    IdToken,
    Jarm,
    LogoutToken,
    HttpMessage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignRequest<'a> {
    pub purpose: SigningPurpose,
    pub algorithm: &'a str,
    pub signing_input: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature(Vec<u8>);

impl Signature {
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignError {
    KeyUnavailable,
    UnsupportedAlgorithm,
    SigningFailed,
}

impl fmt::Display for SignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::KeyUnavailable => "signing key unavailable",
            Self::UnsupportedAlgorithm => "unsupported signing algorithm",
            Self::SigningFailed => "signing operation failed",
        })
    }
}

impl Error for SignError {}

pub trait Signer: Send + Sync {
    fn sign<'a>(
        &'a self,
        request: SignRequest<'a>,
    ) -> impl Future<Output = Result<Signature, SignError>> + Send + 'a;
}
