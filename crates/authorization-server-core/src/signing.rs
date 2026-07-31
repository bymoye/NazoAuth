use std::{error::Error, fmt, future::Future};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SigningPurpose {
    AccessToken,
    IdToken,
    Jarm,
    Introspection,
    LogoutToken,
    HttpMessage,
    SecurityEvent,
    Credential,
    PresentationRequest,
}

impl SigningPurpose {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessToken => "access_token",
            Self::IdToken => "id_token",
            Self::Jarm => "jarm",
            Self::Introspection => "introspection",
            Self::LogoutToken => "logout_token",
            Self::HttpMessage => "http_message",
            Self::SecurityEvent => "security_event",
            Self::Credential => "credential",
            Self::PresentationRequest => "presentation_request",
        }
    }

    #[must_use]
    pub fn from_name(value: &str) -> Option<Self> {
        match value {
            "access_token" => Some(Self::AccessToken),
            "id_token" => Some(Self::IdToken),
            "jarm" => Some(Self::Jarm),
            "introspection" => Some(Self::Introspection),
            "logout_token" => Some(Self::LogoutToken),
            "http_message" => Some(Self::HttpMessage),
            "security_event" => Some(Self::SecurityEvent),
            "credential" => Some(Self::Credential),
            "presentation_request" => Some(Self::PresentationRequest),
            _ => None,
        }
    }
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
