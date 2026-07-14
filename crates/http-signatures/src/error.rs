use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VerifyError {
    #[error("request signature is missing")]
    MissingSignature,
    #[error("request signature fields are malformed")]
    MalformedSignature,
    #[error("request signature selection is ambiguous")]
    AmbiguousSignature,
    #[error("request signature algorithm is unsupported")]
    UnsupportedAlgorithm,
    #[error("request signature tag is invalid")]
    InvalidTag,
    #[error("a required request signature component is missing or invalid")]
    MissingComponent,
    #[error("request signature creation time is invalid")]
    InvalidCreated,
    #[error("request content digest does not match its body")]
    DigestMismatch,
}
