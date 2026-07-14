//! Framework-neutral primitives for HTTP Message Signatures (RFC 9421) and
//! Content-Digest fields (RFC 9530).
//!
//! The crate prepares and parses request and response signature fields,
//! reconstructs signature bases, and computes or validates content digests.

mod digest;
mod error;
mod jwk;
mod request;
mod response;
mod verify;

pub use digest::{content_digest, content_digest_field_matches};
pub use error::VerifyError;
pub use jwk::{JwkSignatureVerificationError, verify_jwk_signature};
pub use request::{
    PreparedSignature, RequestError, RequestInput, RequestPolicy, SignatureFields, prepare_request,
};
pub use response::{
    OriginalRequest, ResponseError, ResponseInput, ResponsePolicy, parse_response_for_verification,
    prepare_response,
};
pub use verify::{VerificationPolicy, VerifiedInput, parse_request_for_verification};
