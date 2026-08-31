//! OpenID for Verifiable Presentations 1.0 Final verifier domain.
//!
//! This crate creates verifier requests, validates direct-post responses, and
//! applies DCQL. Wallet UI, HTTP, storage, X.509 trust, and credential-format
//! cryptography are adapters outside this crate.

mod model;
mod policy;
mod service;
mod store;

pub use model::{
    AuthorizationRequest, AuthorizationResponse, ClientIdPrefix, ClientMetadata,
    DirectPostJwtResponse, PresentationError, PresentationResult, PresentationTransaction,
    RequestMethod, ResponseMode, TransactionData, VerifierInfo,
};
pub use policy::{PresentationPolicy, PresentationPolicyError};
pub use service::{PresentationService, PresentationServiceError, VerifiedPresentation};
pub use store::{
    PresentationCreateIdempotency, PresentationCreateOutcome, PresentationStoreError,
    PresentationStoreFuture, PresentationStorePort, StoredPresentation,
};

pub const VP_TOKEN_RESPONSE_TYPE: &str = "vp_token";
pub const REQUEST_OBJECT_TYPE: &str = "oauth-authz-req+jwt";
