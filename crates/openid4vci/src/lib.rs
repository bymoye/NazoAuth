//! OpenID for Verifiable Credential Issuance 1.0 Final issuer domain.
//!
//! The crate implements issuer-side protocol state and validation. OAuth,
//! HTTP, persistence, credential-format cryptography, and operator policy are
//! supplied through ports so enabling VCI does not alter the authorization
//! server's baseline behavior.

mod metadata;
mod model;
mod offer;
mod proof;
mod service;
mod store;

pub use metadata::{
    BatchCredentialIssuance, CredentialConfiguration, CredentialDisplay, CredentialIssuerMetadata,
    CredentialMetadata, CredentialRequestEncryptionMetadata, EncryptionMetadata, Logo,
    ProofTypeMetadata,
};
pub use model::{
    CredentialError, CredentialIdentifier, CredentialRequest, CredentialResponse,
    CredentialResponseEncryption, DeferredCredentialRequest, IssuedCredential, NotificationEvent,
    NotificationRequest, Proofs,
};
pub use offer::{
    AuthorizationCodeGrant, CredentialOffer, CredentialOfferGrants, PreAuthorizedCodeGrant,
    TxCodeDescription,
};
pub use proof::{ProofError, ProofValidatorPort, ValidatedProof};
pub use service::{
    CredentialDatasetPort, CredentialIssuance, CredentialIssuanceError, CredentialIssuerService,
    DeferredPayload, IssuanceClaim, IssuanceCommit, IssuanceDisposition, IssuanceIdentity,
    PendingCredentialIssuance,
};
pub use store::{
    AuthorizationOfferPort, CredentialAccess, CredentialAuthorization, CredentialResponseEncoding,
    CredentialStoreError, CredentialStoreFuture, CredentialStorePort, DeferredCredential,
    DeferredCredentialClaim, IssuanceNotification, NonceRecord, NotificationHandle,
    StoredCredentialOffer, StoredCredentialResponse,
};

pub const PRE_AUTHORIZED_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
pub const OPENID_CREDENTIAL_AUTHORIZATION_TYPE: &str = "openid_credential";
pub const PROOF_JWT_MEDIA_TYPE: &str = "openid4vci-proof+jwt";
pub const ISSUER_METADATA_JWT_MEDIA_TYPE: &str = "openidvci-issuer-metadata+jwt";
