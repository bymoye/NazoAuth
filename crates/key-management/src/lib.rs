mod authorization_response;
mod client_registration;
mod crypto;
mod database;
mod external;
mod jwks;
mod lifecycle;
mod local;
mod lock;
mod model;
mod mtls_trust;
mod repository;
mod request_object_encryption;
mod serialization;
mod store;
mod token;

pub use client_registration::{
    ClientRegistrationCrypto, SUPPORTED_CLIENT_JWT_SIGNING_ALGS, client_jwks_contains_signing_key,
    client_jwks_contains_signing_key_for_algorithm, client_jwks_matching_encryption_key_count,
    rfc4514_dn_matches, validate_client_jwks, validate_rfc4514_dn, validate_self_signed_mtls_jwks,
};
#[cfg(feature = "test-support")]
pub use model::TestSigningBehavior;
pub use model::{
    ExternalKeyRegistration, HttpSigningLease, KeyHealth, KeyHealthStatus, KeyManager, KeyRecord,
    KeyRecordStatus, KeySettings, KeySnapshot, KeyState, LocalKeyRegistration, ManagedKey,
    Openid4vcMaterial, Openid4vcPublicMaterial, Openid4vcSigningLease, Openid4vcState,
    VerificationKey,
};
pub use mtls_trust::{MtlsTrustAnchorError, ValidatedMtlsTrustAnchor, validate_mtls_trust_anchor};
pub use repository::{
    PersistedSigningKeyset, SealedKeyMaterial, SigningKeyRepository, SigningKeyRepositoryFuture,
    SigningKeyWrappingKeyError, SigningKeyWrappingKeyRing, SigningKeysetCompareAndSwapResult,
    SigningKeysetCreateResult,
};
pub use store::{signing_algorithm_from_name, signing_algorithm_name};
