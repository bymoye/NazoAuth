//! 领域类型聚合模块。
// 每个子模块只描述一种领域概念，本模块只负责向 crate 内部 re-export。
mod authorization_decision;
mod backchannel_logout_worker;
#[cfg(not(test))]
mod ciba_ping_delivery;
#[cfg(test)]
#[path = "../../tests/unit/domain/ciba_ping_delivery.rs"]
mod ciba_ping_delivery_tests;
mod ciba_ping_tls;
pub(crate) mod client_jwe;
pub(crate) mod client_policy;
mod dynamic_registration;
mod local_registration;
mod metadata;
mod mfa_profile;
mod oauth;
pub(crate) mod oidc_claims;
mod oidc_logout;
mod openid4vc;
mod openid4vc_endpoints;
mod passkey;
mod password_login;
mod profile_account;
pub(crate) mod remote_client_documents;
mod resource_server;
mod rows;
mod scim;
pub(crate) mod sector_identifier;
mod session_management;
pub(crate) mod tenancy;
#[cfg(not(test))]
mod token_management;
mod userinfo;

pub(crate) use authorization_decision::ServerAuthorizationDecisionOperations;
#[cfg(not(test))]
pub(crate) use backchannel_logout_worker::{
    BackchannelLogoutWorker, spawn_backchannel_logout_delivery_worker,
};
#[cfg(not(test))]
pub(crate) use ciba_ping_delivery::{CibaPingDeliveryWorker, spawn_ciba_ping_delivery_worker};

pub(crate) use dynamic_registration::DynamicRegistrationConfig;
pub(crate) use dynamic_registration::dynamic_registration_endpoint;
pub(crate) use local_registration::{
    ServerAuthenticationRateLimit, ServerLocalRegistrationOperations,
};
pub(crate) use metadata::{MetadataConfig, ServerMetadataSnapshotSource};
pub(crate) use mfa_profile::{
    MFA_REMEMBERED_COOKIE_NAME, MFA_REMEMBERED_TTL_SECONDS, ServerMfaProfileOperations,
    ServerMfaSecretHasher,
};
pub(crate) use oauth::{
    AuthorizationCodeState, CodePayload, ConsentPayload, ConsumedAuthorizationCode,
    NativeSsoTokenBinding, PushedAuthorizationRequest, RefreshTokenPolicy, TokenIssue,
};
pub(crate) use oidc_logout::{OidcLogoutConfig, OidcLogoutHandles};
pub(crate) use openid4vc::{
    Openid4vcClientAttestationValidator, Openid4vcCredentialCrypto, Openid4vcProofValidator,
};
pub(crate) use openid4vc_endpoints::{
    CredentialDatasetAdminService, PresentationVerifierConfig, PutCredentialDatasetRequest,
    ServerCredentialIssuerOperations, ServerPresentationOperations,
    openid4vci_authorization_detail,
};
pub(crate) use passkey::PasskeyOperationsProvider;
pub(crate) use password_login::ServerPasswordLoginOperations;
pub(crate) use profile_account::ServerProfileAccountOperations;
pub(crate) use resource_server::ResourceServerConfig;
pub(crate) use resource_server::{
    ServerFapiHttpMessageSignatures, ServerFapiMtlsResolver, ServerFapiResourceAuthorizer,
};
pub(crate) use rows::{ClientRow, TokenRow};
pub(crate) use scim::{
    ServerScimBootstrapPasswordProvider, ServerScimCursorProtector, ServerScimEventSigner,
    ServerScimRequestAuthorizer,
};
pub(crate) use session_management::ServerSessionManagementOperations;
#[cfg(not(test))]
pub(crate) use token_management::{
    ServerTokenManagementOperations, ServerTokenManagementRequestGuard,
};
pub(crate) use userinfo::{ServerUserinfoOperations, UserinfoConfig, UserinfoHandles};
