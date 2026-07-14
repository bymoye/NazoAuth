//! 领域类型聚合模块。
// 每个子模块只描述一种领域概念，本模块只负责向 crate 内部 re-export。
mod authorization_decision;
mod backchannel_logout_worker;
pub(crate) mod client_jwe;
pub(crate) mod client_policy;
#[cfg(test)]
#[path = "../../tests/in_source/src/domain/database_user_fixture.rs"]
mod database_user_fixture;
mod dynamic_registration;
mod local_registration;
mod metadata;
mod mfa_profile;
mod oauth;
pub(crate) mod oidc_claims;
mod oidc_logout;
mod passkey;
mod password_login;
mod profile_account;
mod resource_server;
mod rows;
#[cfg(not(test))]
mod scim;
pub(crate) mod sector_identifier;
mod session_management;
pub(crate) mod tenancy;
#[cfg(not(test))]
mod token_management;
mod userinfo;

#[cfg(test)]
pub(crate) use crate::test_support::TestAppState;
pub(crate) use authorization_decision::ServerAuthorizationDecisionOperations;
#[cfg(not(test))]
pub(crate) use backchannel_logout_worker::{
    BackchannelLogoutWorker, spawn_backchannel_logout_delivery_worker,
};
#[cfg(test)]
pub(crate) use database_user_fixture::{
    DatabaseExternalIdentityFixture, DatabasePasskeyFixture, DatabaseUserFixture,
};
pub(crate) use dynamic_registration::DynamicRegistrationConfig;
#[cfg(test)]
pub(crate) use dynamic_registration::DynamicRegistrationHandles;
#[cfg(not(test))]
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
pub(crate) use passkey::PasskeyOperationsProvider;
pub(crate) use password_login::ServerPasswordLoginOperations;
pub(crate) use profile_account::ServerProfileAccountOperations;
pub(crate) use resource_server::ResourceServerConfig;
pub(crate) use resource_server::{
    ServerFapiHttpMessageSignatures, ServerFapiMtlsResolver, ServerFapiResourceAuthorizer,
};
pub(crate) use rows::{ClientRow, TokenRow};
#[cfg(not(test))]
pub(crate) use scim::{
    ServerScimBootstrapPasswordProvider, ServerScimCursorProtector, ServerScimRequestAuthorizer,
};
pub(crate) use session_management::ServerSessionManagementOperations;
#[cfg(not(test))]
pub(crate) use token_management::{
    ServerTokenManagementOperations, ServerTokenManagementRequestGuard,
};
pub(crate) use userinfo::{ServerUserinfoOperations, UserinfoConfig, UserinfoHandles};
