//! Actix transport adapters and protocol response presentation.
//!
//! This crate owns HTTP-framework details. Domain policy and infrastructure
//! access remain in their focused crates.

mod authorization_decision;
mod authorization_request_object;
mod cookies;
mod cors;
mod csrf;
mod dpop;
mod dynamic_client_registration;
mod extract;
mod fapi_resource;
mod local_registration;
mod metadata;
mod mfa_profile;
mod middleware;
mod oidc_logout;
mod passkey;
mod password_login;
mod presenter;
mod profile_account;
mod request_context;
mod runtime_modules;
mod scim;
mod session;
mod session_management;
mod token_client_auth;
mod token_forms;
mod token_management;
mod userinfo;

pub use authorization_decision::{
    AuthorizationDecisionCommand, AuthorizationDecisionEndpoint, AuthorizationDecisionError,
    AuthorizationDecisionForm, AuthorizationDecisionFuture, AuthorizationDecisionOperations,
    AuthorizationDecisionRedirect, authorize_decision,
};
pub use authorization_request_object::{
    request_object_policy_error, request_object_verification_error,
};
pub use cookies::{clear_cookie, cookie_value, make_cookie, with_cookie_headers};
pub use cors::{
    cors_admin, cors_auth_api, cors_browser_token_management, cors_browser_userinfo, cors_scim,
    cors_well_known,
};
pub use csrf::{csrf_error, has_valid_csrf_token_for_cookies};
pub use dpop::{
    DpopErrorContext, dpop_error_response, dpop_proof_header, dpop_proof_present, dpop_target_uris,
};
pub use dynamic_client_registration::{
    ClientIpConfig, ClientIpHeaderMode, ClientIpParseError, DynamicRegistrationClientStore,
    DynamicRegistrationDependencyError, DynamicRegistrationEndpoint,
    DynamicRegistrationEndpointConfig, DynamicRegistrationFuture,
    DynamicRegistrationRateLimitError, DynamicRegistrationRequestGuard,
    DynamicRegistrationSecurity, IpCidr, client_configuration_delete, client_configuration_get,
    client_configuration_put, client_ip_with_config, client_ip_with_context,
    dynamic_client_registration, parse_forwarded_for_value, parse_trusted_proxy_cidrs,
    request_from_trusted_proxy_cidrs,
};
pub use extract::{
    AccessTokenAuthScheme, ResourceAccessToken, authorization_access_token, mfa_json_config,
    mfa_method_not_allowed, mfa_options, request_uses_form_urlencoded, resource_access_token,
};
pub use fapi_resource::{
    FapiAuthorizationError, FapiFuture, FapiHttpMessageSignatures, FapiMtlsThumbprintResolver,
    FapiResourceAuthorizer, FapiResourceEndpoint, FapiResponseSignature,
    FapiSignatureOperationError, FapiSignatureVerificationError, fapi_resource,
};
pub use local_registration::{
    AuthenticationRateLimit, AuthenticationRateLimitError, LocalRegistrationEndpoint,
    LocalRegistrationFuture, LocalRegistrationOperations, RegisterRequest, SendCodeRequest,
    register, send_code,
};
pub use metadata::{
    MetadataEndpointConfig, MetadataHandles, MetadataSnapshot, MetadataSnapshotSource, discovery,
    jwks, oauth_authorization_server_metadata, oauth_protected_resource_metadata,
};
pub use mfa_profile::{
    MfaBackupCodesRegenerated, MfaChallengeCommand, MfaChallengeSuccess, MfaCodeCommand,
    MfaProfileConfig, MfaProfileEndpoint, MfaProfileError, MfaProfileErrorKind, MfaProfileFuture,
    MfaProfileOperations, MfaRequestContext, MfaSessionRotation, MfaStepUpSuccess,
    MfaTotpConfirmation, MfaTotpEnrollment, configure_mfa_challenge_route,
    configure_mfa_profile_routes, mfa_backup_codes_regenerate, mfa_disable, mfa_step_up,
    mfa_totp_begin, mfa_totp_confirm, mfa_verify,
};
pub use middleware::{apply_security_headers, security_headers};
pub use oidc_logout::{
    OidcLogoutCommand, OidcLogoutConfig, OidcLogoutEndpoint, OidcLogoutError, OidcLogoutFuture,
    OidcLogoutOperations, OidcLogoutRequest, OidcLogoutSuccess, oidc_logout,
};
pub use passkey::{
    PasskeyEndpointError, PasskeyFuture, PasskeyLoginBeginRequest, PasskeyLoginConfig,
    PasskeyLoginEndpoint, PasskeyLoginFinishCommand, PasskeyLoginFinishRequest,
    PasskeyLoginOperations, PasskeyProfileConfig, PasskeyProfileContext, PasskeyProfileEndpoint,
    PasskeyProfileOperations, PasskeyRegistrationBeginRequest, PasskeyRegistrationFinishCommand,
    PasskeyRegistrationFinishRequest, configure_passkey_login_routes,
    configure_passkey_profile_routes, passkey_delete, passkey_list, passkey_login_begin,
    passkey_login_finish, passkey_registration_begin, passkey_registration_finish,
};
pub use password_login::{
    PasswordLoginConfig, PasswordLoginEndpoint, PasswordLoginFuture, PasswordLoginOperations, login,
};
pub use presenter::{
    OAuthJsonErrorFields, authorization_error_response, bearer_challenge, bytes_response,
    empty_response, empty_response_no_store, is_oauth_error_description_byte, json_response,
    json_response_no_store, json_response_status, json_response_status_no_store,
    oauth_bearer_error, oauth_error, oauth_error_description, oauth_token_error, redirect_found,
};
pub use profile_account::{
    ProfileAccountEndpoint, ProfileAccountError, ProfileAccountFuture, ProfileAccountOperations,
    ProfileMe, UpdateProfileRequest, profile_applications, profile_me, profile_update,
};
pub use request_context::RequestContext;
pub use runtime_modules::{
    RuntimeModuleAdminEndpoint, RuntimeModuleAdminError, RuntimeModuleAdminFuture,
    RuntimeModuleAdministration, RuntimeModuleEventPageQuery, RuntimeModulePatch,
    admin_patch_runtime_module, admin_runtime_module_events, admin_runtime_modules,
};
pub use scim::{
    ScimAuthorizationError, ScimAuthorizedRequest, ScimBootstrapPasswordProvider,
    ScimCursorProtector, ScimDependencyError, ScimEndpoint, ScimFuture, ScimRequestAuthorizer,
    scim_create_user, scim_delete_user, scim_get_user, scim_list_users, scim_patch_user,
    scim_replace_user, scim_resource_types, scim_schemas, scim_service_provider_config,
};
pub use session::{
    SessionCookieConfig, SessionLogoutEndpoint, login_required_response, logout_response,
    profile_logout, session_lookup_error_response,
};
pub use session_management::{
    CheckSessionStatusQuery, SessionManagementAvailability, SessionManagementConfig,
    SessionManagementEndpoint, SessionManagementError, SessionManagementFuture,
    SessionManagementOperations, check_session_iframe, check_session_status,
};
pub use token_client_auth::{
    ClientCertificateFacts, TokenClientAuthForm, TokenClientAuthTransportFacts,
    token_client_auth_transport_facts,
};
pub use token_forms::{
    TokenForm, TokenFormError, TokenManagementFormError, TokenOnlyForm, parse_token_form,
    parse_token_management_form, token_management_form_error,
    token_management_has_conflicting_client_auth, token_management_oauth_error,
};
pub use token_management::{
    TOKEN_INTROSPECTION_JWT_MEDIA_TYPE, TokenIntrospectionRepresentation, TokenManagementEndpoint,
    TokenManagementError, TokenManagementFuture, TokenManagementOperations,
    TokenManagementRateLimitError, TokenManagementRequestFacts,
    TokenManagementRequestFactsExtractor, TokenManagementRequestGuard, introspect, revoke,
};
pub use userinfo::{
    UserinfoDpopError, UserinfoEndpoint, UserinfoError, UserinfoFuture, UserinfoOperations,
    UserinfoRepresentation, UserinfoSuccess, userinfo,
};
