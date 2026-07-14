#![forbid(unsafe_code)]

//! Runtime- and infrastructure-free authorization-server policy.

mod admin_clients;
mod admin_grants;
mod authorization_details;
mod authorization_policy;
mod authorization_request;
mod authorization_service;
mod ciba;
mod claims;
mod client;
mod client_assertion;
mod client_authentication;
mod client_registration;
mod device;
mod dpop;
mod dynamic_client_registration;
mod error;
mod extension_grants;
mod grant;
mod logout_service;
mod metadata;
mod oauth_parameters;
mod oidc_logout;
mod profile;
mod resource_indicator;
mod sender_constraint;
mod session_management;
mod signing;
mod token;
mod token_endpoint;
mod token_service;
mod transaction;
mod uri_policy;

pub use admin_clients::{
    AdminClientCryptoPort, AdminClientError, AdminClientFuture, AdminClientPolicy,
    AdminClientPortError, AdminClientRepositoryPort, AdminClientService, CreateClientRequest,
    CreatedClient, PatchClientRequest, PreparedClientRegistration, SectorIdentifierFuture,
    SectorIdentifierResolverPort, insert_prepared_client, prepare_client_patch,
    prepare_client_registration,
};
pub use admin_grants::{
    AdminGrantFuture, AdminGrantPage, AdminGrantRepositoryPort, AdminGrantRevocation,
    AdminGrantRevokeError, AdminGrantRevokeFuture, AdminGrantView,
};
pub use authorization_details::{
    AuthorizationDetailsError, SUPPORTED_AUTHORIZATION_DETAILS_TYPES, authorization_details_empty,
    canonical_authorization_details, deserialize_authorization_details,
    empty_authorization_details, high_risk_authorization_details, normalize_authorization_details,
    parse_authorization_details,
};
pub use authorization_policy::{
    AUTHORIZATION_NONCE_MAX_BYTES, AuthorizationCapabilityPolicy, AuthorizationClientPolicy,
    AuthorizationPolicyError, AuthorizationProfilePolicy, AuthorizationResponsePlan,
    AuthorizationResponsePolicyError, AuthorizationResponsePolicyInput, AuthorizationSession,
    AuthorizationSessionDecision, BASELINE_ACR_VALUE, JarmAuthorizationResponse,
    NormalizedAuthorizationRequest, PlainAuthorizationResponse, PromptDirectives,
    PromptNoneDecision, RequestedClaims, SignedJarmAuthorizationResponse,
    UserAuthorizationDecision, authorization_session_decision, normalize_authorization_request,
    parse_user_authorization_decision, plain_authorization_response_uri,
    plan_authorization_response, prompt_none_decision, signed_jarm_authorization_response_uri,
};
pub use authorization_request::{
    AuthorizationRequestError, ExpandedParAdmissionPolicy, NormalizedRequestObject, ParAdmission,
    ParAdmissionError, PushedAuthorizationRequestConsumeError, REQUEST_OBJECT_CLOCK_SKEW_SECONDS,
    REQUEST_OBJECT_MAX_TTL_SECONDS, RawParAdmissionPolicy, RequestObjectClaims,
    RequestObjectJtiPolicy, RequestObjectMode, RequestObjectPolicy, RequestObjectReplay,
    RequestObjectVerificationError, RequestObjectVerificationInput, VerifiedRequestObject,
    normalize_request_object, request_object_uses_unsigned_algorithm,
    unverified_signed_request_object_client_id, validate_expanded_par_admission,
    validate_raw_par_admission, verify_request_object,
};
pub use authorization_service::{
    AuthorizationApprovalCommitError, AuthorizationApprovalError, AuthorizationApprovalInput,
    AuthorizationDecisionAdmissionError, AuthorizationFuture, AuthorizationPortError,
    AuthorizationRateDimension, AuthorizationRepositoryPort, AuthorizationResponseSignInput,
    AuthorizationResponseSignerPort, AuthorizationService, AuthorizationStateStorePort, GrantWrite,
    StoredAuthorizationGrant, pushed_authorization_request_digest,
    stored_grant_covers_requested_authorization,
};
pub use ciba::{
    CibaAtomicResult, CibaCommittedDecision, CibaCreateFailure, CibaDecision,
    CibaDecisionEvaluation, CibaDecisionFailure, CibaPollCommit, CibaPollFailure,
    CibaPollTransition, CibaRequestState, CibaService, CibaStateFuture, CibaStatePortError,
    CibaStateStorePort, CibaStatus, CibaStoredRequest, ciba_retention_deadline,
    evaluate_ciba_decision, evaluate_ciba_poll,
};
pub use claims::{
    AccessTokenClaimsInput, AuthorizationResponseClaimsInput, BackchannelLogoutClaimsInput, Claims,
    ConfirmationClaims, IdTokenClaimsInput, OidcClaimRequest, SUPPORTED_USER_CLAIMS,
    access_token_claims, authorization_response_jwt_claims, backchannel_logout_token_claims,
    id_token_claims, supported_user_claim,
};
pub use client::{ClientProfile, validate_token_request_profile};
pub use client_assertion::{
    CLIENT_ASSERTION_MAX_TTL_SECONDS, CLIENT_ASSERTION_TYPE_JWT_BEARER,
    ClientAssertionValidationError, ClientAssertionVerificationInput, ValidatedClientAssertion,
    unverified_client_assertion_client_id, verify_private_key_jwt,
};
pub use client_authentication::{
    ClientAuthenticationContext, ClientAuthenticationMethod, ClientAuthenticationPolicyError,
    ClientAuthenticationRequirement, PresentedClientCredentials, client_authentication_requirement,
};
pub use client_registration::{ApprovedClient, OAuthClient, ValidatedClientRegistration};
pub use device::{
    ApprovedDeviceAuthorization, DeviceAtomicResult, DeviceAuthorizationApproval,
    DeviceAuthorizationPayload, DeviceAuthorizationRequestError, DeviceAuthorizationRequestPolicy,
    DeviceAuthorizationState, DeviceCreateFailure, DeviceCreateResult, DeviceDecisionFailure,
    DeviceGrantFuture, DeviceGrantPortError, DeviceGrantRepositoryPort, DeviceGrantService,
    DeviceGrantWrite, DevicePollCommit, DevicePollFailure, DevicePollTransition, DeviceStateFuture,
    DeviceStatePortError, DeviceStateStorePort, StoredDeviceAuthorization,
    device_authorization_payload, device_authorization_request_payload, evaluate_device_poll,
};
pub use dpop::{
    DPOP_CLOCK_SKEW_SECONDS, DPOP_REPLAY_TTL_SECONDS, DpopError, DpopNoncePolicy, DpopProofRequest,
    DpopProofVerifier, DpopReplayAudit, DpopStateFuture, DpopStateStoreError, DpopStateStorePort,
    VerifiedDpopProof, issue_authorization_server_dpop_nonce, new_dpop_nonce,
    validate_authorization_server_dpop, validate_authorization_server_dpop_at,
};
pub use dynamic_client_registration::{
    ClientSecretDigesterPort, DynamicClientRegistrationRequest, DynamicRegistrationClientStore,
    DynamicRegistrationDependencyError, DynamicRegistrationError, DynamicRegistrationFuture,
    DynamicRegistrationPolicy, DynamicRegistrationSecretPort, PreparedDynamicClientRegistration,
    parse_client_configuration_update, prepare_dynamic_client_registration,
    response_types_from_client,
};
pub use error::{ProtocolError, ProtocolErrorCode};
pub use extension_grants::{
    ACCESS_TOKEN_TYPE, JWT_BEARER_ASSERTION_CLOCK_SKEW_SECONDS, JWT_BEARER_ASSERTION_MAX_JTI_BYTES,
    JWT_BEARER_ASSERTION_MAX_TTL_SECONDS, JwtBearerAssertionClaims, JwtBearerGrantAdmission,
    JwtBearerGrantError, JwtBearerGrantPolicy, TokenExchangeAdmission, TokenExchangeError,
    TokenExchangePolicy, TokenExchangeRequestInput, TokenExchangeSenderBinding,
    ValidatedJwtBearerAssertion, ValidatedTokenExchangeSubject, admit_jwt_bearer_grant,
    admit_token_exchange, token_exchange_actor_claim, token_exchange_issuance_binding,
    token_exchange_scopes, validate_jwt_bearer_assertion_claims,
    validate_jwt_bearer_grant_prerequisites, validate_token_exchange_access_token,
    validate_token_exchange_grant_prerequisites, validate_token_exchange_subject,
};
pub use grant::{GrantType, UnsupportedGrantType};
pub use logout_service::{
    BACKCHANNEL_LOGOUT_TOKEN_TTL_SECONDS, BackchannelLogoutOutboxPort,
    IdempotentBackchannelLogoutDelivery, LogoutClientRepositoryPort, LogoutDependencyError,
    LogoutExecution, LogoutFuture, LogoutInput, LogoutService, LogoutServiceError, LogoutSession,
    LogoutTokenSignerPort, RegisteredLogoutClient, RpLogoutRequest, logout_operation_key,
};
pub use metadata::{
    AuthorizationServerMetadataInput, CapabilityAdmission, CibaMetadataProfile,
    MetadataAuthorizationServerProfile, MetadataCapabilities, MetadataSigningAlgorithms,
    MetadataSubjectType, ProtectedResourceMetadataInput, authorization_server_metadata,
    module_admissible, protected_resource_metadata,
};
pub use oauth_parameters::{
    has_duplicate_oauth_parameter, is_subset, parse_scope, string_array_values,
    token_audience_contains, token_audience_values,
};
pub use oidc_logout::{
    IdTokenHintClaims, LogoutClient, LogoutPolicyError, audience_contains, frontchannel_logout_url,
    id_token_hint_matches_session, logout_subjects_for_client, oidc_subject_for_client,
    pairwise_subject, resolve_logout_client_id, single_audience, unique_logout_subject_for_client,
    validate_post_logout_redirect,
};
pub use profile::SecurityProfile;
pub use resource_indicator::{
    ResourceIndicatorError, encode_resource_indicators, parse_resource_indicator_parameter,
    parse_resource_indicators,
};
pub use sender_constraint::{
    SenderConstraintPolicy, is_valid_dpop_jkt, normalize_sha256_thumbprint,
};
pub use session_management::{
    OidcSessionStatus, check_oidc_session_state, issue_oidc_session_state, oidc_session_state,
};
pub use signing::{SignError, SignRequest, Signature, Signer, SigningPurpose};
pub use token::{
    BackchannelLogoutDelivery, LostResponseRetry, NewRefreshToken,
    PendingBackchannelLogoutDelivery, RefreshToken, RefreshTokenPersistResult,
};
pub use token_endpoint::{
    AdmittedTokenClient, AppliedSenderConstraint, AuthorizationCodeTokenRequest,
    ClientCredentialsTokenRequest, PresentedSenderConstraint, RefreshTokenRequest,
    TokenClientAuthPresentation, TokenClientAuthenticationContext, TokenClientPolicy,
    TokenEndpointDispatch, TokenEndpointError, TokenEndpointPolicy, TokenEndpointRequestInput,
    admit_token_client, apply_sender_constraint, sender_constraint_policy,
    token_client_authentication_context, token_endpoint_dispatch,
};
pub use token_service::{
    AccessTokenRevocation, AccessTokenSignInput, AuthorizationCodeBeginResult,
    AuthorizationCodeTransitionResult, IdTokenSignInput, IntrospectionSignInput, IssuedAccessToken,
    IssuedAuthorizationCodeTokens, TokenFuture, TokenInspection, TokenPortError,
    TokenRepositoryPort, TokenRevocation, TokenService, TokenSignerPort, TokenStateStorePort,
    validate_sender_constraint,
};
pub use transaction::{
    AuthorizationCodeState, CodePayload, ConsentPayload, ConsumedAuthorizationCode,
    PushedAuthorizationRequest,
};
pub use uri_policy::{
    RedirectUriError, is_loopback_http_url, is_valid_pkce_value, oauth_redirect_uri_matches,
    resolve_registered_redirect_uri, validate_cors_origin, validate_frontend_base_url,
    validate_issuer_url, validate_oauth_redirect_uri, validate_protected_resource_identifier,
};
