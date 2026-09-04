//! Actix transport adapters for OpenID4VCI issuer and OpenID4VP verifier roles.
//!
//! Domain policy remains in `nazo-openid4vci` and `nazo-openid4vp`.

#![forbid(unsafe_code)]

mod vci;
mod vp;

pub use vci::{
    AccessTokenScheme, CreateCredentialOfferRequest, CreateCredentialOfferResponse,
    CredentialEndpointResponse, CredentialHttpError, CredentialIssuerEndpoint,
    CredentialIssuerFuture, CredentialIssuerOperations, CredentialRequestBody,
    CredentialRequestContext, CredentialResponseBody, PreAuthorizedTokenRequest,
    PreAuthorizedTokenResponse, create_credential_offer, credential, credential_issuer_metadata,
    credential_nonce, credential_offer, deferred_credential, notification,
};
pub use vp::{
    CreatePresentationRequest, CreatePresentationResponse, PresentationEndpoint,
    PresentationFuture, PresentationHttpError, PresentationOperations, PresentationResponseBody,
    PresentationResponseInput, create_presentation, presentation_complete, presentation_request,
    presentation_response, presentation_result,
};
