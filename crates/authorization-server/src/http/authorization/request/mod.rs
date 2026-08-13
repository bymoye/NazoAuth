mod flow;
mod form;
mod parameters;
mod policy;
mod prompt_none;
mod pushed;
mod reauth;
mod response;

pub(crate) use super::unverified_request_object_client_id;
use super::{
    AuthorizationEndpoint, AuthorizationRequestContext, apply_request_object_with_context,
    is_pushed_authorization_request_uri,
};

#[cfg(test)]
use flow::authorize_request_with_context;
pub(crate) use flow::{authorize_get, authorize_post};
use form::{parse_authorization_post_form, parse_authorization_query};
use parameters::{
    authorization_duplicate_parameters, authorization_login_query,
    authorization_login_url_for_frontend, claim_request_names,
    outer_request_uri_parameters_match_pushed, preserve_verified_dpop_binding,
    reauth_nonce_parameter,
};
use policy::{credential_configuration_ids, runtime_authorization_capability_error};
use prompt_none::{
    issue_authorization_code_without_interaction_with_context,
    user_grant_covers_requested_scopes_with_context,
};
pub(crate) use pushed::{
    PushedAuthorizationRequestConsumeError, authorization_oauth_error_redirect,
    consume_pushed_authorization_request_with_context,
};
use reauth::{authorization_login_url_with_context, consume_reauth_nonce_with_context};
use response::oauth_json_error;
pub(crate) use response::{
    AuthorizationResponseClientPolicy, AuthorizationResponseRedirect,
    authorization_response_redirect_with_context,
};
#[cfg(test)]
use response::{
    AuthorizationResponseProtection, authorization_response_jwt_redirect,
    authorization_response_jwt_result, authorization_response_redirect_with_protection_context,
};

#[cfg(test)]
use crate::domain::ConsentPayload;
#[cfg(test)]
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::web::{Bytes, Data};
#[cfg(test)]
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::{Duration, Utc};
#[cfg(test)]
use nazo_auth::{
    AuthorizationCapabilityPolicy, AuthorizationClientPolicy, AuthorizationProfilePolicy,
    AuthorizationSession, AuthorizationSessionDecision, normalize_authorization_request,
    parse_scope,
};
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use uuid::Uuid;

#[cfg(test)]
#[path = "../../../../tests/unit/http/authorization/request.rs"]
mod tests;
