//! OpenID Connect CIBA poll/ping grant.
use nazo_http_actix::{
    empty_response, json_response_no_store, oauth_error, oauth_token_error,
    request_uses_form_urlencoded,
};

use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::ValidatedClientAssertion;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::client_jwt_decoding_key;
use crate::adapters::security::extract_client_credentials_with_trusted_proxies;
use crate::adapters::security::has_basic_authorization_scheme;
use crate::adapters::security::random_urlsafe_token;

use crate::domain::client_policy::client_supports_grant;
use crate::domain::client_policy::is_subset;
use crate::domain::client_policy::parse_scope;
use crate::domain::tenancy::DEFAULT_TENANT_ID;

use crate::domain::{ClientRow, RefreshTokenPolicy, TokenIssue};
use crate::settings::{AuthorizationServerProfile, CibaAutomatedDecisionMode, Settings};
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::http::header::{HeaderMap, HeaderValue};
use actix_web::web::{Bytes, Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use nazo_auth::{
    CibaAuthenticationContext, CibaCommittedDecision, CibaCreateFailure, CibaDecision,
    CibaDecisionFailure, CibaPingNotification, CibaPingNotificationStatus, CibaPollCommit,
    CibaPollFailure, CibaRequestState, CibaService, CibaStatePortError, CibaStatus, ClientProfile,
    ProtocolErrorCode, SecurityProfile, SenderConstraintPolicy, ciba_retention_deadline,
    validate_token_request_profile as validate_auth_token_request_profile,
};
use nazo_http_actix::client_ip_with_context;
use nazo_http_actix::{cookie_value, csrf_error, has_valid_csrf_token_for_cookies};
use nazo_valkey::CibaStore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::client_auth::{
    ClientAuthConfig, authenticate_client_with_dependencies,
    consume_token_client_assertion_with_authorization_service,
    consume_token_management_client_assertion_with_authorization_service,
};
use super::issue::TokenIssuanceConfig;
use super::issue::{TokenIssuanceContext, issue_token_response_with_service_and_grant};

use super::{
    ServerTokenService, TokenForm, TokenManagementClientAuthError, client_auth_request_facts,
    token_management_auth_error,
};
use crate::http::authorization::ServerAuthorizationService;
use crate::http::sessions::AdminSessionHandles;
use crate::runtime_modules::ServerRuntimeModuleRegistry;
use actix_web::web::Payload;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::ClientAuthenticationContext;
use nazo_http_actix::{ClientIpHeaderMode, IpCidr};
use std::{collections::HashSet, fmt::Write as _};

mod policy;
mod request;
mod state;

pub(super) use policy::{
    ciba_algorithm_name, ciba_client_assertion_algorithm_supported, ciba_invalid_request,
    ciba_jwt_signing_algorithm_supported, non_empty, validate_ciba_delivery_request,
    validate_ciba_request_object_presence_with_config,
    validate_ciba_security_profile_client_with_config, validate_ciba_token_request_profile,
};
pub(super) use request::{
    apply_ciba_request_object_client_id_hint, ciba_hint_count, ciba_selected_acr,
    parse_backchannel_authentication_form,
    validate_and_apply_ciba_request_object_claims_with_config,
};
pub(super) use state::{
    BackchannelAuthenticationForm, CIBA_AUTOMATED_DECISION_PROFILE, CIBA_BINDING_MESSAGE_MAX_CHARS,
    CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS, CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS,
    CibaAuthenticationRequestClaims, CibaAuthorizationRequestView, CibaDecisionSource,
    CibaRequestObjectReplay, CibaVerificationView, UnverifiedCibaAuthenticationRequestClaims,
    ciba_grant_key, ciba_module_admissible, ciba_start_audit_fields,
};
pub(crate) use state::{
    CIBA_GRANT_TYPE, CibaAutomatedDecisionQuery, CibaDecisionRequest, CibaHttpConfig,
    CibaTokenContext, CibaTokenHandles, ServerCibaService,
};

#[path = "ciba/backchannel.rs"]
mod backchannel;
#[path = "ciba/decision.rs"]
mod decision;
#[path = "ciba/poll.rs"]
mod poll;
pub(crate) use backchannel::backchannel_authentication;
pub(crate) use decision::{
    ciba_automated_decision, ciba_decision, ciba_verification, ciba_verification_page,
};
pub(crate) use poll::token_ciba;

#[cfg(test)]
use decision::{
    ciba_automated_decision_auth_req_id, ciba_automated_decision_request_token,
    ciba_poll_failure_response, complete_ciba_decision, sha256_hex,
};
#[cfg(test)]
use poll::{ciba_auth_req_id_client_error, ciba_token_issue, load_ciba_request_payload};

#[cfg(test)]
#[path = "../../../tests/unit/http/token/ciba.rs"]
mod tests;

#[cfg(test)]
#[path = "../../../tests/unit/http/token/ciba/state.rs"]
mod state_tests;
