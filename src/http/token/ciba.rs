//! OpenID Connect CIBA poll-mode grant.

mod state;

use super::{
    TokenForm, TokenManagementClientAuthError, consume_token_client_assertion,
    consume_token_management_client_assertion, issue_token_response, token_management_auth_error,
    validate_token_request_profile, verify_confidential_client,
};
use crate::http::prelude::*;
use actix_web::web::Payload;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use state::*;
use std::{collections::HashSet, future::Future};

pub(crate) const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";
const CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS: i64 = 300;
const CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS: i64 = 30;
const CIBA_BINDING_MESSAGE_MAX_CHARS: usize = 64;

#[derive(Default)]
struct BackchannelAuthenticationForm {
    request: Option<String>,
    scope: Option<String>,
    login_hint: Option<String>,
    id_token_hint: Option<String>,
    login_hint_token: Option<String>,
    binding_message: Option<String>,
    acr_values: Option<String>,
    requested_expiry_seconds: Option<u64>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

#[derive(Deserialize)]
struct CibaAuthenticationRequestClaims {
    iss: Option<String>,
    aud: Option<Value>,
    exp: Option<i64>,
    nbf: Option<i64>,
    iat: Option<i64>,
    jti: Option<String>,
    scope: Option<String>,
    login_hint: Option<String>,
    id_token_hint: Option<String>,
    login_hint_token: Option<String>,
    binding_message: Option<String>,
    acr_values: Option<String>,
    requested_expiry: Option<Value>,
}

#[derive(Deserialize)]
pub(crate) struct CibaDecisionRequest {
    decision: String,
    csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct CibaAutomatedDecisionQuery {
    token: Option<String>,
    auth_req_id: Option<String>,
    r#type: Option<String>,
    action: Option<String>,
    decision_token: Option<String>,
}

#[derive(serde::Serialize)]
struct CibaVerificationView {
    auth_req_id: String,
    csrf_token: Option<String>,
    request: Option<CibaAuthorizationRequestView>,
}

#[derive(serde::Serialize)]
struct CibaAuthorizationRequestView {
    client_id: String,
    client_name: String,
    scopes: Vec<String>,
    audiences: Vec<String>,
    binding_message: Option<String>,
    interval_seconds: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct CommittedCibaDecision {
    auth_req_id_hash: String,
    state: CibaRequestState,
    decision: CibaDecision,
}

#[derive(Clone, Copy, Debug)]
enum CibaDecisionSource {
    User,
    Automation,
}

impl CibaDecisionSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Automation => "automation",
        }
    }
}

#[derive(Debug)]
enum CibaDecisionFailure {
    Missing,
    UserMismatch,
    AlreadyHandled,
    Expired,
    Storage(CibaStateError),
    Contended,
}

struct AuthorizedCibaPoll {
    initial: StoredCibaRequest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CibaPollCommit {
    AuthorizationPending,
    SlowDown,
    Approved(CibaRequestState),
    Denied,
    Expired,
}

#[derive(Debug)]
enum CibaPollFailure {
    Missing,
    ClientMismatch,
    Storage(CibaStateError),
    Contended,
}

pub(crate) async fn backchannel_authentication(
    state: Data<AppState>,
    req: HttpRequest,
    mut payload: Payload,
) -> HttpResponse {
    if !state.settings.enable_ciba {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut form = match parse_backchannel_authentication_form(&req, &mut payload).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    let has_basic = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim_start().starts_with("Basic "));
    let has_assertion = form.client_assertion_type.is_some() || form.client_assertion.is_some();
    if has_basic && (form.client_id.is_some() || form.client_secret.is_some() || has_assertion)
        || has_assertion && form.client_secret.is_some()
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA request cannot mix client authentication methods.",
        );
    }
    let credentials = extract_client_credentials(
        &req,
        &state.settings,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    let Some(client_id) = credentials.client_id.as_deref() else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    };
    let client = match find_client(&state.diesel_db, client_id).await {
        Ok(Some(client)) if client.is_active => client,
        Ok(_) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query CIBA client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
            );
        }
    };
    if !client_supports_grant(&client, CIBA_GRANT_TYPE) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用 CIBA 授权类型.",
        );
    }
    let assertion = match verify_confidential_client(&state, &req, &client, &credentials) {
        Ok(assertion) => assertion,
        Err(error) => return token_management_auth_error(error),
    };
    if !ciba_client_assertion_algorithm_supported(assertion.as_ref()) {
        return token_management_auth_error(TokenManagementClientAuthError::InvalidClient);
    }
    if let Err(error) =
        consume_token_management_client_assertion(&state, &client, assertion.as_ref()).await
    {
        return token_management_auth_error(error);
    }
    if let Err(response) =
        validate_token_request_profile(&state.settings, &client, credentials.method.as_str())
    {
        return response;
    }
    if let Err(response) =
        validate_ciba_security_profile_client(&state.settings, &client, credentials.method.as_str())
    {
        return response;
    }
    if let Err(response) = validate_ciba_request_object_presence(&state.settings, &client, &form) {
        return response;
    }
    if let Err(response) = validate_and_apply_ciba_request_object_claims(&state, &client, &mut form)
    {
        return response;
    }
    let scopes = parse_scope(form.scope.as_deref().unwrap_or(""));
    if !scopes.iter().any(|scope| scope == "openid")
        || !is_subset(&scopes, &json_array_to_strings(&client.scopes))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "CIBA requires an allowed openid scope.",
        );
    }
    if ciba_hint_count(&form) != 1 || form.login_hint.is_none() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA requires exactly one supported user hint.",
        );
    }
    let Some(login_hint) = form
        .login_hint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA requires login_hint.",
        );
    };
    let user = match find_user_by_email(&state.diesel_db, login_hint).await {
        Ok(Some(user)) if user.is_active => user,
        Ok(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unknown_user_id",
                "CIBA login_hint does not identify an active user.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query CIBA login_hint user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
            );
        }
    };
    let expires_in = form
        .requested_expiry_seconds
        .unwrap_or(state.settings.ciba_auth_req_id_ttl_seconds)
        .min(state.settings.ciba_auth_req_id_ttl_seconds);
    let acr = match ciba_selected_acr(form.acr_values.as_deref()) {
        Some(acr) => Some(acr),
        None if form.acr_values.is_some() => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA acr_values is unsupported.",
            );
        }
        None => None,
    };
    let now = Utc::now().timestamp();
    let expires_at = now.saturating_add(expires_in.min(i64::MAX as u64) as i64);
    let state_payload = CibaRequestState {
        client_id: client.client_id,
        user_id: user.id,
        scopes,
        audiences: vec![state.settings.default_audience.clone()],
        acr,
        binding_message: form.binding_message,
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: state.settings.ciba_poll_interval_seconds,
        expires_at,
        retention_expires_at: ciba_retention_deadline(expires_at),
        last_poll_at: None,
    };
    let auth_req_id =
        match create_unique_ciba_request(&state.valkey, &state_payload, random_urlsafe_token).await
        {
            Ok(auth_req_id) => auth_req_id,
            Err(error) => {
                tracing::warn!(%error, "failed to create CIBA auth_req_id");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "CIBA failed.",
                );
            }
        };
    audit_event(
        "ciba_authorization_started",
        ciba_start_audit_fields(
            &state_payload,
            &auth_req_id,
            Some(blake3_hex(&client_ip(&req, &state.settings))),
        ),
    );
    json_response_no_store(json!({
        "auth_req_id": auth_req_id,
        "expires_in": expires_in,
        "interval": state.settings.ciba_poll_interval_seconds
    }))
}

fn ciba_start_audit_fields(
    state: &CibaRequestState,
    auth_req_id: &str,
    source_ip_hash: Option<String>,
) -> serde_json::Map<String, Value> {
    let mut fields = audit_fields(&[
        ("client_id", json!(state.client_id)),
        ("user_id", json!(state.user_id)),
        ("auth_req_id_hash", json!(blake3_hex(auth_req_id))),
        ("scopes", json!(state.scopes)),
        ("audiences", json!(state.audiences)),
    ]);
    if let Some(source_ip_hash) = source_ip_hash {
        fields.insert("source_ip_hash".to_owned(), json!(source_ip_hash));
    }
    fields
}

async fn parse_backchannel_authentication_form(
    req: &HttpRequest,
    payload: &mut Payload,
) -> Result<BackchannelAuthenticationForm, HttpResponse> {
    if !request_uses_form_urlencoded(req) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA request must use application/x-www-form-urlencoded.",
        ));
    }
    let mut body = Bytes::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA body is invalid.",
            )
        })?;
        if body.len().saturating_add(chunk.len()) > 16 * 1024 {
            return Err(oauth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "CIBA body is too large.",
            ));
        }
        let mut combined = Vec::with_capacity(body.len() + chunk.len());
        combined.extend_from_slice(&body);
        combined.extend_from_slice(&chunk);
        body = Bytes::from(combined);
    }
    let mut form = BackchannelAuthenticationForm::default();
    let mut seen = HashSet::new();
    for (key, value) in url::form_urlencoded::parse(&body) {
        let value = value.into_owned();
        let key = key.into_owned();
        if !seen.insert(key.clone()) {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA parameters must not repeat.",
            ));
        }
        match key.as_str() {
            "request" => form.request = non_empty(value),
            "scope" => form.scope = non_empty(value),
            "login_hint" => form.login_hint = non_empty(value),
            "id_token_hint" => form.id_token_hint = non_empty(value),
            "login_hint_token" => form.login_hint_token = non_empty(value),
            "binding_message" => form.binding_message = non_empty(value),
            "acr_values" => form.acr_values = non_empty(value),
            "requested_expiry" => {
                form.requested_expiry_seconds = parse_requested_expiry_string(&value)
            }
            "client_id" => form.client_id = non_empty(value),
            "client_secret" => form.client_secret = non_empty(value),
            "client_assertion_type" => form.client_assertion_type = non_empty(value),
            "client_assertion" => form.client_assertion = non_empty(value),
            _ => {}
        }
    }
    Ok(form)
}

fn validate_and_apply_ciba_request_object_claims(
    state: &AppState,
    client: &ClientRow,
    form: &mut BackchannelAuthenticationForm,
) -> Result<(), HttpResponse> {
    let Some(request_object) = form.request.as_deref() else {
        return Ok(());
    };
    let claims = signed_ciba_request_object_claims(request_object, client)?;
    let now = Utc::now().timestamp();
    if claims.iss.as_deref() != Some(client.client_id.as_str())
        || !ciba_request_object_audience_valid(&claims, state)
        || !ciba_request_object_times_valid(&claims, now)
        || !ciba_request_object_jti_valid(claims.jti.as_deref())
        || ciba_request_object_hint_count(&claims) != 1
        || claims.login_hint.as_deref().is_none_or(str::is_empty)
    {
        return Err(ciba_invalid_request(
            "CIBA request object claims are invalid.",
        ));
    }
    if let Some(binding_message) = claims.binding_message.as_deref()
        && !ciba_binding_message_is_supported(binding_message)
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_binding_message",
            "CIBA binding_message is unsupported.",
        ));
    }
    merge_request_object_string(
        &mut form.scope,
        claims.scope,
        "CIBA request object scope conflicts with outer parameter.",
    )?;
    merge_request_object_string(
        &mut form.login_hint,
        claims.login_hint,
        "CIBA request object login_hint conflicts with outer parameter.",
    )?;
    merge_request_object_string(
        &mut form.id_token_hint,
        claims.id_token_hint,
        "CIBA request object id_token_hint conflicts with outer parameter.",
    )?;
    merge_request_object_string(
        &mut form.login_hint_token,
        claims.login_hint_token,
        "CIBA request object login_hint_token conflicts with outer parameter.",
    )?;
    merge_request_object_string(
        &mut form.binding_message,
        claims.binding_message,
        "CIBA request object binding_message conflicts with outer parameter.",
    )?;
    merge_request_object_string(
        &mut form.acr_values,
        claims.acr_values,
        "CIBA request object acr_values conflicts with outer parameter.",
    )?;
    if let Some(requested_expiry) = claims.requested_expiry {
        let Some(seconds) = ciba_requested_expiry_seconds(&requested_expiry) else {
            return Err(ciba_invalid_request(
                "CIBA request object requested_expiry is invalid.",
            ));
        };
        if let Some(outer) = form.requested_expiry_seconds
            && outer != seconds
        {
            return Err(ciba_invalid_request(
                "CIBA request object requested_expiry conflicts with outer parameter.",
            ));
        }
        form.requested_expiry_seconds = Some(seconds);
    }
    Ok(())
}

fn signed_ciba_request_object_claims(
    request_object: &str,
    client: &ClientRow,
) -> Result<CibaAuthenticationRequestClaims, HttpResponse> {
    let Some((header_part, _payload_part, signature_part)) = split_compact_jwt(request_object)
    else {
        return Err(ciba_invalid_request(
            "CIBA request object is not a compact JWT.",
        ));
    };
    if signature_part.is_empty() {
        return Err(ciba_invalid_request("CIBA request object must be signed."));
    }
    let header_value = decode_jwt_header_value(header_part)?;
    if header_value.get("alg").and_then(Value::as_str) == Some("none") {
        return Err(ciba_invalid_request("CIBA request object must be signed."));
    }
    let header = jsonwebtoken::decode_header(request_object)
        .map_err(|_| ciba_invalid_request("CIBA request object header is invalid."))?;
    if !ciba_jwt_signing_algorithm_supported(header.alg) {
        return Err(ciba_invalid_request(
            "CIBA request object signing algorithm is unsupported.",
        ));
    }
    let Some(kid) = header.kid.as_deref() else {
        return Err(ciba_invalid_request("CIBA request object is missing kid."));
    };
    let Some(decoding_key) = client_jwt_decoding_key(client, kid, header.alg) else {
        return Err(ciba_invalid_request(
            "CIBA request object signing key is invalid.",
        ));
    };
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_required_spec_claims::<&str>(&[]);
    validation.set_issuer(&[client.client_id.as_str()]);
    jsonwebtoken::decode::<CibaAuthenticationRequestClaims>(
        request_object,
        &decoding_key,
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|_| ciba_invalid_request("CIBA request object signature is invalid."))
}

fn split_compact_jwt(token: &str) -> Option<(&str, &str, &str)> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    parts
        .next()
        .is_none()
        .then_some((header, payload, signature))
}

fn decode_jwt_header_value(header: &str) -> Result<Value, HttpResponse> {
    let bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| ciba_invalid_request("CIBA request object header is invalid."))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ciba_invalid_request("CIBA request object header is invalid."))
}

fn ciba_request_object_audience_valid(
    claims: &CibaAuthenticationRequestClaims,
    state: &AppState,
) -> bool {
    let Some(aud) = claims.aud.as_ref() else {
        return false;
    };
    let issuer = state.settings.issuer.as_str();
    let endpoint = format!("{issuer}/bc-authorize");
    match aud {
        Value::String(value) => value == issuer || value == &endpoint,
        Value::Array(values) => values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| value == issuer || value == endpoint)
        }),
        _ => false,
    }
}

fn ciba_request_object_times_valid(claims: &CibaAuthenticationRequestClaims, now: i64) -> bool {
    let Some(exp) = claims.exp else {
        return false;
    };
    let Some(nbf) = claims.nbf else {
        return false;
    };
    let Some(iat) = claims.iat else {
        return false;
    };
    if exp <= now || nbf > now.saturating_add(CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS) {
        return false;
    }
    if now.saturating_sub(nbf) > CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS {
        return false;
    }
    if exp <= nbf
        || exp.saturating_sub(nbf)
            > CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS
                .saturating_add(CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
    {
        return false;
    }
    if iat > now.saturating_add(CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
        || now.saturating_sub(iat) > CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS
    {
        return false;
    }
    true
}

fn ciba_request_object_jti_valid(jti: Option<&str>) -> bool {
    let Some(jti) = jti else {
        return false;
    };
    let trimmed = jti.trim();
    !trimmed.is_empty() && trimmed.len() <= 128
}

fn ciba_request_object_hint_count(claims: &CibaAuthenticationRequestClaims) -> usize {
    [
        claims.login_hint.as_deref(),
        claims.id_token_hint.as_deref(),
        claims.login_hint_token.as_deref(),
    ]
    .into_iter()
    .filter(|value| value.is_some_and(|value| !value.trim().is_empty()))
    .count()
}

fn ciba_hint_count(form: &BackchannelAuthenticationForm) -> usize {
    [
        form.login_hint.as_deref(),
        form.id_token_hint.as_deref(),
        form.login_hint_token.as_deref(),
    ]
    .into_iter()
    .filter(|value| value.is_some_and(|value| !value.trim().is_empty()))
    .count()
}

fn ciba_selected_acr(acr_values: Option<&str>) -> Option<String> {
    acr_values?
        .split_ascii_whitespace()
        .find(|value| *value == "1")
        .map(ToOwned::to_owned)
}

fn ciba_binding_message_is_supported(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.chars().count() <= CIBA_BINDING_MESSAGE_MAX_CHARS
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii() && !ch.is_ascii_control())
}

fn merge_request_object_string(
    target: &mut Option<String>,
    value: Option<String>,
    conflict_description: &str,
) -> Result<(), HttpResponse> {
    let Some(value) = value.map(|value| value.trim().to_owned()) else {
        return Ok(());
    };
    if value.is_empty() {
        return Err(ciba_invalid_request(
            "CIBA request object parameter is empty.",
        ));
    }
    if let Some(existing) = target.as_deref()
        && existing != value
    {
        return Err(ciba_invalid_request(conflict_description));
    }
    *target = Some(value);
    Ok(())
}

fn ciba_requested_expiry_seconds(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(value) => parse_requested_expiry_string(value),
        _ => None,
    }
    .filter(|seconds| *seconds > 0)
}

fn parse_requested_expiry_string(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
}

fn ciba_invalid_request(description: &str) -> HttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_request", description)
}

fn ciba_client_assertion_algorithm_supported(assertion: Option<&ValidatedClientAssertion>) -> bool {
    assertion.is_none_or(|assertion| ciba_jwt_signing_algorithm_supported(assertion.alg()))
}

fn ciba_jwt_signing_algorithm_supported(alg: jsonwebtoken::Algorithm) -> bool {
    matches!(
        alg,
        jsonwebtoken::Algorithm::EdDSA
            | jsonwebtoken::Algorithm::ES256
            | jsonwebtoken::Algorithm::PS256
    )
}

fn validate_ciba_security_profile_client(
    settings: &Settings,
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    if !settings.ciba_security_profile.requires_fapi2_hardening() {
        return Ok(());
    }
    if client.client_type != "confidential" {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "Fapi2Ciba requires confidential clients.",
            false,
        ));
    }
    if !matches!(
        auth_method,
        "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth"
    ) {
        return Err(oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Fapi2Ciba requires private_key_jwt or mTLS client authentication.",
            false,
        ));
    }
    if !(client.require_dpop_bound_tokens || client.require_mtls_bound_tokens) {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Fapi2Ciba requires sender-constrained access tokens.",
            false,
        ));
    }
    if auth_method == "private_key_jwt"
        && (client.allow_client_assertion_audience_array
            || client.allow_client_assertion_endpoint_audience)
    {
        return Err(oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Fapi2Ciba requires private_key_jwt audience to match the authorization server issuer exactly.",
            false,
        ));
    }
    Ok(())
}

fn validate_ciba_request_object_presence(
    settings: &Settings,
    client: &ClientRow,
    form: &BackchannelAuthenticationForm,
) -> Result<(), HttpResponse> {
    if (client.require_par_request_object
        || settings.ciba_security_profile.requires_fapi2_hardening())
        && form.request.is_none()
    {
        return Err(ciba_invalid_request("CIBA request object is required."));
    }
    Ok(())
}

fn non_empty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.trim().to_owned())
}

pub(crate) async fn ciba_verification_page(
    state: Data<AppState>,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    if !state.settings.enable_ciba {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let location = format!(
        "{}/ciba/{}",
        state.settings.frontend_base_url.trim_end_matches('/'),
        urlencoding::encode(&path.into_inner())
    );
    HttpResponse::Found()
        .insert_header((header::LOCATION, location))
        .insert_header((header::CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .insert_header((header::PRAGMA, HeaderValue::from_static("no-cache")))
        .finish()
}

pub(crate) async fn ciba_verification(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    if !state.settings.enable_ciba {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let auth_req_id = path.into_inner();
    let state_payload = match load_ciba_request_payload(&state, &auth_req_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return oauth_error(
                StatusCode::NOT_FOUND,
                "invalid_request",
                "CIBA request expired.",
            );
        }
        Err(response) => return response,
    };
    if state_payload.user_id != user.id {
        return oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "CIBA request user mismatch.",
        );
    }
    let request = if state_payload.status == CibaStatus::Pending
        && state_payload.expires_at > Utc::now().timestamp()
    {
        match ciba_authorization_request_view(&state, &state_payload).await {
            Ok(value) => value,
            Err(response) => return response,
        }
    } else {
        None
    };
    json_response_no_store(CibaVerificationView {
        auth_req_id,
        csrf_token: cookie_value(&req, &state.settings.csrf_cookie_name),
        request,
    })
}

pub(crate) async fn ciba_automated_decision(
    state: Data<AppState>,
    req: HttpRequest,
    Query(query): Query<CibaAutomatedDecisionQuery>,
) -> HttpResponse {
    if !state.settings.enable_ciba {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let Some(expected_token) = state.settings.ciba_automated_decision_token.as_deref() else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    let Some(actual_token) = query.decision_token.as_deref() else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    if !constant_time_eq(expected_token.as_bytes(), actual_token.as_bytes()) {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let Some(auth_req_id) = query
        .auth_req_id
        .as_deref()
        .or(query.token.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA auth_req_id is required.",
        );
    };
    let decision = match query
        .action
        .as_deref()
        .or(query.r#type.as_deref())
        .map(str::trim)
    {
        Some("allow" | "approve") => CibaDecision::Approve,
        Some("deny") => CibaDecision::Deny,
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA automated decision is invalid.",
            );
        }
    };
    set_ciba_request_decision(
        &state,
        auth_req_id,
        decision,
        None,
        CibaDecisionSource::Automation,
        Some(blake3_hex(&client_ip(&req, &state.settings))),
    )
    .await
}

pub(crate) async fn ciba_decision(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
    Json(payload): Json<CibaDecisionRequest>,
) -> HttpResponse {
    if !state.settings.enable_ciba {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if !has_valid_csrf_token(&state, &req, payload.csrf_token.as_deref()) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let auth_req_id = path.into_inner();
    if !matches!(payload.decision.as_str(), "approve" | "deny") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA decision is invalid.",
        );
    }
    let decision = if payload.decision == "approve" {
        CibaDecision::Approve
    } else {
        CibaDecision::Deny
    };
    set_ciba_request_decision(
        &state,
        &auth_req_id,
        decision,
        Some(user.id),
        CibaDecisionSource::User,
        Some(blake3_hex(&client_ip(&req, &state.settings))),
    )
    .await
}

async fn set_ciba_request_decision(
    state: &AppState,
    auth_req_id: &str,
    decision: CibaDecision,
    expected_user_id: Option<Uuid>,
    source: CibaDecisionSource,
    source_ip_hash: Option<String>,
) -> HttpResponse {
    complete_ciba_decision(
        commit_ciba_decision(&state.valkey, auth_req_id, decision, expected_user_id).await,
        source,
        source_ip_hash,
    )
}

async fn commit_ciba_decision(
    valkey: &fred::prelude::Client,
    auth_req_id: &str,
    decision: CibaDecision,
    expected_user_id: Option<Uuid>,
) -> Result<CommittedCibaDecision, CibaDecisionFailure> {
    for _ in 0..CIBA_TRANSITION_MAX_ATTEMPTS {
        let stored = load_ciba_request_state(valkey, auth_req_id)
            .await
            .map_err(CibaDecisionFailure::Storage)?
            .ok_or(CibaDecisionFailure::Missing)?;
        match evaluate_ciba_decision(
            &stored.state,
            expected_user_id,
            decision,
            Utc::now().timestamp(),
        ) {
            CibaDecisionEvaluation::UserMismatch => {
                return Err(CibaDecisionFailure::UserMismatch);
            }
            CibaDecisionEvaluation::AlreadyHandled => {
                return Err(CibaDecisionFailure::AlreadyHandled);
            }
            CibaDecisionEvaluation::Expired => {
                match delete_ciba_request_state(
                    valkey,
                    auth_req_id,
                    &stored.raw,
                    stored.state.retention_expires_at,
                )
                .await
                .map_err(CibaDecisionFailure::Storage)?
                {
                    ValkeyAtomicResult::Applied | ValkeyAtomicResult::DeadlineElapsed => {
                        return Err(CibaDecisionFailure::Expired);
                    }
                    ValkeyAtomicResult::Conflict => continue,
                }
            }
            CibaDecisionEvaluation::Commit(next) => {
                match replace_ciba_request_state(valkey, auth_req_id, &stored.raw, &next)
                    .await
                    .map_err(CibaDecisionFailure::Storage)?
                {
                    ValkeyAtomicResult::Applied => {
                        return Ok(CommittedCibaDecision {
                            auth_req_id_hash: blake3_hex(auth_req_id),
                            state: next,
                            decision,
                        });
                    }
                    ValkeyAtomicResult::Conflict => continue,
                    ValkeyAtomicResult::DeadlineElapsed => {
                        return Err(CibaDecisionFailure::Expired);
                    }
                }
            }
        }
    }
    Err(CibaDecisionFailure::Contended)
}

fn complete_ciba_decision(
    result: Result<CommittedCibaDecision, CibaDecisionFailure>,
    source: CibaDecisionSource,
    source_ip_hash: Option<String>,
) -> HttpResponse {
    match result {
        Ok(committed) => {
            let event = match committed.decision {
                CibaDecision::Approve => "ciba_authorization_approved",
                CibaDecision::Deny => "ciba_authorization_denied",
            };
            let mut fields = audit_fields(&[
                ("client_id", json!(committed.state.client_id)),
                ("user_id", json!(committed.state.user_id)),
                ("auth_req_id_hash", json!(committed.auth_req_id_hash)),
                ("decision_source", json!(source.as_str())),
            ]);
            if let Some(source_ip_hash) = source_ip_hash {
                fields.insert("source_ip_hash".to_owned(), json!(source_ip_hash));
            }
            audit_event(event, fields);
            json_response_no_store(json!({"success": true}))
        }
        Err(CibaDecisionFailure::Missing | CibaDecisionFailure::Expired) => ciba_error_no_store(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "CIBA request expired.",
        ),
        Err(CibaDecisionFailure::UserMismatch) => ciba_error_no_store(
            StatusCode::FORBIDDEN,
            "access_denied",
            "CIBA request user mismatch.",
        ),
        Err(CibaDecisionFailure::AlreadyHandled) => ciba_error_no_store(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA request was already handled.",
        ),
        Err(CibaDecisionFailure::Storage(error)) => ciba_state_error_response(error),
        Err(CibaDecisionFailure::Contended) => ciba_error_no_store(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA state is busy.",
        ),
    }
}

async fn ciba_authorization_request_view(
    state: &AppState,
    payload: &CibaRequestState,
) -> Result<Option<CibaAuthorizationRequestView>, HttpResponse> {
    let client = match find_client(&state.diesel_db, &payload.client_id).await {
        Ok(Some(client)) if client.is_active => client,
        Ok(_) => return Ok(None),
        Err(error) => {
            tracing::warn!(%error, "failed to load CIBA client for verification page");
            return Err(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA client unavailable.",
            ));
        }
    };
    Ok(Some(CibaAuthorizationRequestView {
        client_id: payload.client_id.clone(),
        client_name: client.client_name,
        scopes: payload.scopes.clone(),
        audiences: payload.audiences.clone(),
        binding_message: payload.binding_message.clone(),
        interval_seconds: payload.interval_seconds,
        issued_at: DateTime::<Utc>::from_timestamp(payload.issued_at, 0).unwrap_or_else(Utc::now),
        expires_at: DateTime::<Utc>::from_timestamp(payload.expires_at, 0).unwrap_or_else(Utc::now),
    }))
}

async fn authorize_ciba_poll<F, Fut>(
    initial: StoredCibaRequest,
    consume_assertion: F,
) -> Result<AuthorizedCibaPoll, HttpResponse>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), HttpResponse>>,
{
    consume_assertion().await?;
    Ok(AuthorizedCibaPoll { initial })
}

async fn commit_ciba_poll(
    valkey: &fred::prelude::Client,
    auth_req_id: &str,
    expected_client_id: &str,
    authorized: AuthorizedCibaPoll,
) -> Result<CibaPollCommit, CibaPollFailure> {
    let mut stored = authorized.initial;
    for _ in 0..CIBA_TRANSITION_MAX_ATTEMPTS {
        if stored.state.client_id != expected_client_id {
            return Err(CibaPollFailure::ClientMismatch);
        }
        let result = match evaluate_ciba_poll(&stored.state, Utc::now().timestamp()) {
            CibaPollTransition::AuthorizationPending(next) => {
                match replace_ciba_request_state(valkey, auth_req_id, &stored.raw, &next)
                    .await
                    .map_err(CibaPollFailure::Storage)?
                {
                    ValkeyAtomicResult::Applied => {
                        return Ok(CibaPollCommit::AuthorizationPending);
                    }
                    result => result,
                }
            }
            CibaPollTransition::SlowDown(next) => {
                match replace_ciba_request_state(valkey, auth_req_id, &stored.raw, &next)
                    .await
                    .map_err(CibaPollFailure::Storage)?
                {
                    ValkeyAtomicResult::Applied => return Ok(CibaPollCommit::SlowDown),
                    result => result,
                }
            }
            CibaPollTransition::Approved => {
                match delete_ciba_request_state(
                    valkey,
                    auth_req_id,
                    &stored.raw,
                    stored.state.retention_expires_at,
                )
                .await
                .map_err(CibaPollFailure::Storage)?
                {
                    ValkeyAtomicResult::Applied => {
                        return Ok(CibaPollCommit::Approved(stored.state));
                    }
                    result => result,
                }
            }
            CibaPollTransition::Denied => {
                match delete_ciba_request_state(
                    valkey,
                    auth_req_id,
                    &stored.raw,
                    stored.state.retention_expires_at,
                )
                .await
                .map_err(CibaPollFailure::Storage)?
                {
                    ValkeyAtomicResult::Applied => return Ok(CibaPollCommit::Denied),
                    result => result,
                }
            }
            CibaPollTransition::Expired => {
                match delete_ciba_request_state(
                    valkey,
                    auth_req_id,
                    &stored.raw,
                    stored.state.retention_expires_at,
                )
                .await
                .map_err(CibaPollFailure::Storage)?
                {
                    ValkeyAtomicResult::Applied => return Ok(CibaPollCommit::Expired),
                    result => result,
                }
            }
        };
        match result {
            ValkeyAtomicResult::Conflict => {
                stored = load_ciba_request_state(valkey, auth_req_id)
                    .await
                    .map_err(CibaPollFailure::Storage)?
                    .ok_or(CibaPollFailure::Missing)?;
            }
            ValkeyAtomicResult::DeadlineElapsed => return Ok(CibaPollCommit::Expired),
            ValkeyAtomicResult::Applied => unreachable!("applied transitions return immediately"),
        }
    }
    Err(CibaPollFailure::Contended)
}

fn ciba_poll_failure_response(failure: CibaPollFailure) -> HttpResponse {
    match failure {
        CibaPollFailure::Missing => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA auth_req_id is expired or consumed.",
            false,
        ),
        CibaPollFailure::ClientMismatch => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA auth_req_id was not issued to this client.",
            false,
        ),
        CibaPollFailure::Storage(error) => {
            tracing::warn!(%error, "CIBA poll state operation failed");
            oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA state unavailable.",
                false,
            )
        }
        CibaPollFailure::Contended => oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA state is busy.",
            false,
        ),
    }
}

pub(crate) async fn token_ciba(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
    auth_method: &str,
) -> HttpResponse {
    if !state.settings.enable_ciba {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "CIBA is not enabled.",
            false,
        );
    }
    let Some(auth_req_id) = form.auth_req_id.as_deref() else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA token request requires auth_req_id.",
            false,
        );
    };
    if !ciba_client_assertion_algorithm_supported(client_assertion) {
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "CIBA private_key_jwt signing algorithm is unsupported.",
            false,
        );
    }
    if let Err(response) =
        validate_ciba_security_profile_client(&state.settings, client, auth_method)
    {
        return response;
    }
    let (dpop_jkt, mtls_x5t_s256) = match ciba_issue_binding(state, req, client).await {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    let initial = match load_ciba_request_state(&state.valkey, auth_req_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "CIBA auth_req_id is expired.",
                false,
            );
        }
        Err(error) => return ciba_poll_failure_response(CibaPollFailure::Storage(error)),
    };
    if let Some(response) = ciba_auth_req_id_client_error(&initial.state, client) {
        return response;
    }
    let authorized = match authorize_ciba_poll(initial, || async {
        consume_token_client_assertion(state, client, client_assertion).await
    })
    .await
    {
        Ok(authorized) => authorized,
        Err(response) => return response,
    };
    let ciba =
        match commit_ciba_poll(&state.valkey, auth_req_id, &client.client_id, authorized).await {
            Ok(CibaPollCommit::AuthorizationPending) => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "authorization_pending",
                    "CIBA authorization is pending.",
                    false,
                );
            }
            Ok(CibaPollCommit::SlowDown) => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "slow_down",
                    "CIBA polling too fast.",
                    false,
                );
            }
            Ok(CibaPollCommit::Denied) => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "access_denied",
                    "CIBA authorization was denied.",
                    false,
                );
            }
            Ok(CibaPollCommit::Expired) => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "expired_token",
                    "CIBA auth_req_id is expired.",
                    false,
                );
            }
            Ok(CibaPollCommit::Approved(ciba)) => ciba,
            Err(failure) => return ciba_poll_failure_response(failure),
        };
    let user = match find_user_by_id(&state.diesel_db, ciba.user_id).await {
        Ok(Some(user)) if user.is_active => user,
        Ok(_) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "CIBA user is unavailable.",
                false,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load CIBA user");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
                false,
            );
        }
    };
    let subject = match ciba_subject_for_client(&state.settings, ciba.user_id, client) {
        Ok(subject) => subject,
        Err(error) => {
            tracing::warn!(%error, "failed to compute CIBA subject");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
                false,
            );
        }
    };
    let issue = ciba_token_issue(user.id, subject, ciba, dpop_jkt, mtls_x5t_s256);
    issue_token_response(state, client, issue).await
}

fn ciba_auth_req_id_client_error(
    ciba: &CibaRequestState,
    client: &ClientRow,
) -> Option<HttpResponse> {
    (ciba.client_id != client.client_id).then(|| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA auth_req_id was not issued to this client.",
            false,
        )
    })
}

fn ciba_token_issue(
    user_id: Uuid,
    subject: String,
    ciba: CibaRequestState,
    dpop_jkt: Option<String>,
    mtls_x5t_s256: Option<String>,
) -> TokenIssue {
    TokenIssue {
        user_id: Some(user_id),
        subject,
        scopes: ciba.scopes,
        authorization_details: json!([]),
        audiences: ciba.audiences,
        nonce: None,
        auth_time: Some(Utc::now().timestamp()),
        amr: vec!["ciba".to_owned()],
        oidc_sid: None,
        acr: ciba.acr,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        id_token_user: None,
        include_refresh: true,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: dpop_jkt.clone(),
        refresh_token_dpop_jkt: dpop_jkt,
        mtls_x5t_s256: mtls_x5t_s256.clone(),
        refresh_token_mtls_x5t_s256: mtls_x5t_s256,
        authorization_code_hash: None,
        actor: None,
        issued_token_type: None,
        native_sso: None,
    }
}

async fn ciba_issue_binding(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
) -> Result<(Option<String>, Option<String>), HttpResponse> {
    if client.require_dpop_bound_tokens {
        let dpop_jkt = validate_dpop_proof(state, req, None, None)
            .await
            .map_err(|error| dpop_error_response(error, DpopErrorContext::TokenEndpoint))?;
        if dpop_jkt.is_none() {
            return Err(dpop_error_response(
                DpopError::MissingProof,
                DpopErrorContext::TokenEndpoint,
            ));
        }
        return Ok((dpop_jkt, None));
    }
    if client.require_mtls_bound_tokens {
        let Some(x5t_s256) = request_mtls_thumbprint(req, &state.settings) else {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "CIBA requires mTLS sender constraint.",
                false,
            ));
        };
        return Ok((None, Some(x5t_s256)));
    }
    Ok((None, None))
}

fn ciba_subject_for_client(
    settings: &Settings,
    user_id: Uuid,
    client: &ClientRow,
) -> anyhow::Result<String> {
    let redirect_uri = json_array_to_strings(&client.redirect_uris)
        .into_iter()
        .next()
        .unwrap_or_default();
    compute_subject_for_client(
        settings,
        user_id,
        &client.subject_type,
        client.sector_identifier_host.as_deref(),
        &redirect_uri,
    )
}

async fn load_ciba_request_payload(
    state: &AppState,
    auth_req_id: &str,
) -> Result<Option<CibaRequestState>, HttpResponse> {
    load_ciba_request_state(&state.valkey, auth_req_id)
        .await
        .map(|stored| stored.map(|stored| stored.state))
        .map_err(ciba_state_error_response)
}

fn ciba_state_error_response(error: CibaStateError) -> HttpResponse {
    tracing::warn!(%error, "failed to load CIBA state");
    ciba_error_no_store(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "CIBA state unavailable.",
    )
}

fn ciba_error_no_store(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    let mut response = oauth_error(status, error, description);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/ciba.rs"]
mod tests;

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/ciba_state.rs"]
mod state_tests;
