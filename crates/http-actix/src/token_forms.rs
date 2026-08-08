//! Token endpoint and token-management wire-form parsing.
// 表单结构在多个 token 子模块之间共享。
use crate::oauth_token_error;
use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::Bytes,
};
use nazo_auth::parse_resource_indicators;
use std::collections::HashSet;

pub struct TokenForm {
    pub grant_type: String,
    pub code: Option<String>,
    pub device_code: Option<String>,
    pub auth_req_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub device_secret: Option<String>,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
    pub assertion: Option<String>,
    pub requested_token_type: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub audiences: Vec<String>,
    pub has_audience_param: bool,
}

pub struct TokenOnlyForm {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

pub struct PreAuthorizedTokenParameters {
    pub pre_authorized_code: Option<String>,
    pub tx_code: Option<String>,
    pub invalid: bool,
}

pub struct ParsedTokenForm {
    pub form: TokenForm,
    pub pre_authorized: PreAuthorizedTokenParameters,
}

#[derive(Debug)]
pub enum TokenFormError {
    InvalidContentType,
    InvalidEncoding,
    DuplicateParameter,
    InvalidResourceParameter,
    MissingGrantType,
}

#[derive(Debug)]
pub enum TokenManagementFormError {
    InvalidContentType,
    InvalidEncoding,
    DuplicateParameter,
    MissingToken,
}

pub fn token_management_oauth_error(
    status: StatusCode,
    error: &str,
    description: &str,
) -> HttpResponse {
    oauth_token_error(status, error, description, false)
}

pub fn token_management_has_conflicting_client_auth(has_basic: bool, form: &TokenOnlyForm) -> bool {
    let has_assertion = form.client_assertion_type.is_some() || form.client_assertion.is_some();
    has_basic && (form.client_id.is_some() || form.client_secret.is_some() || has_assertion)
        || has_assertion && form.client_secret.is_some()
}

pub fn token_management_form_error(error: TokenManagementFormError) -> HttpResponse {
    match error {
        TokenManagementFormError::InvalidContentType => token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token management 请求必须使用 application/x-www-form-urlencoded.",
        ),
        TokenManagementFormError::InvalidEncoding => token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token management 请求体必须使用 UTF-8 编码.",
        ),
        TokenManagementFormError::DuplicateParameter => token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "OAuth 参数不能重复.",
        ),
        TokenManagementFormError::MissingToken => {
            token_management_oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "缺少 token.")
        }
    }
}

pub fn parse_token_form(req: &HttpRequest, body: &Bytes) -> Result<TokenForm, TokenFormError> {
    parse_token_form_with_pre_authorized(req, body).map(|parsed| parsed.form)
}

pub fn parse_token_form_with_pre_authorized(
    req: &HttpRequest,
    body: &Bytes,
) -> Result<ParsedTokenForm, TokenFormError> {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(TokenFormError::InvalidContentType);
    }

    let raw = std::str::from_utf8(body).map_err(|_| TokenFormError::InvalidEncoding)?;
    let mut seen = HashSet::new();
    let mut form = TokenForm {
        grant_type: String::new(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        audiences: Vec::new(),
        has_audience_param: false,
    };
    let mut pre_authorized = PreAuthorizedTokenParameters {
        pre_authorized_code: None,
        tx_code: None,
        invalid: false,
    };

    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        match key.as_ref() {
            "resource" => {
                let resource = parse_resource_indicators(&[value.into_owned()])
                    .map_err(|_| TokenFormError::InvalidResourceParameter)?
                    .into_iter()
                    .next()
                    .expect("single resource parameter must produce one resource");
                if seen.contains("audience") {
                    return Err(TokenFormError::DuplicateParameter);
                }
                seen.insert("resource");
                if form.audiences.iter().any(|existing| existing == &resource) {
                    return Err(TokenFormError::DuplicateParameter);
                }
                form.audiences.push(resource);
            }
            "grant_type" => {
                accept_token_parameter_once(&mut seen, "grant_type")?;
                form.grant_type = value.into_owned();
            }
            "code" => {
                accept_token_parameter_once(&mut seen, "code")?;
                form.code = non_empty(value.into_owned());
            }
            "device_code" => {
                accept_token_parameter_once(&mut seen, "device_code")?;
                form.device_code = non_empty(value.into_owned());
            }
            "auth_req_id" => {
                accept_token_parameter_once(&mut seen, "auth_req_id")?;
                form.auth_req_id = non_empty(value.into_owned());
            }
            "redirect_uri" => {
                accept_token_parameter_once(&mut seen, "redirect_uri")?;
                form.redirect_uri = non_empty(value.into_owned());
            }
            "code_verifier" => {
                accept_token_parameter_once(&mut seen, "code_verifier")?;
                form.code_verifier = non_empty(value.into_owned());
            }
            "refresh_token" => {
                accept_token_parameter_once(&mut seen, "refresh_token")?;
                form.refresh_token = non_empty(value.into_owned());
            }
            "device_secret" => {
                accept_token_parameter_once(&mut seen, "device_secret")?;
                form.device_secret = non_empty(value.into_owned());
            }
            "scope" => {
                accept_token_parameter_once(&mut seen, "scope")?;
                form.scope = non_empty(value.into_owned());
            }
            "client_id" => {
                accept_token_parameter_once(&mut seen, "client_id")?;
                form.client_id = non_empty(value.into_owned());
            }
            "client_secret" => {
                accept_token_parameter_once(&mut seen, "client_secret")?;
                form.client_secret = non_empty(value.into_owned());
            }
            "client_assertion_type" => {
                accept_token_parameter_once(&mut seen, "client_assertion_type")?;
                form.client_assertion_type = non_empty(value.into_owned());
            }
            "client_assertion" => {
                accept_token_parameter_once(&mut seen, "client_assertion")?;
                form.client_assertion = non_empty(value.into_owned());
            }
            "assertion" => {
                accept_token_parameter_once(&mut seen, "assertion")?;
                form.assertion = non_empty(value.into_owned());
            }
            "requested_token_type" => {
                accept_token_parameter_once(&mut seen, "requested_token_type")?;
                form.requested_token_type = non_empty(value.into_owned());
            }
            "subject_token" => {
                accept_token_parameter_once(&mut seen, "subject_token")?;
                form.subject_token = non_empty(value.into_owned());
            }
            "subject_token_type" => {
                accept_token_parameter_once(&mut seen, "subject_token_type")?;
                form.subject_token_type = non_empty(value.into_owned());
            }
            "actor_token" => {
                accept_token_parameter_once(&mut seen, "actor_token")?;
                form.actor_token = non_empty(value.into_owned());
            }
            "actor_token_type" => {
                accept_token_parameter_once(&mut seen, "actor_token_type")?;
                form.actor_token_type = non_empty(value.into_owned());
            }
            "audience" => {
                accept_token_parameter_once(&mut seen, "audience")?;
                if !form.audiences.is_empty() {
                    return Err(TokenFormError::DuplicateParameter);
                }
                if let Some(value) = non_empty(value.into_owned()) {
                    form.audiences.push(value);
                }
                form.has_audience_param = true;
            }
            "pre-authorized_code" => {
                if pre_authorized.pre_authorized_code.is_some() || value.is_empty() {
                    pre_authorized.invalid = true;
                } else {
                    pre_authorized.pre_authorized_code = Some(value.into_owned());
                }
            }
            "tx_code" => {
                if pre_authorized.tx_code.is_some() || value.is_empty() {
                    pre_authorized.invalid = true;
                } else {
                    pre_authorized.tx_code = Some(value.into_owned());
                }
            }
            _ => continue,
        }
    }

    if form.grant_type.trim().is_empty() {
        return Err(TokenFormError::MissingGrantType);
    }
    Ok(ParsedTokenForm {
        form,
        pre_authorized,
    })
}

pub fn parse_token_management_form(
    req: &HttpRequest,
    body: &Bytes,
) -> Result<TokenOnlyForm, TokenManagementFormError> {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(TokenManagementFormError::InvalidContentType);
    }

    let raw = std::str::from_utf8(body).map_err(|_| TokenManagementFormError::InvalidEncoding)?;
    let mut seen = HashSet::new();
    let mut form = TokenOnlyForm {
        token: String::new(),
        token_type_hint: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
    };

    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        match key.as_ref() {
            "token" => {
                accept_token_management_parameter_once(&mut seen, "token")?;
                form.token = value.into_owned();
            }
            "token_type_hint" => {
                accept_token_management_parameter_once(&mut seen, "token_type_hint")?;
                form.token_type_hint = non_empty(value.into_owned());
            }
            "client_id" => {
                accept_token_management_parameter_once(&mut seen, "client_id")?;
                form.client_id = non_empty(value.into_owned());
            }
            "client_secret" => {
                accept_token_management_parameter_once(&mut seen, "client_secret")?;
                form.client_secret = non_empty(value.into_owned());
            }
            "client_assertion_type" => {
                accept_token_management_parameter_once(&mut seen, "client_assertion_type")?;
                form.client_assertion_type = non_empty(value.into_owned());
            }
            "client_assertion" => {
                accept_token_management_parameter_once(&mut seen, "client_assertion")?;
                form.client_assertion = non_empty(value.into_owned());
            }
            _ => continue,
        }
    }

    if form.token.trim().is_empty() {
        return Err(TokenManagementFormError::MissingToken);
    }
    Ok(form)
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn accept_token_parameter_once(
    seen: &mut HashSet<&'static str>,
    key: &'static str,
) -> Result<(), TokenFormError> {
    if seen.insert(key) {
        Ok(())
    } else {
        Err(TokenFormError::DuplicateParameter)
    }
}

fn accept_token_management_parameter_once(
    seen: &mut HashSet<&'static str>,
    key: &'static str,
) -> Result<(), TokenManagementFormError> {
    if seen.insert(key) {
        Ok(())
    } else {
        Err(TokenManagementFormError::DuplicateParameter)
    }
}
