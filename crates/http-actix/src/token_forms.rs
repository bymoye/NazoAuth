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
    let mut resource_values = HashSet::new();
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

    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let key = key.into_owned();
        let value = value.into_owned();
        match key.as_str() {
            "resource" => {
                let resource = parse_resource_indicators(&[value])
                    .map_err(|_| TokenFormError::InvalidResourceParameter)?
                    .into_iter()
                    .next()
                    .expect("single resource parameter must produce one resource");
                if seen.contains("audience") {
                    return Err(TokenFormError::DuplicateParameter);
                }
                seen.insert(key);
                if !resource_values.insert(resource.clone()) {
                    return Err(TokenFormError::DuplicateParameter);
                }
                form.audiences.push(resource);
            }
            "grant_type" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.grant_type = value;
            }
            "code" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.code = non_empty(value);
            }
            "device_code" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.device_code = non_empty(value);
            }
            "auth_req_id" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.auth_req_id = non_empty(value);
            }
            "redirect_uri" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.redirect_uri = non_empty(value);
            }
            "code_verifier" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.code_verifier = non_empty(value);
            }
            "refresh_token" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.refresh_token = non_empty(value);
            }
            "device_secret" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.device_secret = non_empty(value);
            }
            "scope" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.scope = non_empty(value);
            }
            "client_id" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.client_id = non_empty(value);
            }
            "client_secret" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.client_secret = non_empty(value);
            }
            "client_assertion_type" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.client_assertion_type = non_empty(value);
            }
            "client_assertion" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.client_assertion = non_empty(value);
            }
            "assertion" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.assertion = non_empty(value);
            }
            "requested_token_type" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.requested_token_type = non_empty(value);
            }
            "subject_token" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.subject_token = non_empty(value);
            }
            "subject_token_type" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.subject_token_type = non_empty(value);
            }
            "actor_token" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.actor_token = non_empty(value);
            }
            "actor_token_type" => {
                accept_token_parameter_once(&mut seen, key)?;
                form.actor_token_type = non_empty(value);
            }
            "audience" => {
                accept_token_parameter_once(&mut seen, key)?;
                if !form.audiences.is_empty() {
                    return Err(TokenFormError::DuplicateParameter);
                }
                if let Some(value) = non_empty(value) {
                    form.audiences.push(value);
                }
                form.has_audience_param = true;
            }
            _ => continue,
        }
    }

    if form.grant_type.trim().is_empty() {
        return Err(TokenFormError::MissingGrantType);
    }
    Ok(form)
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
        let key = key.into_owned();
        let value = value.into_owned();
        match key.as_str() {
            "token" => {
                accept_token_management_parameter_once(&mut seen, key)?;
                form.token = value;
            }
            "token_type_hint" => {
                accept_token_management_parameter_once(&mut seen, key)?;
                form.token_type_hint = non_empty(value);
            }
            "client_id" => {
                accept_token_management_parameter_once(&mut seen, key)?;
                form.client_id = non_empty(value);
            }
            "client_secret" => {
                accept_token_management_parameter_once(&mut seen, key)?;
                form.client_secret = non_empty(value);
            }
            "client_assertion_type" => {
                accept_token_management_parameter_once(&mut seen, key)?;
                form.client_assertion_type = non_empty(value);
            }
            "client_assertion" => {
                accept_token_management_parameter_once(&mut seen, key)?;
                form.client_assertion = non_empty(value);
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
    seen: &mut HashSet<String>,
    key: String,
) -> Result<(), TokenFormError> {
    if seen.insert(key) {
        Ok(())
    } else {
        Err(TokenFormError::DuplicateParameter)
    }
}

fn accept_token_management_parameter_once(
    seen: &mut HashSet<String>,
    key: String,
) -> Result<(), TokenManagementFormError> {
    if seen.insert(key) {
        Ok(())
    } else {
        Err(TokenManagementFormError::DuplicateParameter)
    }
}
