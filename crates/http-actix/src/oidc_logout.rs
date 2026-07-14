use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{Method, StatusCode, header},
    web::{Bytes, Data, Payload},
};
use futures_util::StreamExt as _;
use serde_json::json;

use crate::{
    clear_cookie, cookie_value, has_valid_csrf_token_for_cookies, json_response_no_store,
    oauth_error, redirect_found, request_uses_form_urlencoded, with_cookie_headers,
};

const LOGOUT_FORM_MAX_BYTES: usize = 16 * 1024;

pub type OidcLogoutFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OidcLogoutSuccess, OidcLogoutError>> + Send + 'a>>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OidcLogoutRequest {
    pub id_token_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcLogoutCommand {
    pub request: OidcLogoutRequest,
    pub session_id: Option<String>,
    pub csrf_authorized: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcLogoutSuccess {
    pub redirect_uri: Option<String>,
    pub frontchannel_logout_urls: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcLogoutError {
    SessionLookupUnavailable,
    InvalidIdTokenHint,
    ClientAudienceMismatch,
    AmbiguousAudience,
    ClientRequiredForRedirect,
    ClientNotFound,
    ClientLookupUnavailable,
    RegisteredClientRequired,
    UnregisteredRedirect,
    InvalidRedirect,
    UnauthorizedSession,
    SigningUnavailable,
    OutboxUnavailable,
    SessionDeleteUnavailable,
}

pub trait OidcLogoutOperations: Send + Sync {
    fn logout(&self, command: OidcLogoutCommand) -> OidcLogoutFuture<'_>;
}

#[derive(Clone)]
pub struct OidcLogoutConfig {
    session_cookie_name: Box<str>,
    csrf_cookie_name: Box<str>,
    cookie_secure: bool,
}

impl OidcLogoutConfig {
    #[must_use]
    pub fn new(
        session_cookie_name: impl Into<Box<str>>,
        csrf_cookie_name: impl Into<Box<str>>,
        cookie_secure: bool,
    ) -> Self {
        Self {
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            cookie_secure,
        }
    }
}

#[derive(Clone)]
pub struct OidcLogoutEndpoint {
    operations: Arc<dyn OidcLogoutOperations>,
    config: OidcLogoutConfig,
}

impl OidcLogoutEndpoint {
    #[must_use]
    pub fn new(operations: Arc<dyn OidcLogoutOperations>, config: OidcLogoutConfig) -> Self {
        Self { operations, config }
    }
}

pub async fn oidc_logout(
    endpoint: Data<OidcLogoutEndpoint>,
    request: HttpRequest,
    mut payload: Payload,
) -> HttpResponse {
    let logout_request = match parse_logout_request(&request, &mut payload).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let command = OidcLogoutCommand {
        request: logout_request,
        session_id: cookie_value(&request, &endpoint.config.session_cookie_name),
        csrf_authorized: has_valid_csrf_token_for_cookies(
            &request,
            None,
            &endpoint.config.session_cookie_name,
            &endpoint.config.csrf_cookie_name,
        ),
    };
    match endpoint.operations.logout(command).await {
        Ok(success) => success_response(&endpoint, success),
        Err(error) => error_response(error),
    }
}

async fn parse_logout_request(
    request: &HttpRequest,
    payload: &mut Payload,
) -> Result<OidcLogoutRequest, HttpResponse> {
    let mut parsed = parse_logout_pairs(request.query_string())?;
    if request.method() != Method::POST {
        return Ok(parsed);
    }
    if !request_uses_form_urlencoded(request) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "logout POST must use application/x-www-form-urlencoded.",
        ));
    }
    let mut body = Bytes::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "logout request body is invalid.",
            )
        })?;
        if body.len().saturating_add(chunk.len()) > LOGOUT_FORM_MAX_BYTES {
            return Err(oauth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "logout request body is too large.",
            ));
        }
        let mut combined = Vec::with_capacity(body.len() + chunk.len());
        combined.extend_from_slice(&body);
        combined.extend_from_slice(&chunk);
        body = Bytes::from(combined);
    }
    merge_logout_pairs(&mut parsed, &body)?;
    Ok(parsed)
}

fn parse_logout_pairs(raw: &str) -> Result<OidcLogoutRequest, HttpResponse> {
    let mut parsed = OidcLogoutRequest::default();
    merge_logout_pairs(&mut parsed, raw.as_bytes())?;
    Ok(parsed)
}

fn merge_logout_pairs(parsed: &mut OidcLogoutRequest, raw: &[u8]) -> Result<(), HttpResponse> {
    for (key, value) in url::form_urlencoded::parse(raw) {
        let value = value.trim();
        match key.as_ref() {
            "id_token_hint" => set_once(&mut parsed.id_token_hint, value)?,
            "client_id" => set_once(&mut parsed.client_id, value)?,
            "post_logout_redirect_uri" => {
                set_once(&mut parsed.post_logout_redirect_uri, value)?;
            }
            "state" => set_once(&mut parsed.state, value)?,
            _ => {}
        }
    }
    Ok(())
}

fn set_once(field: &mut Option<String>, value: &str) -> Result<(), HttpResponse> {
    if field.is_some() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "duplicate logout parameter.",
        ));
    }
    field.replace(value.to_owned());
    Ok(())
}

fn success_response(endpoint: &OidcLogoutEndpoint, success: OidcLogoutSuccess) -> HttpResponse {
    let response = if success.frontchannel_logout_urls.is_empty() {
        match success.redirect_uri {
            Some(location) => redirect_found(location),
            None => json_response_no_store(json!({"success": true})),
        }
    } else {
        HttpResponse::Ok()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .insert_header((header::PRAGMA, "no-cache"))
            .content_type("text/html; charset=utf-8")
            .body(frontchannel_logout_document(
                &success.frontchannel_logout_urls,
                success.redirect_uri.as_deref(),
            ))
    };
    with_cookie_headers(
        response,
        &[
            clear_cookie(
                &endpoint.config.session_cookie_name,
                endpoint.config.cookie_secure,
            ),
            clear_cookie(
                &endpoint.config.csrf_cookie_name,
                endpoint.config.cookie_secure,
            ),
        ],
    )
}

fn error_response(error: OidcLogoutError) -> HttpResponse {
    let session_delete_failed = error == OidcLogoutError::SessionDeleteUnavailable;
    let (status, code, description) = match error {
        OidcLogoutError::SessionLookupUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "logout session lookup failed.",
        ),
        OidcLogoutError::InvalidIdTokenHint => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "id_token_hint is invalid.",
        ),
        OidcLogoutError::ClientAudienceMismatch => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id does not match id_token_hint audience.",
        ),
        OidcLogoutError::AmbiguousAudience => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required when id_token_hint has multiple audiences.",
        ),
        OidcLogoutError::ClientRequiredForRedirect => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id or id_token_hint is required with post_logout_redirect_uri.",
        ),
        OidcLogoutError::ClientNotFound => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "logout client is not registered or active.",
        ),
        OidcLogoutError::ClientLookupUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "logout client lookup failed.",
        ),
        OidcLogoutError::RegisteredClientRequired => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "post_logout_redirect_uri requires a registered client.",
        ),
        OidcLogoutError::UnregisteredRedirect => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "post_logout_redirect_uri is not registered.",
        ),
        OidcLogoutError::InvalidRedirect => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "post_logout_redirect_uri is invalid.",
        ),
        OidcLogoutError::UnauthorizedSession => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "logout request is not authorized for the current OP session.",
        ),
        OidcLogoutError::SigningUnavailable
        | OidcLogoutError::OutboxUnavailable
        | OidcLogoutError::SessionDeleteUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "back-channel logout persistence failed.",
        ),
    };
    let mut response = oauth_error(status, code, description);
    if session_delete_failed {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        response
            .headers_mut()
            .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    }
    response
}

fn frontchannel_logout_document(frontchannel_urls: &[String], redirect: Option<&str>) -> String {
    let iframe_count = frontchannel_urls.len();
    let iframe_onload = if redirect.is_some() {
        " onload=\"nazoFrontchannelLogoutFrameDone()\""
    } else {
        ""
    };
    let iframes = frontchannel_urls
        .iter()
        .map(|url| {
            format!(
                "<iframe title=\"OIDC Front-Channel Logout\" src=\"{}\"{}></iframe>",
                escape_html_attribute(url),
                iframe_onload
            )
        })
        .collect::<String>();
    let redirect_script = redirect.map_or_else(String::new, |location| {
        format!(
            concat!(
                "<script>",
                "(function(){{",
                "var remaining={iframe_count};",
                "var redirected=false;",
                "function finish(){{",
                "if(redirected){{return;}}",
                "redirected=true;",
                "window.location.replace('{location}');",
                "}}",
                "window.nazoFrontchannelLogoutFrameDone=function(){{",
                "remaining-=1;",
                "if(remaining<=0){{setTimeout(finish,50);}}",
                "}};",
                "setTimeout(finish,2500);",
                "}})();",
                "</script>"
            ),
            iframe_count = iframe_count,
            location = escape_js_string(location)
        )
    });
    format!(
        concat!(
            "<!doctype html><html><head><meta charset=\"utf-8\">",
            "<meta http-equiv=\"cache-control\" content=\"no-store\">",
            "<style>iframe{{display:none;width:0;height:0;border:0}}</style>",
            "</head><body>{redirect_script}{iframes}</body></html>"
        ),
        iframes = iframes,
        redirect_script = redirect_script
    )
}

fn escape_html_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_js_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}
