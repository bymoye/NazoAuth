use std::{future::Future, pin::Pin, sync::Arc};

use crate::{
    clear_cookie, cookie_value, csrf_error, has_valid_csrf_token_for_cookies, oauth_error,
    redirect_found, request_uses_form_urlencoded, with_cookie_headers,
};
use actix_web::{
    HttpRequest, HttpResponse,
    http::{Method, StatusCode, header},
    web::{Data, Payload},
};
use futures_util::StreamExt as _;

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
    pub user_confirmed: bool,
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
    ConfirmationRequired,
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
    let parsed = match parse_logout_request(&request, &mut payload).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let session_id = cookie_value(&request, &endpoint.config.session_cookie_name);
    let csrf_cookie = cookie_value(&request, &endpoint.config.csrf_cookie_name);
    let csrf_authorized = has_valid_csrf_token_for_cookies(
        &request,
        parsed
            .user_confirmed
            .then_some(parsed.csrf_token.as_deref())
            .flatten(),
        &endpoint.config.session_cookie_name,
        &endpoint.config.csrf_cookie_name,
    );
    if parsed.user_confirmed && !csrf_authorized {
        return csrf_error();
    }
    let user_confirmed = parsed.user_confirmed;
    let logout_request = (!user_confirmed).then(|| parsed.request.clone());
    let command = OidcLogoutCommand {
        request: parsed.request,
        session_id,
        csrf_authorized,
        user_confirmed,
    };
    match endpoint.operations.logout(command).await {
        Ok(success) => success_response(&endpoint, success),
        Err(error) => error_response(error, csrf_cookie.as_deref(), logout_request.as_ref()),
    }
}

#[derive(Default)]
struct ParsedOidcLogoutRequest {
    request: OidcLogoutRequest,
    csrf_token: Option<String>,
    user_confirmed: bool,
}

async fn parse_logout_request(
    request: &HttpRequest,
    payload: &mut Payload,
) -> Result<ParsedOidcLogoutRequest, HttpResponse> {
    let mut parsed = parse_logout_pairs(request.query_string())?;
    if request.method() != Method::POST {
        if parsed.user_confirmed || parsed.csrf_token.is_some() {
            return Err(invalid_logout_request(
                "logout confirmation must use HTTP POST.",
            ));
        }
        return Ok(parsed);
    }
    if !request_uses_form_urlencoded(request) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "logout POST must use application/x-www-form-urlencoded.",
        ));
    }
    let mut body = Vec::with_capacity(LOGOUT_FORM_MAX_BYTES);
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
        body.extend_from_slice(&chunk);
    }
    merge_logout_pairs(&mut parsed, &body)?;
    Ok(parsed)
}

fn parse_logout_pairs(raw: &str) -> Result<ParsedOidcLogoutRequest, HttpResponse> {
    let mut parsed = ParsedOidcLogoutRequest::default();
    merge_logout_pairs(&mut parsed, raw.as_bytes())?;
    Ok(parsed)
}

fn merge_logout_pairs(
    parsed: &mut ParsedOidcLogoutRequest,
    raw: &[u8],
) -> Result<(), HttpResponse> {
    for (key, value) in url::form_urlencoded::parse(raw) {
        match key.as_ref() {
            "id_token_hint" => set_once(&mut parsed.request.id_token_hint, &value)?,
            "client_id" => set_once(&mut parsed.request.client_id, &value)?,
            "post_logout_redirect_uri" => {
                set_once(&mut parsed.request.post_logout_redirect_uri, &value)?;
            }
            "state" => set_once(&mut parsed.request.state, &value)?,
            "_nazo_csrf" => set_once(&mut parsed.csrf_token, &value)?,
            "_nazo_logout_confirm" => {
                if parsed.user_confirmed || value != "true" {
                    return Err(invalid_logout_request("invalid logout confirmation."));
                }
                parsed.user_confirmed = true;
            }
            _ => {}
        }
    }
    Ok(())
}

fn invalid_logout_request(description: &'static str) -> HttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_request", description)
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
            None => logout_success_response(),
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

fn error_response(
    error: OidcLogoutError,
    csrf_token: Option<&str>,
    request: Option<&OidcLogoutRequest>,
) -> HttpResponse {
    if error.is_user_confirmable()
        && let Some(request) = request
        && let Some(csrf_token) = csrf_token
    {
        let preserved_request = (error == OidcLogoutError::ConfirmationRequired).then_some(request);
        return logout_confirmation_response(csrf_token, preserved_request);
    }
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
        OidcLogoutError::ConfirmationRequired => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "logout requires End-User confirmation.",
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

impl OidcLogoutError {
    const fn is_user_confirmable(self) -> bool {
        matches!(
            self,
            Self::InvalidIdTokenHint
                | Self::ClientAudienceMismatch
                | Self::AmbiguousAudience
                | Self::ClientRequiredForRedirect
                | Self::ClientNotFound
                | Self::RegisteredClientRequired
                | Self::UnregisteredRedirect
                | Self::InvalidRedirect
                | Self::ConfirmationRequired
        )
    }
}

fn logout_confirmation_response(
    csrf_token: &str,
    request: Option<&OidcLogoutRequest>,
) -> HttpResponse {
    let preserved_fields = request.map_or_else(String::new, logout_request_hidden_fields);
    HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::PRAGMA, "no-cache"))
        .content_type("text/html; charset=utf-8")
        .body(format!(
            concat!(
                "<!doctype html><html><head><meta charset=\"utf-8\">",
                "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
                "<meta http-equiv=\"cache-control\" content=\"no-store\">",
                "<title>Confirm sign out</title></head><body>",
                "<main id=\"nazo-logout-confirmation\"><h1>Sign out?</h1>",
                "<p>The requesting application could not be bound to this session. ",
                "Confirm to sign out of the OpenID Provider without using its redirect data.</p>",
                "<form method=\"post\" action=\"/logout\">",
                "<input type=\"hidden\" name=\"_nazo_logout_confirm\" value=\"true\">",
                "<input type=\"hidden\" name=\"_nazo_csrf\" value=\"{}\">{}",
                "<button id=\"nazo-logout-confirm\" type=\"submit\">Sign out</button>",
                "<a id=\"nazo-logout-cancel\" href=\"/\">Cancel</a>",
                "</form></main></body></html>"
            ),
            escape_html_attribute(csrf_token),
            preserved_fields,
        ))
}

fn logout_request_hidden_fields(request: &OidcLogoutRequest) -> String {
    [
        ("id_token_hint", request.id_token_hint.as_deref()),
        ("client_id", request.client_id.as_deref()),
        (
            "post_logout_redirect_uri",
            request.post_logout_redirect_uri.as_deref(),
        ),
        ("state", request.state.as_deref()),
    ]
    .into_iter()
    .filter_map(|(name, value)| {
        value.map(|value| {
            format!(
                "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
                escape_html_attribute(value)
            )
        })
    })
    .collect()
}

fn logout_success_response() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::PRAGMA, "no-cache"))
        .content_type("text/html; charset=utf-8")
        .body(logout_success_document())
}

fn logout_success_document() -> &'static str {
    concat!(
        "<!doctype html><html><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<meta http-equiv=\"cache-control\" content=\"no-store\">",
        "<title>Signed out</title></head><body>",
        "<main id=\"nazo-logout-success\"><h1>You are signed out.</h1></main>",
        "</body></html>"
    )
}

fn frontchannel_logout_document(frontchannel_urls: &[String], redirect: Option<&str>) -> String {
    let iframe_count = frontchannel_urls.len();
    let iframe_onload = if redirect.is_some() {
        " onload=\"nazoFrontchannelLogoutFrameDone(this)\""
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
                "var completed=new WeakSet();",
                "function finish(){{",
                "if(redirected){{return;}}",
                "redirected=true;",
                "window.location.replace('{location}');",
                "}}",
                "window.nazoFrontchannelLogoutFrameDone=function(frame){{",
                "if(completed.has(frame)){{return;}}",
                "completed.add(frame);",
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
    let redirect_fallback = redirect.map_or_else(String::new, |location| {
        format!(
            concat!(
                "<p><a id=\"nazo-frontchannel-logout-continue\" href=\"{}\">",
                "Continue after sign-out</a></p>"
            ),
            escape_html_attribute(location)
        )
    });
    format!(
        concat!(
            "<!doctype html><html><head><meta charset=\"utf-8\">",
            "<meta http-equiv=\"cache-control\" content=\"no-store\">",
            "<style>iframe{{display:none;width:0;height:0;border:0}}</style>",
            "</head><body><main id=\"nazo-logout-success\">",
            "<h1>You are signed out.</h1>{redirect_fallback}</main>",
            "{redirect_script}{iframes}</body></html>"
        ),
        iframes = iframes,
        redirect_script = redirect_script,
        redirect_fallback = redirect_fallback,
    )
}

fn escape_html_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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
