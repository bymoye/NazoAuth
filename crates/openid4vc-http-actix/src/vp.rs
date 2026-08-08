use std::{borrow::Cow, collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

use actix_web::{HttpRequest, HttpResponse, http::header, web};
use nazo_openid4vp::{AuthorizationResponse, PresentationResult, PresentationTransaction};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub type PresentationFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, PartialEq)]
pub enum PresentationResponseBody {
    RequestObject(String),
    Json(Value),
}

#[derive(Clone, Debug, PartialEq)]
pub enum PresentationResponseInput {
    DirectPost(AuthorizationResponse),
    DirectPostJwt(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentationHttpError {
    pub status: u16,
    pub error: &'static str,
    pub description: &'static str,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePresentationRequest {
    pub wallet_authorization_endpoint: String,
    pub dcql_query: nazo_digital_credentials::DcqlQuery,
    #[serde(default)]
    pub haip: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Vec<Value>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CreatePresentationResponse {
    pub transaction_id: Uuid,
    pub authorization_url: String,
    pub expires_in: u64,
}

pub trait PresentationOperations: Send + Sync {
    fn create<'a>(
        &'a self,
        request: CreatePresentationRequest,
    ) -> PresentationFuture<'a, Result<CreatePresentationResponse, PresentationHttpError>>;
    fn request<'a>(
        &'a self,
        transaction_id: Uuid,
        wallet_nonce: Option<&'a str>,
    ) -> PresentationFuture<'a, Result<PresentationResponseBody, PresentationHttpError>>;
    fn respond<'a>(
        &'a self,
        transaction_id: Uuid,
        response: PresentationResponseInput,
    ) -> PresentationFuture<'a, Result<Option<String>, PresentationHttpError>>;
    fn result<'a>(
        &'a self,
        transaction_id: Uuid,
    ) -> PresentationFuture<'a, Result<PresentationResult, PresentationHttpError>>;
}

#[derive(Clone)]
pub struct PresentationEndpoint {
    operations: Arc<dyn PresentationOperations>,
    management_token: Arc<[u8]>,
}

impl PresentationEndpoint {
    pub fn new(
        operations: Arc<dyn PresentationOperations>,
        management_token: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            operations,
            management_token: management_token.into().into(),
        }
    }

    fn management_authorized(&self, request: &HttpRequest) -> bool {
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim)
            .is_some_and(|provided| constant_time_eq(provided.as_bytes(), &self.management_token))
    }
}

pub async fn create_presentation(
    endpoint: web::Data<PresentationEndpoint>,
    request: HttpRequest,
    body: web::Json<CreatePresentationRequest>,
) -> HttpResponse {
    if !endpoint.management_authorized(&request) {
        return management_unauthorized();
    }
    match endpoint.operations.create(body.into_inner()).await {
        Ok(value) => json_no_store(value),
        Err(error) => presentation_error(error),
    }
}

pub async fn presentation_request(
    endpoint: web::Data<PresentationEndpoint>,
    transaction_id: web::Path<Uuid>,
    form: Option<web::Form<WalletNonceForm>>,
) -> HttpResponse {
    let wallet_nonce = form.as_ref().map(|form| form.wallet_nonce.as_str());
    match endpoint
        .operations
        .request(*transaction_id, wallet_nonce)
        .await
    {
        Ok(PresentationResponseBody::RequestObject(jwt)) => HttpResponse::Ok()
            .insert_header((header::CONTENT_TYPE, "application/oauth-authz-req+jwt"))
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .body(jwt),
        Ok(PresentationResponseBody::Json(value)) => json_no_store(value),
        Err(error) => presentation_error(error),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct WalletNonceForm {
    pub wallet_nonce: String,
}

pub async fn presentation_response(
    endpoint: web::Data<PresentationEndpoint>,
    transaction_id: web::Path<Uuid>,
    request: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    let response = match parse_presentation_response(&request, &body) {
        Ok(response) => response,
        Err(error) => return presentation_error(error),
    };
    match endpoint.operations.respond(*transaction_id, response).await {
        Ok(Some(redirect_uri)) => HttpResponse::Ok()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .json(serde_json::json!({"redirect_uri": redirect_uri})),
        Ok(None) => HttpResponse::Ok()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .json(serde_json::json!({})),
        Err(error) => presentation_error(error),
    }
}

pub async fn presentation_complete() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::REFERRER_POLICY, "no-referrer"))
        .insert_header(("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"))
        .body("<!doctype html><meta charset=utf-8><title>Presentation complete</title><p>Presentation complete.</p>")
}

fn parse_presentation_response(
    request: &HttpRequest,
    body: &[u8],
) -> Result<PresentationResponseInput, PresentationHttpError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(invalid_response(
            "Presentation responses must use application/x-www-form-urlencoded.",
        ));
    }
    let mut values: BTreeMap<Cow<'_, str>, Cow<'_, str>> = BTreeMap::new();
    for (name, value) in url::form_urlencoded::parse(body) {
        if values.insert(name, value).is_some() {
            return Err(invalid_response(
                "Presentation response parameters must not repeat.",
            ));
        }
    }
    if let Some(response) = values.remove("response") {
        if !values.is_empty() {
            return Err(invalid_response(
                "direct_post.jwt cannot be mixed with plaintext parameters.",
            ));
        }
        return Ok(PresentationResponseInput::DirectPostJwt(
            response.into_owned(),
        ));
    }
    let vp_token = values.remove("vp_token").map(|value| {
        serde_json::from_str(value.as_ref()).unwrap_or_else(|_| Value::String(value.into_owned()))
    });
    let response = AuthorizationResponse {
        vp_token,
        state: values.remove("state").map(Cow::into_owned),
        error: values.remove("error").map(Cow::into_owned),
        error_description: values.remove("error_description").map(Cow::into_owned),
    };
    if !values.is_empty() {
        return Err(invalid_response(
            "Presentation response contains unknown parameters.",
        ));
    }
    Ok(PresentationResponseInput::DirectPost(response))
}

fn invalid_response(description: &'static str) -> PresentationHttpError {
    PresentationHttpError {
        status: 400,
        error: "invalid_request",
        description,
    }
}

pub async fn presentation_result(
    endpoint: web::Data<PresentationEndpoint>,
    request: HttpRequest,
    transaction_id: web::Path<Uuid>,
) -> HttpResponse {
    if !endpoint.management_authorized(&request) {
        return management_unauthorized();
    }
    match endpoint.operations.result(*transaction_id).await {
        Ok(result) => json_no_store(result),
        Err(error) => presentation_error(error),
    }
}

fn management_unauthorized() -> HttpResponse {
    HttpResponse::Unauthorized()
        .insert_header((header::WWW_AUTHENTICATE, "Bearer"))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(serde_json::json!({
            "error": "invalid_token",
            "error_description": "Verifier management authentication is required."
        }))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn json_no_store(value: impl Serialize) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(value)
}

fn presentation_error(error: PresentationHttpError) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(error.status)
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    HttpResponse::build(status)
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(serde_json::json!({
            "error": error.error,
            "error_description": error.description,
        }))
}

#[allow(dead_code)]
fn _assert_transaction_is_send_sync(_: &PresentationTransaction) {}
