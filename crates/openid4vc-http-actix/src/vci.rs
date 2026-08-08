use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{HttpRequest, HttpResponse, http::header, web};
use nazo_openid4vci::{
    CredentialIssuerMetadata, CredentialOffer, CredentialRequest, CredentialResponse,
    DeferredCredentialRequest, NotificationRequest,
};
use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

pub type CredentialIssuerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type ClientCertificateExtractor = dyn Fn(&HttpRequest) -> Option<String> + Send + Sync;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessTokenScheme {
    Bearer,
    Dpop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRequestContext {
    pub bearer_token: String,
    pub access_token_scheme: AccessTokenScheme,
    pub dpop_proof: Option<String>,
    /// Verified client-certificate thumbprint supplied by the deployment's
    /// certificate adapter.  The transport layer never derives this from an
    /// ordinary request header.
    pub mtls_x5t_s256: Option<String>,
    pub request_url: String,
    pub method: &'static str,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CredentialResponseBody {
    Json(CredentialResponse),
    Jwt(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialEndpointResponse<T> {
    pub body: T,
    pub dpop_nonce: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CredentialRequestBody<T> {
    Json(T),
    Jwt(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreAuthorizedTokenRequest {
    pub pre_authorized_code: String,
    pub tx_code: Option<String>,
    pub client_id: Option<String>,
    pub dpop_proof: Option<String>,
    pub client_attestation: Option<String>,
    pub client_attestation_pop: Option<String>,
    pub request_url: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PreAuthorizedTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_details: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCredentialOfferRequest {
    pub subject_id: Uuid,
    pub credential_configuration_ids: Vec<String>,
    pub grant_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,
    #[serde(default = "default_offer_lifetime")]
    pub expires_in: u64,
}

const fn default_offer_lifetime() -> u64 {
    300
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CreateCredentialOfferResponse {
    pub offer_id: Uuid,
    pub credential_offer_uri: String,
    pub credential_offer: CredentialOffer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialHttpError {
    pub status: u16,
    pub error: &'static str,
    pub description: &'static str,
    pub dpop_nonce: Option<String>,
}

pub trait CredentialIssuerOperations: Send + Sync {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>>;
    fn offer<'a>(
        &'a self,
        offer_id: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>>;
    fn nonce(
        &self,
        dpop_proof: Option<&str>,
    ) -> CredentialIssuerFuture<'_, Result<String, CredentialHttpError>>;
    fn credential<'a>(
        &'a self,
        context: CredentialRequestContext,
        request: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    >;
    fn deferred<'a>(
        &'a self,
        context: CredentialRequestContext,
        request: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    >;
    fn notify<'a>(
        &'a self,
        context: CredentialRequestContext,
        request: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>;
    fn pre_authorized_token<'a>(
        &'a self,
        request: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>>;
    fn create_offer<'a>(
        &'a self,
        request: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>;
}

#[derive(Clone)]
pub struct CredentialIssuerEndpoint {
    operations: Arc<dyn CredentialIssuerOperations>,
    management_token: Arc<[u8]>,
    client_certificate_extractor: Option<Arc<ClientCertificateExtractor>>,
}

impl CredentialIssuerEndpoint {
    pub fn new(
        operations: Arc<dyn CredentialIssuerOperations>,
        management_token: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            operations,
            management_token: management_token.into().into(),
            client_certificate_extractor: None,
        }
    }

    /// Configure the deployment-specific, already-verified client-certificate
    /// extractor used by protected credential endpoints.
    ///
    /// The extractor is intentionally injected by the server composition root:
    /// only that layer knows whether certificates come from direct TLS or a
    /// trusted, verified proxy.  The generic transport adapter does not read
    /// certificate headers itself.
    pub fn with_client_certificate_extractor(
        mut self,
        extractor: impl Fn(&HttpRequest) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.client_certificate_extractor = Some(Arc::new(extractor));
        self
    }

    pub async fn pre_authorized_token(
        &self,
        request: PreAuthorizedTokenRequest,
    ) -> Result<PreAuthorizedTokenResponse, CredentialHttpError> {
        self.operations.pre_authorized_token(request).await
    }

    pub fn management_authorized(&self, request: &HttpRequest) -> bool {
        authorized_by_exact_bearer(request, &self.management_token)
    }
}

fn authorized_by_exact_bearer(request: &HttpRequest, expected: &[u8]) -> bool {
    !expected.is_empty()
        && request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| !value.is_empty() && value.trim() == *value)
            .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected))
}

fn management_unauthorized() -> HttpResponse {
    HttpResponse::Unauthorized()
        .insert_header((header::WWW_AUTHENTICATE, "Bearer"))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(serde_json::json!({"error":"invalid_token"}))
}

pub async fn create_credential_offer(
    endpoint: web::Data<CredentialIssuerEndpoint>,
    request: HttpRequest,
    body: web::Json<CreateCredentialOfferRequest>,
) -> HttpResponse {
    if !endpoint.management_authorized(&request) {
        return management_unauthorized();
    }
    match endpoint.operations.create_offer(body.into_inner()).await {
        Ok(response) => json_no_store(response),
        Err(error) => credential_error(error),
    }
}

pub async fn credential_issuer_metadata(
    endpoint: web::Data<CredentialIssuerEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    match endpoint.operations.metadata().await {
        Ok(metadata) if accepts_signed_metadata(&request) => match metadata.signed_metadata {
            Some(jwt) => HttpResponse::Ok()
                .insert_header((header::CONTENT_TYPE, "application/jwt"))
                .insert_header((header::CACHE_CONTROL, "no-store"))
                .body(jwt),
            None => credential_error(CredentialHttpError {
                status: 406,
                error: "invalid_request",
                description: "Signed credential issuer metadata is unavailable.",
                dpop_nonce: None,
            }),
        },
        Ok(metadata) => json_no_store(metadata),
        Err(error) => credential_error(error),
    }
}

pub async fn credential_offer(
    endpoint: web::Data<CredentialIssuerEndpoint>,
    offer_id: web::Path<String>,
) -> HttpResponse {
    match endpoint.operations.offer(&offer_id).await {
        Ok(offer) => json_no_store(offer),
        Err(error) => credential_error(error),
    }
}

pub async fn credential_nonce(
    endpoint: web::Data<CredentialIssuerEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    match endpoint
        .operations
        .nonce(
            request
                .headers()
                .get("DPoP")
                .and_then(|value| value.to_str().ok()),
        )
        .await
    {
        Ok(c_nonce) => json_no_store(serde_json::json!({"c_nonce": c_nonce})),
        Err(error) => credential_error(error),
    }
}

pub async fn credential(
    endpoint: web::Data<CredentialIssuerEndpoint>,
    request: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    let context = match protected_context(
        &request,
        "POST",
        endpoint.client_certificate_extractor.as_deref(),
    ) {
        Ok(context) => context,
        Err(error) => return credential_error(error),
    };
    let body = match credential_body(&request, &body) {
        Ok(body) => body,
        Err(error) => return credential_error(error),
    };
    match endpoint.operations.credential(context, body).await {
        Ok(response) => credential_success(response),
        Err(error) => credential_error(error),
    }
}

pub async fn deferred_credential(
    endpoint: web::Data<CredentialIssuerEndpoint>,
    request: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    let context = match protected_context(
        &request,
        "POST",
        endpoint.client_certificate_extractor.as_deref(),
    ) {
        Ok(context) => context,
        Err(error) => return credential_error(error),
    };
    let body = match deferred_body(&request, &body) {
        Ok(body) => body,
        Err(error) => return credential_error(error),
    };
    match endpoint.operations.deferred(context, body).await {
        Ok(response) => credential_success(response),
        Err(error) => credential_error(error),
    }
}

pub async fn notification(
    endpoint: web::Data<CredentialIssuerEndpoint>,
    request: HttpRequest,
    body: web::Json<NotificationRequest>,
) -> HttpResponse {
    let context = match protected_context(
        &request,
        "POST",
        endpoint.client_certificate_extractor.as_deref(),
    ) {
        Ok(context) => context,
        Err(error) => return credential_error(error),
    };
    match endpoint.operations.notify(context, body.into_inner()).await {
        Ok(response) => {
            let mut builder = HttpResponse::NoContent();
            builder.insert_header((header::CACHE_CONTROL, "no-store"));
            insert_dpop_nonce(&mut builder, response.dpop_nonce);
            builder.finish()
        }
        Err(error) => credential_error(error),
    }
}

fn protected_context(
    request: &HttpRequest,
    method: &'static str,
    client_certificate_extractor: Option<&ClientCertificateExtractor>,
) -> Result<CredentialRequestContext, CredentialHttpError> {
    let (access_token_scheme, bearer_token) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().split_once(' '))
        .and_then(|(scheme, token)| {
            let scheme = if scheme.eq_ignore_ascii_case("Bearer") {
                AccessTokenScheme::Bearer
            } else if scheme.eq_ignore_ascii_case("DPoP") {
                AccessTokenScheme::Dpop
            } else {
                return None;
            };
            let token = token.trim();
            (!token.is_empty()).then_some((scheme, token))
        })
        .ok_or(CredentialHttpError {
            status: 401,
            error: "invalid_token",
            description: "A Bearer or DPoP access token is required.",
            dpop_nonce: None,
        })?;
    let dpop_proofs = request.headers().get_all("DPoP");
    let dpop_proof_count = dpop_proofs.count();
    if dpop_proof_count > 1 {
        return Err(CredentialHttpError {
            status: 401,
            error: "invalid_dpop_proof",
            description: "Exactly one DPoP proof header is allowed.",
            dpop_nonce: None,
        });
    }
    let dpop_proof = request
        .headers()
        .get("DPoP")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    Ok(CredentialRequestContext {
        bearer_token: bearer_token.to_owned(),
        access_token_scheme,
        dpop_proof,
        mtls_x5t_s256: client_certificate_extractor.and_then(|extractor| extractor(request)),
        request_url: request.uri().to_string(),
        method,
    })
}

fn credential_success(
    response: CredentialEndpointResponse<CredentialResponseBody>,
) -> HttpResponse {
    let CredentialEndpointResponse { body, dpop_nonce } = response;
    let accepted =
        matches!(&body, CredentialResponseBody::Json(value) if value.transaction_id.is_some());
    let status = if accepted {
        actix_web::http::StatusCode::ACCEPTED
    } else {
        actix_web::http::StatusCode::OK
    };
    let mut builder = HttpResponse::build(status);
    builder.insert_header((header::CACHE_CONTROL, "no-store"));
    insert_dpop_nonce(&mut builder, dpop_nonce);
    match body {
        CredentialResponseBody::Json(value) => builder.json(value),
        CredentialResponseBody::Jwt(value) => builder
            .insert_header((header::CONTENT_TYPE, "application/jwt"))
            .body(value),
    }
}

fn insert_dpop_nonce(builder: &mut actix_web::HttpResponseBuilder, nonce: Option<String>) {
    if let Some(nonce) = nonce {
        builder.insert_header((header::HeaderName::from_static("dpop-nonce"), nonce));
    }
}

fn accepts_signed_metadata(request: &HttpRequest) -> bool {
    request
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(|item| item.split(';').next().unwrap_or("").trim())
                .any(|mime| mime.eq_ignore_ascii_case("application/jwt"))
        })
}

fn credential_body(
    request: &HttpRequest,
    body: &[u8],
) -> Result<CredentialRequestBody<CredentialRequest>, CredentialHttpError> {
    parse_body(request, body)
}

fn deferred_body(
    request: &HttpRequest,
    body: &[u8],
) -> Result<CredentialRequestBody<DeferredCredentialRequest>, CredentialHttpError> {
    parse_body(request, body)
}

fn parse_body<T: serde::de::DeserializeOwned>(
    request: &HttpRequest,
    body: &[u8],
) -> Result<CredentialRequestBody<T>, CredentialHttpError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    match content_type {
        "application/json" => serde_json::from_slice(body).map(CredentialRequestBody::Json),
        "application/jwt" => std::str::from_utf8(body)
            .map(|value| CredentialRequestBody::Jwt(value.to_owned()))
            .map_err(|_| serde_json::Error::io(std::io::Error::other("invalid UTF-8"))),
        _ => {
            return Err(CredentialHttpError {
                status: 415,
                error: "invalid_credential_request",
                description: "Credential requests must use application/json or application/jwt.",
                dpop_nonce: None,
            });
        }
    }
    .map_err(|_| CredentialHttpError {
        status: 400,
        error: "invalid_credential_request",
        description: "Credential request body is malformed.",
        dpop_nonce: None,
    })
}

fn json_no_store(value: impl Serialize) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(value)
}

fn credential_error(error: CredentialHttpError) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(error.status)
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = HttpResponse::build(status);
    response.insert_header((header::CACHE_CONTROL, "no-store"));
    if status == actix_web::http::StatusCode::UNAUTHORIZED {
        let challenge = if matches!(error.error, "use_dpop_nonce" | "invalid_dpop_proof") {
            format!("DPoP error=\"{}\"", error.error)
        } else {
            "Bearer".to_owned()
        };
        response.insert_header((header::WWW_AUTHENTICATE, challenge));
    }
    if let Some(nonce) = error.dpop_nonce {
        response.insert_header(("DPoP-Nonce", nonce));
    }
    response.json(serde_json::json!({
        "error": error.error,
        "error_description": error.description,
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
