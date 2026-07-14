use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    body::to_bytes,
    http::{StatusCode, header},
    web::{Bytes, Data},
};
use chrono::Utc;
use nazo_http_signatures::{
    OriginalRequest, RequestInput, ResponseInput, ResponsePolicy, SignatureFields,
    VerificationPolicy, VerifiedInput, content_digest, content_digest_field_matches,
    parse_request_for_verification, prepare_response,
};
use nazo_resource_server::{
    AccessTokenScheme, DpopProofVerifierError, ProtectedResourceAuthorizationContext,
    ProtectedResourceAuthorizationError, ProtectedResourceAuthorizationRequest,
    ProtectedResourceAuthorizationResult, ResourceServerVerifierError,
};
use serde_json::json;

use crate::{
    AccessTokenAuthScheme, ResourceAccessToken, json_response_no_store, oauth_bearer_error,
    oauth_error, resource_access_token,
};

const FAPI_HTTP_SIGNATURE_FUTURE_SKEW_SECONDS: i64 = 5;

pub type FapiFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug)]
pub enum FapiAuthorizationError {
    Protocol(ProtectedResourceAuthorizationError),
    UseDpopNonce(String),
    DpopNonceUnavailable,
}

pub trait FapiResourceAuthorizer: Send + Sync {
    fn authorize<'a>(
        &'a self,
        request: ProtectedResourceAuthorizationRequest<'a>,
        context: ProtectedResourceAuthorizationContext<'a>,
    ) -> FapiFuture<'a, Result<ProtectedResourceAuthorizationResult, FapiAuthorizationError>>;
}

pub trait FapiMtlsThumbprintResolver: Send + Sync {
    fn resolve(&self, request: &HttpRequest) -> Option<String>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FapiSignatureVerificationError {
    Invalid,
    Replay,
    LookupUnavailable,
    ReplayUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FapiSignatureOperationError {
    Unavailable,
}

pub trait FapiResponseSignature: Send + Sync {
    fn kid(&self) -> &str;
    fn algorithm(&self) -> &str;
    fn sign<'a>(
        &'a self,
        signature_base: &'a [u8],
    ) -> FapiFuture<'a, Result<Vec<u8>, FapiSignatureOperationError>>;
}

pub trait FapiHttpMessageSignatures: Send + Sync {
    fn enabled(&self) -> bool;

    fn verify_and_consume<'a>(
        &'a self,
        tenant_id: &'a str,
        client_id: &'a str,
        input: &'a VerifiedInput,
    ) -> FapiFuture<'a, Result<(), FapiSignatureVerificationError>>;

    fn response_signature(
        &self,
    ) -> Result<Arc<dyn FapiResponseSignature>, FapiSignatureOperationError>;
}

#[derive(Clone)]
pub struct FapiResourceEndpoint {
    issuer: String,
    mtls_endpoint_base_url: String,
    signature_max_age_seconds: i64,
    authorizer: Arc<dyn FapiResourceAuthorizer>,
    mtls: Arc<dyn FapiMtlsThumbprintResolver>,
    signatures: Arc<dyn FapiHttpMessageSignatures>,
}

impl FapiResourceEndpoint {
    pub fn new(
        issuer: impl Into<String>,
        mtls_endpoint_base_url: impl Into<String>,
        signature_max_age_seconds: i64,
        authorizer: Arc<dyn FapiResourceAuthorizer>,
        mtls: Arc<dyn FapiMtlsThumbprintResolver>,
        signatures: Arc<dyn FapiHttpMessageSignatures>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            mtls_endpoint_base_url: mtls_endpoint_base_url.into(),
            signature_max_age_seconds,
            authorizer,
            mtls,
            signatures,
        }
    }
}

pub async fn fapi_resource(
    endpoint: Data<FapiResourceEndpoint>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let signatures_enabled = endpoint.signatures.enabled();
    let original =
        signatures_enabled.then(|| CapturedRequest::capture(&endpoint.issuer, &request, &body));
    let response = fapi_resource_inner(&endpoint, &request, &body, original.as_ref()).await;
    match original {
        Some(original) => sign_response(&endpoint, &original, response).await,
        None => response,
    }
}

async fn fapi_resource_inner(
    endpoint: &FapiResourceEndpoint,
    request: &HttpRequest,
    body: &Bytes,
    original: Option<&CapturedRequest>,
) -> HttpResponse {
    let (scheme, access_token) = match resource_access_token(request, body, original.is_some()) {
        ResourceAccessToken::Present(scheme, token) => (scheme, token),
        ResourceAccessToken::Missing => {
            return oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "缺少访问令牌.");
        }
        ResourceAccessToken::InvalidRequest => {
            return oauth_bearer_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Only one access token transport method may be used.",
            );
        }
    };
    let dpop_proof = single_header(request, "dpop");
    if dpop_proof.is_err() {
        return invalid_dpop_response("DPoP proof is malformed.");
    }
    let dpop_proof = dpop_proof.ok().flatten();
    let verified_signature = match original {
        Some(original) => match original.parse(endpoint.signature_max_age_seconds) {
            Ok(verified) => Some(verified),
            Err(()) => {
                return oauth_bearer_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "HTTP message signature is missing or invalid.",
                );
            }
        },
        None => None,
    };
    let mtls_thumbprint = endpoint.mtls.resolve(request);
    let primary_target = endpoint_uri(&endpoint.issuer, request.path());
    let alternate_target = endpoint_uri(&endpoint.mtls_endpoint_base_url, request.path());
    let target_uris = if alternate_target == primary_target {
        vec![primary_target.as_str()]
    } else {
        vec![primary_target.as_str(), alternate_target.as_str()]
    };
    let authorization_request = ProtectedResourceAuthorizationRequest {
        access_token: &access_token,
        scheme: match scheme {
            AccessTokenAuthScheme::Bearer => AccessTokenScheme::Bearer,
            AccessTokenAuthScheme::DPoP => AccessTokenScheme::Dpop,
        },
        dpop_proof,
    };
    let result = endpoint
        .authorizer
        .authorize(
            authorization_request,
            ProtectedResourceAuthorizationContext {
                method: request.method().as_str(),
                target_uris: &target_uris,
                mtls_x5t_s256: mtls_thumbprint.as_deref(),
            },
        )
        .await;
    let authorized = match result {
        Ok(authorized) => authorized,
        Err(error) => return authorization_error_response(error, scheme),
    };

    if let Some(verified) = verified_signature.as_ref() {
        let Some(tenant_id) = authorized.token.tenant_id.as_deref() else {
            return oauth_bearer_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "访问令牌租户边界无效.",
            );
        };
        match endpoint
            .signatures
            .verify_and_consume(tenant_id, &authorized.token.client_id, verified)
            .await
        {
            Ok(()) => {}
            Err(FapiSignatureVerificationError::Invalid) => {
                return oauth_bearer_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "HTTP message signature is missing or invalid.",
                );
            }
            Err(FapiSignatureVerificationError::Replay) => {
                return oauth_bearer_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "HTTP message signature replay detected.",
                );
            }
            Err(FapiSignatureVerificationError::LookupUnavailable) => {
                return oauth_bearer_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "resource 查询失败.",
                );
            }
            Err(FapiSignatureVerificationError::ReplayUnavailable) => {
                return oauth_bearer_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "resource 暂时不可用.",
                );
            }
        }
    }

    let audience = match authorized.token.audiences.as_slice() {
        [audience] => serde_json::Value::String(audience.clone()),
        audiences => json!(audiences),
    };
    let mut response = json_response_no_store(json!({
        "sub": authorized.token.subject,
        "client_id": authorized.token.client_id,
        "scope": authorized.token.scopes.join(" "),
        "aud": audience,
    }));
    response.headers_mut().insert(
        header_name("x-fapi-interaction-id"),
        interaction_id(request),
    );
    response
}

fn authorization_error_response(
    error: FapiAuthorizationError,
    scheme: AccessTokenAuthScheme,
) -> HttpResponse {
    match error {
        FapiAuthorizationError::UseDpopNonce(nonce) => use_dpop_nonce_response(&nonce),
        FapiAuthorizationError::DpopNonceUnavailable => dpop_nonce_unavailable_response(),
        FapiAuthorizationError::Protocol(error) => protocol_error_response(error, scheme),
    }
}

fn protocol_error_response(
    error: ProtectedResourceAuthorizationError,
    scheme: AccessTokenAuthScheme,
) -> HttpResponse {
    match error {
        ProtectedResourceAuthorizationError::UseDpopNonce(nonce) => use_dpop_nonce_response(&nonce),
        ProtectedResourceAuthorizationError::InvalidToken(
            ResourceServerVerifierError::AudienceMismatch,
        ) => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌 audience 不适用于该资源.",
        ),
        ProtectedResourceAuthorizationError::InvalidToken(_) => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌无效或已过期.",
        ),
        ProtectedResourceAuthorizationError::InvalidTenantBoundary => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌租户边界无效.",
        ),
        ProtectedResourceAuthorizationError::Revoked => {
            oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "访问令牌已失效.")
        }
        ProtectedResourceAuthorizationError::DependencyUnavailable(
            nazo_resource_server::ProtectedResourceDependencyError::DpopNonceStoreUnavailable,
        ) => dpop_nonce_unavailable_response(),
        ProtectedResourceAuthorizationError::DependencyUnavailable(_) => oauth_bearer_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "resource 查询失败.",
        ),
        ProtectedResourceAuthorizationError::TokenNotDpopBound => {
            invalid_dpop_response("Token is not DPoP-bound.")
        }
        ProtectedResourceAuthorizationError::MissingSenderConstraint => match scheme {
            AccessTokenAuthScheme::DPoP => invalid_dpop_response_with_status(
                StatusCode::UNAUTHORIZED,
                "DPoP proof is required.",
            ),
            AccessTokenAuthScheme::Bearer => oauth_bearer_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "mTLS-bound access token requires a verified client certificate.",
            ),
        },
        ProtectedResourceAuthorizationError::DpopBindingMismatch => {
            invalid_dpop_response("DPoP binding mismatch.")
        }
        ProtectedResourceAuthorizationError::ReplayDetected => {
            invalid_dpop_response("DPoP proof jti has already been used.")
        }
        ProtectedResourceAuthorizationError::InvalidDpopProof(error) => {
            let description = match error {
                DpopProofVerifierError::MalformedProof => "DPoP proof is malformed.",
                DpopProofVerifierError::ReplayDetected => "DPoP proof jti has already been used.",
                _ => "DPoP proof validation failed.",
            };
            invalid_dpop_response(description)
        }
        ProtectedResourceAuthorizationError::MtlsBindingMismatch => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "mTLS-bound access token certificate mismatch.",
        ),
    }
}

fn use_dpop_nonce_response(nonce: &str) -> HttpResponse {
    let mut response = oauth_error(
        StatusCode::UNAUTHORIZED,
        "use_dpop_nonce",
        "Authorization server requires nonce in DPoP proof.",
    );
    if let Ok(value) = header::HeaderValue::from_str(nonce) {
        response
            .headers_mut()
            .insert(header_name("dpop-nonce"), value);
    }
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("DPoP error=\"use_dpop_nonce\""),
    );
    response
}

fn dpop_nonce_unavailable_response() -> HttpResponse {
    let mut response = oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "DPoP nonce validation is unavailable.",
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("DPoP error=\"server_error\""),
    );
    response
}

fn invalid_dpop_response(description: &str) -> HttpResponse {
    invalid_dpop_response_with_status(StatusCode::BAD_REQUEST, description)
}

fn invalid_dpop_response_with_status(status: StatusCode, description: &str) -> HttpResponse {
    let mut response = oauth_error(status, "invalid_dpop_proof", description);
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("DPoP error=\"invalid_dpop_proof\""),
    );
    response
}

#[derive(Clone, Debug)]
enum CapturedHeader {
    Missing,
    Unique(String),
    Invalid,
}

impl CapturedHeader {
    fn capture(request: &HttpRequest, name: &str) -> Self {
        let mut values = request.headers().get_all(name);
        let Some(value) = values.next() else {
            return Self::Missing;
        };
        if values.next().is_some() {
            return Self::Invalid;
        }
        value
            .to_str()
            .map_or(Self::Invalid, |value| Self::Unique(value.to_owned()))
    }

    fn unique(&self) -> Result<Option<&str>, ()> {
        match self {
            Self::Missing => Ok(None),
            Self::Unique(value) => Ok(Some(value)),
            Self::Invalid => Err(()),
        }
    }
}

struct CapturedRequest {
    method: String,
    target_uri: String,
    body: Bytes,
    authorization: CapturedHeader,
    dpop: CapturedHeader,
    content_digest: CapturedHeader,
    signature_input: CapturedHeader,
    signature: CapturedHeader,
    safe_headers: Vec<(String, String)>,
    captured_at: i64,
}

impl CapturedRequest {
    fn capture(issuer: &str, request: &HttpRequest, body: &Bytes) -> Self {
        let target_uri = endpoint_uri(
            issuer,
            request
                .uri()
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or_else(|| request.path()),
        );
        let safe_headers = request
            .headers()
            .keys()
            .filter_map(|name| {
                let name = name.as_str().to_ascii_lowercase();
                if matches!(name.as_str(), "signature" | "signature-input") {
                    return None;
                }
                let mut values = request.headers().get_all(name.as_str());
                let value = values.next()?;
                if values.next().is_some() {
                    return None;
                }
                let value = value.to_str().ok()?;
                if value.chars().any(char::is_control) {
                    return None;
                }
                Some((name, value.to_owned()))
            })
            .collect();
        Self {
            method: request.method().as_str().to_owned(),
            target_uri,
            body: body.clone(),
            authorization: CapturedHeader::capture(request, "authorization"),
            dpop: CapturedHeader::capture(request, "dpop"),
            content_digest: CapturedHeader::capture(request, "content-digest"),
            signature_input: CapturedHeader::capture(request, "signature-input"),
            signature: CapturedHeader::capture(request, "signature"),
            safe_headers,
            captured_at: Utc::now().timestamp(),
        }
    }

    fn signature_fields(&self) -> Result<SignatureFields, ()> {
        match (self.signature_input.unique()?, self.signature.unique()?) {
            (Some(signature_input), Some(signature)) => Ok(SignatureFields {
                signature_input: signature_input.to_owned(),
                signature: signature.to_owned(),
            }),
            _ => Err(()),
        }
    }

    fn verification_headers(&self) -> Result<Vec<(&str, &str)>, ()> {
        let mut headers = self
            .safe_headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        for (name, captured) in [
            ("authorization", &self.authorization),
            ("dpop", &self.dpop),
            ("content-digest", &self.content_digest),
        ] {
            if !headers.iter().any(|(existing, _)| *existing == name)
                && let Some(value) = captured.unique()?
            {
                headers.push((name, value));
            }
        }
        Ok(headers)
    }

    fn parse(&self, max_age_seconds: i64) -> Result<VerifiedInput, ()> {
        let fields = self.signature_fields()?;
        let headers = self.verification_headers()?;
        parse_request_for_verification(
            RequestInput {
                method: &self.method,
                target_uri: &self.target_uri,
                headers: &headers,
                body: &self.body,
            },
            fields,
            VerificationPolicy {
                now: self.captured_at,
                max_age_seconds,
                future_skew_seconds: FAPI_HTTP_SIGNATURE_FUTURE_SKEW_SECONDS,
            },
        )
        .map_err(|_| ())
    }

    fn valid_digest(&self) -> Option<&str> {
        let value = self.content_digest.unique().ok().flatten()?;
        (!self.body.is_empty() && content_digest_field_matches(value, &self.body))
            .then(|| value.trim_matches([' ', '\t']))
    }
}

async fn sign_response(
    endpoint: &FapiResourceEndpoint,
    original: &CapturedRequest,
    response: HttpResponse,
) -> HttpResponse {
    let status = response.status();
    let response_headers = response.headers().clone();
    let response_body = match to_bytes(response.into_body()).await {
        Ok(body) => body,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let digest = (!response_body.is_empty()).then(|| content_digest(&response_body));
    let mut signature_headers = digest
        .as_deref()
        .map(|value| vec![("content-digest", value)])
        .unwrap_or_default();
    let mut covered_headers = Vec::new();
    for name in ["content-type", "x-fapi-interaction-id"] {
        if let Some(value) = response_headers
            .get(name)
            .and_then(|value| value.to_str().ok())
        {
            signature_headers.push((name, value));
            covered_headers.push(name);
        }
    }
    let request_digest = original.valid_digest();
    let mut request_headers = original
        .safe_headers
        .iter()
        .filter(|(name, _)| name != "content-digest")
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    if let Some(digest) = request_digest {
        request_headers.push(("content-digest", digest));
    }
    let request_fields = original.signature_fields().ok();
    let signer = match endpoint.signatures.response_signature() {
        Ok(signer) => signer,
        Err(FapiSignatureOperationError::Unavailable) => {
            return HttpResponse::ServiceUnavailable().finish();
        }
    };
    let signing = match prepare_response(
        ResponseInput {
            status: status.as_u16(),
            headers: &signature_headers,
            body: &response_body,
        },
        OriginalRequest {
            input: RequestInput {
                method: &original.method,
                target_uri: &original.target_uri,
                headers: &request_headers,
                body: request_digest.map_or(b"", |_| original.body.as_ref()),
            },
            signature_fields: request_fields.as_ref(),
        },
        ResponsePolicy {
            created: Utc::now().timestamp(),
            keyid: signer.kid(),
            algorithm: signer.algorithm(),
            covered_headers: &covered_headers,
            covered_request_headers: &[],
        },
    ) {
        Ok(signing) => signing,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let signature = match signer.sign(signing.signature_base()).await {
        Ok(signature) => signature,
        Err(FapiSignatureOperationError::Unavailable) => {
            return HttpResponse::ServiceUnavailable().finish();
        }
    };
    let fields = signing.finish(&signature);
    let mut builder = HttpResponse::build(status);
    for (name, value) in &response_headers {
        if name != header::CONTENT_LENGTH
            && !matches!(
                name.as_str(),
                "content-digest" | "signature-input" | "signature"
            )
        {
            builder.append_header((name.clone(), value.clone()));
        }
    }
    if let Some(digest) = digest {
        builder.insert_header(("content-digest", digest));
    }
    builder.insert_header(("signature-input", fields.signature_input));
    builder.insert_header(("signature", fields.signature));
    builder.body(response_body)
}

fn single_header<'a>(request: &'a HttpRequest, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = request.headers().get_all(name);
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    value.to_str().map(Some).map_err(|_| ())
}

fn endpoint_uri(base: &str, path_and_query: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path_and_query)
}

fn interaction_id(request: &HttpRequest) -> header::HeaderValue {
    request
        .headers()
        .get("x-fapi-interaction-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| header::HeaderValue::from_str(value).ok())
        .unwrap_or_else(|| {
            header::HeaderValue::from_str(&uuid::Uuid::now_v7().to_string())
                .expect("UUID is a valid header value")
        })
}

fn header_name(name: &'static str) -> header::HeaderName {
    header::HeaderName::from_static(name)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use actix_web::{App, http::header, test, web};
    use nazo_resource_server::{
        ProtectedResourceAuthorizationResult, VerifiedAccessToken, VerifiedSenderConstraintProof,
    };
    use serde_json::{Value, json};

    use super::*;

    struct Authorizer {
        calls: Arc<AtomicUsize>,
    }

    impl FapiResourceAuthorizer for Authorizer {
        fn authorize<'a>(
            &'a self,
            _request: ProtectedResourceAuthorizationRequest<'a>,
            _context: ProtectedResourceAuthorizationContext<'a>,
        ) -> FapiFuture<'a, Result<ProtectedResourceAuthorizationResult, FapiAuthorizationError>>
        {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Ok(ProtectedResourceAuthorizationResult {
                    token: VerifiedAccessToken {
                        issuer: "https://auth.example".to_owned(),
                        subject: "subject-1".to_owned(),
                        tenant_id: Some("01900000-0000-7000-8000-000000000001".to_owned()),
                        client_id: "client-1".to_owned(),
                        audiences: vec!["resource-1".to_owned()],
                        scopes: vec!["openid".to_owned(), "profile".to_owned()],
                        jti: "jti-1".to_owned(),
                        exp: i64::MAX,
                        cnf: None,
                        authorization_details: Value::Null,
                    },
                    sender_constraint: VerifiedSenderConstraintProof::default(),
                })
            })
        }
    }

    struct NoMtls;

    impl FapiMtlsThumbprintResolver for NoMtls {
        fn resolve(&self, _request: &HttpRequest) -> Option<String> {
            None
        }
    }

    struct DisabledSignatures;

    impl FapiHttpMessageSignatures for DisabledSignatures {
        fn enabled(&self) -> bool {
            false
        }

        fn verify_and_consume<'a>(
            &'a self,
            _tenant_id: &'a str,
            _client_id: &'a str,
            _input: &'a VerifiedInput,
        ) -> FapiFuture<'a, Result<(), FapiSignatureVerificationError>> {
            Box::pin(async { unreachable!("disabled signatures are not verified") })
        }

        fn response_signature(
            &self,
        ) -> Result<Arc<dyn FapiResponseSignature>, FapiSignatureOperationError> {
            Err(FapiSignatureOperationError::Unavailable)
        }
    }

    #[derive(Clone, Copy)]
    enum AuthorizationOutcome {
        Success,
        UseNonce,
        NonceUnavailable,
        InvalidDpop,
    }

    struct RecordingAuthorizer {
        calls: Arc<AtomicUsize>,
        targets: Arc<Mutex<Vec<Vec<String>>>>,
        outcome: AuthorizationOutcome,
    }

    impl FapiResourceAuthorizer for RecordingAuthorizer {
        fn authorize<'a>(
            &'a self,
            _request: ProtectedResourceAuthorizationRequest<'a>,
            context: ProtectedResourceAuthorizationContext<'a>,
        ) -> FapiFuture<'a, Result<ProtectedResourceAuthorizationResult, FapiAuthorizationError>>
        {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.targets.lock().unwrap().push(
                context
                    .target_uris
                    .iter()
                    .map(|target| (*target).to_owned())
                    .collect(),
            );
            let outcome = self.outcome;
            Box::pin(async move {
                match outcome {
                    AuthorizationOutcome::Success => Ok(successful_authorization()),
                    AuthorizationOutcome::UseNonce => {
                        Err(FapiAuthorizationError::UseDpopNonce("nonce-1".to_owned()))
                    }
                    AuthorizationOutcome::NonceUnavailable => {
                        Err(FapiAuthorizationError::DpopNonceUnavailable)
                    }
                    AuthorizationOutcome::InvalidDpop => Err(FapiAuthorizationError::Protocol(
                        ProtectedResourceAuthorizationError::InvalidDpopProof(
                            DpopProofVerifierError::InvalidSignature,
                        ),
                    )),
                }
            })
        }
    }

    fn successful_authorization() -> ProtectedResourceAuthorizationResult {
        ProtectedResourceAuthorizationResult {
            token: VerifiedAccessToken {
                issuer: "https://auth.example".to_owned(),
                subject: "subject-1".to_owned(),
                tenant_id: Some("01900000-0000-7000-8000-000000000001".to_owned()),
                client_id: "client-1".to_owned(),
                audiences: vec!["resource-1".to_owned()],
                scopes: vec!["openid".to_owned(), "profile".to_owned()],
                jti: "jti-1".to_owned(),
                exp: i64::MAX,
                cnf: None,
                authorization_details: Value::Null,
            },
            sender_constraint: VerifiedSenderConstraintProof::default(),
        }
    }

    struct TestResponseSigner {
        fail: bool,
        bases: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl FapiResponseSignature for TestResponseSigner {
        fn kid(&self) -> &str {
            "response-key"
        }

        fn algorithm(&self) -> &str {
            "ed25519"
        }

        fn sign<'a>(
            &'a self,
            signature_base: &'a [u8],
        ) -> FapiFuture<'a, Result<Vec<u8>, FapiSignatureOperationError>> {
            self.bases.lock().unwrap().push(signature_base.to_vec());
            let fail = self.fail;
            Box::pin(async move {
                if fail {
                    Err(FapiSignatureOperationError::Unavailable)
                } else {
                    Ok(vec![7; 64])
                }
            })
        }
    }

    struct EnabledSignatures {
        verification: Result<(), FapiSignatureVerificationError>,
        verify_calls: Arc<AtomicUsize>,
        signer: Arc<TestResponseSigner>,
    }

    impl FapiHttpMessageSignatures for EnabledSignatures {
        fn enabled(&self) -> bool {
            true
        }

        fn verify_and_consume<'a>(
            &'a self,
            _tenant_id: &'a str,
            _client_id: &'a str,
            _input: &'a VerifiedInput,
        ) -> FapiFuture<'a, Result<(), FapiSignatureVerificationError>> {
            self.verify_calls.fetch_add(1, Ordering::Relaxed);
            let result = self.verification;
            Box::pin(async move { result })
        }

        fn response_signature(
            &self,
        ) -> Result<Arc<dyn FapiResponseSignature>, FapiSignatureOperationError> {
            Ok(self.signer.clone())
        }
    }

    struct SignatureTestState {
        endpoint: Data<FapiResourceEndpoint>,
        authorizer_calls: Arc<AtomicUsize>,
        targets: Arc<Mutex<Vec<Vec<String>>>>,
        verify_calls: Arc<AtomicUsize>,
        bases: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    fn signature_endpoint(
        outcome: AuthorizationOutcome,
        verification: Result<(), FapiSignatureVerificationError>,
        signer_fails: bool,
    ) -> SignatureTestState {
        let authorizer_calls = Arc::new(AtomicUsize::new(0));
        let targets = Arc::new(Mutex::new(Vec::new()));
        let verify_calls = Arc::new(AtomicUsize::new(0));
        let bases = Arc::new(Mutex::new(Vec::new()));
        let endpoint = Data::new(FapiResourceEndpoint::new(
            "https://auth.example",
            "https://mtls.auth.example",
            60,
            Arc::new(RecordingAuthorizer {
                calls: authorizer_calls.clone(),
                targets: targets.clone(),
                outcome,
            }),
            Arc::new(NoMtls),
            Arc::new(EnabledSignatures {
                verification,
                verify_calls: verify_calls.clone(),
                signer: Arc::new(TestResponseSigner {
                    fail: signer_fails,
                    bases: bases.clone(),
                }),
            }),
        ));
        SignatureTestState {
            endpoint,
            authorizer_calls,
            targets,
            verify_calls,
            bases,
        }
    }

    fn request_signature_fields(method: &str, body: &[u8], dpop: Option<&str>) -> SignatureFields {
        let authorization = "Bearer access-token";
        let digest = (!body.is_empty()).then(|| content_digest(body));
        let mut headers = vec![("authorization", authorization)];
        if let Some(dpop) = dpop {
            headers.push(("dpop", dpop));
        }
        if let Some(digest) = digest.as_deref() {
            headers.push(("content-digest", digest));
        }
        nazo_http_signatures::prepare_request(
            RequestInput {
                method,
                target_uri: "https://auth.example/fapi/resource",
                headers: &headers,
                body,
            },
            nazo_http_signatures::RequestPolicy {
                created: Utc::now().timestamp(),
                keyid: "client-key",
                algorithm: "ed25519",
                covered_headers: &[],
            },
        )
        .unwrap()
        .finish(&[3; 64])
    }

    fn endpoint(calls: Arc<AtomicUsize>) -> Data<FapiResourceEndpoint> {
        Data::new(FapiResourceEndpoint::new(
            "https://auth.example",
            "https://mtls.auth.example",
            60,
            Arc::new(Authorizer { calls }),
            Arc::new(NoMtls),
            Arc::new(DisabledSignatures),
        ))
    }

    #[actix_web::test]
    async fn handler_extracts_calls_core_and_preserves_success_contract() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = test::init_service(
            App::new().app_data(endpoint(calls.clone())).service(
                web::resource("/fapi/resource")
                    .route(web::get().to(fapi_resource))
                    .route(web::post().to(fapi_resource)),
            ),
        )
        .await;
        let request = test::TestRequest::get()
            .uri("/fapi/resource")
            .insert_header((header::AUTHORIZATION, "Bearer access-token"))
            .insert_header(("x-fapi-interaction-id", "interaction-1"))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response.headers().get("x-fapi-interaction-id").unwrap(),
            "interaction-1"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert!(!response.headers().contains_key("signature-input"));
        assert!(!response.headers().contains_key("signature"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            test::read_body_json::<Value, _>(response).await,
            json!({
                "sub": "subject-1",
                "client_id": "client-1",
                "scope": "openid profile",
                "aud": "resource-1"
            })
        );
    }

    #[actix_web::test]
    async fn missing_token_preserves_bearer_error_and_skips_core() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = test::init_service(
            App::new()
                .app_data(endpoint(calls.clone()))
                .route("/fapi/resource", web::get().to(fapi_resource)),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::get().uri("/fapi/resource").to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer error=\"invalid_token\", error_description=\"Request failed.\""
        );
        assert_eq!(
            test::read_body_json::<Value, _>(response).await,
            json!({"error":"invalid_token","error_description":"Request failed."})
        );
    }

    #[actix_web::test]
    async fn signed_get_uses_one_authorization_call_and_signs_the_success_response() {
        let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
        let app = test::init_service(
            App::new()
                .app_data(state.endpoint.clone())
                .route("/fapi/resource", web::get().to(fapi_resource)),
        )
        .await;
        let fields = request_signature_fields("GET", b"", None);
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/fapi/resource")
                .insert_header((header::AUTHORIZATION, "Bearer access-token"))
                .insert_header(("signature-input", fields.signature_input))
                .insert_header(("signature", fields.signature))
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 1);
        assert_eq!(state.verify_calls.load(Ordering::Relaxed), 1);
        assert!(response.headers().contains_key("signature-input"));
        assert!(response.headers().contains_key("signature"));
        let digest = response
            .headers()
            .get("content-digest")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body = test::read_body(response).await;
        assert!(content_digest_field_matches(&digest, &body));
        assert_eq!(
            *state.targets.lock().unwrap(),
            vec![vec![
                "https://auth.example/fapi/resource".to_owned(),
                "https://mtls.auth.example/fapi/resource".to_owned(),
            ]]
        );
        let bases = state.bases.lock().unwrap();
        let base = std::str::from_utf8(&bases[0]).unwrap();
        assert!(base.contains("\"@status\""));
        assert!(base.contains("\"@method\";req"));
        assert!(base.contains("\"@target-uri\";req"));
        assert!(base.contains("\"signature\";req"));
    }

    #[actix_web::test]
    async fn signed_post_binds_the_received_request_digest() {
        let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
        let app = test::init_service(
            App::new()
                .app_data(state.endpoint.clone())
                .route("/fapi/resource", web::post().to(fapi_resource)),
        )
        .await;
        let body = b"operation=read";
        let digest = content_digest(body);
        let fields = request_signature_fields("POST", body, None);
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/fapi/resource")
                .insert_header((header::AUTHORIZATION, "Bearer access-token"))
                .insert_header(("content-digest", digest.as_str()))
                .insert_header(("signature-input", fields.signature_input))
                .insert_header(("signature", fields.signature))
                .set_payload(body.as_slice())
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 1);
        assert_eq!(state.verify_calls.load(Ordering::Relaxed), 1);
        let bases = state.bases.lock().unwrap();
        let base = std::str::from_utf8(&bases[0]).unwrap();
        assert!(base.contains("\"content-digest\";req"));
        assert!(base.contains(digest.as_str()));
    }

    #[actix_web::test]
    async fn malformed_or_duplicate_signature_fields_fail_before_authorization_and_are_signed() {
        for duplicate in [false, true] {
            let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
            let app = test::init_service(
                App::new()
                    .app_data(state.endpoint.clone())
                    .route("/fapi/resource", web::get().to(fapi_resource)),
            )
            .await;
            let mut request = test::TestRequest::get()
                .uri("/fapi/resource")
                .insert_header((header::AUTHORIZATION, "Bearer access-token"));
            if duplicate {
                request = request
                    .append_header(("signature-input", "sig=()"))
                    .append_header(("signature-input", "sig=()"))
                    .insert_header(("signature", "sig=:AA=:"));
            }
            let response = test::call_service(&app, request.to_request()).await;

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 0);
            assert_eq!(state.verify_calls.load(Ordering::Relaxed), 0);
            assert!(response.headers().contains_key("signature-input"));
            assert!(response.headers().contains_key("signature"));
            assert!(!response.headers().contains_key(header::CACHE_CONTROL));
        }
    }

    #[actix_web::test]
    async fn duplicate_dpop_header_preserves_invalid_dpop_contract_and_skips_core() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = test::init_service(
            App::new()
                .app_data(endpoint(calls.clone()))
                .route("/fapi/resource", web::get().to(fapi_resource)),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/fapi/resource")
                .insert_header((header::AUTHORIZATION, "DPoP access-token"))
                .append_header(("dpop", "first"))
                .append_header(("dpop", "second"))
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "DPoP error=\"invalid_dpop_proof\""
        );
        assert_eq!(
            test::read_body_json::<Value, _>(response).await,
            json!({
                "error": "invalid_dpop_proof",
                "error_description": "DPoP proof is malformed."
            })
        );
    }

    #[actix_web::test]
    async fn nonce_challenge_and_nonce_dependency_failure_keep_exact_signed_http_contracts() {
        for (outcome, status, error, description, challenge) in [
            (
                AuthorizationOutcome::UseNonce,
                StatusCode::UNAUTHORIZED,
                "use_dpop_nonce",
                "Authorization server requires nonce in DPoP proof.",
                "DPoP error=\"use_dpop_nonce\"",
            ),
            (
                AuthorizationOutcome::NonceUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "DPoP nonce validation is unavailable.",
                "DPoP error=\"server_error\"",
            ),
        ] {
            let state = signature_endpoint(outcome, Ok(()), false);
            let app = test::init_service(
                App::new()
                    .app_data(state.endpoint.clone())
                    .route("/fapi/resource", web::get().to(fapi_resource)),
            )
            .await;
            let fields = request_signature_fields("GET", b"", Some("proof"));
            let response = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/fapi/resource")
                    .insert_header((header::AUTHORIZATION, "Bearer access-token"))
                    .insert_header(("dpop", "proof"))
                    .insert_header(("signature-input", fields.signature_input))
                    .insert_header(("signature", fields.signature))
                    .to_request(),
            )
            .await;

            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
                challenge
            );
            if matches!(outcome, AuthorizationOutcome::UseNonce) {
                assert_eq!(response.headers().get("dpop-nonce").unwrap(), "nonce-1");
            }
            assert!(response.headers().contains_key("signature-input"));
            assert_eq!(
                test::read_body_json::<Value, _>(response).await,
                json!({"error": error, "error_description": description})
            );
        }
    }

    #[actix_web::test]
    async fn signature_verification_failures_preserve_status_and_signed_error_contracts() {
        for (verification, status) in [
            (
                Err(FapiSignatureVerificationError::Invalid),
                StatusCode::UNAUTHORIZED,
            ),
            (
                Err(FapiSignatureVerificationError::Replay),
                StatusCode::UNAUTHORIZED,
            ),
            (
                Err(FapiSignatureVerificationError::LookupUnavailable),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                Err(FapiSignatureVerificationError::ReplayUnavailable),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let state = signature_endpoint(AuthorizationOutcome::Success, verification, false);
            let app = test::init_service(
                App::new()
                    .app_data(state.endpoint.clone())
                    .route("/fapi/resource", web::get().to(fapi_resource)),
            )
            .await;
            let fields = request_signature_fields("GET", b"", None);
            let response = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri("/fapi/resource")
                    .insert_header((header::AUTHORIZATION, "Bearer access-token"))
                    .insert_header(("signature-input", fields.signature_input))
                    .insert_header(("signature", fields.signature))
                    .to_request(),
            )
            .await;

            assert_eq!(response.status(), status);
            assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 1);
            assert_eq!(state.verify_calls.load(Ordering::Relaxed), 1);
            assert!(response.headers().contains_key("signature-input"));
            assert!(response.headers().contains_key("signature"));
        }
    }

    #[actix_web::test]
    async fn response_signer_failure_returns_an_empty_unsigned_503() {
        let state = signature_endpoint(AuthorizationOutcome::InvalidDpop, Ok(()), true);
        let app = test::init_service(
            App::new()
                .app_data(state.endpoint.clone())
                .route("/fapi/resource", web::get().to(fapi_resource)),
        )
        .await;
        let fields = request_signature_fields("GET", b"", None);
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/fapi/resource")
                .insert_header((header::AUTHORIZATION, "Bearer access-token"))
                .insert_header(("signature-input", fields.signature_input))
                .insert_header(("signature", fields.signature))
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key("signature-input"));
        assert!(!response.headers().contains_key("signature"));
        assert!(test::read_body(response).await.is_empty());
    }

    #[actix_web::test]
    async fn response_signing_preserves_multiple_physical_header_values() {
        let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
        let fields = request_signature_fields("GET", b"", None);
        let request = test::TestRequest::get()
            .uri("/fapi/resource")
            .insert_header((header::AUTHORIZATION, "Bearer access-token"))
            .insert_header(("signature-input", fields.signature_input))
            .insert_header(("signature", fields.signature))
            .to_http_request();
        let original = CapturedRequest::capture("https://auth.example", &request, &Bytes::new());
        let response = HttpResponse::Ok()
            .append_header((header::SET_COOKIE, "first=1; Secure"))
            .append_header((header::SET_COOKIE, "second=2; Secure"))
            .json(json!({"ok": true}));

        let signed = sign_response(&state.endpoint, &original, response).await;
        assert_eq!(signed.status(), StatusCode::OK);
        assert_eq!(signed.headers().get_all(header::SET_COOKIE).count(), 2);
        assert!(signed.headers().contains_key("signature-input"));
        assert!(signed.headers().contains_key("signature"));
    }

    #[actix_web::test]
    async fn signature_enabled_endpoint_rejects_form_body_access_tokens_before_core() {
        let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
        let app = test::init_service(
            App::new()
                .app_data(state.endpoint.clone())
                .route("/fapi/resource", web::post().to(fapi_resource)),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/fapi/resource")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .set_payload("access_token=form-token")
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 0);
        assert_eq!(state.verify_calls.load(Ordering::Relaxed), 0);
        assert!(response.headers().contains_key("signature-input"));
        assert!(response.headers().contains_key("signature"));
        assert_eq!(
            test::read_body_json::<Value, _>(response).await,
            json!({
                "error": "invalid_request",
                "error_description": "Only one access token transport method may be used."
            })
        );
    }

    #[actix_web::test]
    async fn bearer_dpop_and_mtls_protocol_errors_keep_exact_http_contracts() {
        use nazo_resource_server::ProtectedResourceDependencyError;

        let cases = vec![
            (
                ProtectedResourceAuthorizationError::InvalidToken(
                    ResourceServerVerifierError::AudienceMismatch,
                ),
                AccessTokenAuthScheme::Bearer,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Request failed.",
                "Bearer error=\"invalid_token\", error_description=\"Request failed.\"",
            ),
            (
                ProtectedResourceAuthorizationError::InvalidToken(
                    ResourceServerVerifierError::Expired,
                ),
                AccessTokenAuthScheme::Bearer,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Request failed.",
                "Bearer error=\"invalid_token\", error_description=\"Request failed.\"",
            ),
            (
                ProtectedResourceAuthorizationError::InvalidTenantBoundary,
                AccessTokenAuthScheme::Bearer,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Request failed.",
                "Bearer error=\"invalid_token\", error_description=\"Request failed.\"",
            ),
            (
                ProtectedResourceAuthorizationError::Revoked,
                AccessTokenAuthScheme::Bearer,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Request failed.",
                "Bearer error=\"invalid_token\", error_description=\"Request failed.\"",
            ),
            (
                ProtectedResourceAuthorizationError::DependencyUnavailable(
                    ProtectedResourceDependencyError::RevocationLookupUnavailable,
                ),
                AccessTokenAuthScheme::Bearer,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Request failed.",
                "Bearer error=\"server_error\", error_description=\"Request failed.\"",
            ),
            (
                ProtectedResourceAuthorizationError::TokenNotDpopBound,
                AccessTokenAuthScheme::DPoP,
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                "Token is not DPoP-bound.",
                "DPoP error=\"invalid_dpop_proof\"",
            ),
            (
                ProtectedResourceAuthorizationError::MissingSenderConstraint,
                AccessTokenAuthScheme::DPoP,
                StatusCode::UNAUTHORIZED,
                "invalid_dpop_proof",
                "DPoP proof is required.",
                "DPoP error=\"invalid_dpop_proof\"",
            ),
            (
                ProtectedResourceAuthorizationError::MissingSenderConstraint,
                AccessTokenAuthScheme::Bearer,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "mTLS-bound access token requires a verified client certificate.",
                "Bearer error=\"invalid_token\", error_description=\"mTLS-bound access token requires a verified client certificate.\"",
            ),
            (
                ProtectedResourceAuthorizationError::DpopBindingMismatch,
                AccessTokenAuthScheme::DPoP,
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                "DPoP binding mismatch.",
                "DPoP error=\"invalid_dpop_proof\"",
            ),
            (
                ProtectedResourceAuthorizationError::ReplayDetected,
                AccessTokenAuthScheme::DPoP,
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                "DPoP proof jti has already been used.",
                "DPoP error=\"invalid_dpop_proof\"",
            ),
            (
                ProtectedResourceAuthorizationError::InvalidDpopProof(
                    DpopProofVerifierError::MalformedProof,
                ),
                AccessTokenAuthScheme::DPoP,
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                "DPoP proof is malformed.",
                "DPoP error=\"invalid_dpop_proof\"",
            ),
            (
                ProtectedResourceAuthorizationError::InvalidDpopProof(
                    DpopProofVerifierError::ReplayDetected,
                ),
                AccessTokenAuthScheme::DPoP,
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                "DPoP proof jti has already been used.",
                "DPoP error=\"invalid_dpop_proof\"",
            ),
            (
                ProtectedResourceAuthorizationError::InvalidDpopProof(
                    DpopProofVerifierError::InvalidSignature,
                ),
                AccessTokenAuthScheme::DPoP,
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                "DPoP proof validation failed.",
                "DPoP error=\"invalid_dpop_proof\"",
            ),
            (
                ProtectedResourceAuthorizationError::MtlsBindingMismatch,
                AccessTokenAuthScheme::Bearer,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "mTLS-bound access token certificate mismatch.",
                "Bearer error=\"invalid_token\", error_description=\"mTLS-bound access token certificate mismatch.\"",
            ),
            (
                ProtectedResourceAuthorizationError::DependencyUnavailable(
                    ProtectedResourceDependencyError::DpopNonceStoreUnavailable,
                ),
                AccessTokenAuthScheme::DPoP,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "DPoP nonce validation is unavailable.",
                "DPoP error=\"server_error\"",
            ),
        ];

        for (error, scheme, status, code, description, challenge) in cases {
            let response = protocol_error_response(error, scheme);
            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            assert_eq!(
                response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
                challenge
            );
            let body = to_bytes(response.into_body()).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"error": code, "error_description": description})
            );
        }

        let nonce = "resource-nonce-1";
        let response = protocol_error_response(
            ProtectedResourceAuthorizationError::UseDpopNonce(nonce.to_owned()),
            AccessTokenAuthScheme::DPoP,
        );
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get("dpop-nonce").unwrap(), nonce);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "DPoP error=\"use_dpop_nonce\""
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&to_bytes(response.into_body()).await.unwrap())
                .unwrap(),
            json!({
                "error": "use_dpop_nonce",
                "error_description": "Authorization server requires nonce in DPoP proof."
            })
        );
    }
}
