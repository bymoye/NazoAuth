use actix_web::{
    HttpResponse,
    http::{
        StatusCode,
        header::{self, HeaderMap, HeaderName, HeaderValue},
    },
};
use nazo_auth::DpopError;

use crate::oauth_error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DpopErrorContext {
    TokenEndpoint,
    ProtectedResource,
}

pub fn dpop_proof_present(headers: &HeaderMap) -> bool {
    headers.contains_key(HeaderName::from_static("dpop"))
}

pub fn dpop_proof_header(headers: &HeaderMap) -> Result<Option<&str>, DpopError> {
    let mut values = headers.get_all(HeaderName::from_static("dpop"));
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(DpopError::MalformedProof);
    }
    let value = value
        .to_str()
        .map_err(|_| DpopError::MalformedProof)?
        .trim();
    Ok((!value.is_empty()).then_some(value))
}

/// Builds the exact configured endpoint URIs accepted by the DPoP core.
///
/// The request Host and forwarding headers are intentionally not consulted;
/// trusted deployment configuration remains the authority for external URIs.
pub fn dpop_target_uris(issuer: &str, mtls_endpoint_base_url: &str, path: &str) -> [String; 2] {
    [
        format!("{}{path}", issuer.trim_end_matches('/')),
        format!("{}{path}", mtls_endpoint_base_url.trim_end_matches('/')),
    ]
}

pub fn dpop_error_response(error: DpopError, context: DpopErrorContext) -> HttpResponse {
    let description = match &error {
        DpopError::MissingProof => "DPoP proof is required.",
        DpopError::MalformedProof => "DPoP proof is malformed.",
        DpopError::InvalidProof => "DPoP proof validation failed.",
        DpopError::ReplayDetected(_) => "DPoP proof jti has already been used.",
        DpopError::BindingMismatch => "DPoP binding mismatch.",
        DpopError::TokenNotBound => "Token is not DPoP-bound.",
        DpopError::UseNonce(_) => "Authorization server requires nonce in DPoP proof.",
        DpopError::NonceStoreUnavailable => "DPoP nonce validation is unavailable.",
    };
    let status = match (&error, context) {
        (DpopError::MissingProof, DpopErrorContext::TokenEndpoint) => StatusCode::BAD_REQUEST,
        (DpopError::MissingProof | DpopError::UseNonce(_), DpopErrorContext::ProtectedResource) => {
            StatusCode::UNAUTHORIZED
        }
        (DpopError::NonceStoreUnavailable, _) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    let error_code = match &error {
        DpopError::UseNonce(_) => "use_dpop_nonce",
        DpopError::NonceStoreUnavailable => "server_error",
        _ => "invalid_dpop_proof",
    };
    let mut response = oauth_error(status, error_code, description);
    if context == DpopErrorContext::TokenEndpoint {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    if let DpopError::UseNonce(nonce) = error
        && let Ok(value) = HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static("dpop-nonce"), value);
    }
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&format!("DPoP error=\"{error_code}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("DPoP")),
    );
    response
}

#[cfg(test)]
#[path = "../tests/unit/dpop.rs"]
mod tests;
