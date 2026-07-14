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
mod tests {
    use actix_web::{body::to_bytes, http::header, test::TestRequest};
    use nazo_auth::DpopReplayAudit;

    use super::*;

    #[test]
    fn header_parser_rejects_duplicate_or_non_utf8_proofs() {
        let duplicate = TestRequest::default()
            .insert_header(("DPoP", "proof-1"))
            .append_header(("DPoP", "proof-2"))
            .to_http_request();
        assert_eq!(
            dpop_proof_header(duplicate.headers()),
            Err(DpopError::MalformedProof)
        );

        let non_utf8 = TestRequest::default()
            .insert_header((
                "DPoP",
                HeaderValue::from_bytes(b"\xff").expect("header bytes"),
            ))
            .to_http_request();
        assert_eq!(
            dpop_proof_header(non_utf8.headers()),
            Err(DpopError::MalformedProof)
        );
    }

    #[test]
    fn header_parser_distinguishes_absent_blank_and_present_proofs() {
        let absent = TestRequest::default().to_http_request();
        assert_eq!(dpop_proof_header(absent.headers()), Ok(None));
        assert!(!dpop_proof_present(absent.headers()));

        let blank = TestRequest::default()
            .insert_header(("DPoP", "  "))
            .to_http_request();
        assert_eq!(dpop_proof_header(blank.headers()), Ok(None));
        assert!(dpop_proof_present(blank.headers()));

        let present = TestRequest::default()
            .insert_header(("DPoP", " proof.jwt "))
            .to_http_request();
        assert_eq!(dpop_proof_header(present.headers()), Ok(Some("proof.jwt")));
    }

    #[test]
    fn target_uris_ignore_untrusted_request_authority() {
        assert_eq!(
            dpop_target_uris("https://issuer.example/", "https://mtls.example/", "/token"),
            [
                "https://issuer.example/token".to_owned(),
                "https://mtls.example/token".to_owned()
            ]
        );
    }

    #[actix_web::test]
    async fn token_endpoint_errors_preserve_status_headers_content_type_and_body() {
        let cases = [
            (DpopError::MissingProof, StatusCode::BAD_REQUEST),
            (DpopError::MalformedProof, StatusCode::BAD_REQUEST),
            (
                DpopError::ReplayDetected(DpopReplayAudit {
                    jti_hash: "hash".to_owned(),
                    key_id: None,
                }),
                StatusCode::BAD_REQUEST,
            ),
            (
                DpopError::NonceStoreUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ];
        for (error, expected_status) in cases {
            let response = dpop_error_response(error, DpopErrorContext::TokenEndpoint);
            assert_eq!(response.status(), expected_status);
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
            let body = to_bytes(response.into_body()).await.expect("response body");
            let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON error");
            assert!(body["error"].is_string());
            assert!(body["error_description"].is_string());
        }
    }

    #[test]
    fn nonce_challenge_preserves_context_specific_status_and_headers() {
        let token = dpop_error_response(
            DpopError::UseNonce("nonce-1".to_owned()),
            DpopErrorContext::TokenEndpoint,
        );
        assert_eq!(token.status(), StatusCode::BAD_REQUEST);
        assert_eq!(token.headers().get("dpop-nonce").unwrap(), "nonce-1");

        let resource = dpop_error_response(
            DpopError::UseNonce("nonce-1".to_owned()),
            DpopErrorContext::ProtectedResource,
        );
        assert_eq!(resource.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resource.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            r#"DPoP error="use_dpop_nonce""#
        );
        assert!(!resource.headers().contains_key(header::CACHE_CONTROL));
    }
}
