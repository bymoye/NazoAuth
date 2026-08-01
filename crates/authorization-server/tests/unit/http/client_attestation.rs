use super::*;
use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};

#[test]
fn client_attestation_headers_require_one_complete_pair() {
    let mut headers = HeaderMap::new();
    assert_eq!(client_attestation_headers(&headers), Ok(None));

    headers.insert(
        HeaderName::from_static("oauth-client-attestation"),
        HeaderValue::from_static("attestation"),
    );
    assert_eq!(client_attestation_headers(&headers), Err(()));

    headers.insert(
        HeaderName::from_static("oauth-client-attestation-pop"),
        HeaderValue::from_static("proof"),
    );
    assert_eq!(
        client_attestation_headers(&headers),
        Ok(Some(("attestation", "proof")))
    );
}

#[test]
fn client_attestation_headers_reject_duplicates() {
    let mut headers = HeaderMap::new();
    headers.append(
        HeaderName::from_static("oauth-client-attestation"),
        HeaderValue::from_static("attestation-1"),
    );
    headers.append(
        HeaderName::from_static("oauth-client-attestation"),
        HeaderValue::from_static("attestation-2"),
    );
    headers.insert(
        HeaderName::from_static("oauth-client-attestation-pop"),
        HeaderValue::from_static("proof"),
    );

    assert_eq!(client_attestation_headers(&headers), Err(()));
}
