use super::fixtures::*;
use super::*;
use crate::presentation::{
    PresentedAccessTokenScheme, http_authorization_headers, http_dpop_headers,
    presented_authorization_token, query_has_access_token, single_dpop_header,
};
use serde_json::json;

#[test]
fn authorization_header_parser_rejects_missing_duplicate_and_malformed_values() {
    assert_eq!(
        presented_authorization_token(&[]).unwrap_err(),
        ResourceServerRequestError::MissingToken
    );
    assert_eq!(
        presented_authorization_token(&["Bearer token-1", "Bearer token-2"]).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
    assert_eq!(
        presented_authorization_token(&["Bearer"]).unwrap_err(),
        ResourceServerRequestError::MissingToken
    );
    assert_eq!(
        presented_authorization_token(&["   "]).unwrap_err(),
        ResourceServerRequestError::MissingToken
    );
    assert_eq!(
        presented_authorization_token(&["Bearer token extra"]).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
    assert_eq!(
        presented_authorization_token(&["Basic token"]).unwrap_err(),
        ResourceServerRequestError::MissingToken
    );
}

#[test]
fn authorization_header_parser_accepts_bearer_and_dpop_case_insensitively() {
    let bearer = presented_authorization_token(&["bearer access-token"]).unwrap();
    let dpop = presented_authorization_token(&["DPoP access-token"]).unwrap();

    assert_eq!(bearer, (PresentedAccessTokenScheme::Bearer, "access-token"));
    assert_eq!(dpop, (PresentedAccessTokenScheme::Dpop, "access-token"));
}

#[test]
fn dpop_header_parser_requires_exactly_one_non_empty_proof() {
    assert_eq!(
        single_dpop_header(&[]).unwrap_err(),
        ResourceServerRequestError::MissingSenderConstraint
    );
    assert_eq!(
        single_dpop_header(&["proof-1", "proof-2"]).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
    assert_eq!(
        single_dpop_header(&["  "]).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
    assert_eq!(single_dpop_header(&["proof-1"]).unwrap(), "proof-1");
}

#[test]
fn access_token_query_detection_decodes_form_keys_only() {
    assert!(!query_has_access_token(None));
    assert!(!query_has_access_token(Some("token=access_token")));
    assert!(query_has_access_token(Some("access_token=secret")));
    assert!(query_has_access_token(Some(
        "resource=x&access%5Ftoken=secret"
    )));
}

#[test]
fn raw_http_header_extractors_fail_closed_on_non_utf8_values() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
    );
    assert_eq!(
        http_authorization_headers(&headers).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );

    let mut headers = http::HeaderMap::new();
    headers.insert(
        "dpop",
        http::HeaderValue::from_bytes(b"proof-\xff").unwrap(),
    );
    assert_eq!(
        http_dpop_headers(&headers).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
}

#[test]
fn http_request_authorizer_inserts_verified_claims_into_extensions() {
    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let mut request = http::Request::builder()
        .uri("https://api.example/orders")
        .header(http::header::AUTHORIZATION, token)
        .body(())
        .unwrap();

    let verified = authorize_http_request(&fixture.verifier, &mut request).unwrap();

    assert_eq!(verified.subject, "subject-1");
    assert_eq!(
        request
            .extensions()
            .get::<VerifiedAccessToken>()
            .unwrap()
            .client_id,
        "client-1"
    );
}

#[test]
fn request_authorizer_rejects_query_access_tokens() {
    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let error = authorize_resource_request(
        &fixture.verifier,
        &[token.as_str()],
        Some("access_token=query-token"),
        &SenderConstraintProof::default(),
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::InvalidRequest);
}

#[test]
fn request_authorizer_rejects_duplicate_authorization_headers() {
    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let error = authorize_resource_request(
        &fixture.verifier,
        &[token.as_str(), token.as_str()],
        None,
        &SenderConstraintProof::default(),
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::InvalidRequest);
}

#[test]
fn request_authorizer_requires_verified_dpop_binding_context() {
    let fixture = fixture();
    let token = token(&fixture, json!({"cnf": {"jkt": "jkt-1"}}), None);
    let header = dpop(&token);
    let error = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof::default(),
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::MissingSenderConstraint);

    let verified = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof {
            dpop_jkt: Some("jkt-1".to_owned()),
            mtls_x5t_s256: None,
        },
    )
    .unwrap();

    assert_eq!(verified.cnf.unwrap().jkt, Some("jkt-1".to_owned()));
}

#[test]
fn request_authorizer_requires_verified_mtls_binding_context() {
    let fixture = fixture();
    let token = token(&fixture, json!({"cnf": {"x5t#S256": "thumb-1"}}), None);
    let header = bearer(&token);
    let error = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof::default(),
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::MissingSenderConstraint);

    let verified = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof {
            dpop_jkt: None,
            mtls_x5t_s256: Some("thumb-1".to_owned()),
        },
    )
    .unwrap();

    assert_eq!(verified.cnf.unwrap().x5t_s256, Some("thumb-1".to_owned()));
}

#[test]
fn dpop_request_authorizer_rejects_query_access_tokens() {
    let fixture = fixture();
    let error = authorize_dpop_resource_request(
        &fixture.verifier,
        &DpopProofVerifier::new(DpopProofVerifierConfig::default()),
        &["DPoP access-token"],
        "ignored-proof",
        Some("access_token=query-token"),
        "GET",
        "https://resource.example/data",
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::InvalidRequest);
}

#[test]
fn dpop_request_authorizer_rejects_bearer_scheme() {
    let fixture = fixture();
    let error = authorize_dpop_resource_request(
        &fixture.verifier,
        &DpopProofVerifier::new(DpopProofVerifierConfig::default()),
        &["Bearer access-token"],
        "ignored-proof",
        None,
        "GET",
        "https://resource.example/data",
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::MissingSenderConstraint);
}
