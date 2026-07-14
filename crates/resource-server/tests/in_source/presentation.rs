use super::*;
use crate::{
    ConfirmationClaims, ResourceServerRequestError, VerifiedAccessToken,
    VerifiedSenderConstraintProof,
};
use http::{HeaderMap, HeaderValue};
use serde_json::json;

fn headers(values: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in values {
        map.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    map
}

#[test]
fn http_authorization_headers_accepts_single_header() {
    let map = headers(&[("authorization", "Bearer token-1")]);
    let result = http_authorization_headers(&map).unwrap();
    assert_eq!(result, vec!["Bearer token-1"]);
}

#[test]
fn http_authorization_headers_accepts_multiple_headers() {
    let mut map = HeaderMap::new();
    map.append("authorization", "Bearer token-1".parse().unwrap());
    map.append("authorization", "Bearer token-2".parse().unwrap());
    let result = http_authorization_headers(&map).unwrap();
    assert_eq!(result, vec!["Bearer token-1", "Bearer token-2"]);
}

#[test]
fn http_authorization_headers_rejects_invalid_utf8() {
    let mut map = HeaderMap::new();
    map.insert(
        "authorization",
        HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
    );
    assert_eq!(
        http_authorization_headers(&map).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
}

#[test]
fn http_authorization_headers_returns_empty_for_no_headers() {
    let map = HeaderMap::new();
    let result = http_authorization_headers(&map).unwrap();
    assert!(result.is_empty());
}

#[test]
fn http_dpop_headers_accepts_single_header() {
    let map = headers(&[("dpop", "proof-1")]);
    let result = http_dpop_headers(&map).unwrap();
    assert_eq!(result, vec!["proof-1"]);
}

#[test]
fn http_dpop_headers_accepts_multiple_headers() {
    let mut map = HeaderMap::new();
    map.append("dpop", "proof-1".parse().unwrap());
    map.append("dpop", "proof-2".parse().unwrap());
    let result = http_dpop_headers(&map).unwrap();
    assert_eq!(result, vec!["proof-1", "proof-2"]);
}

#[test]
fn http_dpop_headers_rejects_invalid_utf8() {
    let mut map = HeaderMap::new();
    map.insert("dpop", HeaderValue::from_bytes(b"proof-\xff").unwrap());
    assert_eq!(
        http_dpop_headers(&map).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
}

#[test]
fn http_dpop_headers_returns_empty_for_no_headers() {
    let map = HeaderMap::new();
    let result = http_dpop_headers(&map).unwrap();
    assert!(result.is_empty());
}

#[test]
fn single_dpop_header_accepts_one_value() {
    assert_eq!(single_dpop_header(&["proof-1"]).unwrap(), "proof-1");
}

#[test]
fn single_dpop_header_rejects_empty_slice() {
    assert_eq!(
        single_dpop_header(&[]).unwrap_err(),
        ResourceServerRequestError::MissingSenderConstraint
    );
}

#[test]
fn single_dpop_header_rejects_multiple_values() {
    assert_eq!(
        single_dpop_header(&["proof-1", "proof-2"]).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
}

#[test]
fn single_dpop_header_rejects_whitespace_only() {
    assert_eq!(
        single_dpop_header(&["  "]).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
}

#[test]
fn query_has_access_token_detects_present() {
    assert!(query_has_access_token(Some("access_token=secret")));
}

#[test]
fn query_has_access_token_detects_absent() {
    assert!(!query_has_access_token(None));
    assert!(!query_has_access_token(Some("token=access_token")));
}

#[test]
fn query_has_access_token_ignores_other_params() {
    assert!(query_has_access_token(Some(
        "resource=x&access_token=secret"
    )));
}

#[test]
fn query_has_access_token_handles_url_encoded() {
    assert!(query_has_access_token(Some(
        "resource=x&access%5Ftoken=secret"
    )));
}

#[test]
fn presented_authorization_token_accepts_bearer() {
    assert_eq!(
        presented_authorization_token(&["Bearer token-1"]).unwrap(),
        (PresentedAccessTokenScheme::Bearer, "token-1")
    );
}

#[test]
fn presented_authorization_token_accepts_dpop() {
    assert_eq!(
        presented_authorization_token(&["DPoP token-1"]).unwrap(),
        (PresentedAccessTokenScheme::Dpop, "token-1")
    );
}

#[test]
fn presented_authorization_token_case_insensitive_scheme() {
    assert_eq!(
        presented_authorization_token(&["bearer token-1"]).unwrap(),
        (PresentedAccessTokenScheme::Bearer, "token-1")
    );
    assert_eq!(
        presented_authorization_token(&["dpop token-1"]).unwrap(),
        (PresentedAccessTokenScheme::Dpop, "token-1")
    );
}

#[test]
fn presented_authorization_token_rejects_empty_values() {
    assert_eq!(
        presented_authorization_token(&[]).unwrap_err(),
        ResourceServerRequestError::MissingToken
    );
}

#[test]
fn presented_authorization_token_rejects_multiple_values() {
    assert_eq!(
        presented_authorization_token(&["Bearer token-1", "Bearer token-2"]).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
}

#[test]
fn presented_authorization_token_rejects_missing_token() {
    assert_eq!(
        presented_authorization_token(&["Bearer"]).unwrap_err(),
        ResourceServerRequestError::MissingToken
    );
}

#[test]
fn presented_authorization_token_rejects_extra_parts() {
    assert_eq!(
        presented_authorization_token(&["Bearer token extra"]).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
}

#[test]
fn presented_authorization_token_rejects_unknown_scheme() {
    assert_eq!(
        presented_authorization_token(&["Basic token"]).unwrap_err(),
        ResourceServerRequestError::MissingToken
    );
}

fn verified_token(cnf: Option<ConfirmationClaims>) -> VerifiedAccessToken {
    VerifiedAccessToken {
        issuer: "issuer".to_owned(),
        subject: "subject".to_owned(),
        tenant_id: Some("00000000-0000-0000-0000-000000000001".to_owned()),
        client_id: "client-1".to_owned(),
        audiences: vec!["audience".to_owned()],
        scopes: Vec::new(),
        jti: "jti-1".to_owned(),
        exp: i64::MAX,
        cnf,
        authorization_details: json!([]),
    }
}

fn empty_proof() -> VerifiedSenderConstraintProof {
    VerifiedSenderConstraintProof {
        dpop_jkt: None,
        mtls_x5t_s256: None,
    }
}

#[test]
fn validate_presented_sender_constraint_no_cnf_bearer_ok() {
    let result = validate_presented_sender_constraint(
        PresentedAccessTokenScheme::Bearer,
        &verified_token(None),
        &empty_proof(),
    );
    assert!(result.is_ok());
}

#[test]
fn validate_presented_sender_constraint_no_cnf_dpop_fails() {
    let result = validate_presented_sender_constraint(
        PresentedAccessTokenScheme::Dpop,
        &verified_token(None),
        &empty_proof(),
    );
    assert_eq!(
        result,
        Err(ResourceServerRequestError::MissingSenderConstraint)
    );
}

#[test]
fn validate_presented_sender_constraint_cnf_jkt_with_dpop_and_matching_proof() {
    let token = verified_token(Some(ConfirmationClaims {
        jkt: Some("jkt-1".to_owned()),
        x5t_s256: None,
    }));
    let proof = VerifiedSenderConstraintProof {
        dpop_jkt: Some("jkt-1".to_owned()),
        mtls_x5t_s256: None,
    };
    assert!(
        validate_presented_sender_constraint(PresentedAccessTokenScheme::Dpop, &token, &proof,)
            .is_ok()
    );
}

#[test]
fn validate_presented_sender_constraint_cnf_jkt_without_dpop_fails() {
    let token = verified_token(Some(ConfirmationClaims {
        jkt: Some("jkt-1".to_owned()),
        x5t_s256: None,
    }));
    let result = validate_presented_sender_constraint(
        PresentedAccessTokenScheme::Bearer,
        &token,
        &empty_proof(),
    );
    assert_eq!(
        result,
        Err(ResourceServerRequestError::MissingSenderConstraint)
    );
}

#[test]
fn validate_presented_sender_constraint_cnf_jkt_dpop_jkt_mismatch() {
    let token = verified_token(Some(ConfirmationClaims {
        jkt: Some("jkt-1".to_owned()),
        x5t_s256: None,
    }));
    let proof = VerifiedSenderConstraintProof {
        dpop_jkt: Some("jkt-other".to_owned()),
        mtls_x5t_s256: None,
    };
    let result =
        validate_presented_sender_constraint(PresentedAccessTokenScheme::Dpop, &token, &proof);
    assert_eq!(result, Err(ResourceServerRequestError::DpopBindingMismatch));
}

#[test]
fn validate_presented_sender_constraint_cnf_jkt_dpop_missing_proof() {
    let token = verified_token(Some(ConfirmationClaims {
        jkt: Some("jkt-1".to_owned()),
        x5t_s256: None,
    }));
    let result = validate_presented_sender_constraint(
        PresentedAccessTokenScheme::Dpop,
        &token,
        &empty_proof(),
    );
    assert_eq!(
        result,
        Err(ResourceServerRequestError::MissingSenderConstraint)
    );
}

#[test]
fn validate_presented_sender_constraint_cnf_x5t_with_mtls_matching() {
    let token = verified_token(Some(ConfirmationClaims {
        jkt: None,
        x5t_s256: Some("thumb-1".to_owned()),
    }));
    let proof = VerifiedSenderConstraintProof {
        dpop_jkt: None,
        mtls_x5t_s256: Some("thumb-1".to_owned()),
    };
    assert!(
        validate_presented_sender_constraint(PresentedAccessTokenScheme::Bearer, &token, &proof,)
            .is_ok()
    );
}

#[test]
fn validate_presented_sender_constraint_cnf_x5t_mismatch() {
    let token = verified_token(Some(ConfirmationClaims {
        jkt: None,
        x5t_s256: Some("thumb-1".to_owned()),
    }));
    let proof = VerifiedSenderConstraintProof {
        dpop_jkt: None,
        mtls_x5t_s256: Some("thumb-other".to_owned()),
    };
    let result =
        validate_presented_sender_constraint(PresentedAccessTokenScheme::Bearer, &token, &proof);
    assert_eq!(result, Err(ResourceServerRequestError::MtlsBindingMismatch));
}

#[test]
fn validate_presented_sender_constraint_cnf_x5t_missing_mtls_proof() {
    let token = verified_token(Some(ConfirmationClaims {
        jkt: None,
        x5t_s256: Some("thumb-1".to_owned()),
    }));
    let result = validate_presented_sender_constraint(
        PresentedAccessTokenScheme::Bearer,
        &token,
        &empty_proof(),
    );
    assert_eq!(
        result,
        Err(ResourceServerRequestError::MissingSenderConstraint)
    );
}

#[test]
fn validate_presented_sender_constraint_cnf_without_jkt_or_x5t_fails() {
    let token = verified_token(Some(ConfirmationClaims {
        jkt: None,
        x5t_s256: None,
    }));
    let result = validate_presented_sender_constraint(
        PresentedAccessTokenScheme::Bearer,
        &token,
        &empty_proof(),
    );
    assert_eq!(
        result,
        Err(ResourceServerRequestError::MissingSenderConstraint)
    );
}
