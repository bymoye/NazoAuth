use super::*;

#[test]
fn authorization_code_dpop_missing_proof_uses_invalid_grant() {
    let response = authorization_code_dpop_error_response(DpopError::MissingProof);

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
}

#[test]
fn authorization_code_dpop_holder_key_failures_use_invalid_grant() {
    for error in [
        DpopError::MalformedProof,
        DpopError::InvalidProof,
        DpopError::ReplayDetected(nazo_auth::DpopReplayAudit {
            jti_hash: "hash".to_owned(),
            key_id: None,
        }),
        DpopError::BindingMismatch,
        DpopError::TokenNotBound,
    ] {
        let response = authorization_code_dpop_error_response(error);

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(&response), "invalid_grant");
        assert!(
            response.headers().get(header::WWW_AUTHENTICATE).is_none(),
            "authorization code holder-of-key failures are OAuth grant errors, not DPoP challenges"
        );
    }
}

#[test]
fn authorization_code_dpop_nonce_challenge_keeps_dpop_error() {
    let response =
        authorization_code_dpop_error_response(DpopError::UseNonce("nonce-1".to_owned()));

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "use_dpop_nonce");
    assert_eq!(
        response.headers().get("dpop-nonce").unwrap(),
        HeaderValue::from_static("nonce-1")
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(r#"DPoP error="use_dpop_nonce""#)
    );
}

#[test]
fn authorization_code_mtls_holder_key_failures_use_invalid_request() {
    let response = authorization_code_mtls_holder_error_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_request");
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
}

#[test]
fn authorization_code_client_mismatch_uses_invalid_grant() {
    let response = authorization_code_client_mismatch_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
}
