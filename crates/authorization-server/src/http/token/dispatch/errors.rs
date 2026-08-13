use actix_web::HttpResponse;
use actix_web::http::{StatusCode, header};
use nazo_http_actix::{TokenForm, oauth_token_error};

pub(super) fn authorization_code_holder_missing_client_error(
    dpop_bound: bool,
    mtls_bound: bool,
) -> Option<HttpResponse> {
    if mtls_bound {
        return Some(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization code proof of possession validation failed.",
            false,
        ));
    }
    if dpop_bound {
        return Some(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code proof of possession validation failed.",
            false,
        ));
    }
    None
}

pub(super) fn client_credentials_holder_missing_client_error(
    form: &TokenForm,
    dpop_present: bool,
) -> Option<HttpResponse> {
    if form.grant_type != "client_credentials" || dpop_present {
        return None;
    }
    Some(oauth_token_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "client_credentials requires a holder-of-key proof.",
        false,
    ))
}

pub(super) fn pre_authorized_token_error(
    error: nazo_openid4vc_http_actix::CredentialHttpError,
) -> HttpResponse {
    let mut response = oauth_token_error(
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
        error.error,
        error.description,
        false,
    );
    if let Some(challenge) = match error.error {
        "use_dpop_nonce" => Some(header::HeaderValue::from_static(
            r#"DPoP error="use_dpop_nonce""#,
        )),
        "invalid_dpop_proof" => Some(header::HeaderValue::from_static(
            r#"DPoP error="invalid_dpop_proof""#,
        )),
        _ => None,
    } {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
    }
    if let Some(nonce) = error.dpop_nonce
        && let Ok(value) = header::HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("dpop-nonce"), value);
    }
    response
}
