use super::*;

pub(crate) fn ciba_invalid_request(description: &str) -> HttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_request", description)
}

pub(crate) fn ciba_client_assertion_algorithm_supported(
    assertion: Option<&ValidatedClientAssertion>,
) -> bool {
    assertion.is_none_or(|assertion| ciba_jwt_signing_algorithm_supported(assertion.algorithm()))
}

pub(crate) fn ciba_jwt_signing_algorithm_supported(alg: jsonwebtoken::Algorithm) -> bool {
    matches!(
        alg,
        jsonwebtoken::Algorithm::EdDSA
            | jsonwebtoken::Algorithm::ES256
            | jsonwebtoken::Algorithm::PS256
    )
}

pub(crate) fn ciba_algorithm_name(alg: jsonwebtoken::Algorithm) -> Option<&'static str> {
    match alg {
        jsonwebtoken::Algorithm::EdDSA => Some("EdDSA"),
        jsonwebtoken::Algorithm::ES256 => Some("ES256"),
        jsonwebtoken::Algorithm::PS256 => Some("PS256"),
        _ => None,
    }
}

pub(crate) fn validate_ciba_delivery_request(
    client: &ClientRow,
    form: &BackchannelAuthenticationForm,
) -> Result<(), HttpResponse> {
    match client.backchannel_token_delivery_mode.as_str() {
        "poll" if form.client_notification_token.is_some() => Err(ciba_invalid_request(
            "poll-mode CIBA clients must not send client_notification_token.",
        )),
        "poll" => Ok(()),
        "ping" => {
            let Some(token) = form.client_notification_token.as_deref() else {
                return Err(ciba_invalid_request(
                    "ping-mode CIBA clients must send client_notification_token.",
                ));
            };
            if !valid_client_notification_token(token) {
                return Err(ciba_invalid_request(
                    "client_notification_token is invalid or does not provide 128 bits of entropy.",
                ));
            }
            if client.backchannel_client_notification_endpoint.is_none() {
                return Err(ciba_invalid_request(
                    "ping-mode CIBA client has no notification endpoint.",
                ));
            }
            Ok(())
        }
        _ => Err(ciba_invalid_request(
            "CIBA client delivery mode is unsupported.",
        )),
    }
}

pub(crate) fn valid_client_notification_token(token: &str) -> bool {
    let unpadded = token.trim_end_matches('=');
    (22..=1024).contains(&token.len())
        && !unpadded.is_empty()
        && unpadded.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && token[unpadded.len()..].bytes().all(|byte| byte == b'=')
}

pub(crate) fn validate_ciba_security_profile_client_with_config(
    config: &CibaHttpConfig,
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    if !config.ciba_fapi_profile {
        return Ok(());
    }
    if client.client_type != "confidential" {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "FAPI-CIBA requires confidential clients.",
            false,
        ));
    }
    if !matches!(
        auth_method,
        "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth"
    ) {
        return Err(oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "FAPI-CIBA requires private_key_jwt or mTLS client authentication.",
            false,
        ));
    }
    let sender_constraint_valid = if config.ciba_fapi2_hardening {
        client.require_dpop_bound_tokens || client.require_mtls_bound_tokens
    } else {
        client.require_mtls_bound_tokens
    };
    if !sender_constraint_valid {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "FAPI-CIBA requires an mTLS holder-of-key access token.",
            false,
        ));
    }
    if config.ciba_fapi2_hardening
        && auth_method == "private_key_jwt"
        && (client.allow_client_assertion_audience_array
            || client.allow_client_assertion_endpoint_audience)
    {
        return Err(oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Fapi2Ciba requires private_key_jwt audience to match the authorization server issuer exactly.",
            false,
        ));
    }
    Ok(())
}

pub(crate) fn validate_ciba_token_request_profile(
    config: &CibaHttpConfig,
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    let profile = if config
        .authorization_server_profile
        .effective_client_policy(client)
        .requires_fapi2_security()
    {
        SecurityProfile::Fapi2Security
    } else {
        SecurityProfile::Baseline
    };
    let sender_constraint = match (
        client.require_dpop_bound_tokens,
        client.require_mtls_bound_tokens,
    ) {
        (false, false) => SenderConstraintPolicy::BearerAllowed,
        (true, false) => SenderConstraintPolicy::DpopRequired,
        (false, true) => SenderConstraintPolicy::MtlsRequired,
        (true, true) => SenderConstraintPolicy::DpopOrMtls,
    };
    validate_auth_token_request_profile(
        profile,
        ClientProfile {
            client_type: &client.client_type,
            authentication_method: auth_method,
            sender_constraint,
        },
    )
    .map_err(|error| {
        let status = if error.code == ProtocolErrorCode::InvalidClient {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::BAD_REQUEST
        };
        oauth_token_error(status, error.code.as_str(), error.description, false)
    })
}

pub(crate) fn validate_ciba_request_object_presence_with_config(
    config: &CibaHttpConfig,
    client: &ClientRow,
    form: &BackchannelAuthenticationForm,
) -> Result<(), HttpResponse> {
    if (client.require_par_request_object || config.ciba_fapi_profile) && form.request.is_none() {
        return Err(ciba_invalid_request("CIBA request object is required."));
    }
    Ok(())
}

pub(crate) fn non_empty(value: String) -> Option<String> {
    let value = value.trim().to_owned();
    (!value.is_empty()).then_some(value)
}
