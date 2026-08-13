use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use nazo_http_actix::{PreAuthorizedTokenParameters, oauth_token_error};

pub(super) fn pre_authorized_parameters(
    parameters: &mut PreAuthorizedTokenParameters,
) -> Result<(String, Option<String>), HttpResponse> {
    if parameters.invalid {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Pre-authorized issuance parameters must be non-empty and must not repeat.",
            false,
        ));
    }
    parameters
        .pre_authorized_code
        .take()
        .map(|code| (code, parameters.tx_code.take()))
        .ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "pre-authorized_code is required.",
                false,
            )
        })
}

#[cfg(test)]
#[path = "../../../../tests/unit/http/token/dispatch/pre_authorized.rs"]
mod tests;
