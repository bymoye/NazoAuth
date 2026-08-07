use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use actix_web::web::Bytes;
use nazo_http_actix::oauth_token_error;

pub(super) fn pre_authorized_parameters(
    body: &Bytes,
) -> Result<(String, Option<String>), HttpResponse> {
    let mut pre_authorized_code = None;
    let mut tx_code = None;
    for (name, value) in url::form_urlencoded::parse(body) {
        match name.as_ref() {
            "pre-authorized_code" if pre_authorized_code.is_none() && !value.is_empty() => {
                pre_authorized_code = Some(value.into_owned());
            }
            "tx_code" if tx_code.is_none() && !value.is_empty() => {
                tx_code = Some(value.into_owned());
            }
            "pre-authorized_code" | "tx_code" => {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Pre-authorized issuance parameters must be non-empty and must not repeat.",
                    false,
                ));
            }
            _ => {}
        }
    }
    pre_authorized_code
        .map(|code| (code, tx_code))
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
