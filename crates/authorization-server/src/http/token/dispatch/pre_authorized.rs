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
mod tests {
    use super::pre_authorized_parameters;
    use actix_web::http::StatusCode;
    use actix_web::web::Bytes;

    #[test]
    fn parses_required_code_and_optional_tx_code_once() {
        let parsed = pre_authorized_parameters(&Bytes::from_static(
            b"pre-authorized_code=code-1&tx_code=1234&ignored=value",
        ))
        .expect("valid pre-authorized token parameters");
        assert_eq!(parsed, ("code-1".to_owned(), Some("1234".to_owned())));
    }

    #[test]
    fn rejects_missing_empty_and_repeated_issuance_parameters() {
        for body in [
            "",
            "tx_code=1234",
            "pre-authorized_code=",
            "pre-authorized_code=one&pre-authorized_code=two",
            "tx_code=one&tx_code=two",
        ] {
            let error = pre_authorized_parameters(&Bytes::from(body))
                .expect_err("invalid pre-authorized parameters must fail");
            assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        }
    }
}
