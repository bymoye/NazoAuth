use actix_web::{
    Error,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header::{self, HeaderMap, HeaderName, HeaderValue},
    middleware::Next,
};

pub async fn security_headers<B>(
    request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody,
{
    let is_check_session_iframe = request.path() == "/check_session";
    let mut response = next.call(request).await?;
    apply_security_headers(response.headers_mut(), is_check_session_iframe);
    Ok(response)
}

pub fn apply_security_headers(headers: &mut HeaderMap, is_check_session_iframe: bool) {
    if !is_check_session_iframe {
        insert_static_header(headers, header::X_FRAME_OPTIONS, "DENY");
        insert_static_header(
            headers,
            HeaderName::from_static("content-security-policy"),
            "frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
        );
    } else {
        insert_static_header(
            headers,
            HeaderName::from_static("content-security-policy"),
            "base-uri 'none'; object-src 'none'",
        );
    }
    insert_static_header(
        headers,
        HeaderName::from_static("referrer-policy"),
        "no-referrer",
    );
    insert_static_header(
        headers,
        HeaderName::from_static("permissions-policy"),
        "interest-cohort=()",
    );
    insert_static_header(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
}

fn insert_static_header(headers: &mut HeaderMap, name: HeaderName, value: &'static str) {
    if !headers.contains_key(&name) {
        headers.insert(name, HeaderValue::from_static(value));
    }
}
