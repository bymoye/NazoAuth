fn delivery_payload_response(raw: &str) -> HttpResponse {
    match serde_json::from_str(raw) {
        Ok(value) => delivery_value_response(value),
        Err(_) => authorization_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "凭据内容无效.",
        ),
    }
}

use super::*;
use nazo_http_actix::OAuthJsonErrorFields;

#[actix_web::test]
async fn delivery_payload_response_adds_read_once_notice_without_dropping_credentials() {
    let response = delivery_payload_response(
        r#"{"delivery_state":"committed","request_id":"00000000-0000-0000-0000-000000000010","user_id":"00000000-0000-0000-0000-000000000011","approved_client_id":"00000000-0000-0000-0000-000000000012","client_id":"client-1","client_secret":"secret-1","client_name":"Example"}"#,
    );

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(actix_web::http::header::CACHE_CONTROL),
        Some(&actix_web::http::header::HeaderValue::from_static(
            "no-store"
        ))
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["client_id"], "client-1");
    assert_eq!(body["client_secret"], "secret-1");
    assert_eq!(body["client_name"], "Example");
    assert!(body.get("delivery_state").is_none());
    assert!(body.get("approved_client_id").is_none());
    assert_eq!(
        body["read_once_notice"],
        "此凭据已完成一次性读取并销毁，请立即保存敏感信息。"
    );
}

#[test]
fn delivery_payload_response_rejects_uncommitted_or_orphaned_payloads() {
    for payload in [
        r#"{"delivery_state":"staged","client_id":"client-1","client_secret":"secret-1"}"#,
        r#"{"client_id":"client-1","client_secret":"secret-1"}"#,
    ] {
        let response = delivery_payload_response(payload);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[test]
fn delivery_payload_response_fails_closed_for_corrupted_stored_payload() {
    let response = delivery_payload_response("{not-json");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
}
