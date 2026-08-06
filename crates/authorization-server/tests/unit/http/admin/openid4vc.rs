use super::*;

#[actix_web::test]
async fn dataset_error_preserves_protocol_status_and_no_store_boundary() {
    let response = dataset_error(CredentialHttpError {
        status: 409,
        error: "invalid_request",
        description: "dataset conflict",
        dpop_nonce: None,
    });

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("credential error body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body).expect("credential error body should be JSON");
    assert_eq!(
        body.get("error"),
        Some(&serde_json::json!("invalid_request"))
    );
    assert_eq!(
        body.get("error_description"),
        Some(&serde_json::json!("dataset conflict"))
    );
}

#[test]
fn dataset_error_fails_closed_for_invalid_http_status_values() {
    let response = dataset_error(CredentialHttpError {
        status: 0,
        error: "server_error",
        description: "unavailable",
        dpop_nonce: None,
    });

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
