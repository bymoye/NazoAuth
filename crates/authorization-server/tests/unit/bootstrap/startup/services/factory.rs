use super::*;
use actix_web::{App, HttpResponse, test, web};
use futures_util::{StreamExt as _, stream};
use std::pin::Pin;
use std::time::Duration;

async fn test_request_timeout<B>(
    request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody + 'static,
{
    request_timeout_with_duration(request, next, Duration::from_millis(10)).await
}

fn delayed_payload() -> actix_web::dev::Payload {
    let stream = stream::once(async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok::<web::Bytes, actix_web::error::PayloadError>(web::Bytes::from_static(
            br#"{"value":"ok"}"#,
        ))
    });
    let stream: Pin<
        Box<dyn futures_util::Stream<Item = Result<web::Bytes, actix_web::error::PayloadError>>>,
    > = Box::pin(stream);
    actix_web::dev::Payload::from(stream)
}

#[actix_web::test]
async fn request_timeout_covers_typed_json_extractor() {
    let app = test::init_service(App::new().wrap(from_fn(test_request_timeout)).route(
        "/json",
        web::post().to(|_: web::Json<serde_json::Value>| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = test::TestRequest::post()
        .uri("/json")
        .insert_header(("content-type", "application/json"))
        .to_request();
    let (request, _) = request.replace_payload(delayed_payload());
    let error = test::try_call_service(&app, request)
        .await
        .expect_err("slow JSON body must time out");

    assert_eq!(
        error.as_response_error().status_code(),
        actix_web::http::StatusCode::REQUEST_TIMEOUT
    );
}

#[actix_web::test]
async fn request_timeout_covers_raw_payload_extractor() {
    let app = test::init_service(App::new().wrap(from_fn(test_request_timeout)).route(
        "/raw",
        web::post().to(|mut payload: web::Payload| async move {
            while payload.next().await.is_some() {}
            HttpResponse::Ok().finish()
        }),
    ))
    .await;

    let request = test::TestRequest::post().uri("/raw").to_request();
    let (request, _) = request.replace_payload(delayed_payload());
    let error = test::try_call_service(&app, request)
        .await
        .expect_err("slow raw payload must time out");

    assert_eq!(
        error.as_response_error().status_code(),
        actix_web::http::StatusCode::REQUEST_TIMEOUT
    );
}
