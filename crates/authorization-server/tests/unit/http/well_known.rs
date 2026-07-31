use actix_web::{body::to_bytes, http::StatusCode};

use super::*;

#[actix_web::test]
async fn lifecycle_documents_are_closed() {
    assert_eq!(live().await.into_inner(), json!({"status": "live"}));
    assert_eq!(startup().await.into_inner(), json!({"status": "started"}));
    assert_eq!(
        captcha_config().await.into_inner(),
        json!({
            "turnstile_enabled": false,
            "turnstile_site_key": null,
            "registration_enabled": true
        })
    );
}

#[actix_web::test]
async fn readiness_reports_each_dependency_without_leaking_errors() {
    for (postgresql, valkey, status, expected) in [
        (true, true, StatusCode::OK, "ready"),
        (false, true, StatusCode::SERVICE_UNAVAILABLE, "not_ready"),
        (true, false, StatusCode::SERVICE_UNAVAILABLE, "not_ready"),
        (false, false, StatusCode::SERVICE_UNAVAILABLE, "not_ready"),
    ] {
        let response = readiness_response(postgresql, valkey);
        assert_eq!(response.status(), status);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
        assert_eq!(body["status"], expected);
        assert_eq!(
            body["checks"]["postgresql"]["status"],
            if postgresql { "up" } else { "down" }
        );
        assert_eq!(
            body["checks"]["valkey"]["status"],
            if valkey { "up" } else { "down" }
        );
    }
}
