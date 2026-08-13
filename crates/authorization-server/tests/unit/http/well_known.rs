use std::time::Duration;

use actix_web::{body::to_bytes, http::StatusCode, web::Data};
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};

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
        let response = readiness_response(postgresql, valkey, true);
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

    let response = readiness_response(true, true, false);
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["checks"]["signing_keys"]["status"], "down");
}

#[actix_web::test]
async fn readiness_probes_both_unavailable_dependencies_and_returns_only_closed_statuses() {
    let database = nazo_postgres::create_pool(
        "postgresql://unused:unused@127.0.0.1:1/unused?connect_timeout=1",
        1,
    )
    .unwrap();
    let mut builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url("redis://127.0.0.1:1").expect("test Valkey URL should parse"),
    );
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = Duration::from_millis(50);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = Duration::from_millis(50);
        connection.internal_command_timeout = Duration::from_millis(50);
        connection.max_command_attempts = 1;
    });
    let client = builder.build().expect("test Valkey client should build");
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(client);
    let dependencies = Data::new(ReadinessDependencies::new(
        database,
        connection,
        nazo_key_management::KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA),
    ));

    let response = ready(dependencies).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["checks"]["postgresql"]["status"], "down");
    assert_eq!(body["checks"]["valkey"]["status"], "down");
    assert_eq!(body["checks"]["signing_keys"]["status"], "up");
    assert_eq!(body.as_object().unwrap().len(), 2);
}
