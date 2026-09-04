use actix_web::{body::to_bytes, http::StatusCode, web::Data};

use super::*;

struct TestTransientStateHealth(bool);

impl crate::bootstrap::TransientStateHealthPort for TestTransientStateHealth {
    fn check(&self) -> crate::bootstrap::TransientStateFuture<'_, ()> {
        let healthy = self.0;
        Box::pin(async move {
            if healthy {
                Ok(())
            } else {
                Err(crate::bootstrap::TransientStateError::Unavailable)
            }
        })
    }
}

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
    for (database, valkey, status, expected) in [
        (true, true, StatusCode::OK, "ready"),
        (false, true, StatusCode::SERVICE_UNAVAILABLE, "not_ready"),
        (true, false, StatusCode::SERVICE_UNAVAILABLE, "not_ready"),
        (false, false, StatusCode::SERVICE_UNAVAILABLE, "not_ready"),
    ] {
        let response = readiness_response(database, valkey, true);
        assert_eq!(response.status(), status);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
        assert_eq!(body["status"], expected);
        assert_eq!(
            body["checks"]["database"]["status"],
            if database { "up" } else { "down" }
        );
        assert_eq!(
            body["checks"]["transient_state"]["status"],
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
    let dependencies = Data::new(ReadinessDependencies::new(
        Arc::new(nazo_postgres::PostgresHealthCheck::new(database)),
        Arc::new(TestTransientStateHealth(false)),
        nazo_key_management::KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA),
    ));

    let response = ready(dependencies).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["checks"]["database"]["status"], "down");
    assert_eq!(body["checks"]["transient_state"]["status"], "down");
    assert_eq!(body["checks"]["signing_keys"]["status"], "up");
    assert_eq!(body.as_object().unwrap().len(), 2);
}
