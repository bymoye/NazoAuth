use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};

use actix_web::{
    App,
    http::{Method, StatusCode},
    test, web,
};
use nazo_runtime_modules::{ModuleId, ModuleRevision};
use serde_json::json;

use super::*;

struct TestSnapshots {
    calls: AtomicUsize,
}

impl MetadataSnapshotSource for TestSnapshots {
    fn snapshot(&self) -> MetadataSnapshot {
        self.calls.fetch_add(1, Ordering::Relaxed);
        MetadataSnapshot {
            active_modules: Arc::new(ActiveModuleSnapshot {
                revision: ModuleRevision::new(7),
                accepting: [ModuleId::Ciba].into_iter().collect(),
                draining: BTreeSet::new(),
            }),
            active_signing_algorithms: vec!["RS256"],
            id_token_signing_algorithms: vec!["RS256", "PS256"],
            response_signing_algorithms: vec!["PS256"],
            jwks: json!({"keys": [{"kid": "current", "alg": "PS256"}]}),
        }
    }
}

fn handles(source: Arc<TestSnapshots>) -> MetadataHandles {
    MetadataHandles::new(
        MetadataEndpointConfig {
            issuer: "https://issuer.example".to_owned(),
            mtls_endpoint_base_url: "https://mtls.issuer.example".to_owned(),
            mtls_enabled: false,
            authorization_server_profile: MetadataAuthorizationServerProfile::Oauth2Baseline,
            ciba_profile: CibaMetadataProfile::FapiCiba,
            subject_type: MetadataSubjectType::Public,
            pairwise_subject_enabled: false,
            protected_resource_identifier: "https://issuer.example/fapi/resource".to_owned(),
            require_pushed_authorization_requests: false,
        },
        source,
    )
}

#[actix_web::test]
async fn focused_metadata_routes_preserve_transport_and_snapshot_contracts() {
    let source = Arc::new(TestSnapshots {
        calls: AtomicUsize::new(0),
    });
    let app = test::init_service(
        App::new()
            .app_data(Data::new(handles(source.clone())))
            .service(
                web::scope("/.well-known")
                    .route("/openid-configuration", web::get().to(discovery))
                    .route(
                        "/oauth-authorization-server",
                        web::get().to(oauth_authorization_server_metadata),
                    )
                    .route(
                        "/oauth-protected-resource",
                        web::get().to(oauth_protected_resource_metadata),
                    )
                    .route(
                        "/oauth-protected-resource/{tail:.*}",
                        web::get().to(oauth_protected_resource_metadata),
                    ),
            )
            .service(web::resource("/jwks.json").route(web::get().to(jwks))),
    )
    .await;

    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let response =
            test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json"),
            "GET {path}"
        );
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["issuer"], "https://issuer.example");
        assert_eq!(
            body["grant_types_supported"][3],
            "urn:openid:params:grant-type:ciba"
        );
        assert_eq!(
            body["id_token_signing_alg_values_supported"],
            json!(["PS256", "RS256"])
        );
        assert_eq!(
            body["authorization_signing_alg_values_supported"],
            json!(["PS256"])
        );
    }

    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/fapi/resource",
    ] {
        let response =
            test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json"),
            "GET {path}"
        );
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["resource"], "https://issuer.example/fapi/resource");
        assert_eq!(
            body["authorization_servers"],
            json!(["https://issuer.example"])
        );
    }

    let response = test::call_service(
        &app,
        test::TestRequest::get().uri("/jwks.json").to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["keys"][0]["kid"], "current");
    assert_eq!(source.calls.load(Ordering::Relaxed), 5);

    for (path, expected_status) in [
        ("/.well-known/openid-configuration", StatusCode::NOT_FOUND),
        (
            "/.well-known/oauth-authorization-server",
            StatusCode::NOT_FOUND,
        ),
        (
            "/.well-known/oauth-protected-resource",
            StatusCode::NOT_FOUND,
        ),
        (
            "/.well-known/oauth-protected-resource/fapi/resource",
            StatusCode::NOT_FOUND,
        ),
        ("/jwks.json", StatusCode::METHOD_NOT_ALLOWED),
    ] {
        for method in [Method::POST, Method::OPTIONS] {
            let response = test::call_service(
                &app,
                test::TestRequest::default()
                    .method(method.clone())
                    .uri(path)
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), expected_status, "{method} {path}");
        }
    }
    assert_eq!(source.calls.load(Ordering::Relaxed), 5);
}
