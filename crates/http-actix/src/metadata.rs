use std::sync::Arc;

use actix_web::web::{Data, Json};
use nazo_auth::{
    AuthorizationServerMetadataInput, CibaMetadataProfile, MetadataAuthorizationServerProfile,
    MetadataSigningAlgorithms, MetadataSubjectType, ProtectedResourceMetadataInput,
    authorization_server_metadata, protected_resource_metadata,
};
use nazo_runtime_modules::ActiveModuleSnapshot;
use serde_json::Value;

/// Owned, transport-facing configuration used to render standard metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataEndpointConfig {
    pub issuer: String,
    pub mtls_endpoint_base_url: String,
    pub mtls_enabled: bool,
    pub authorization_server_profile: MetadataAuthorizationServerProfile,
    pub ciba_profile: CibaMetadataProfile,
    pub subject_type: MetadataSubjectType,
    pub pairwise_subject_enabled: bool,
    pub protected_resource_identifier: String,
    pub require_pushed_authorization_requests: bool,
    pub request_uri_parameter_enabled: bool,
}

/// One request's immutable view of module admission and public signing data.
#[derive(Clone, Debug)]
pub struct MetadataSnapshot {
    pub active_modules: Arc<ActiveModuleSnapshot>,
    pub active_signing_algorithms: Vec<&'static str>,
    pub id_token_signing_algorithms: Vec<&'static str>,
    pub response_signing_algorithms: Vec<&'static str>,
    pub jwks: Value,
}

/// Supplies public, request-facing snapshots without exposing key lifecycle or storage details.
pub trait MetadataSnapshotSource: Send + Sync {
    fn snapshot(&self) -> MetadataSnapshot;
}

/// Focused Actix dependency for discovery, RFC 8414/RFC 9728 metadata, and JWKS.
#[derive(Clone)]
pub struct MetadataHandles {
    config: MetadataEndpointConfig,
    snapshots: Arc<dyn MetadataSnapshotSource>,
}

impl MetadataHandles {
    #[must_use]
    pub fn new(config: MetadataEndpointConfig, snapshots: Arc<dyn MetadataSnapshotSource>) -> Self {
        Self { config, snapshots }
    }

    fn authorization_server_metadata(&self, snapshot: &MetadataSnapshot) -> Value {
        authorization_server_metadata(
            AuthorizationServerMetadataInput {
                issuer: &self.config.issuer,
                mtls_endpoint_base_url: &self.config.mtls_endpoint_base_url,
                mtls_enabled: self.config.mtls_enabled,
                profile: self.config.authorization_server_profile,
                ciba_profile: self.config.ciba_profile,
                subject_type: self.config.subject_type,
                pairwise_subject_enabled: self.config.pairwise_subject_enabled,
                protected_resource_identifier: &self.config.protected_resource_identifier,
                require_pushed_authorization_requests: self
                    .config
                    .require_pushed_authorization_requests,
                request_uri_parameter_enabled: self.config.request_uri_parameter_enabled,
                signing_algorithms: MetadataSigningAlgorithms {
                    active: &snapshot.active_signing_algorithms,
                    id_token: &snapshot.id_token_signing_algorithms,
                    response: &snapshot.response_signing_algorithms,
                },
            },
            &snapshot.active_modules,
        )
    }

    fn protected_resource_metadata(&self, snapshot: &MetadataSnapshot) -> Value {
        protected_resource_metadata(
            ProtectedResourceMetadataInput {
                issuer: &self.config.issuer,
                protected_resource_identifier: &self.config.protected_resource_identifier,
                mtls_enabled: self.config.mtls_enabled,
            },
            &snapshot.active_modules,
        )
    }
}

/// OIDC Discovery metadata. A single immutable snapshot is used for the whole document.
pub async fn discovery(handles: Data<MetadataHandles>) -> Json<Value> {
    let snapshot = handles.snapshots.snapshot();
    Json(handles.authorization_server_metadata(&snapshot))
}

/// RFC 8414 Authorization Server metadata.
pub async fn oauth_authorization_server_metadata(handles: Data<MetadataHandles>) -> Json<Value> {
    let snapshot = handles.snapshots.snapshot();
    Json(handles.authorization_server_metadata(&snapshot))
}

/// RFC 9728 Protected Resource metadata.
pub async fn oauth_protected_resource_metadata(handles: Data<MetadataHandles>) -> Json<Value> {
    let snapshot = handles.snapshots.snapshot();
    Json(handles.protected_resource_metadata(&snapshot))
}

/// Public JSON Web Key Set derived from the current key snapshot.
pub async fn jwks(handles: Data<MetadataHandles>) -> Json<Value> {
    Json(handles.snapshots.snapshot().jwks)
}

#[cfg(test)]
mod tests {
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
                request_uri_parameter_enabled: false,
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
}
