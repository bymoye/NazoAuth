use std::sync::{Arc, Mutex};

use actix_web::{App, http::header, test, web};
use nazo_auth::{
    AdminClientCryptoPort, SectorIdentifierFuture, SectorIdentifierResolverPort,
    ValidatedClientRegistration,
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::*;

const RP_METADATA_CHOICE_FIELDS: &[&str] = &[
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
    "id_token_encryption_alg_values_supported",
    "id_token_encryption_enc_values_supported",
    "userinfo_signing_alg_values_supported",
    "userinfo_encryption_alg_values_supported",
    "userinfo_encryption_enc_values_supported",
    "request_object_signing_alg_values_supported",
    "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc_values_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported",
    "backchannel_authentication_request_signing_alg_values_supported",
    "authorization_signing_alg_values_supported",
    "authorization_encryption_alg_values_supported",
    "authorization_encryption_enc_values_supported",
    "introspection_signing_alg_values_supported",
    "introspection_encryption_alg_values_supported",
    "introspection_encryption_enc_values_supported",
];

#[derive(Clone)]
struct FakeStore {
    client: Arc<Mutex<Option<OAuthClient>>>,
    conformance_lease_id: Arc<Mutex<Option<Uuid>>>,
}

impl FakeStore {
    fn new() -> Self {
        Self {
            client: Arc::new(Mutex::new(Some(client()))),
            conformance_lease_id: Arc::new(Mutex::new(None)),
        }
    }
}

impl DynamicRegistrationClientStore for FakeStore {
    fn insert<'a>(
        &'a self,
        prepared: &'a PreparedClientRegistration,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        let inserted = OAuthClient {
            id: Uuid::now_v7(),
            tenant_id: prepared.tenant.tenant_id.as_uuid(),
            realm_id: prepared.tenant.realm_id.as_uuid(),
            organization_id: prepared.tenant.organization_id.as_uuid(),
            registration: prepared.registration.clone(),
            require_mtls_bound_tokens: prepared.require_mtls_bound_tokens,
            is_active: true,
        };
        *self
            .conformance_lease_id
            .lock()
            .expect("conformance lease lock") = prepared.conformance_lease_id;
        *self.client.lock().expect("client lock") = Some(inserted.clone());
        Box::pin(async move { Ok(inserted) })
    }

    fn by_registration_access_token<'a>(
        &'a self,
        _tenant_id: Uuid,
        client_id: &'a str,
        _token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<OAuthClient>> {
        let found = self
            .client
            .lock()
            .expect("client lock")
            .clone()
            .filter(|client| client.client_id == client_id);
        Box::pin(async move { Ok(found) })
    }

    fn has_client_secret(&self, _client_id: Uuid) -> DynamicRegistrationFuture<'_, bool> {
        Box::pin(async { Ok(true) })
    }

    fn client_secret_salt(
        &self,
        _client_id: Uuid,
    ) -> DynamicRegistrationFuture<'_, Option<String>> {
        Box::pin(async { Ok(Some("salt".to_owned())) })
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        _client_id: Uuid,
        candidate_digest: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool> {
        let matches = candidate_digest == "digest:current-secret:pepper:salt";
        Box::pin(async move { Ok(matches) })
    }

    fn rotate_credentials<'a>(
        &'a self,
        _tenant_id: Uuid,
        _client_id: Uuid,
        _client_secret_hash: Option<&'a str>,
        _expected_registration_access_token_hash: &'a str,
        _new_registration_access_token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        let client = self.client.lock().expect("client lock").clone();
        Box::pin(async move { client.ok_or(DynamicRegistrationDependencyError::Unavailable) })
    }

    fn replace_registration<'a>(
        &'a self,
        client: &'a OAuthClient,
        _client_secret_hash: Option<&'a str>,
        _expected_registration_access_token_hash: &'a str,
        _new_registration_access_token_hash: Option<&'a str>,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        *self.client.lock().expect("client lock") = Some(client.clone());
        Box::pin(async move { Ok(client.clone()) })
    }

    fn deactivate<'a>(
        &'a self,
        _tenant_id: Uuid,
        _client_id: Uuid,
        _expected_registration_access_token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool> {
        *self.client.lock().expect("client lock") = None;
        Box::pin(async { Ok(true) })
    }
}

#[derive(Clone, Copy)]
struct FakeSecurity;

impl SectorIdentifierResolverPort for FakeSecurity {
    fn resolve<'a>(&'a self, _uri: &'a str) -> SectorIdentifierFuture<'a> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl RemoteJwksResolverPort for FakeSecurity {
    fn resolve<'a>(&'a self, _uri: &'a str) -> RemoteJwksFuture<'a> {
        Box::pin(async { Ok(json!({"keys": []})) })
    }
}

impl AdminClientCryptoPort for FakeSecurity {
    fn response_signing_algorithms(&self) -> Vec<String> {
        vec!["RS256".to_owned(), "PS256".to_owned()]
    }

    fn issue_client_secret(&self, _pepper: &str) -> (String, String) {
        ("issued-secret".to_owned(), "stored-secret-hash".to_owned())
    }

    fn validate_jwks(&self, _jwks: &Value) -> Result<(), String> {
        Ok(())
    }

    fn validate_rfc4514_dn(&self, value: &str) -> Result<(), String> {
        (!value.trim().is_empty() && value.contains('='))
            .then_some(())
            .ok_or_else(|| "invalid RFC 4514 DN".to_owned())
    }

    fn matching_encryption_key_count(&self, _jwks: &Value, _algorithm: &str) -> usize {
        1
    }

    fn contains_signing_key(&self, _jwks: &Value) -> bool {
        true
    }

    fn valid_self_signed_mtls_jwks(&self, _jwks: &Value) -> bool {
        true
    }
}

impl DynamicRegistrationSecretPort for FakeSecurity {
    fn random_token(&self) -> String {
        "registration-token".to_owned()
    }

    fn token_hash(&self, token: &str) -> String {
        format!("token-hash:{token}")
    }

    fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool {
        left == right
    }
}

impl ClientSecretDigesterPort for FakeSecurity {
    fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String {
        format!("digest:{secret}:{pepper}:{salt}")
    }
}

#[derive(Clone)]
struct FakeGuard {
    enabled: bool,
    rate_limit: Option<DynamicRegistrationRateLimitError>,
    initial_access_lease: Result<Option<Uuid>, DynamicRegistrationDependencyError>,
}

impl DynamicRegistrationRequestGuard for FakeGuard {
    fn accepts_new_requests(&self) -> bool {
        self.enabled
    }

    fn enforce_rate_limit<'a>(
        &'a self,
        _source_ip: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DynamicRegistrationRateLimitError>> + Send + 'a>>
    {
        let result = self.rate_limit.map_or(Ok(()), Err);
        Box::pin(async move { result })
    }

    fn conformance_lease_for_initial_access_token<'a>(
        &'a self,
        _token: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<Uuid>> {
        let result = self.initial_access_lease;
        Box::pin(async move { result })
    }

    fn audit(&self, _event: &'static str, _client: &OAuthClient, _source_ip: &str) {}
}

fn endpoint(enabled: bool) -> DynamicRegistrationEndpoint {
    endpoint_with_store(enabled, FakeStore::new())
}

fn endpoint_with_store(enabled: bool, store: FakeStore) -> DynamicRegistrationEndpoint {
    endpoint_with_store_and_lease_lookup(enabled, store, Ok(None))
}

fn endpoint_with_store_and_lease_lookup(
    enabled: bool,
    store: FakeStore,
    initial_access_lease: Result<Option<Uuid>, DynamicRegistrationDependencyError>,
) -> DynamicRegistrationEndpoint {
    DynamicRegistrationEndpoint::new(
        DynamicRegistrationEndpointConfig {
            issuer: "https://issuer.example".to_owned(),
            default_audience: "https://api.example".to_owned(),
            pairwise_subject_secret: None,
            client_secret_pepper: "pepper".to_owned(),
            initial_access_token: Some("initial-token".to_owned()),
            client_ip_header_mode: ClientIpHeaderMode::None,
            trusted_proxy_cidrs: Vec::new(),
            id_token_signing_algs: vec!["RS256", "PS256"],
            response_signing_algs: vec!["RS256", "PS256"],
            request_object_encryption_algs: vec!["RSA-OAEP-256"],
            request_object_encryption_encs: vec!["A256GCM"],
        },
        Arc::new(store),
        Arc::new(FakeSecurity),
        DynamicRegistrationSecurityServices::new(
            Arc::new(FakeSecurity),
            Arc::new(FakeSecurity),
            Arc::new(FakeSecurity),
            Arc::new(FakeSecurity),
        ),
        Arc::new(FakeGuard {
            enabled,
            rate_limit: None,
            initial_access_lease,
        }),
    )
}

fn configure(config: &mut web::ServiceConfig) {
    config.route("/register", web::post().to(dynamic_client_registration));
    config.service(
        web::resource("/register/{client_id}")
            .route(web::get().to(client_configuration_get))
            .route(web::put().to(client_configuration_put))
            .route(web::delete().to(client_configuration_delete)),
    );
}

#[actix_web::test]
async fn bearer_credentials_are_closed_to_exact_non_empty_scheme_and_expected_token() {
    assert!(!initial_access_token_authorized(
        &FakeSecurity,
        Some("Bearer initial-token"),
        None,
    ));
    assert!(!initial_access_token_authorized(
        &FakeSecurity,
        None,
        Some("initial-token"),
    ));
    assert!(!initial_access_token_authorized(
        &FakeSecurity,
        Some("Bearer   "),
        Some("initial-token"),
    ));
    assert!(initial_access_token_authorized(
        &FakeSecurity,
        Some("bearer initial-token"),
        Some("initial-token"),
    ));
    assert!(!initial_access_token_authorized(
        &FakeSecurity,
        Some("Bearer initial-token extra"),
        Some("initial-token"),
    ));
    assert!(initial_access_token_authorized(
        &FakeSecurity,
        Some("  Bearer initial-token  "),
        Some("initial-token"),
    ));

    let request = test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
        .to_http_request();
    assert_eq!(bearer_token(&request), Some("registration-token"));
}

#[actix_web::test]
async fn untrusted_peer_cannot_spoof_forwarded_source_ip() {
    let config = ClientIpConfig::new(
        &[IpCidr::parse("192.0.2.0/24").expect("network")],
        ClientIpHeaderMode::XForwardedFor,
    );
    let request = test::TestRequest::default()
        .peer_addr("198.51.100.10:443".parse().expect("peer"))
        .insert_header(("x-forwarded-for", "203.0.113.9"))
        .to_http_request();

    assert_eq!(client_ip_with_config(&request, &config), "198.51.100.10");
}

#[actix_web::test]
async fn trusted_proxy_chain_selects_nearest_untrusted_hop() {
    let config = ClientIpConfig::new(
        &[IpCidr::parse("192.0.2.0/24").expect("network")],
        ClientIpHeaderMode::XForwardedFor,
    );
    let request = test::TestRequest::default()
        .peer_addr("192.0.2.10:443".parse().expect("peer"))
        .insert_header(("x-forwarded-for", "203.0.113.9, 192.0.2.20"))
        .to_http_request();

    assert_eq!(client_ip_with_config(&request, &config), "203.0.113.9");
}

#[actix_web::test]
async fn disabled_module_rejects_every_method_before_body_or_credentials() {
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint(false)))
            .configure(configure),
    )
    .await;
    for request in [
        test::TestRequest::post()
            .uri("/register")
            .set_payload("not-json")
            .to_request(),
        test::TestRequest::get()
            .uri("/register/client-test")
            .to_request(),
        test::TestRequest::put()
            .uri("/register/client-test")
            .set_payload("not-json")
            .to_request(),
        test::TestRequest::delete()
            .uri("/register/client-test")
            .to_request(),
    ] {
        let response = test::call_service(&service, request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[actix_web::test]
async fn registration_authentication_error_keeps_bearer_and_no_store_contract() {
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint(true)))
            .configure(configure),
    )
    .await;
    let response = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/register")
            .set_json(json!({}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static("application/json"))
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE),
        Some(&header::HeaderValue::from_static(
            "Bearer error=\"invalid_token\", error_description=\"Initial access token is missing or invalid.\""
        ))
    );
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["error"], "invalid_token");
}

#[actix_web::test]
async fn configured_initial_access_token_keeps_secure_unleased_policy() {
    let store = FakeStore::new();
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint_with_store_and_lease_lookup(
                true,
                store.clone(),
                Ok(Some(Uuid::now_v7())),
            )))
            .configure(configure),
    )
    .await;

    let response = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/register")
            .insert_header((header::AUTHORIZATION, "Bearer initial-token"))
            .set_json(json!({
                "redirect_uris": ["https://client.example/callback"]
            }))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        *store
            .conformance_lease_id
            .lock()
            .expect("conformance lease lock"),
        None
    );
    let stored = store
        .client
        .lock()
        .expect("client lock")
        .clone()
        .expect("registered client");
    assert!(
        stored
            .security_policy
            .as_ref()
            .is_some_and(|policy| !policy.allow_confidential_oidc_without_pkce)
    );
}

#[actix_web::test]
async fn leased_initial_access_token_binds_exception_and_update_preserves_both() {
    let lease_id = Uuid::now_v7();
    let store = FakeStore::new();
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint_with_store_and_lease_lookup(
                true,
                store.clone(),
                Ok(Some(lease_id)),
            )))
            .configure(configure),
    )
    .await;

    let created = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/register")
            .insert_header((header::AUTHORIZATION, "Bearer leased-token"))
            .set_json(json!({
                "redirect_uris": ["https://client.example/callback"]
            }))
            .to_request(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: Value = test::read_body_json(created).await;
    let client_id = created["client_id"].as_str().expect("client id");
    assert_eq!(
        *store
            .conformance_lease_id
            .lock()
            .expect("conformance lease lock"),
        Some(lease_id)
    );
    assert!(
        store
            .client
            .lock()
            .expect("client lock")
            .as_ref()
            .and_then(|client| client.security_policy.as_ref())
            .is_some_and(|policy| policy.allow_confidential_oidc_without_pkce)
    );

    let updated = test::call_service(
        &service,
        test::TestRequest::put()
            .uri(&format!("/register/{client_id}"))
            .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
            .set_json(json!({
                "client_id": client_id,
                "client_secret": "current-secret",
                "client_name": "Updated leased client",
                "redirect_uris": ["https://client.example/callback"]
            }))
            .to_request(),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(
        *store
            .conformance_lease_id
            .lock()
            .expect("conformance lease lock"),
        Some(lease_id)
    );
    assert!(
        store
            .client
            .lock()
            .expect("client lock")
            .as_ref()
            .and_then(|client| client.security_policy.as_ref())
            .is_some_and(|policy| policy.allow_confidential_oidc_without_pkce)
    );
}

#[actix_web::test]
async fn leased_public_client_is_bound_without_confidential_pkce_exception() {
    let lease_id = Uuid::now_v7();
    let store = FakeStore::new();
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint_with_store_and_lease_lookup(
                true,
                store.clone(),
                Ok(Some(lease_id)),
            )))
            .configure(configure),
    )
    .await;

    let response = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/register")
            .insert_header((header::AUTHORIZATION, "Bearer leased-token"))
            .set_json(json!({
                "token_endpoint_auth_method": "none",
                "redirect_uris": ["https://client.example/callback"]
            }))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        *store
            .conformance_lease_id
            .lock()
            .expect("conformance lease lock"),
        Some(lease_id)
    );
    assert!(
        store
            .client
            .lock()
            .expect("client lock")
            .as_ref()
            .and_then(|client| client.security_policy.as_ref())
            .is_some_and(|policy| !policy.allow_confidential_oidc_without_pkce)
    );
}

#[actix_web::test]
async fn unknown_leased_initial_access_token_remains_invalid() {
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint(true)))
            .configure(configure),
    )
    .await;
    let response = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/register")
            .insert_header((header::AUTHORIZATION, "Bearer unknown-token"))
            .set_json(json!({}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["error"], "invalid_token");
}

#[actix_web::test]
async fn leased_initial_access_lookup_failure_fails_closed() {
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint_with_store_and_lease_lookup(
                true,
                FakeStore::new(),
                Err(DynamicRegistrationDependencyError::Unavailable),
            )))
            .configure(configure),
    )
    .await;
    let response = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/register")
            .insert_header((header::AUTHORIZATION, "Bearer leased-token"))
            .set_json(json!({}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["error"], "server_error");
}

#[actix_web::test]
async fn registration_and_management_methods_keep_wire_contracts() {
    let endpoint = endpoint(true);
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint))
            .configure(configure),
    )
    .await;
    let created = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/register")
            .insert_header((header::AUTHORIZATION, "Bearer initial-token"))
            .set_json(json!({
                "client_name": "Registered Client",
                "redirect_uris": ["https://client.example/callback"],
                "grant_types": [
                    "authorization_code",
                    "urn:openid:params:grant-type:ciba"
                ],
                "jwks_uri": "https://client.example/jwks.json",
                "request_uris": ["https://client.example/request.jwt"],
                "initiate_login_uri": "https://client.example/login/initiate",
                "logo_uri": "https://client.example/logo.svg",
                "policy_uri": "https://client.example/privacy",
                "tos_uri": "https://client.example/terms",
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["PS256", "RS256"],
                "id_token_encryption_alg_values_supported": ["RSA-OAEP-256"],
                "id_token_encryption_enc_values_supported": ["A256GCM"],
                "userinfo_signing_alg_values_supported": ["PS256"],
                "userinfo_encryption_alg_values_supported": ["ECDH-ES"],
                "userinfo_encryption_enc_values_supported": ["A256GCM"],
                "request_object_signing_alg_values_supported": ["PS256"],
                "request_object_encryption_alg_values_supported": ["RSA-OAEP-256"],
                "request_object_encryption_enc_values_supported": ["A256GCM"],
                "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                "token_endpoint_auth_signing_alg_values_supported": ["PS256"],
                "backchannel_authentication_request_signing_alg_values_supported": ["PS256"],
                "authorization_signing_alg_values_supported": ["PS256"],
                "authorization_encryption_alg_values_supported": ["ECDH-ES"],
                "authorization_encryption_enc_values_supported": ["A256GCM"],
                "introspection_signing_alg_values_supported": ["PS256"],
                "introspection_encryption_alg_values_supported": ["ECDH-ES"],
                "introspection_encryption_enc_values_supported": ["A256GCM"]
            }))
            .to_request(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(
        created.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    let created: Value = test::read_body_json(created).await;
    let client_id = created["client_id"].as_str().expect("client id");
    assert_eq!(created["registration_access_token"], "registration-token");
    assert!(created.get("client_secret").is_none());
    assert_eq!(created["jwks_uri"], "https://client.example/jwks.json");
    assert!(created.get("jwks").is_none());
    assert_eq!(
        created["request_uris"],
        json!(["https://client.example/request.jwt"])
    );
    assert_eq!(
        created["initiate_login_uri"],
        "https://client.example/login/initiate"
    );
    assert_eq!(created["logo_uri"], "https://client.example/logo.svg");
    assert_eq!(created["policy_uri"], "https://client.example/privacy");
    assert_eq!(created["tos_uri"], "https://client.example/terms");
    assert_eq!(created["subject_type"], "public");
    assert_eq!(created["id_token_signed_response_alg"], "PS256");
    assert_eq!(created["id_token_encrypted_response_alg"], "RSA-OAEP-256");
    assert_eq!(created["id_token_encrypted_response_enc"], "A256GCM");
    assert_eq!(created["userinfo_signed_response_alg"], "PS256");
    assert_eq!(created["userinfo_encrypted_response_alg"], "ECDH-ES");
    assert_eq!(created["userinfo_encrypted_response_enc"], "A256GCM");
    assert_eq!(created["request_object_signing_alg"], "PS256");
    assert_eq!(created["request_object_encryption_alg"], "RSA-OAEP-256");
    assert_eq!(created["request_object_encryption_enc"], "A256GCM");
    assert_eq!(created["token_endpoint_auth_method"], "private_key_jwt");
    assert_eq!(created["token_endpoint_auth_signing_alg"], "PS256");
    assert_eq!(
        created["backchannel_authentication_request_signing_alg"],
        "PS256"
    );
    assert_eq!(created["authorization_signed_response_alg"], "PS256");
    assert_eq!(created["authorization_encrypted_response_alg"], "ECDH-ES");
    assert_eq!(created["authorization_encrypted_response_enc"], "A256GCM");
    assert_eq!(created["introspection_signed_response_alg"], "PS256");
    assert_eq!(created["introspection_encrypted_response_alg"], "ECDH-ES");
    assert_eq!(created["introspection_encrypted_response_enc"], "A256GCM");
    for &choices in RP_METADATA_CHOICE_FIELDS {
        assert!(
            created.get(choices).is_none(),
            "{choices} must be input-only"
        );
    }
    assert!(created["client_id_issued_at"].is_i64());
    assert_eq!(
        created["registration_client_uri"],
        format!("https://issuer.example/register/{client_id}")
    );

    let read = test::call_service(
        &service,
        test::TestRequest::get()
            .uri(&format!("/register/{client_id}"))
            .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
            .to_request(),
    )
    .await;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(
        read.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    let read: Value = test::read_body_json(read).await;
    assert_eq!(read["registration_access_token"], "registration-token");
    assert!(read.get("client_secret").is_none());
    for selected in [
        "subject_type",
        "id_token_signed_response_alg",
        "id_token_encrypted_response_alg",
        "id_token_encrypted_response_enc",
        "userinfo_signed_response_alg",
        "userinfo_encrypted_response_alg",
        "userinfo_encrypted_response_enc",
        "request_object_signing_alg",
        "request_object_encryption_alg",
        "request_object_encryption_enc",
        "token_endpoint_auth_method",
        "token_endpoint_auth_signing_alg",
        "backchannel_authentication_request_signing_alg",
        "authorization_signed_response_alg",
        "authorization_encrypted_response_alg",
        "authorization_encrypted_response_enc",
        "introspection_signed_response_alg",
        "introspection_encrypted_response_alg",
        "introspection_encrypted_response_enc",
    ] {
        assert_eq!(
            read[selected], created[selected],
            "{selected} must round-trip"
        );
    }
    for &choices in RP_METADATA_CHOICE_FIELDS {
        assert!(
            read.get(choices).is_none(),
            "{choices} must remain input-only"
        );
    }

    let update = test::call_service(
        &service,
        test::TestRequest::put()
            .uri(&format!("/register/{client_id}"))
            .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
            .set_json(json!({
                "client_id": client_id,
                "client_secret": "current-secret",
                "client_name": "Updated Client",
                "redirect_uris": ["https://client.example/callback"]
            }))
            .to_request(),
    )
    .await;
    assert_eq!(update.status(), StatusCode::OK);
    let updated: Value = test::read_body_json(update).await;
    assert_eq!(updated["client_name"], "Updated Client");
    let updated_client_id = updated["client_id"].as_str().expect("updated client id");

    let deleted = test::call_service(
        &service,
        test::TestRequest::delete()
            .uri(&format!("/register/{updated_client_id}"))
            .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
            .to_request(),
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        deleted.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
}

#[actix_web::test]
async fn client_configuration_update_preserves_server_managed_security_policy() {
    let store = FakeStore::new();
    {
        let mut guard = store.client.lock().expect("client lock");
        let current = guard.as_mut().expect("fixture client");
        current
            .security_policy
            .as_mut()
            .expect("explicit fixture policy")
            .session_management = true;
    }
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint_with_store(true, store.clone())))
            .configure(configure),
    )
    .await;

    let response = test::call_service(
        &service,
        test::TestRequest::put()
            .uri("/register/client-test")
            .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
            .set_json(json!({
                "client_id": "client-test",
                "client_secret": "current-secret",
                "client_name": "Updated Client",
                "redirect_uris": ["https://client.example/callback"]
            }))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let stored = store
        .client
        .lock()
        .expect("client lock")
        .clone()
        .expect("updated client");
    assert!(
        stored
            .security_policy
            .as_ref()
            .is_some_and(|policy| policy.session_management)
    );
}

#[actix_web::test]
async fn client_configuration_update_preserves_absent_server_managed_policy() {
    let store = FakeStore::new();
    store
        .client
        .lock()
        .expect("client lock")
        .as_mut()
        .expect("fixture client")
        .registration
        .security_policy = None;
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint_with_store(true, store.clone())))
            .configure(configure),
    )
    .await;

    let response = test::call_service(
        &service,
        test::TestRequest::put()
            .uri("/register/client-test")
            .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
            .set_json(json!({
                "client_id": "client-test",
                "client_secret": "current-secret",
                "client_name": "Updated Client",
                "redirect_uris": ["https://client.example/callback"]
            }))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        store
            .client
            .lock()
            .expect("client lock")
            .as_ref()
            .is_some_and(|client| client.security_policy.is_none())
    );
}

#[actix_web::test]
async fn client_configuration_update_validates_current_server_managed_policy() {
    let store = FakeStore::new();
    store
        .client
        .lock()
        .expect("client lock")
        .as_mut()
        .expect("fixture client")
        .registration
        .security_policy
        .as_mut()
        .expect("explicit fixture policy")
        .version = u16::MAX;
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint_with_store(true, store.clone())))
            .configure(configure),
    )
    .await;

    let response = test::call_service(
        &service,
        test::TestRequest::put()
            .uri("/register/client-test")
            .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
            .set_json(json!({
                "client_id": "client-test",
                "client_secret": "current-secret",
                "client_name": "Updated Client",
                "redirect_uris": ["https://client.example/callback"]
            }))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let stored = store
        .client
        .lock()
        .expect("client lock")
        .clone()
        .expect("unchanged client");
    assert_eq!(stored.client_name, "Client");
}

#[actix_web::test]
async fn client_configuration_read_preserves_authenticated_registration_token() {
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint(true)))
            .configure(configure),
    )
    .await;
    let response = test::call_service(
        &service,
        test::TestRequest::get()
            .uri("/register/client-test")
            .insert_header((
                header::AUTHORIZATION,
                "Bearer authenticated-registration-token",
            ))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = test::read_body_json(response).await;
    assert_eq!(
        body["registration_access_token"],
        "authenticated-registration-token"
    );
}

#[actix_web::test]
async fn rate_limit_error_keeps_oauth_code_and_retry_after() {
    let mut endpoint = endpoint(true);
    endpoint.request_guard = Arc::new(FakeGuard {
        enabled: true,
        rate_limit: Some(DynamicRegistrationRateLimitError::Limited {
            retry_after_seconds: 30,
        }),
        initial_access_lease: Ok(None),
    });
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint))
            .configure(configure),
    )
    .await;
    let response = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/register")
            .insert_header((header::AUTHORIZATION, "Bearer initial-token"))
            .set_json(json!({}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "30");
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["error"], "temporarily_unavailable");
}

fn client() -> OAuthClient {
    OAuthClient {
        id: Uuid::now_v7(),
        tenant_id: Uuid::nil(),
        realm_id: Uuid::nil(),
        organization_id: Uuid::nil(),
        registration: ValidatedClientRegistration {
            client_id: "client-test".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            post_logout_redirect_uris: Vec::new(),
            scopes: vec!["openid".to_owned()],
            allowed_audiences: vec!["https://api.example".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            token_endpoint_auth_method: "client_secret_basic".to_owned(),
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            backchannel_token_delivery_mode: "poll".to_owned(),
            backchannel_client_notification_endpoint: None,
            backchannel_authentication_request_signing_alg: None,
            backchannel_user_code_parameter: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: Vec::new(),
            tls_client_auth_san_uri: Vec::new(),
            tls_client_auth_san_ip: Vec::new(),
            tls_client_auth_san_email: Vec::new(),
            jwks_uri: None,
            jwks: None,
            request_uris: Vec::new(),
            initiate_login_uri: None,
            presentation: nazo_auth::ClientPresentationMetadata::default(),
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_signing_alg: None,
            introspection_signed_response_alg: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            security_policy: Some(nazo_auth::ClientSecurityPolicy::default()),
        },
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}
