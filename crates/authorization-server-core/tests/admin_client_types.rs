use nazo_auth::{
    AdminClientCryptoPort, AdminClientError, AdminClientPolicy, ClientPresentationMetadata,
    ClientSecurityPolicy, CreatedClient, OAuthClient, PatchClientRequest,
    PreparedClientRegistration, SectorIdentifierFuture, SectorIdentifierResolverPort,
    ValidatedClientRegistration, prepare_client_patch,
};
use nazo_identity::TenantContext;
use serde_json::json;
use uuid::Uuid;

struct TestCrypto;

impl AdminClientCryptoPort for TestCrypto {
    fn response_signing_algorithms(&self) -> Vec<String> {
        ["EdDSA", "ES256", "PS256", "RS256"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn issue_client_secret(&self, _pepper: &str) -> (String, String) {
        ("issued-secret".to_owned(), "hashed-secret".to_owned())
    }

    fn validate_jwks(&self, _jwks: &serde_json::Value) -> Result<(), String> {
        Ok(())
    }

    fn validate_rfc4514_dn(&self, _value: &str) -> Result<(), String> {
        Ok(())
    }

    fn matching_encryption_key_count(&self, _jwks: &serde_json::Value, _algorithm: &str) -> usize {
        1
    }

    fn contains_signing_key(&self, _jwks: &serde_json::Value) -> bool {
        true
    }

    fn valid_self_signed_mtls_jwks(&self, _jwks: &serde_json::Value) -> bool {
        true
    }
}

struct StaticSectorIdentifier(Vec<String>);

impl SectorIdentifierResolverPort for StaticSectorIdentifier {
    fn resolve<'a>(&'a self, _uri: &'a str) -> SectorIdentifierFuture<'a> {
        let values = self.0.clone();
        Box::pin(async move { Ok(values) })
    }
}

fn registration() -> ValidatedClientRegistration {
    ValidatedClientRegistration {
        client_id: "client-types".to_owned(),
        client_name: "Types client".to_owned(),
        client_type: "public".to_owned(),
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_owned()],
        allowed_audiences: vec!["resource://default".to_owned()],
        grant_types: vec!["authorization_code".to_owned()],
        token_endpoint_auth_method: "none".to_owned(),
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
        require_dpop_bound_tokens: false,
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        backchannel_token_delivery_mode: "poll".to_owned(),
        backchannel_client_notification_endpoint: None,
        backchannel_authentication_request_signing_alg: None,
        backchannel_user_code_parameter: false,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
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
        presentation: ClientPresentationMetadata::default(),
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
        security_policy: Some(ClientSecurityPolicy::default()),
    }
}

fn prepared() -> PreparedClientRegistration {
    PreparedClientRegistration {
        tenant: TenantContext::default(),
        conformance_lease_id: Some(Uuid::now_v7()),
        registration: registration(),
        require_mtls_bound_tokens: true,
        issued_secret: Some("issued-secret".to_owned()),
        client_secret_hash: Some("hashed-secret".to_owned()),
        registration_access_token_blake3: Some("registration-token-digest".to_owned()),
    }
}

#[test]
fn prepared_and_created_client_debug_redacts_all_secret_material() {
    let mut value = prepared();
    let debug = format!("{value:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("issued-secret"));
    assert!(!debug.contains("hashed-secret"));
    assert!(!debug.contains("registration-token-digest"));

    assert_eq!(value.client_name, "Types client");
    value.client_name = "Updated client".to_owned();
    assert_eq!(value.registration.client_name, "Updated client");

    let created = CreatedClient {
        client: OAuthClient {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            organization_id: Uuid::now_v7(),
            registration: value.registration,
            require_mtls_bound_tokens: true,
            is_active: true,
        },
        issued_secret: Some("created-secret".to_owned()),
    };
    let created_debug = format!("{created:?}");
    assert!(!created_debug.contains("created-secret"));
    assert!(created_debug.contains("[REDACTED]"));
    assert_eq!(created.client.client_id, "client-types");
    assert_eq!(json!(created.client.scopes), json!(["openid"]));
}

fn oauth_client() -> OAuthClient {
    OAuthClient {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        realm_id: Uuid::now_v7(),
        organization_id: Uuid::now_v7(),
        registration: registration(),
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}

fn policy(pairwise_subject_secret: Option<&str>) -> AdminClientPolicy {
    AdminClientPolicy {
        tenant: TenantContext::default(),
        pairwise_subject_secret: pairwise_subject_secret.map(str::to_owned),
        client_secret_pepper: "pepper".to_owned(),
    }
}

#[test]
fn client_patch_preserves_pairwise_host_and_rejects_unsafe_transitions() {
    let crypto = TestCrypto;
    let resolver = StaticSectorIdentifier(vec!["https://client.example/callback".to_owned()]);

    let mut cached = oauth_client();
    cached.subject_type = "pairwise".to_owned();
    cached.sector_identifier_uri = Some("https://sector.example/sector.json".to_owned());
    cached.sector_identifier_host = Some("client.example".to_owned());
    let cached = futures_executor::block_on(prepare_client_patch(
        cached,
        PatchClientRequest {
            subject_type: Some("pairwise".to_owned()),
            ..PatchClientRequest::default()
        },
        &policy(Some("pairwise-secret")),
        &resolver,
        &crypto,
    ))
    .expect("existing pairwise host should be retained");
    assert_eq!(
        cached.sector_identifier_host.as_deref(),
        Some("client.example")
    );

    let mut immutable = oauth_client();
    immutable.sector_identifier_uri = Some("https://sector.example/sector.json".to_owned());
    let error = futures_executor::block_on(prepare_client_patch(
        immutable,
        PatchClientRequest {
            sector_identifier_uri: Some("https://other.example/sector.json".to_owned()),
            ..PatchClientRequest::default()
        },
        &policy(Some("pairwise-secret")),
        &resolver,
        &crypto,
    ))
    .expect_err("pairwise sector identifier must be immutable");
    assert!(matches!(error, AdminClientError::InvalidRequest(_)));

    let error = futures_executor::block_on(prepare_client_patch(
        oauth_client(),
        PatchClientRequest {
            subject_type: Some("pairwise".to_owned()),
            ..PatchClientRequest::default()
        },
        &policy(None),
        &resolver,
        &crypto,
    ))
    .expect_err("pairwise clients require the deployment secret");
    assert!(matches!(error, AdminClientError::InvalidRequest(_)));

    let resolved = futures_executor::block_on(prepare_client_patch(
        oauth_client(),
        PatchClientRequest {
            subject_type: Some("pairwise".to_owned()),
            sector_identifier_uri: Some("https://sector.example/sector.json".to_owned()),
            ..PatchClientRequest::default()
        },
        &policy(Some("pairwise-secret")),
        &resolver,
        &crypto,
    ))
    .expect("sector identifier document should resolve");
    assert_eq!(
        resolved.sector_identifier_host.as_deref(),
        Some("sector.example")
    );
}

#[test]
fn client_patch_applies_optional_registration_metadata_as_one_update() {
    let crypto = TestCrypto;
    let resolver = StaticSectorIdentifier(vec!["https://client.example/callback".to_owned()]);
    let updated = futures_executor::block_on(prepare_client_patch(
        oauth_client(),
        PatchClientRequest {
            scopes: Some(vec!["openid".to_owned(), "profile".to_owned()]),
            allowed_audiences: Some(vec!["resource://accounts".to_owned()]),
            grant_types: Some(vec![
                "authorization_code".to_owned(),
                "urn:openid:params:grant-type:ciba".to_owned(),
            ]),
            require_dpop_bound_tokens: Some(true),
            require_mtls_bound_tokens: Some(false),
            allow_client_assertion_audience_array: Some(false),
            allow_client_assertion_endpoint_audience: Some(false),
            require_par_request_object: Some(false),
            backchannel_token_delivery_mode: Some("ping".to_owned()),
            backchannel_client_notification_endpoint: Some(
                " https://client.example/ciba/notify ".to_owned(),
            ),
            backchannel_authentication_request_signing_alg: Some("PS256".to_owned()),
            backchannel_user_code_parameter: Some(false),
            backchannel_logout_uri: Some(" https://client.example/backchannel ".to_owned()),
            backchannel_logout_session_required: Some(true),
            frontchannel_logout_uri: Some(" https://client.example/frontchannel ".to_owned()),
            frontchannel_logout_session_required: Some(true),
            tls_client_auth_subject_dn: Some("CN=client".to_owned()),
            tls_client_auth_cert_sha256: Some("aa".repeat(32)),
            tls_client_auth_san_dns: Some(vec!["client.example".to_owned()]),
            tls_client_auth_san_uri: Some(vec!["https://client.example/san".to_owned()]),
            tls_client_auth_san_ip: Some(vec!["127.0.0.1".to_owned()]),
            tls_client_auth_san_email: Some(vec!["admin@client.example".to_owned()]),
            jwks: Some(json!({"keys": []})),
            is_active: Some(false),
            ..PatchClientRequest::default()
        },
        &policy(None),
        &resolver,
        &crypto,
    ))
    .expect("optional client metadata should be applied atomically");

    assert_eq!(updated.scopes, ["openid", "profile"]);
    assert_eq!(updated.allowed_audiences, ["resource://accounts"]);
    assert!(updated.require_dpop_bound_tokens);
    assert_eq!(updated.backchannel_token_delivery_mode, "ping");
    assert_eq!(
        updated.backchannel_client_notification_endpoint.as_deref(),
        Some("https://client.example/ciba/notify")
    );
    assert_eq!(updated.tls_client_auth_san_ip, ["127.0.0.1"]);
    assert!(!updated.is_active);
}

#[test]
fn admin_client_ports_and_errors_have_stable_operator_messages() {
    use nazo_auth::{AdminClientError, AdminClientPortError};

    for (error, expected) in [
        (
            AdminClientPortError::Unavailable,
            "admin client repository unavailable",
        ),
        (
            AdminClientPortError::Conflict,
            "admin client repository conflict",
        ),
        (
            AdminClientPortError::CorruptData,
            "admin client repository returned corrupt data",
        ),
        (
            AdminClientPortError::Unexpected,
            "unexpected admin client repository failure",
        ),
    ] {
        assert_eq!(error.to_string(), expected);
    }
    for (error, expected) in [
        (AdminClientError::NotFound, "admin client not found"),
        (
            AdminClientError::Consistency("invariant".to_owned()),
            "invariant",
        ),
        (
            AdminClientError::Repository(AdminClientPortError::Unavailable),
            "admin client repository unavailable",
        ),
    ] {
        assert_eq!(error.to_string(), expected);
    }
}
