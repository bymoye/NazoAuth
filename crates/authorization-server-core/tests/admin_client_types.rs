use nazo_auth::{
    ClientPresentationMetadata, ClientSecurityPolicy, CreatedClient, OAuthClient,
    PreparedClientRegistration, ValidatedClientRegistration,
};
use nazo_identity::TenantContext;
use serde_json::json;
use uuid::Uuid;

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
