use super::*;

fn client_request() -> CreateClientRequest {
    CreateClientRequest {
        client_name: "ordinary managed client".to_owned(),
        client_type: "public".to_owned(),
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_owned()],
        allowed_audiences: Vec::new(),
        grant_types: vec!["authorization_code".to_owned()],
        token_endpoint_auth_method: "none".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
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
        subject_type: None,
        sector_identifier_uri: None,
        security_policy: nazo_auth::ClientSecurityPolicy::default(),
    }
}

fn preparation() -> ServerTenantResourcePreparation {
    let tenant = nazo_identity::TenantContext::default_system();
    let database = nazo_postgres::create_pool("postgresql://unused:unused@127.0.0.1:1/unused", 1)
        .expect("lazy database pool");
    let service = web::Data::new(ServerAdminClientService::new(
        nazo_postgres::OAuthClientRepository::new(database),
        crate::http::admin::clients::ServerSectorIdentifierResolver,
        crate::http::admin::clients::ServerAdminClientCrypto::new(
            crate::test_support::test_key_manager(),
        ),
        nazo_auth::AdminClientPolicy {
            tenant,
            pairwise_subject_secret: Some("pairwise-subject-secret".to_owned()),
            client_secret_pepper: crate::adapters::security::LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER
                .to_owned(),
        },
    ));
    ServerTenantResourcePreparation::new(service)
}

#[actix_web::test]
async fn server_preparation_hashes_passwords_and_prepares_both_client_secret_modes() {
    let preparation = preparation();
    let tenant = nazo_identity::TenantContext::default_system();

    let password_hash = preparation
        .hash_user_password("correct horse battery staple".to_owned())
        .await
        .expect("password hash");
    assert_ne!(password_hash, "correct horse battery staple");
    assert!(password_hash.starts_with("$argon2"));

    let public = preparation
        .prepare_oauth_client(client_request(), None, tenant)
        .await
        .expect("public client");
    assert_eq!(public.client.tenant_id, tenant.tenant_id.as_uuid());
    assert!(public.client.is_active);
    assert_eq!(public.client_secret_hash, None);

    let mut confidential_request = client_request();
    confidential_request.client_type = "confidential".to_owned();
    confidential_request.token_endpoint_auth_method = "client_secret_basic".to_owned();
    let supplied_secret = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg".to_owned();
    let confidential = preparation
        .prepare_oauth_client(
            confidential_request.clone(),
            Some(supplied_secret.clone()),
            tenant,
        )
        .await
        .expect("confidential client with controller-supplied secret");
    assert!(confidential.client_secret_hash.is_some());
    assert!(
        !confidential
            .client_secret_hash
            .as_deref()
            .is_some_and(|hash| hash.contains(&supplied_secret))
    );

    assert!(matches!(
        preparation
            .prepare_oauth_client(confidential_request, None, tenant)
            .await,
        Err(TenantResourcePreparationError::Rejected)
    ));
}

#[actix_web::test]
async fn server_preparation_rejects_invalid_secret_and_tenant_drift() {
    let preparation = preparation();
    let tenant = nazo_identity::TenantContext::default_system();

    let mut confidential = client_request();
    confidential.client_type = "confidential".to_owned();
    confidential.token_endpoint_auth_method = "client_secret_basic".to_owned();
    assert!(matches!(
        preparation
            .prepare_oauth_client(confidential, Some(String::new()), tenant)
            .await,
        Err(TenantResourcePreparationError::Rejected)
    ));

    let another_tenant = nazo_identity::TenantContext {
        tenant_id: nazo_identity::TenantId::new(Uuid::now_v7()).expect("tenant"),
        realm_id: nazo_identity::RealmId::new(Uuid::now_v7()).expect("realm"),
        organization_id: nazo_identity::OrganizationId::new(Uuid::now_v7()).expect("organization"),
    };
    assert!(matches!(
        preparation
            .prepare_oauth_client(client_request(), None, another_tenant)
            .await,
        Err(TenantResourcePreparationError::Rejected)
    ));
}

#[test]
fn machine_management_never_exposes_loopback_http_on_a_non_loopback_bind() {
    let exposed: SocketAddr = "0.0.0.0:8000".parse().unwrap();
    let loopback: SocketAddr = "127.0.0.1:8000".parse().unwrap();

    assert!(validate_management_transport(TransportMode::LoopbackHttp, exposed).is_err());
    assert!(validate_management_transport(TransportMode::LoopbackHttp, loopback).is_ok());
    assert!(validate_management_transport(TransportMode::DirectTls, exposed).is_ok());
    assert!(validate_management_transport(TransportMode::TrustedProxy, exposed).is_ok());
}

#[test]
fn capability_advertises_every_executable_resource_kind() {
    assert_eq!(
        supported_resource_kinds(false),
        vec![
            TenantResourceKind::User,
            TenantResourceKind::OauthClient,
            TenantResourceKind::MtlsTrustAnchor,
            TenantResourceKind::Openid4vcTrustPolicy,
        ]
    );
    assert_eq!(
        supported_resource_kinds(true),
        vec![
            TenantResourceKind::User,
            TenantResourceKind::OauthClient,
            TenantResourceKind::MtlsTrustAnchor,
            TenantResourceKind::Openid4vcTrustPolicy,
            TenantResourceKind::Openid4vcDataset,
        ]
    );
}

#[test]
fn admin_client_failures_preserve_rejected_vs_unavailable_boundary() {
    for error in [
        AdminClientError::InvalidRequest("invalid".to_owned()),
        AdminClientError::NotFound,
    ] {
        assert!(matches!(
            map_admin_client_error(error),
            TenantResourcePreparationError::Rejected
        ));
    }
    for error in [
        AdminClientError::Repository(nazo_auth::AdminClientPortError::Unavailable),
        AdminClientError::Lookup(nazo_auth::AdminClientPortError::CorruptData),
        AdminClientError::Write(nazo_auth::AdminClientPortError::Conflict),
        AdminClientError::Consistency("drift".to_owned()),
    ] {
        assert!(matches!(
            map_admin_client_error(error),
            TenantResourcePreparationError::Unavailable
        ));
    }
}
