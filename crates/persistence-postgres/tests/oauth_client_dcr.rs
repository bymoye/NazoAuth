use diesel::{
    sql_query,
    sql_types::{Bool, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_auth::{
    DynamicRegistrationClientStore, DynamicRegistrationDependencyError, OAuthClient,
    ValidatedClientRegistration,
};
use nazo_identity::{TenantContext, ports::RepositoryError};
use nazo_postgres::{ConformanceLeaseTokenDigests, OAuthClientRepository, create_pool, get_conn};
use uuid::Uuid;

fn test_repository() -> Option<OAuthClientRepository> {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()?;
    Some(OAuthClientRepository::new(
        create_pool(database_url, 4).unwrap(),
    ))
}

fn client(tenant: TenantContext) -> OAuthClient {
    OAuthClient {
        id: Uuid::now_v7(),
        tenant_id: tenant.tenant_id.as_uuid(),
        realm_id: tenant.realm_id.as_uuid(),
        organization_id: tenant.organization_id.as_uuid(),
        registration: ValidatedClientRegistration {
            client_id: format!("dcr-race-{}", Uuid::now_v7()),
            client_name: "DCR race".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            post_logout_redirect_uris: vec![],
            scopes: vec!["openid".to_owned()],
            allowed_audiences: vec![],
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
            backchannel_logout_session_required: true,
            backchannel_token_delivery_mode: "poll".to_owned(),
            backchannel_client_notification_endpoint: None,
            backchannel_authentication_request_signing_alg: None,
            backchannel_user_code_parameter: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: vec![],
            tls_client_auth_san_uri: vec![],
            tls_client_auth_san_ip: vec![],
            tls_client_auth_san_email: vec![],
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

#[tokio::test]
async fn conformance_lease_rejects_invalid_capability_material_before_database_access() {
    let repository = nazo_postgres::ConformanceLeaseRepository::new(
        create_pool("postgres://invalid:invalid@127.0.0.1:1/never", 1)
            .expect("invalid test pool should still be constructible"),
    );
    let tenant_id = Uuid::now_v7();
    let valid_material = "a".repeat(64);
    let valid_token = "b".repeat(64);

    for ttl in [
        nazo_postgres::MIN_CONFORMANCE_LEASE_SECONDS - 1,
        nazo_postgres::MAX_CONFORMANCE_LEASE_SECONDS + 1,
    ] {
        assert!(matches!(
            repository
                .create(
                    tenant_id,
                    "oidf-test",
                    &valid_material,
                    ConformanceLeaseTokenDigests::default(),
                    None,
                    ttl,
                )
                .await,
            Err(RepositoryError::Consistency(_))
        ));
    }
    for profile in [String::new(), "x".repeat(65)] {
        assert!(matches!(
            repository
                .create(
                    tenant_id,
                    &profile,
                    &valid_material,
                    ConformanceLeaseTokenDigests::default(),
                    None,
                    nazo_postgres::MIN_CONFORMANCE_LEASE_SECONDS,
                )
                .await,
            Err(RepositoryError::Consistency(_))
        ));
    }
    for material in ["A".repeat(64), "z".repeat(64), "short".to_owned()] {
        assert!(matches!(
            repository
                .create(
                    tenant_id,
                    "oidf-test",
                    &material,
                    ConformanceLeaseTokenDigests::default(),
                    None,
                    nazo_postgres::MIN_CONFORMANCE_LEASE_SECONDS,
                )
                .await,
            Err(RepositoryError::Consistency(_))
        ));
    }
    assert!(matches!(
        repository
            .create(
                tenant_id,
                "oidf-test",
                &valid_material,
                ConformanceLeaseTokenDigests {
                    dynamic_registration_initial_access_token_sha256: Some("invalid"),
                    ciba_automated_decision_token_sha256: None,
                },
                None,
                nazo_postgres::MIN_CONFORMANCE_LEASE_SECONDS,
            )
            .await,
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        repository
            .create(
                tenant_id,
                "oidf-test",
                &valid_material,
                ConformanceLeaseTokenDigests {
                    dynamic_registration_initial_access_token_sha256: None,
                    ciba_automated_decision_token_sha256: Some(&valid_token),
                },
                None,
                nazo_postgres::MIN_CONFORMANCE_LEASE_SECONDS,
            )
            .await,
        Err(RepositoryError::Consistency(_))
    ));
}

#[tokio::test]
async fn expired_conformance_lease_fails_closed_before_idempotent_physical_cleanup() {
    let database_url =
        match std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL")) {
            Ok(database_url) => database_url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!("CI requires NAZO_TEST_DATABASE_URL or DATABASE_URL")
            }
            Err(_) => return,
        };
    let pool = create_pool(database_url, 4).unwrap();
    let clients = OAuthClientRepository::new(pool.clone());
    let leases = nazo_postgres::ConformanceLeaseRepository::new(pool.clone());
    let tenant = TenantContext::default_system();
    let public_material = serde_json::json!({"schema": 1, "keys": ["public-only"]});
    let lease = leases
        .create(
            tenant.tenant_id.as_uuid(),
            "oidf-test",
            &"a".repeat(64),
            ConformanceLeaseTokenDigests::default(),
            Some(public_material.clone()),
            60,
        )
        .await
        .unwrap();
    let leased_client = client(tenant);
    clients
        .insert(&leased_client, None, None, Some(lease.id))
        .await
        .unwrap();
    assert_eq!(
        leases
            .active_public_material_for_client(leased_client.tenant_id, &leased_client.client_id,)
            .await
            .unwrap(),
        Some(public_material),
    );
    assert!(
        leases
            .active_for_client_profile(
                leased_client.tenant_id,
                &leased_client.client_id,
                "oidf-test",
            )
            .await
            .unwrap()
    );
    assert!(
        !leases
            .active_for_client_profile(
                leased_client.tenant_id,
                &leased_client.client_id,
                "oidc-fapi-ciba",
            )
            .await
            .unwrap()
    );
    let active_profile_material = leases
        .active_public_materials_for_profile(leased_client.tenant_id, "oidf-test")
        .await
        .unwrap();
    assert_eq!(active_profile_material.len(), 1);
    assert_eq!(active_profile_material[0].lease_id, lease.id);
    assert_eq!(
        leases
            .active_public_material_for_lease(leased_client.tenant_id, lease.id)
            .await
            .unwrap(),
        Some(active_profile_material[0].public_material.clone()),
    );
    assert!(
        clients
            .by_client_id(leased_client.tenant_id, &leased_client.client_id)
            .await
            .unwrap()
            .unwrap()
            .is_active
    );

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE conformance_leases SET created_at = CURRENT_TIMESTAMP - INTERVAL '2 minutes', expires_at = CURRENT_TIMESTAMP - INTERVAL '1 minute' WHERE id = $1",
    )
    .bind::<SqlUuid, _>(lease.id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    assert!(
        clients
            .by_client_id(leased_client.tenant_id, &leased_client.client_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        leases
            .active_public_materials_for_profile(leased_client.tenant_id, "oidf-test")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        leases
            .active_public_material_for_lease(leased_client.tenant_id, lease.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !leases
            .active_for_client_profile(
                leased_client.tenant_id,
                &leased_client.client_id,
                "oidf-test",
            )
            .await
            .unwrap()
    );
    assert!(clients.update_metadata(&leased_client).await.is_err());
    let late_client = client(tenant);
    assert!(
        clients
            .insert(&late_client, None, None, Some(lease.id))
            .await
            .is_err()
    );
    let cleaned = leases.cleanup().await.unwrap();
    assert!(cleaned.cleaned_leases >= 1);
    assert!(cleaned.deleted_clients >= 1);
    assert!(
        clients
            .by_client_id(leased_client.tenant_id, &leased_client.client_id)
            .await
            .unwrap()
            .is_none()
    );
    let listed = leases.list(leased_client.tenant_id).await.unwrap();
    let tombstone = listed
        .iter()
        .find(|candidate| candidate.id == lease.id)
        .unwrap();
    assert!(tombstone.revoked_at.is_some());
    assert!(tombstone.cleaned_at.is_some());
    assert!(tombstone.public_material.is_none());
    leases.cleanup().await.unwrap();
}

#[tokio::test]
async fn revoked_conformance_lease_fails_closed_without_restart_or_cleanup() {
    let database_url =
        match std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL")) {
            Ok(database_url) => database_url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!("CI requires NAZO_TEST_DATABASE_URL or DATABASE_URL")
            }
            Err(_) => return,
        };
    let pool = create_pool(database_url, 4).unwrap();
    let clients = OAuthClientRepository::new(pool.clone());
    let leases = nazo_postgres::ConformanceLeaseRepository::new(pool);
    let tenant = TenantContext::default_system();
    let initial_access_token_sha256 = format!("{:064x}", Uuid::now_v7().as_u128());
    let unknown_initial_access_token_sha256 = format!("{:064x}", Uuid::now_v7().as_u128());
    let ciba_decision_token_sha256 = format!("{:064x}", Uuid::now_v7().as_u128());
    let other_ciba_decision_token_sha256 = format!("{:064x}", Uuid::now_v7().as_u128());
    assert!(matches!(
        leases
            .create(
                tenant.tenant_id.as_uuid(),
                "openid4vc",
                &"d".repeat(64),
                ConformanceLeaseTokenDigests {
                    dynamic_registration_initial_access_token_sha256: Some(
                        &initial_access_token_sha256,
                    ),
                    ciba_automated_decision_token_sha256: None,
                },
                None,
                60,
            )
            .await,
        Err(RepositoryError::Consistency(_))
    ));
    let lease = leases
        .create(
            tenant.tenant_id.as_uuid(),
            "oidc-fapi-ciba",
            &"b".repeat(64),
            ConformanceLeaseTokenDigests {
                dynamic_registration_initial_access_token_sha256: Some(
                    &initial_access_token_sha256,
                ),
                ciba_automated_decision_token_sha256: Some(&ciba_decision_token_sha256),
            },
            None,
            60,
        )
        .await
        .unwrap();
    assert_eq!(
        leases
            .active_dynamic_registration_lease_id(
                tenant.tenant_id.as_uuid(),
                "oidc-fapi-ciba",
                &initial_access_token_sha256,
            )
            .await
            .unwrap(),
        Some(lease.id)
    );
    assert!(matches!(
        leases
            .active_dynamic_registration_lease_id(
                tenant.tenant_id.as_uuid(),
                "openid4vc",
                &initial_access_token_sha256,
            )
            .await,
        Err(RepositoryError::Consistency(_))
    ));
    assert_eq!(
        leases
            .active_dynamic_registration_lease_id(
                tenant.tenant_id.as_uuid(),
                "oidc-fapi-ciba",
                &unknown_initial_access_token_sha256,
            )
            .await
            .unwrap(),
        None
    );
    let leased_client = client(tenant);
    clients
        .insert(&leased_client, None, None, Some(lease.id))
        .await
        .unwrap();
    assert_eq!(
        leases
            .active_ciba_automated_decision_lease_id(
                leased_client.tenant_id,
                "oidc-fapi-ciba",
                &ciba_decision_token_sha256,
            )
            .await
            .unwrap(),
        Some(lease.id)
    );
    let other_lease = leases
        .create(
            tenant.tenant_id.as_uuid(),
            "oidc-fapi-ciba",
            &format!("{:064x}", Uuid::now_v7().as_u128()),
            ConformanceLeaseTokenDigests {
                dynamic_registration_initial_access_token_sha256: None,
                ciba_automated_decision_token_sha256: Some(&other_ciba_decision_token_sha256),
            },
            None,
            60,
        )
        .await
        .unwrap();
    let other_leased_client = client(tenant);
    clients
        .insert(&other_leased_client, None, None, Some(other_lease.id))
        .await
        .unwrap();
    assert_eq!(
        leases
            .active_ciba_automated_decision_lease_id(
                other_leased_client.tenant_id,
                "oidc-fapi-ciba",
                &other_ciba_decision_token_sha256,
            )
            .await
            .unwrap(),
        Some(other_lease.id)
    );
    assert_ne!(ciba_decision_token_sha256, other_ciba_decision_token_sha256);
    assert!(
        leases
            .active_for_client_lease_profile(
                leased_client.tenant_id,
                &leased_client.client_id,
                lease.id,
                "oidc-fapi-ciba",
            )
            .await
            .unwrap()
    );
    assert!(
        !leases
            .active_for_client_lease_profile(
                leased_client.tenant_id,
                &leased_client.client_id,
                other_lease.id,
                "oidc-fapi-ciba",
            )
            .await
            .unwrap()
    );
    assert!(
        !leases
            .active_for_client_lease_profile(
                other_leased_client.tenant_id,
                &other_leased_client.client_id,
                lease.id,
                "oidc-fapi-ciba",
            )
            .await
            .unwrap()
    );
    assert!(
        leases
            .active_for_client_lease_profile(
                other_leased_client.tenant_id,
                &other_leased_client.client_id,
                other_lease.id,
                "oidc-fapi-ciba",
            )
            .await
            .unwrap()
    );

    leases
        .revoke(leased_client.tenant_id, lease.id)
        .await
        .unwrap();
    assert_eq!(
        leases
            .active_dynamic_registration_lease_id(
                tenant.tenant_id.as_uuid(),
                "oidc-fapi-ciba",
                &initial_access_token_sha256,
            )
            .await
            .unwrap(),
        None
    );
    assert!(
        leases
            .list(leased_client.tenant_id)
            .await
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.id == lease.id)
            .is_some_and(|candidate| {
                candidate
                    .dynamic_registration_initial_access_token_sha256
                    .is_none()
                    && candidate.ciba_automated_decision_token_sha256.is_none()
            })
    );
    assert!(
        !leases
            .active_for_client_profile(
                leased_client.tenant_id,
                &leased_client.client_id,
                "oidc-fapi-ciba",
            )
            .await
            .unwrap()
    );

    assert_eq!(
        leases
            .active_ciba_automated_decision_lease_id(
                leased_client.tenant_id,
                "oidc-fapi-ciba",
                &ciba_decision_token_sha256,
            )
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        leases
            .active_ciba_automated_decision_lease_id(
                other_leased_client.tenant_id,
                "oidc-fapi-ciba",
                &other_ciba_decision_token_sha256,
            )
            .await
            .unwrap(),
        Some(other_lease.id)
    );
    leases
        .revoke(other_leased_client.tenant_id, other_lease.id)
        .await
        .unwrap();

    leases.cleanup().await.unwrap();
}

fn registration_token(client: &OAuthClient, label: &str) -> String {
    format!("{label}-{}", client.id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dcr_replace_cannot_resurrect_a_concurrently_deleted_client() {
    let Ok(database_url) =
        std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"))
    else {
        return;
    };
    let pool = create_pool(database_url, 4).unwrap();
    let repository = OAuthClientRepository::new(pool.clone());
    let client = client(TenantContext::default_system());
    let initial_token = registration_token(&client, "registration-token");
    let rotated_token = registration_token(&client, "rotated-token");
    repository
        .insert(&client, None, Some(initial_token.as_str()), None)
        .await
        .unwrap();

    let (deleted_tx, deleted_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let pool_for_delete = pool.clone();
    let client_id = client.id;
    let tenant_id = client.tenant_id;
    let delete = tokio::spawn(async move {
        let mut connection = get_conn(&pool_for_delete).await.unwrap();
        connection
            .transaction::<(), diesel::result::Error, _>(async move |connection| {
                sql_query("UPDATE oauth_clients SET is_active = FALSE, registration_access_token_blake3 = NULL WHERE tenant_id = $1 AND id = $2")
                    .bind::<SqlUuid, _>(tenant_id)
                    .bind::<SqlUuid, _>(client_id)
                    .execute(connection)
                    .await?;
                let _ = deleted_tx.send(());
                let _ = release_rx.await;
                Ok(())
            })
            .await
            .unwrap();
    });
    deleted_rx.await.unwrap();
    let repository_for_put = repository.clone();
    let stale = client.clone();
    let put = tokio::spawn(async move {
        repository_for_put
            .replace_registration(
                &stale,
                None,
                initial_token.as_str(),
                Some(rotated_token.as_str()),
            )
            .await
    });
    tokio::task::yield_now().await;
    let _ = release_tx.send(());
    delete.await.unwrap();
    assert_eq!(put.await.unwrap().unwrap_err(), RepositoryError::NotFound);
    assert!(
        !repository
            .by_id(client.id)
            .await
            .unwrap()
            .unwrap()
            .is_active
    );

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM oauth_clients WHERE id = $1")
        .bind::<SqlUuid, _>(client.id)
        .execute(&mut connection)
        .await
        .unwrap();
}

#[tokio::test]
async fn dynamic_profile_metadata_round_trips_through_postgres() {
    let Some(repository) = test_repository() else {
        return;
    };
    let mut client = client(TenantContext::default_system());
    client.jwks_uri = Some("https://client.example/jwks.json".to_owned());
    client.jwks = Some(serde_json::json!({"keys": []}));
    client.request_uris = vec!["https://client.example/request.jwt".to_owned()];
    client.initiate_login_uri = Some("https://client.example/login/initiate".to_owned());
    client.presentation = nazo_auth::ClientPresentationMetadata {
        logo_uri: Some("https://client.example/logo.svg".to_owned()),
        policy_uri: Some("https://client.example/privacy".to_owned()),
        tos_uri: Some("https://client.example/terms".to_owned()),
    };
    client.grant_types = vec!["urn:openid:params:grant-type:ciba".to_owned()];
    client.backchannel_token_delivery_mode = "ping".to_owned();
    client.backchannel_client_notification_endpoint =
        Some("https://client.example/ciba-notification".to_owned());
    client.backchannel_authentication_request_signing_alg = Some("PS256".to_owned());
    let initial_token = registration_token(&client, "registration-token");
    let rotated_token = registration_token(&client, "rotated-registration-token");

    repository
        .insert(&client, None, Some(initial_token.as_str()), None)
        .await
        .unwrap();
    let persisted = repository.by_id(client.id).await.unwrap().unwrap();
    assert_eq!(persisted.jwks_uri, client.jwks_uri);
    assert_eq!(persisted.jwks, client.jwks);
    assert_eq!(persisted.request_uris, client.request_uris);
    assert_eq!(persisted.initiate_login_uri, client.initiate_login_uri);
    assert_eq!(persisted.presentation, client.presentation);
    assert_eq!(persisted.security_policy, client.security_policy);
    assert_eq!(
        persisted.backchannel_token_delivery_mode,
        client.backchannel_token_delivery_mode
    );
    assert_eq!(
        persisted.backchannel_client_notification_endpoint,
        client.backchannel_client_notification_endpoint
    );
    assert_eq!(
        persisted.backchannel_authentication_request_signing_alg,
        client.backchannel_authentication_request_signing_alg
    );
    assert!(!persisted.backchannel_user_code_parameter);

    let mut replacement = client.clone();
    replacement.registration.client_id = format!("replacement-{}", Uuid::now_v7());
    let replaced = repository
        .replace_registration(
            &replacement,
            None,
            initial_token.as_str(),
            Some(rotated_token.as_str()),
        )
        .await
        .unwrap();
    assert_eq!(replaced.client_id, client.client_id);

    repository
        .deactivate(client.tenant_id, client.id, rotated_token.as_str())
        .await
        .unwrap();
}

#[tokio::test]
async fn registration_token_rotation_rejects_a_stale_authenticated_token() {
    let Some(repository) = test_repository() else {
        return;
    };
    let client = client(TenantContext::default_system());
    let initial_token = registration_token(&client, "registration-token");
    let rotated_token = registration_token(&client, "rotated-token");
    let attacker_token = registration_token(&client, "attacker-token");
    repository
        .insert(&client, None, Some(initial_token.as_str()), None)
        .await
        .unwrap();

    repository
        .rotate_credentials(
            client.tenant_id,
            client.id,
            None,
            initial_token.as_str(),
            rotated_token.as_str(),
        )
        .await
        .unwrap();
    assert_eq!(
        repository
            .rotate_credentials(
                client.tenant_id,
                client.id,
                None,
                initial_token.as_str(),
                attacker_token.as_str(),
            )
            .await
            .unwrap_err(),
        RepositoryError::NotFound
    );

    repository
        .deactivate(client.tenant_id, client.id, rotated_token.as_str())
        .await
        .unwrap();
}

#[tokio::test]
async fn dynamic_registration_store_preserves_atomic_credential_semantics() {
    let Ok(database_url) =
        std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"))
    else {
        return;
    };
    let pool = create_pool(database_url, 4).unwrap();
    let repository = OAuthClientRepository::new(pool.clone());
    let mut client = client(TenantContext::default_system());
    let initial_token = registration_token(&client, "registration-token");
    let rotated_token = registration_token(&client, "rotated-token");
    let stale_token = registration_token(&client, "stale-write");
    let replacement_token = registration_token(&client, "replacement-token");
    repository
        .insert(&client, None, Some(initial_token.as_str()), None)
        .await
        .unwrap();
    let registered = repository
        .by_registration_access_token(client.tenant_id, &client.client_id, initial_token.as_str())
        .await
        .unwrap()
        .expect("active registration access token should resolve its client");
    assert_eq!(registered.id, client.id);
    assert!(!repository.has_client_secret(client.id).await.unwrap());
    assert!(
        repository
            .active_for_user(Uuid::now_v7())
            .await
            .unwrap()
            .is_empty()
    );

    DynamicRegistrationClientStore::rotate_credentials(
        &repository,
        client.tenant_id,
        client.id,
        None,
        initial_token.as_str(),
        rotated_token.as_str(),
    )
    .await
    .unwrap();
    assert_eq!(
        DynamicRegistrationClientStore::rotate_credentials(
            &repository,
            client.tenant_id,
            client.id,
            None,
            initial_token.as_str(),
            stale_token.as_str(),
        )
        .await
        .unwrap_err(),
        DynamicRegistrationDependencyError::StaleCredentials
    );

    client.registration.client_name = "Updated DCR client".to_owned();
    let replaced = DynamicRegistrationClientStore::replace_registration(
        &repository,
        &client,
        None,
        rotated_token.as_str(),
        Some(replacement_token.as_str()),
    )
    .await
    .unwrap();
    assert_eq!(replaced.client_name, "Updated DCR client");

    assert!(
        DynamicRegistrationClientStore::deactivate(
            &repository,
            client.tenant_id,
            client.id,
            replacement_token.as_str(),
        )
        .await
        .unwrap()
    );
    assert_eq!(
        DynamicRegistrationClientStore::deactivate(
            &repository,
            client.tenant_id,
            client.id,
            replacement_token.as_str(),
        )
        .await
        .unwrap_err(),
        DynamicRegistrationDependencyError::StaleCredentials
    );

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM oauth_clients WHERE id = $1")
        .bind::<SqlUuid, _>(client.id)
        .execute(&mut connection)
        .await
        .unwrap();
}

#[derive(diesel::QueryableByName)]
struct LeaseStillActive {
    #[diesel(sql_type = Bool)]
    active: bool,
}

#[tokio::test]
async fn ciba_decision_claim_releases_pool_connection_before_callback() {
    let Ok(database_url) =
        std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"))
    else {
        return;
    };
    let pool = create_pool(database_url, 1).unwrap();
    let leases = nazo_postgres::ConformanceLeaseRepository::new(pool.clone());
    let clients = OAuthClientRepository::new(pool.clone());
    let tenant = TenantContext::default_system();
    let lease = leases
        .create(
            tenant.tenant_id.as_uuid(),
            "oidc-fapi-ciba",
            &"b".repeat(64),
            ConformanceLeaseTokenDigests::default(),
            None,
            60,
        )
        .await
        .unwrap();
    let client = client(tenant);
    clients
        .insert(&client, None, None, Some(lease.id))
        .await
        .unwrap();
    assert_eq!(
        leases
            .active_lease_id_for_client(
                tenant.tenant_id.as_uuid(),
                &client.client_id,
                "oidc-fapi-ciba",
            )
            .await
            .unwrap(),
        Some(lease.id)
    );
    assert_eq!(
        leases
            .active_lease_id_for_client(
                tenant.tenant_id.as_uuid(),
                &client.client_id,
                "different-profile",
            )
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        leases
            .active_lease_id_for_client(
                tenant.tenant_id.as_uuid(),
                "missing-client",
                "oidc-fapi-ciba",
            )
            .await
            .unwrap(),
        None
    );

    let (decision_started_tx, decision_started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let decision_leases = leases.clone();
    let decision_client_id = client.client_id.clone();
    let callback_pool = pool.clone();
    let decision = tokio::spawn(async move {
        decision_leases
            .with_active_ciba_decision(
                tenant.tenant_id.into(),
                &decision_client_id,
                Some(lease.id),
                |lease_expires_at| async move {
                    // A pool of one proves that the callback did not inherit
                    // the claim transaction's connection. Token issuance
                    // performs the same nested-database acquisition.
                    let mut nested = get_conn(&callback_pool).await.unwrap();
                    let probe = sql_query(
                        "SELECT EXISTS(SELECT 1 FROM conformance_leases WHERE id = $1) AS active",
                    )
                    .bind::<SqlUuid, _>(lease.id)
                    .get_result::<LeaseStillActive>(&mut nested)
                    .await
                    .unwrap();
                    assert!(probe.active);
                    drop(nested);
                    decision_started_tx.send(lease_expires_at).unwrap();
                    release_rx.await.unwrap();
                    lease_expires_at
                },
            )
            .await
    });
    let lease_expires_at = decision_started_rx.await.unwrap();
    assert!(lease_expires_at.is_some());

    let (revoke_started_tx, revoke_started_rx) = tokio::sync::oneshot::channel();
    let revoke_leases = leases.clone();
    let revoke = tokio::spawn(async move {
        revoke_started_tx.send(()).unwrap();
        revoke_leases
            .revoke(tenant.tenant_id.as_uuid().to_owned(), lease.id)
            .await
    });
    revoke_started_rx.await.unwrap();
    tokio::task::yield_now().await;

    let mut connection = get_conn(&pool).await.unwrap();
    let active = sql_query(
        "SELECT EXISTS(SELECT 1 FROM conformance_leases WHERE id = $1 AND revoked_at IS NULL) AS active",
    )
    .bind::<SqlUuid, _>(lease.id)
    .get_result::<LeaseStillActive>(&mut connection)
    .await
    .unwrap();
    assert!(
        active.active,
        "revoke must wait for the decision CAS callback"
    );

    drop(connection);
    release_tx.send(()).unwrap();
    assert!(decision.await.unwrap().unwrap().unwrap().is_some());
    assert_eq!(revoke.await.unwrap().unwrap(), 1);

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM oauth_clients WHERE id = $1")
        .bind::<SqlUuid, _>(client.id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM conformance_leases WHERE id = $1")
        .bind::<SqlUuid, _>(lease.id)
        .execute(&mut connection)
        .await
        .unwrap();
}
