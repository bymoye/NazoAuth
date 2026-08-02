use diesel::{sql_query, sql_types::Uuid as SqlUuid};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_auth::{
    DynamicRegistrationClientStore, DynamicRegistrationDependencyError, OAuthClient,
    ValidatedClientRegistration,
};
use nazo_identity::{TenantContext, ports::RepositoryError};
use nazo_postgres::{OAuthClientRepository, create_pool, get_conn};
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
    let lease = leases
        .create(tenant.tenant_id.as_uuid(), "oidf-test", &"a".repeat(64), 60)
        .await
        .unwrap();
    let client = client(tenant);
    clients
        .insert(&client, None, None, Some(lease.id))
        .await
        .unwrap();
    assert!(
        clients
            .by_client_id(client.tenant_id, &client.client_id)
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
            .by_client_id(client.tenant_id, &client.client_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(clients.update_metadata(&client).await.is_err());
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
            .by_client_id(client.tenant_id, &client.client_id)
            .await
            .unwrap()
            .is_none()
    );
    let listed = leases.list(client.tenant_id).await.unwrap();
    let tombstone = listed
        .iter()
        .find(|candidate| candidate.id == lease.id)
        .unwrap();
    assert!(tombstone.revoked_at.is_some());
    assert!(tombstone.cleaned_at.is_some());
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
