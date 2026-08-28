use diesel::{sql_query, sql_types::Uuid as SqlUuid};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_auth::{
    DynamicRegistrationClientStore, DynamicRegistrationDependencyError, OAuthClient,
    PreparedClientRegistration, ValidatedClientRegistration,
};
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantId, ports::RepositoryError};
use nazo_postgres::{DbPool, OAuthClientRepository, create_pool, get_conn};
use uuid::Uuid;

fn test_repository() -> Option<OAuthClientRepository> {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()?;
    Some(OAuthClientRepository::new(
        create_pool(database_url, 4).unwrap(),
    ))
}

fn test_pool() -> Option<DbPool> {
    let database_url =
        std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"));
    match database_url {
        Ok(database_url) => Some(create_pool(database_url, 4).unwrap()),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!("CI requires NAZO_TEST_DATABASE_URL or DATABASE_URL")
        }
        Err(_) => None,
    }
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
            security_policy: nazo_auth::ClientSecurityPolicy::default(),
        },
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}

fn registration_token(client: &OAuthClient, label: &str) -> String {
    format!("{label}-{}", client.id)
}

#[tokio::test]
async fn oauth_client_reads_fail_closed_across_tenants() {
    let Some(pool) = test_pool() else {
        return;
    };
    let repository = OAuthClientRepository::new(pool.clone());
    let default_tenant = TenantContext::default_system();
    let other_tenant_id = Uuid::now_v7();
    let other_realm_id = Uuid::now_v7();
    let other_organization_id = Uuid::now_v7();
    let other_tenant = TenantContext {
        tenant_id: TenantId::new(other_tenant_id).unwrap(),
        realm_id: RealmId::new(other_realm_id).unwrap(),
        organization_id: OrganizationId::new(other_organization_id).unwrap(),
    };
    let user_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "INSERT INTO tenants (id, slug, display_name) VALUES ($1, $1::text, 'Client boundary tenant')",
    )
    .bind::<SqlUuid, _>(other_tenant_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO realms (id, tenant_id, slug, display_name) VALUES ($1, $2, $1::text, 'Client boundary realm')",
    )
    .bind::<SqlUuid, _>(other_realm_id)
    .bind::<SqlUuid, _>(other_tenant_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO organizations (id, tenant_id, slug, display_name) VALUES ($1, $2, $1::text, 'Client boundary organization')",
    )
    .bind::<SqlUuid, _>(other_organization_id)
    .bind::<SqlUuid, _>(other_tenant_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, password_hash) VALUES ($1, $2, $3, $4, $1::text, $1::text || '@example.test', 'test-only')",
    )
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(default_tenant.tenant_id.as_uuid())
    .bind::<SqlUuid, _>(default_tenant.realm_id.as_uuid())
    .bind::<SqlUuid, _>(default_tenant.organization_id.as_uuid())
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    let mut default_client = client(default_tenant);
    let mut other_client = client(other_tenant);
    let shared_protocol_id = format!("tenant-boundary-{}", Uuid::now_v7());
    default_client.client_id = shared_protocol_id.clone();
    other_client.client_id = shared_protocol_id.clone();
    let secret_hash = "client-secret-v1:tenant-salt:tenant-digest";
    repository
        .insert(&default_client, Some(secret_hash), None)
        .await
        .unwrap();
    repository
        .insert(&other_client, Some(secret_hash), None)
        .await
        .unwrap();

    let default_lookup = repository
        .by_client_id(default_client.tenant_id, &shared_protocol_id)
        .await
        .unwrap()
        .unwrap();
    let other_lookup = repository
        .by_client_id(other_client.tenant_id, &shared_protocol_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(default_lookup.id, default_client.id);
    assert_eq!(other_lookup.id, other_client.id);
    assert!(
        repository
            .by_id(other_client.tenant_id, default_client.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !repository
            .has_client_secret(other_client.tenant_id, default_client.id)
            .await
            .unwrap()
    );
    assert_eq!(
        repository
            .client_secret_salt(other_client.tenant_id, default_client.id)
            .await
            .unwrap(),
        None
    );
    assert!(
        !repository
            .client_secret_digest_matches(other_client.tenant_id, default_client.id, secret_hash,)
            .await
            .unwrap()
    );

    let (default_page, default_total) = repository
        .page(default_client.tenant_id, 0, 10_000)
        .await
        .unwrap();
    let (other_page, other_total) = repository
        .page(other_client.tenant_id, 0, 10_000)
        .await
        .unwrap();
    assert!(default_total >= 1);
    assert!(other_total >= 1);
    assert!(
        default_page
            .iter()
            .all(|item| item.tenant_id == default_client.tenant_id)
    );
    assert!(
        other_page
            .iter()
            .all(|item| item.tenant_id == other_client.tenant_id)
    );
    assert!(default_page.iter().any(|item| item.id == default_client.id));
    assert!(!default_page.iter().any(|item| item.id == other_client.id));
    assert!(other_page.iter().any(|item| item.id == other_client.id));
    assert!(!other_page.iter().any(|item| item.id == default_client.id));

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "INSERT INTO user_client_grants (tenant_id, user_id, client_id, first_authorized_at, last_authorized_at, last_scopes, last_resource_indicators, last_authorization_details, authorization_count) VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '[\"openid\"]'::jsonb, '[]'::jsonb, '[]'::jsonb, 1)",
    )
    .bind::<SqlUuid, _>(default_client.tenant_id)
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(default_client.id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    assert_eq!(
        repository
            .applications_for_user(default_client.tenant_id, user_id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        repository
            .applications_for_user(other_client.tenant_id, user_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repository
            .active_for_tenant_user(other_client.tenant_id, user_id)
            .await
            .unwrap()
            .is_empty()
    );

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM user_client_grants WHERE user_id = $1")
        .bind::<SqlUuid, _>(user_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM users WHERE id = $1")
        .bind::<SqlUuid, _>(user_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM oauth_clients WHERE id = $1 OR id = $2")
        .bind::<SqlUuid, _>(default_client.id)
        .bind::<SqlUuid, _>(other_client.id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM organizations WHERE id = $1")
        .bind::<SqlUuid, _>(other_organization_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM realms WHERE id = $1")
        .bind::<SqlUuid, _>(other_realm_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM tenants WHERE id = $1")
        .bind::<SqlUuid, _>(other_tenant_id)
        .execute(&mut connection)
        .await
        .unwrap();
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
        .insert(&client, None, Some(initial_token.as_str()))
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
            .by_id(client.tenant_id, client.id)
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
        .insert(&client, None, Some(initial_token.as_str()))
        .await
        .unwrap();
    let persisted = repository
        .by_id(client.tenant_id, client.id)
        .await
        .unwrap()
        .unwrap();
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
        .insert(&client, None, Some(initial_token.as_str()))
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
        .insert(&client, None, Some(initial_token.as_str()))
        .await
        .unwrap();
    let registered = repository
        .by_registration_access_token(client.tenant_id, &client.client_id, initial_token.as_str())
        .await
        .unwrap()
        .expect("active registration access token should resolve its client");
    assert_eq!(registered.id, client.id);
    assert!(
        !repository
            .has_client_secret(client.tenant_id, client.id)
            .await
            .unwrap()
    );
    assert!(
        repository
            .active_for_tenant_user(client.tenant_id, Uuid::now_v7())
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

#[tokio::test]
async fn dynamic_registration_store_round_trips_registration_and_secret_material() {
    let Ok(database_url) =
        std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"))
    else {
        return;
    };
    let pool = create_pool(database_url, 4).unwrap();
    let repository = OAuthClientRepository::new(pool.clone());
    let tenant = TenantContext::default_system();
    let template = client(tenant);
    let initial_token = registration_token(&template, "trait-initial");
    let initial_secret_hash = "client-secret-v1:initial-salt:initial-digest";
    let prepared = PreparedClientRegistration {
        tenant,
        registration: template.registration.clone(),
        require_mtls_bound_tokens: template.require_mtls_bound_tokens,
        issued_secret: None,
        client_secret_hash: Some(initial_secret_hash.to_owned()),
        registration_access_token_blake3: Some(initial_token.clone()),
    };

    let inserted = DynamicRegistrationClientStore::insert(&repository, &prepared)
        .await
        .unwrap();
    assert_eq!(inserted.client_id, template.client_id);
    assert_eq!(inserted.tenant_id, tenant.tenant_id.as_uuid());
    assert!(
        DynamicRegistrationClientStore::by_registration_access_token(
            &repository,
            tenant.tenant_id.as_uuid(),
            &inserted.client_id,
            &initial_token,
        )
        .await
        .unwrap()
        .is_some()
    );
    assert!(
        DynamicRegistrationClientStore::has_client_secret(
            &repository,
            inserted.tenant_id,
            inserted.id,
        )
        .await
        .unwrap()
    );
    assert_eq!(
        DynamicRegistrationClientStore::client_secret_salt(
            &repository,
            inserted.tenant_id,
            inserted.id,
        )
        .await
        .unwrap(),
        Some("initial-salt".to_owned())
    );
    assert!(
        DynamicRegistrationClientStore::client_secret_digest_matches(
            &repository,
            inserted.tenant_id,
            inserted.id,
            initial_secret_hash,
        )
        .await
        .unwrap()
    );
    assert!(
        !DynamicRegistrationClientStore::client_secret_digest_matches(
            &repository,
            inserted.tenant_id,
            inserted.id,
            "client-secret-v1:wrong-salt:wrong-digest",
        )
        .await
        .unwrap()
    );

    let rotated_token = registration_token(&inserted, "trait-rotated");
    let rotated_secret_hash = "client-secret-v1:rotated-salt:rotated-digest";
    DynamicRegistrationClientStore::rotate_credentials(
        &repository,
        inserted.tenant_id,
        inserted.id,
        Some(rotated_secret_hash),
        &initial_token,
        &rotated_token,
    )
    .await
    .unwrap();
    assert!(
        DynamicRegistrationClientStore::by_registration_access_token(
            &repository,
            inserted.tenant_id,
            &inserted.client_id,
            &initial_token,
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(
        DynamicRegistrationClientStore::by_registration_access_token(
            &repository,
            inserted.tenant_id,
            &inserted.client_id,
            &rotated_token,
        )
        .await
        .unwrap()
        .is_some()
    );
    assert_eq!(
        DynamicRegistrationClientStore::client_secret_salt(
            &repository,
            inserted.tenant_id,
            inserted.id,
        )
        .await
        .unwrap(),
        Some("rotated-salt".to_owned())
    );
    assert!(
        DynamicRegistrationClientStore::client_secret_digest_matches(
            &repository,
            inserted.tenant_id,
            inserted.id,
            rotated_secret_hash,
        )
        .await
        .unwrap()
    );

    let mut replacement = inserted.clone();
    replacement.registration.client_name = "Trait replacement".to_owned();
    let replacement_token = registration_token(&inserted, "trait-replacement");
    let replacement_secret_hash = "client-secret-v1:replacement-salt:replacement-digest";
    let replaced = DynamicRegistrationClientStore::replace_registration(
        &repository,
        &replacement,
        Some(replacement_secret_hash),
        &rotated_token,
        Some(replacement_token.as_str()),
    )
    .await
    .unwrap();
    assert_eq!(replaced.client_name, "Trait replacement");
    assert!(
        DynamicRegistrationClientStore::by_registration_access_token(
            &repository,
            inserted.tenant_id,
            &inserted.client_id,
            &rotated_token,
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(
        DynamicRegistrationClientStore::by_registration_access_token(
            &repository,
            inserted.tenant_id,
            &inserted.client_id,
            &replacement_token,
        )
        .await
        .unwrap()
        .is_some()
    );
    assert_eq!(
        DynamicRegistrationClientStore::client_secret_salt(
            &repository,
            inserted.tenant_id,
            inserted.id,
        )
        .await
        .unwrap(),
        Some("replacement-salt".to_owned())
    );
    assert!(
        DynamicRegistrationClientStore::client_secret_digest_matches(
            &repository,
            inserted.tenant_id,
            inserted.id,
            replacement_secret_hash,
        )
        .await
        .unwrap()
    );

    assert!(
        DynamicRegistrationClientStore::deactivate(
            &repository,
            inserted.tenant_id,
            inserted.id,
            &replacement_token,
        )
        .await
        .unwrap()
    );
    assert!(
        DynamicRegistrationClientStore::by_registration_access_token(
            &repository,
            inserted.tenant_id,
            &inserted.client_id,
            &replacement_token,
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(
        !DynamicRegistrationClientStore::has_client_secret(
            &repository,
            inserted.tenant_id,
            inserted.id,
        )
        .await
        .unwrap()
    );
    assert_eq!(
        DynamicRegistrationClientStore::client_secret_salt(
            &repository,
            inserted.tenant_id,
            inserted.id,
        )
        .await
        .unwrap(),
        None
    );
    assert!(
        !DynamicRegistrationClientStore::client_secret_digest_matches(
            &repository,
            inserted.tenant_id,
            inserted.id,
            replacement_secret_hash,
        )
        .await
        .unwrap()
    );

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM oauth_clients WHERE id = $1")
        .bind::<SqlUuid, _>(inserted.id)
        .execute(&mut connection)
        .await
        .unwrap();
}

#[tokio::test]
async fn dynamic_registration_store_maps_repository_failures_to_unavailable() {
    let repository = OAuthClientRepository::new(
        create_pool("postgres://invalid:invalid@127.0.0.1:1/never", 1)
            .expect("invalid test pool should still be constructible"),
    );
    let tenant = TenantContext::default_system();
    let template = client(tenant);
    let initial_token = registration_token(&template, "unavailable-initial");
    let prepared = PreparedClientRegistration {
        tenant,
        registration: template.registration.clone(),
        require_mtls_bound_tokens: template.require_mtls_bound_tokens,
        issued_secret: None,
        client_secret_hash: Some("client-secret-v1:unavailable-salt:unavailable-digest".to_owned()),
        registration_access_token_blake3: Some(initial_token.clone()),
    };

    assert_eq!(
        DynamicRegistrationClientStore::insert(&repository, &prepared)
            .await
            .unwrap_err(),
        DynamicRegistrationDependencyError::Unavailable
    );
    assert_eq!(
        repository.upsert(&template, None).await.unwrap_err(),
        RepositoryError::Unavailable
    );
    assert_eq!(
        repository.update_metadata(&template).await.unwrap_err(),
        RepositoryError::Unavailable
    );
    assert_eq!(
        DynamicRegistrationClientStore::by_registration_access_token(
            &repository,
            tenant.tenant_id.as_uuid(),
            &template.client_id,
            &initial_token,
        )
        .await
        .unwrap_err(),
        DynamicRegistrationDependencyError::Unavailable
    );
    assert_eq!(
        DynamicRegistrationClientStore::has_client_secret(
            &repository,
            template.tenant_id,
            template.id,
        )
        .await
        .unwrap_err(),
        DynamicRegistrationDependencyError::Unavailable
    );
    assert_eq!(
        DynamicRegistrationClientStore::client_secret_salt(
            &repository,
            template.tenant_id,
            template.id,
        )
        .await
        .unwrap_err(),
        DynamicRegistrationDependencyError::Unavailable
    );
    assert_eq!(
        DynamicRegistrationClientStore::client_secret_digest_matches(
            &repository,
            template.tenant_id,
            template.id,
            "client-secret-v1:unavailable-salt:unavailable-digest",
        )
        .await
        .unwrap_err(),
        DynamicRegistrationDependencyError::Unavailable
    );
    assert_eq!(
        DynamicRegistrationClientStore::rotate_credentials(
            &repository,
            tenant.tenant_id.as_uuid(),
            template.id,
            None,
            &initial_token,
            "unavailable-rotated",
        )
        .await
        .unwrap_err(),
        DynamicRegistrationDependencyError::Unavailable
    );
    assert_eq!(
        DynamicRegistrationClientStore::replace_registration(
            &repository,
            &template,
            None,
            &initial_token,
            Some("unavailable-replacement"),
        )
        .await
        .unwrap_err(),
        DynamicRegistrationDependencyError::Unavailable
    );
    assert_eq!(
        DynamicRegistrationClientStore::deactivate(
            &repository,
            tenant.tenant_id.as_uuid(),
            template.id,
            &initial_token,
        )
        .await
        .unwrap_err(),
        DynamicRegistrationDependencyError::Unavailable
    );
}
