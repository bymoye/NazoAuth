use diesel::{sql_query, sql_types::Uuid as SqlUuid};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_auth::{OAuthClient, ValidatedClientRegistration};
use nazo_identity::{TenantContext, ports::RepositoryError};
use nazo_postgres::{OAuthClientRepository, create_pool, get_conn};
use uuid::Uuid;

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
            allow_authorization_code_without_pkce: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: true,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: vec![],
            tls_client_auth_san_uri: vec![],
            tls_client_auth_san_ip: vec![],
            tls_client_auth_san_email: vec![],
            jwks: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
        },
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dcr_replace_cannot_resurrect_a_concurrently_deleted_client() {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    let pool = create_pool(database_url, 4).unwrap();
    let repository = OAuthClientRepository::new(pool.clone());
    let client = client(TenantContext::default_system());
    repository
        .insert(&client, None, Some("registration-token"))
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
            .replace_registration(&stale, None, Some("rotated-token"))
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
