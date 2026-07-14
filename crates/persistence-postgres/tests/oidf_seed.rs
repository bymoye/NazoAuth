use diesel::{QueryableByName, sql_query, sql_types::BigInt};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{OAuthClient, ValidatedClientRegistration};
use nazo_postgres::{
    OidfSeedClient, OidfSeedUser, create_pool, run_pending_migrations, seed_oidf_atomically,
};
use uuid::Uuid;

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI OIDF seed tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn user(suffix: &str, password_hash: &str) -> OidfSeedUser {
    OidfSeedUser {
        tenant_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        realm_id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
        organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
        username: format!("oidf-seed-{suffix}"),
        email: format!("oidf-seed-{suffix}@example.test"),
        password_hash: password_hash.to_owned(),
    }
}

fn client(suffix: &str, name: String) -> OidfSeedClient {
    OidfSeedClient {
        client: OAuthClient {
            id: Uuid::now_v7(),
            tenant_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            realm_id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
            registration: ValidatedClientRegistration {
                client_id: format!("oidf-seed-{suffix}"),
                client_name: name,
                client_type: "confidential".to_owned(),
                redirect_uris: vec!["https://client.example/callback".to_owned()],
                post_logout_redirect_uris: vec![],
                scopes: vec!["openid".to_owned()],
                allowed_audiences: vec!["resource://default".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
                token_endpoint_auth_method: "client_secret_basic".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier_uri: None,
                sector_identifier_host: None,
                require_dpop_bound_tokens: false,
                allow_client_assertion_audience_array: false,
                allow_client_assertion_endpoint_audience: false,
                require_par_request_object: false,
                allow_authorization_code_without_pkce: true,
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
        },
        client_secret_hash: Some("test-client-secret-hash".to_owned()),
    }
}

async fn count(connection: &mut AsyncPgConnection, query: String) -> i64 {
    sql_query(query)
        .get_result::<CountRow>(connection)
        .await
        .unwrap()
        .count
}

#[tokio::test]
async fn oidf_seed_rolls_back_user_and_earlier_clients_when_a_later_client_fails() {
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url).await.unwrap();
    let suffix = Uuid::now_v7().simple().to_string();
    let baseline_user = user(&suffix, "old-password-hash");
    let baseline_client = client(&format!("{suffix}-valid"), "Original client".to_owned());
    let pool = create_pool(&database_url, 2).unwrap();
    seed_oidf_atomically(
        &pool,
        &baseline_user,
        std::slice::from_ref(&baseline_client),
    )
    .await
    .unwrap();

    let seed_user = user(&suffix, "new-password-hash");
    let valid = client(&format!("{suffix}-valid"), "Updated client".to_owned());
    let invalid = client(&format!("{suffix}-invalid"), "x".repeat(201));

    let error = seed_oidf_atomically(&pool, &seed_user, &[valid, invalid])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("too long"));

    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    assert_eq!(
        count(
            &mut connection,
            format!(
                "SELECT COUNT(*)::bigint AS count FROM users WHERE email = '{}' AND password_hash = 'old-password-hash'",
                seed_user.email
            )
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &mut connection,
            format!("SELECT COUNT(*)::bigint AS count FROM oauth_clients WHERE client_id = 'oidf-seed-{suffix}-valid' AND client_name = 'Original client'")
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &mut connection,
            format!("SELECT COUNT(*)::bigint AS count FROM oauth_clients WHERE client_id = 'oidf-seed-{suffix}-invalid'")
        )
        .await,
        0
    );

    sql_query(format!(
        "DELETE FROM oauth_clients WHERE client_id = 'oidf-seed-{suffix}-valid'"
    ))
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(format!(
        "DELETE FROM users WHERE email = '{}'",
        seed_user.email
    ))
    .execute(&mut connection)
    .await
    .unwrap();
}

#[tokio::test]
async fn oidf_seed_is_idempotent_and_preserves_non_oidf_clients() {
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url).await.unwrap();
    let suffix = Uuid::now_v7().simple().to_string();
    let seed_user = user(&suffix, "first-password-hash");
    let seeded_client = client(&suffix, "OIDF Client".to_owned());
    let sentinel_id = format!("non-oidf-{suffix}");
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    sql_query(format!(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, redirect_uris, scopes, grant_types, token_endpoint_auth_method) VALUES ('{sentinel_id}', 'Non OIDF Client', 'confidential', '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, 'client_secret_basic')"
    ))
    .execute(&mut connection)
    .await
    .unwrap();

    let pool = create_pool(&database_url, 2).unwrap();
    seed_oidf_atomically(&pool, &seed_user, std::slice::from_ref(&seeded_client))
        .await
        .unwrap();
    let updated_user = user(&suffix, "second-password-hash");
    seed_oidf_atomically(&pool, &updated_user, &[seeded_client])
        .await
        .unwrap();

    assert_eq!(
        count(
            &mut connection,
            format!("SELECT COUNT(*)::bigint AS count FROM users WHERE email = '{}' AND password_hash = 'second-password-hash'", updated_user.email)
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &mut connection,
            format!("SELECT COUNT(*)::bigint AS count FROM oauth_clients WHERE client_id = 'oidf-seed-{suffix}'")
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &mut connection,
            format!("SELECT COUNT(*)::bigint AS count FROM oauth_clients WHERE client_id = '{sentinel_id}'")
        )
        .await,
        1
    );

    sql_query(format!(
        "DELETE FROM oauth_clients WHERE client_id IN ('oidf-seed-{suffix}', '{sentinel_id}')"
    ))
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(format!(
        "DELETE FROM users WHERE email = '{}'",
        updated_user.email
    ))
    .execute(&mut connection)
    .await
    .unwrap();
}
