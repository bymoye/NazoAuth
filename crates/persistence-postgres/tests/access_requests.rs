use diesel::{
    sql_query,
    sql_types::{BigInt, Text, Uuid as SqlUuid},
};
use diesel_async::RunQueryDsl;
use nazo_auth::ValidatedClientRegistration;
use nazo_identity::{
    AccessRequestStatus, NewAccessRequest, TenantContext, TenantId, UserId, ports::RepositoryError,
};
use nazo_postgres::{AccessRequestRepository, OAuthClientRepository, create_pool, get_conn};
use uuid::Uuid;

async fn fixture() -> Option<(nazo_postgres::DbPool, TenantContext, UserId)> {
    let database_url =
        match std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL")) {
            Ok(database_url) => database_url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!("CI requires NAZO_TEST_DATABASE_URL or DATABASE_URL")
            }
            Err(_) => return None,
        };
    let pool = create_pool(database_url, 8).expect("test pool can be built");
    let tenant = TenantContext::default_system();
    let user_id = UserId::new(Uuid::now_v7()).unwrap();
    let token = Uuid::now_v7().simple().to_string();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, password_hash) VALUES ($1,$2,$3,$4,$5,$6,'test')")
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.realm_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.organization_id.as_uuid())
        .bind::<Text, _>(format!("access-{token}"))
        .bind::<Text, _>(format!("access-{token}@example.test"))
        .execute(&mut connection)
        .await
        .unwrap();
    Some((pool, tenant, user_id))
}

async fn cleanup(pool: &nazo_postgres::DbPool, user_id: UserId) {
    if let Ok(mut connection) = get_conn(pool).await {
        let _ = sql_query("DELETE FROM users WHERE id = $1")
            .bind::<SqlUuid, _>(user_id.as_uuid())
            .execute(&mut connection)
            .await;
    }
}

fn new_request(tenant: TenantContext, user_id: UserId, suffix: &str) -> NewAccessRequest {
    NewAccessRequest {
        tenant_id: tenant.tenant_id,
        user_id,
        site_name: format!("Access {suffix}"),
        site_url: format!("https://{suffix}.example.test"),
        request_description: "integration test".to_owned(),
    }
}

fn client(suffix: &str) -> ValidatedClientRegistration {
    ValidatedClientRegistration {
        client_id: format!("access-client-{suffix}"),
        client_name: format!("Access Client {suffix}"),
        client_type: "public".to_owned(),
        redirect_uris: vec!["https://client.example.test/callback".to_owned()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_owned()],
        allowed_audiences: Vec::new(),
        grant_types: vec!["authorization_code".to_owned()],
        token_endpoint_auth_method: "none".to_owned(),
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
        require_dpop_bound_tokens: false,
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        allow_authorization_code_without_pkce: false,
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
        jwks: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
    }
}

#[tokio::test]
async fn create_list_cancel_and_detail_are_tenant_and_owner_scoped() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let created = repository
        .create(new_request(
            tenant,
            user_id,
            &Uuid::now_v7().simple().to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(
        repository
            .list_for_user(tenant.tenant_id, user_id)
            .await
            .unwrap()
            .iter()
            .filter(|request| request.id == created.id)
            .count(),
        1
    );
    let other_tenant = TenantId::new(Uuid::now_v7()).unwrap();
    assert!(
        repository
            .by_id(other_tenant, created.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repository
            .list_for_user(other_tenant, user_id)
            .await
            .unwrap()
            .is_empty()
    );
    repository
        .cancel_pending(tenant.tenant_id, user_id, created.id)
        .await
        .unwrap();
    assert!(
        repository
            .by_id(tenant.tenant_id, created.id)
            .await
            .unwrap()
            .is_none()
    );
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn create_rejects_user_from_a_different_tenant() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let other_tenant = TenantId::new(Uuid::now_v7()).unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind::<SqlUuid, _>(other_tenant.as_uuid())
        .bind::<Text, _>(format!("cross-tenant-{}", other_tenant.as_uuid().simple()))
        .bind::<Text, _>("Cross Tenant")
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let error = repository
        .create(NewAccessRequest {
            tenant_id: other_tenant,
            user_id,
            site_name: "Cross Tenant".to_owned(),
            site_url: "https://cross-tenant.example.test".to_owned(),
            request_description: "must be rejected".to_owned(),
        })
        .await
        .unwrap_err();

    assert_eq!(error, RepositoryError::NotFound);
    assert!(
        repository
            .list_for_user(other_tenant, user_id)
            .await
            .unwrap()
            .is_empty()
    );
    cleanup(&pool, user_id).await;
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM tenants WHERE id = $1")
        .bind::<SqlUuid, _>(other_tenant.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    let _ = tenant;
}

#[tokio::test]
async fn concurrent_approval_has_one_cas_winner_and_rolls_back_losing_client() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let request = repository
        .create(new_request(
            tenant,
            user_id,
            &Uuid::now_v7().simple().to_string(),
        ))
        .await
        .unwrap();
    let left_client = client(&Uuid::now_v7().simple().to_string());
    let right_client = client(&Uuid::now_v7().simple().to_string());
    let client_ids = [
        left_client.client_id.clone(),
        right_client.client_id.clone(),
    ];
    let (left, right) = tokio::join!(
        repository.approve(tenant, request.id, user_id, &left_client, None, None),
        repository.approve(tenant, request.id, user_id, &right_client, None, None)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(
        matches!(left, Err(RepositoryError::AlreadyProcessed))
            || matches!(right, Err(RepositoryError::AlreadyProcessed))
    );
    let state = repository
        .by_id(tenant.tenant_id, request.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.status, AccessRequestStatus::Approved);
    let mut connection = get_conn(&pool).await.unwrap();
    let count = sql_query("SELECT COUNT(*)::bigint AS count FROM oauth_clients WHERE client_id = $1 OR client_id = $2")
        .bind::<Text, _>(&client_ids[0])
        .bind::<Text, _>(&client_ids[1])
        .get_result::<CountRow>(&mut connection)
        .await
        .unwrap()
        .count;
    assert_eq!(
        count, 1,
        "losing approval transaction must roll back its client"
    );
    drop(connection);
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn approval_rejects_mismatched_actor_context() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let request = repository
        .create(new_request(
            tenant,
            user_id,
            &Uuid::now_v7().simple().to_string(),
        ))
        .await
        .unwrap();
    let actor_error = repository
        .approve(
            tenant,
            request.id,
            UserId::new(Uuid::now_v7()).unwrap(),
            &client(&Uuid::now_v7().simple().to_string()),
            None,
            None,
        )
        .await
        .unwrap_err();

    assert!(matches!(actor_error, RepositoryError::Consistency(_)));
    assert_eq!(
        repository
            .by_id(tenant.tenant_id, request.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AccessRequestStatus::Pending
    );
    cleanup(&pool, user_id).await;
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[tokio::test]
async fn concurrent_rejection_has_one_cas_winner() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let request = repository
        .create(new_request(
            tenant,
            user_id,
            &Uuid::now_v7().simple().to_string(),
        ))
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        repository.reject(tenant.tenant_id, request.id, user_id, "left".to_owned()),
        repository.reject(tenant.tenant_id, request.id, user_id, "right".to_owned())
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(
        matches!(left, Err(RepositoryError::Conflict))
            || matches!(right, Err(RepositoryError::Conflict))
    );
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn duplicate_client_conflict_does_not_report_request_as_processed() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let suffix = Uuid::now_v7().simple().to_string();
    let first = repository
        .create(new_request(tenant, user_id, &format!("first-{suffix}")))
        .await
        .unwrap();
    let prepared = client(&suffix);
    let approved = repository
        .approve(tenant, first.id, user_id, &prepared, None, None)
        .await
        .unwrap();
    let client_repository = OAuthClientRepository::new(pool.clone());
    assert_eq!(
        client_repository
            .by_id(approved.id)
            .await
            .unwrap()
            .unwrap()
            .client_id,
        approved.client_id
    );
    assert_eq!(
        client_repository
            .by_client_id(tenant.tenant_id.as_uuid(), &approved.client_id)
            .await
            .unwrap()
            .unwrap()
            .id,
        approved.id
    );
    assert!(
        repository
            .approved_delivery_matches(
                tenant.tenant_id,
                user_id,
                first.id,
                approved.id,
                &approved.client_id,
            )
            .await
            .unwrap()
    );
    assert!(
        !repository
            .approved_delivery_matches(
                tenant.tenant_id,
                user_id,
                first.id,
                approved.id,
                "wrong-client-id",
            )
            .await
            .unwrap()
    );
    let second = repository
        .create(new_request(tenant, user_id, &format!("second-{suffix}")))
        .await
        .unwrap();

    let error = repository
        .approve(tenant, second.id, user_id, &prepared, None, None)
        .await
        .unwrap_err();

    assert_eq!(error, RepositoryError::Conflict);
    assert_eq!(
        repository
            .by_id(tenant.tenant_id, second.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AccessRequestStatus::Pending
    );
    cleanup(&pool, user_id).await;
}
