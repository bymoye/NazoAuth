use chrono::{Duration, Utc};
use diesel::{
    QueryableByName, sql_query,
    sql_types::{SmallInt, Text, Uuid as SqlUuid},
};
use diesel_async::RunQueryDsl;
use nazo_identity::{
    MtlsTrustAnchorStatus, NewMtlsTrustAnchorRequest, TenantContext, UserId, ports::RepositoryError,
};
use nazo_postgres::{MtlsTrustAnchorRepository, create_pool, get_conn, run_pending_migrations};
use uuid::Uuid;

#[derive(QueryableByName)]
struct TrustEventRow {
    #[diesel(sql_type = SmallInt)]
    action: i16,
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI mTLS trust tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn request(
    tenant: TenantContext,
    user_id: UserId,
    client_id: &str,
    digest_digit: char,
) -> NewMtlsTrustAnchorRequest {
    NewMtlsTrustAnchorRequest {
        tenant_id: tenant.tenant_id,
        user_id,
        client_id: client_id.to_owned(),
        certificate_pem: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
            .to_owned(),
        certificate_sha256: std::iter::repeat_n(digest_digit, 64).collect(),
        subject_dn: "CN=Trust Anchor Test".to_owned(),
        not_before: Utc::now() - Duration::hours(2),
        not_after: Utc::now() + Duration::hours(1),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_trust_lifecycle_is_owned_two_person_current_and_revocable() {
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url).await.unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let tenant = TenantContext::default_system();
    let requester = UserId::new(Uuid::now_v7()).unwrap();
    let reviewer = UserId::new(Uuid::now_v7()).unwrap();
    let client_database_id = Uuid::now_v7();
    let bound_client_database_id = Uuid::now_v7();
    let suffix = Uuid::now_v7().simple().to_string();
    let client_id = format!("mtls-trust-{suffix}");
    let bound_client_id = format!("mtls-bound-token-{suffix}");
    let mut connection = get_conn(&pool).await.unwrap();

    for (user_id, role, admin_level) in [(requester, "user", 0), (reviewer, "admin", 1)] {
        sql_query(
            "INSERT INTO users (
                id, tenant_id, realm_id, organization_id, username, email, password_hash, role,
                admin_level
             ) VALUES ($1,$2,$3,$4,$5,$6,'test',$7,$8)",
        )
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.realm_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.organization_id.as_uuid())
        .bind::<Text, _>(format!("mtls-{role}-{suffix}"))
        .bind::<Text, _>(format!("mtls-{role}-{suffix}@example.test"))
        .bind::<Text, _>(role)
        .bind::<diesel::sql_types::Integer, _>(admin_level)
        .execute(&mut connection)
        .await
        .unwrap();
    }
    sql_query(
        "INSERT INTO oauth_clients (
            id, tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            redirect_uris, scopes, grant_types, token_endpoint_auth_method
         ) VALUES ($1,$2,$3,$4,$5,'mTLS trust test','confidential',
            '[]'::jsonb,'[\"openid\"]'::jsonb,'[\"authorization_code\"]'::jsonb,
            'tls_client_auth')",
    )
    .bind::<SqlUuid, _>(client_database_id)
    .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
    .bind::<SqlUuid, _>(tenant.realm_id.as_uuid())
    .bind::<SqlUuid, _>(tenant.organization_id.as_uuid())
    .bind::<Text, _>(&client_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO oauth_clients (
            id, tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            redirect_uris, scopes, grant_types, token_endpoint_auth_method,
            require_mtls_bound_tokens
         ) VALUES ($1,$2,$3,$4,$5,'mTLS bound-token trust test','confidential',
            '[]'::jsonb,'[\"openid\"]'::jsonb,'[\"authorization_code\"]'::jsonb,
            'private_key_jwt',TRUE)",
    )
    .bind::<SqlUuid, _>(bound_client_database_id)
    .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
    .bind::<SqlUuid, _>(tenant.realm_id.as_uuid())
    .bind::<SqlUuid, _>(tenant.organization_id.as_uuid())
    .bind::<Text, _>(&bound_client_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO client_access_requests (
            tenant_id, user_id, site_name, site_url, request_description, status,
            resolved_by_user_id, approved_client_id, resolved_at
         ) VALUES ($1,$2,'mTLS test','https://client.example','test',1,$3,$4,now())",
    )
    .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
    .bind::<SqlUuid, _>(requester.as_uuid())
    .bind::<SqlUuid, _>(reviewer.as_uuid())
    .bind::<SqlUuid, _>(client_database_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO client_access_requests (
            tenant_id, user_id, site_name, site_url, request_description, status,
            resolved_by_user_id, approved_client_id, resolved_at
         ) VALUES ($1,$2,'mTLS bound-token test','https://bound.example','test',1,$3,$4,now())",
    )
    .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
    .bind::<SqlUuid, _>(requester.as_uuid())
    .bind::<SqlUuid, _>(reviewer.as_uuid())
    .bind::<SqlUuid, _>(bound_client_database_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    let repository = MtlsTrustAnchorRepository::new(pool.clone());
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET is_active = FALSE WHERE id = $1")
        .bind::<SqlUuid, _>(requester.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert_eq!(
        repository
            .create_for_owned_client(request(tenant, requester, &client_id, 'd'))
            .await,
        Err(RepositoryError::NotFound),
        "a disabled requester cannot create trust material even if an old session bypasses HTTP checks"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET is_active = TRUE WHERE id = $1")
        .bind::<SqlUuid, _>(requester.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert_eq!(
        repository
            .create_for_owned_client(request(tenant, requester, &client_id, '9'))
            .await,
        Err(RepositoryError::NotFound),
        "the public CA approval control plane must not widen a subject-only tls_client_auth registration"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE oauth_clients
         SET tls_client_auth_cert_sha256 = $2
         WHERE id = $1",
    )
    .bind::<SqlUuid, _>(client_database_id)
    .bind::<Text, _>(std::iter::repeat_n('9', 64).collect::<String>())
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    let bound_request = repository
        .create_for_owned_client(request(tenant, requester, &bound_client_id, 'c'))
        .await
        .expect("RFC 8705 certificate-bound tokens are independent from the client auth method");
    repository
        .approve(tenant.tenant_id, bound_request.id, reviewer, None)
        .await
        .unwrap();
    let self_review = repository
        .create_for_owned_client(request(tenant, requester, &client_id, 'a'))
        .await
        .unwrap();
    assert_eq!(
        repository
            .approve(tenant.tenant_id, self_review.id, requester, None)
            .await,
        Err(RepositoryError::Conflict)
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET admin_level = 0 WHERE id = $1")
        .bind::<SqlUuid, _>(reviewer.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert_eq!(
        repository
            .approve(tenant.tenant_id, self_review.id, reviewer, None)
            .await,
        Err(RepositoryError::Conflict),
        "repository mutations must fail closed when HTTP-layer admin checks are bypassed"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET admin_level = 1 WHERE id = $1")
        .bind::<SqlUuid, _>(reviewer.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let approved = repository
        .approve(
            tenant.tenant_id,
            self_review.id,
            reviewer,
            Some("verified out of band".to_owned()),
        )
        .await
        .unwrap();
    assert_eq!(
        MtlsTrustAnchorStatus::from_code(approved.status),
        Some(MtlsTrustAnchorStatus::Approved)
    );
    assert!(
        repository
            .active_bundle(tenant.tenant_id)
            .await
            .unwrap()
            .contains("TEST")
    );
    let revoked = repository
        .revoke(
            tenant.tenant_id,
            self_review.id,
            reviewer,
            "certificate retired".to_owned(),
        )
        .await
        .unwrap();
    assert_eq!(
        MtlsTrustAnchorStatus::from_code(revoked.status),
        Some(MtlsTrustAnchorStatus::Revoked)
    );
    assert!(
        repository
            .active_bundle(tenant.tenant_id)
            .await
            .unwrap()
            .contains("TEST"),
        "revoking one client trust request must not remove another client's active anchor"
    );

    for digest_digit in ['0', '1', '2', '3'] {
        let request = repository
            .create_for_owned_client(request(tenant, requester, &client_id, digest_digit))
            .await
            .unwrap();
        repository
            .approve(tenant.tenant_id, request.id, reviewer, None)
            .await
            .unwrap();
    }
    let mut second_batch = Vec::new();
    for digest_digit in ['4', '5', '6', '7'] {
        second_batch.push(
            repository
                .create_for_owned_client(request(tenant, requester, &client_id, digest_digit))
                .await
                .unwrap(),
        );
    }
    for request in second_batch.drain(..3) {
        repository
            .approve(tenant.tenant_id, request.id, reviewer, None)
            .await
            .unwrap();
    }
    let ninth = repository
        .create_for_owned_client(request(tenant, requester, &client_id, '8'))
        .await
        .unwrap();
    let competitors = [second_batch.pop().unwrap(), ninth];
    let mut approvals = tokio::task::JoinSet::new();
    for request in competitors {
        let repository = repository.clone();
        approvals.spawn(async move {
            (
                request.id,
                repository
                    .approve(tenant.tenant_id, request.id, reviewer, None)
                    .await,
            )
        });
    }
    let mut approved_count = 7;
    let mut rejected_by_quota = 0;
    let mut quota_rejected_request_id = None;
    while let Some(result) = approvals.join_next().await {
        let (request_id, result) = result.unwrap();
        match result {
            Ok(_) => approved_count += 1,
            Err(RepositoryError::Conflict) => {
                rejected_by_quota += 1;
                quota_rejected_request_id = Some(request_id);
            }
            Err(error) => panic!("unexpected concurrent approval result: {error}"),
        }
    }
    assert_eq!(approved_count, 8);
    assert_eq!(rejected_by_quota, 1);

    for digest_digit in ['c', 'd', 'e'] {
        repository
            .create_for_owned_client(request(tenant, requester, &client_id, digest_digit))
            .await
            .unwrap();
    }
    assert_eq!(
        repository
            .create_for_owned_client(request(tenant, requester, &client_id, 'f'))
            .await,
        Err(RepositoryError::Conflict),
        "pending trust requests are bounded before persistence"
    );
    repository
        .reject(
            tenant.tenant_id,
            quota_rejected_request_id.unwrap(),
            reviewer,
            Some("active trust-anchor quota reached".to_owned()),
        )
        .await
        .unwrap();

    let expired = repository
        .create_for_owned_client(request(tenant, requester, &client_id, 'b'))
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE oauth_client_mtls_trust_anchor_requests
         SET not_after = CURRENT_TIMESTAMP - INTERVAL '1 hour'
         WHERE id = $1",
    )
    .bind::<SqlUuid, _>(expired.id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert_eq!(
        repository
            .approve(tenant.tenant_id, expired.id, reviewer, None)
            .await,
        Err(RepositoryError::Conflict)
    );
    let rejected = repository
        .reject(
            tenant.tenant_id,
            expired.id,
            reviewer,
            Some("certificate expired before review".to_owned()),
        )
        .await
        .unwrap();
    assert_eq!(
        MtlsTrustAnchorStatus::from_code(rejected.status),
        Some(MtlsTrustAnchorStatus::Rejected)
    );

    let mut connection = get_conn(&pool).await.unwrap();
    let events = sql_query(
        "SELECT action
         FROM oauth_client_mtls_trust_anchor_events
         WHERE request_id IN ($1,$2,$3)
         ORDER BY created_at, id",
    )
    .bind::<SqlUuid, _>(bound_request.id)
    .bind::<SqlUuid, _>(self_review.id)
    .bind::<SqlUuid, _>(expired.id)
    .load::<TrustEventRow>(&mut connection)
    .await
    .unwrap()
    .into_iter()
    .map(|event| event.action)
    .collect::<Vec<_>>();
    assert_eq!(events.iter().filter(|action| **action == 0).count(), 3);
    assert_eq!(events.iter().filter(|action| **action == 1).count(), 2);
    assert_eq!(events.iter().filter(|action| **action == 2).count(), 1);
    assert_eq!(events.iter().filter(|action| **action == 3).count(), 1);
    sql_query(
        "DELETE FROM oauth_client_mtls_trust_anchor_events
         WHERE request_id IN (
             SELECT id FROM oauth_client_mtls_trust_anchor_requests
             WHERE client_id IN ($1,$2)
         )",
    )
    .bind::<SqlUuid, _>(client_database_id)
    .bind::<SqlUuid, _>(bound_client_database_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query("DELETE FROM oauth_client_mtls_trust_anchor_requests WHERE client_id IN ($1,$2)")
        .bind::<SqlUuid, _>(client_database_id)
        .bind::<SqlUuid, _>(bound_client_database_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM client_access_requests WHERE approved_client_id IN ($1,$2)")
        .bind::<SqlUuid, _>(client_database_id)
        .bind::<SqlUuid, _>(bound_client_database_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM oauth_clients WHERE id IN ($1,$2)")
        .bind::<SqlUuid, _>(client_database_id)
        .bind::<SqlUuid, _>(bound_client_database_id)
        .execute(&mut connection)
        .await
        .unwrap();
    for user_id in [requester, reviewer] {
        sql_query("DELETE FROM users WHERE id = $1")
            .bind::<SqlUuid, _>(user_id.as_uuid())
            .execute(&mut connection)
            .await
            .unwrap();
    }
}
