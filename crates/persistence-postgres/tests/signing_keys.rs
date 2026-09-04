//! Real-database proof of the tenant-bound signing-key repository contract.
use diesel::{sql_query, sql_types::Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use nazo_key_management::{
    PersistedSigningKeyset, SigningKeyRepository, SigningKeysetCompareAndSwapResult,
    SigningKeysetCreateResult,
};
use nazo_postgres::{SigningKeysetRepository, create_pool, run_pending_migrations};
use serde_json::json;
use uuid::Uuid;

fn candidate(revision: i64, marker: u8) -> PersistedSigningKeyset {
    PersistedSigningKeyset {
        revision,
        public_metadata: json!({"active_kid": format!("key-{marker}")}),
        encrypted_private_material: vec![marker; 48],
        wrapping_key_id: "deployment-test".to_owned(),
    }
}

#[tokio::test]
async fn signing_key_repository_converges_and_isolates_tenants() -> anyhow::Result<()> {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("signing-key integration test requires a PostgreSQL test database");
    run_pending_migrations(&database_url).await?;
    let pool = create_pool(database_url, 4)?;
    let tenant_a = Uuid::now_v7();
    let tenant_b = Uuid::now_v7();
    {
        let mut connection = pool.get().await?;
        for tenant in [tenant_a, tenant_b] {
            sql_query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $1::text, 'Signing-key test')")
                .bind::<SqlUuid, _>(tenant)
                .execute(&mut connection).await?;
        }
    }
    let first = SigningKeysetRepository::for_tenant(pool.clone(), tenant_a);
    let second = SigningKeysetRepository::for_tenant(pool.clone(), tenant_a);
    let other = SigningKeysetRepository::for_tenant(pool.clone(), tenant_b);
    assert!(SigningKeyRepository::load(&first).await?.is_none());

    let (left, right) = tokio::join!(
        first.create_if_absent(candidate(1, 1)),
        second.create_if_absent(candidate(1, 2)),
    );
    let (left, right) = (left?, right?);
    assert_eq!(
        usize::from(matches!(left, SigningKeysetCreateResult::Created(_)))
            + usize::from(matches!(right, SigningKeysetCreateResult::Created(_))),
        1
    );
    let record = |result| match result {
        SigningKeysetCreateResult::Created(record)
        | SigningKeysetCreateResult::Existing(record) => record,
    };
    let (left, right) = (record(left), record(right));
    assert_eq!(left.public_metadata, right.public_metadata);
    assert_eq!(
        left.encrypted_private_material,
        right.encrypted_private_material
    );
    assert!(SigningKeyRepository::load(&other).await?.is_none());

    let (left, right) = tokio::join!(
        first.compare_and_swap(1, candidate(2, 3)),
        second.compare_and_swap(1, candidate(2, 4)),
    );
    let (left, right) = (left?, right?);
    assert_eq!(
        usize::from(matches!(
            left,
            SigningKeysetCompareAndSwapResult::Applied(_)
        )) + usize::from(matches!(
            right,
            SigningKeysetCompareAndSwapResult::Applied(_)
        )),
        1
    );
    let record = |result| match result {
        SigningKeysetCompareAndSwapResult::Applied(record)
        | SigningKeysetCompareAndSwapResult::Conflict(record) => record,
    };
    let (left, right) = (record(left), record(right));
    assert_eq!(left.revision, 2);
    assert_eq!(left.public_metadata, right.public_metadata);
    assert_eq!(
        left.encrypted_private_material,
        right.encrypted_private_material
    );
    assert!(first.compare_and_swap(2, candidate(4, 5)).await.is_err());

    assert!(matches!(
        other.create_if_absent(candidate(1, 6)).await?,
        SigningKeysetCreateResult::Created(_)
    ));
    assert_eq!(
        SigningKeyRepository::load(&other)
            .await?
            .unwrap()
            .encrypted_private_material,
        vec![6; 48]
    );
    // A replacement adapter reconstructs the same generation without any local files.
    let restarted = SigningKeysetRepository::for_tenant(pool.clone(), tenant_a);
    assert_eq!(
        SigningKeyRepository::load(&restarted)
            .await?
            .unwrap()
            .public_metadata,
        left.public_metadata
    );
    assert_eq!(
        SigningKeyRepository::load(&restarted)
            .await?
            .unwrap()
            .wrapping_key_id,
        "deployment-test"
    );

    let mut connection = pool.get().await?;
    for tenant in [tenant_a, tenant_b] {
        sql_query("DELETE FROM tenants WHERE id = $1")
            .bind::<SqlUuid, _>(tenant)
            .execute(&mut connection)
            .await?;
    }
    assert!(SigningKeyRepository::load(&first).await?.is_none());
    Ok(())
}
