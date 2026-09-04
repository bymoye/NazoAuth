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
async fn database_managers_share_encrypted_keys_and_restart_without_local_files()
-> anyhow::Result<()> {
    use nazo_key_management::{KeyManager, KeySettings, SigningKeyWrappingKeyRing};
    use std::sync::Arc;

    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("signing-key integration test requires a PostgreSQL test database");
    run_pending_migrations(&database_url).await?;
    let pool = create_pool(database_url, 4)?;
    let tenant = Uuid::now_v7();
    sql_query(
        "INSERT INTO tenants (id, slug, display_name) VALUES ($1, $1::text, 'Shared-key managers')",
    )
    .bind::<SqlUuid, _>(tenant)
    .execute(&mut pool.get().await?)
    .await?;
    let directory = std::env::temp_dir().join(format!("nazo-shared-key-proof-{tenant}"));
    let settings = KeySettings {
        keys_dir: directory.clone(),
        external_command: Vec::new(),
        external_timeout: std::time::Duration::from_secs(1),
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let repository: Arc<dyn SigningKeyRepository> =
        Arc::new(SigningKeysetRepository::for_tenant(pool.clone(), tenant));
    let second_repository: Arc<dyn SigningKeyRepository> =
        Arc::new(SigningKeysetRepository::for_tenant(pool.clone(), tenant));
    let ring = SigningKeyWrappingKeyRing::new("first", [17_u8; 32], None)?;
    let (first, second) = tokio::join!(
        KeyManager::load_or_create_database(
            settings.clone(),
            tenant,
            repository.clone(),
            ring.clone()
        ),
        KeyManager::load_or_create_database(settings.clone(), tenant, second_repository, ring),
    );
    let (first, second) = (first?, second?);
    let original_kid = first.snapshot().active_kid.clone();
    assert_eq!(original_kid, second.snapshot().active_kid);
    assert!(!directory.exists());
    let persisted = SigningKeyRepository::load(repository.as_ref())
        .await?
        .unwrap();
    assert_eq!(persisted.revision, 1);
    assert!(
        !persisted
            .public_metadata
            .to_string()
            .contains("private_pkcs8_der")
    );
    assert!(
        !persisted
            .public_metadata
            .to_string()
            .contains("request_object_private_pem")
    );
    let wrong = SigningKeyWrappingKeyRing::new("first", [18_u8; 32], None)?;
    assert!(
        KeyManager::load_or_create_database(settings.clone(), tenant, repository.clone(), wrong)
            .await
            .is_err()
    );

    drop(first);
    drop(second);
    let rolling_ring = SigningKeyWrappingKeyRing::new(
        "second",
        [19_u8; 32],
        Some(("first".to_owned(), [17_u8; 32])),
    )?;
    let rolling = KeyManager::load_or_create_database(
        settings.clone(),
        tenant,
        repository.clone(),
        rolling_ring,
    )
    .await?;
    rolling.refresh().await?;
    assert_eq!(
        SigningKeyRepository::load(repository.as_ref())
            .await?
            .unwrap()
            .wrapping_key_id,
        "second"
    );
    drop(rolling);
    let restarted = KeyManager::load_or_create_database(
        settings,
        tenant,
        repository,
        SigningKeyWrappingKeyRing::new("second", [19_u8; 32], None)?,
    )
    .await?;
    assert_eq!(restarted.snapshot().active_kid, original_kid);
    assert!(!directory.exists());
    sql_query("DELETE FROM tenants WHERE id = $1")
        .bind::<SqlUuid, _>(tenant)
        .execute(&mut pool.get().await?)
        .await?;
    Ok(())
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
