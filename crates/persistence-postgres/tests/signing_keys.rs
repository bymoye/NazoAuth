//! Real-database proof of the tenant-bound signing-key repository contract.
use std::collections::BTreeMap;

use chrono::{Duration, Utc};
use diesel::{sql_query, sql_types::Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use nazo_auth::{SignRequest, Signer, SigningPurpose};
use nazo_digital_credentials::{
    CertificateRevocationEntry, CertificateRevocationSnapshot, CertificateRevocationStatus,
    certificate_identity,
};
use nazo_key_management::{
    KeyManager, KeySettings, Openid4vcMaterial, Openid4vcPublicMaterial, PersistedSigningKeyset,
    SigningKeyRepository, SigningKeyWrappingKeyRing, SigningKeysetCompareAndSwapResult,
    SigningKeysetCreateResult,
};
use nazo_postgres::{SigningKeysetRepository, create_pool, run_pending_migrations};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MDOC_ISSUER: &str = "https://issuer.example";

struct MdocFixture {
    signing_key_pem: String,
    iaca_private_key_pem: String,
    material: Openid4vcMaterial,
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn mdoc_fixture(signing_kid: &str) -> MdocFixture {
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("P-256 signing key");
    let signing_key_pem = signing_key.serialize_pem();

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("P-256 IACA key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("IACA certificate");

    let mut leaf_params =
        CertificateParams::new(vec!["issuer.example".to_owned()]).expect("DS certificate params");
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf = leaf_params
        .signed_by(&signing_key, &ca)
        .expect("DS certificate");

    let ca_pem = ca.pem();
    let leaf_pem = leaf.pem();
    let iaca_private_key_pem = ca.key().serialize_pem();
    let iaca_material = format!("{iaca_private_key_pem}{leaf_pem}{ca_pem}");
    let iaca_id = sha256_hex(ca.der());
    let snapshot = CertificateRevocationSnapshot {
        version: CertificateRevocationSnapshot::VERSION,
        this_update: Utc::now() - Duration::minutes(1),
        next_update: Utc::now() + Duration::hours(1),
        entries: vec![CertificateRevocationEntry {
            issuer: MDOC_ISSUER.to_owned(),
            certificate: certificate_identity(leaf.der()),
            status: CertificateRevocationStatus::Good,
            revoked_at: None,
        }],
    };
    MdocFixture {
        signing_key_pem,
        iaca_private_key_pem,
        material: Openid4vcMaterial {
            public: Openid4vcPublicMaterial {
                signing_kid: signing_kid.to_owned(),
                certificate_chain_pem: format!("{leaf_pem}{ca_pem}"),
                trust_anchors_pem: ca_pem,
                revocation_snapshot: Some(snapshot),
            },
            iaca_private_materials: BTreeMap::from([(iaca_id, iaca_material)]),
        },
    }
}

fn rotated_material(previous: &MdocFixture, next: &MdocFixture) -> Openid4vcMaterial {
    let mut material = next.material.clone();
    material.public.trust_anchors_pem = format!(
        "{}{}",
        previous.material.public.trust_anchors_pem, material.public.trust_anchors_pem
    );
    let mut snapshot = previous
        .material
        .public
        .revocation_snapshot
        .clone()
        .expect("initial mdoc revocation snapshot");
    snapshot.entries.extend(
        material
            .public
            .revocation_snapshot
            .take()
            .expect("rotated mdoc revocation snapshot")
            .entries,
    );
    material.public.revocation_snapshot = Some(snapshot);
    material
        .iaca_private_materials
        .extend(previous.material.iaca_private_materials.clone());
    material
}

fn assert_same_runtime_public_material(
    actual: &Openid4vcPublicMaterial,
    expected: &Openid4vcPublicMaterial,
) {
    assert_eq!(actual.signing_kid, expected.signing_kid);
    assert_eq!(actual.certificate_chain_pem, expected.certificate_chain_pem);
    assert_eq!(actual.trust_anchors_pem, expected.trust_anchors_pem);
    assert_eq!(
        actual
            .revocation_snapshot
            .as_ref()
            .map(|snapshot| (snapshot.version, snapshot.entries.clone())),
        expected
            .revocation_snapshot
            .as_ref()
            .map(|snapshot| (snapshot.version, snapshot.entries.clone())),
    );
}

fn database_key_settings(keys_dir: std::path::PathBuf) -> KeySettings {
    KeySettings {
        keys_dir,
        external_command: Vec::new(),
        external_timeout: std::time::Duration::from_secs(1),
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    }
}

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
async fn database_managed_openid4vc_material_survives_refresh_rotation_and_restart()
-> anyhow::Result<()> {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("signing-key integration test requires a PostgreSQL test database");
    run_pending_migrations(&database_url).await?;
    let pool = create_pool(database_url, 4)?;
    let tenant = Uuid::now_v7();
    sql_query(
        "INSERT INTO tenants (id, slug, display_name) VALUES ($1, $1::text, 'Managed mdoc test')",
    )
    .bind::<SqlUuid, _>(tenant)
    .execute(&mut pool.get().await?)
    .await?;

    let keys_dir = std::env::temp_dir().join(format!("nazo-managed-mdoc-{tenant}"));
    let settings = database_key_settings(keys_dir.clone());
    let wrapping_keys = SigningKeyWrappingKeyRing::new("mdoc-test", [37_u8; 32], None)?;
    let repository: std::sync::Arc<dyn SigningKeyRepository> =
        std::sync::Arc::new(SigningKeysetRepository::for_tenant(pool.clone(), tenant));
    let second_repository: std::sync::Arc<dyn SigningKeyRepository> =
        std::sync::Arc::new(SigningKeysetRepository::for_tenant(pool.clone(), tenant));

    let first = KeyManager::load_or_create_database(
        settings.clone(),
        tenant,
        repository.clone(),
        wrapping_keys.clone(),
    )
    .await?;
    let second = KeyManager::load_or_create_database(
        settings.clone(),
        tenant,
        second_repository,
        wrapping_keys.clone(),
    )
    .await?;
    let initial = mdoc_fixture("mdoc-signing-1");
    let initial_state = first.database_openid4vc_state().await?;
    assert!(initial_state.material.is_none());
    first
        .database_commit_openid4vc(
            initial_state.revision,
            initial.material.clone(),
            Some(initial.signing_key_pem.clone()),
        )
        .await?;

    second.refresh().await?;
    let second_state = second.database_openid4vc_state().await?;
    assert_eq!(second_state.material, Some(initial.material.clone()));
    let old_jwk = second
        .snapshot()
        .verification_key("mdoc-signing-1")
        .unwrap()
        .public_jwk
        .clone();
    let old_lease = second.prepare_openid4vc_signing()?;
    assert_eq!(old_lease.kid(), "mdoc-signing-1");
    let old_lease_material = old_lease.material().clone();
    assert_same_runtime_public_material(&old_lease_material, &initial.material.public);
    let old_signature = second
        .sign(SignRequest {
            purpose: SigningPurpose::Credential,
            algorithm: "ES256",
            signing_input: b"managed-mdoc-signing-input",
        })
        .await?;
    assert!(!old_signature.as_bytes().is_empty());

    let next = mdoc_fixture("mdoc-signing-2");
    let rotated = rotated_material(&initial, &next);
    let rotated_state = first.database_openid4vc_state().await?;
    first
        .database_commit_openid4vc(
            rotated_state.revision,
            rotated.clone(),
            Some(next.signing_key_pem.clone()),
        )
        .await?;
    second.refresh().await?;

    // The captured lease owns the old generation, including its certificate
    // projection, while the manager now serves the rotated generation.
    assert_eq!(old_lease.kid(), "mdoc-signing-1");
    assert_eq!(old_lease.material(), &old_lease_material);
    let old_jwt = old_lease
        .encode_jwt(
            SigningPurpose::Credential,
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
            &json!({"sub": "old-generation"}),
        )
        .await?;
    assert_eq!(
        jsonwebtoken::decode_header(&old_jwt)?.kid.as_deref(),
        Some("mdoc-signing-1")
    );

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    let old_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(old_jwk)?;
    let old_decoding_key = jsonwebtoken::DecodingKey::from_jwk(&old_jwk)?;
    jsonwebtoken::decode::<serde_json::Value>(&old_jwt, &old_decoding_key, &validation)?;
    let new_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(
        second
            .snapshot()
            .verification_key("mdoc-signing-2")
            .unwrap()
            .public_jwk
            .clone(),
    )?;
    assert!(
        jsonwebtoken::decode::<serde_json::Value>(
            &old_jwt,
            &jsonwebtoken::DecodingKey::from_jwk(&new_jwk)?,
            &validation
        )
        .is_err()
    );

    let current_lease = second.prepare_openid4vc_signing()?;
    assert_eq!(current_lease.kid(), "mdoc-signing-2");
    assert_same_runtime_public_material(current_lease.material(), &rotated.public);

    let fresh_dir = std::env::temp_dir().join(format!("nazo-managed-mdoc-fresh-{tenant}"));
    assert!(!fresh_dir.exists());
    let fresh = KeyManager::load_or_create_database(
        database_key_settings(fresh_dir.clone()),
        tenant,
        repository.clone(),
        wrapping_keys,
    )
    .await?;
    assert!(!fresh_dir.exists());
    let fresh_state = fresh.database_openid4vc_state().await?;
    assert_eq!(fresh_state.material, Some(rotated.clone()));
    let fresh_lease = fresh.prepare_openid4vc_signing()?;
    assert_same_runtime_public_material(fresh_lease.material(), &rotated.public);

    let persisted = SigningKeyRepository::load(repository.as_ref())
        .await?
        .expect("managed keyset remains persisted");
    assert!(
        persisted
            .public_metadata
            .pointer("/openid4vc/iaca_private_materials")
            .is_none()
    );
    let public_metadata = persisted.public_metadata.to_string();
    assert!(!public_metadata.contains("PRIVATE KEY"));
    assert!(!public_metadata.contains(&initial.iaca_private_key_pem));
    assert!(!public_metadata.contains(&next.iaca_private_key_pem));
    assert!(!public_metadata.contains(&initial.signing_key_pem));
    assert!(!public_metadata.contains(&next.signing_key_pem));

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
