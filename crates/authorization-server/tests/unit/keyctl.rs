use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::SigningPurpose;
use nazo_key_management::{
    KeyManager, KeySettings, LocalKeyRegistration, Openid4vcMaterial, PersistedSigningKeyset,
    SigningKeyRepository, SigningKeyRepositoryFuture, SigningKeyWrappingKeyRing,
    SigningKeysetCompareAndSwapResult, SigningKeysetCreateResult,
};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use uuid::Uuid;

use super::*;

#[derive(Default)]
struct MemorySigningKeyRepository(Mutex<Option<PersistedSigningKeyset>>);

impl SigningKeyRepository for MemorySigningKeyRepository {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>> {
        Box::pin(async move { Ok(self.0.lock().expect("repository mutex").clone()) })
    }

    fn create_if_absent(
        &self,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        Box::pin(async move {
            let mut record = self.0.lock().expect("repository mutex");
            Ok(match record.clone() {
                Some(existing) => SigningKeysetCreateResult::Existing(existing),
                None => {
                    *record = Some(candidate.clone());
                    SigningKeysetCreateResult::Created(candidate)
                }
            })
        })
    }

    fn compare_and_swap(
        &self,
        expected_revision: i64,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult> {
        Box::pin(async move {
            let mut record = self.0.lock().expect("repository mutex");
            let current = record
                .clone()
                .ok_or_else(|| anyhow::anyhow!("repository has no keyset"))?;
            Ok(if current.revision == expected_revision {
                *record = Some(candidate.clone());
                SigningKeysetCompareAndSwapResult::Applied(candidate)
            } else {
                SigningKeysetCompareAndSwapResult::Conflict(current)
            })
        })
    }
}

struct MemoryOperatorPersistence {
    repository: Arc<MemorySigningKeyRepository>,
}

impl crate::operator_task::OperatorPersistence for MemoryOperatorPersistence {
    fn signing_key_repository(
        &self,
        _tenant_id: Uuid,
    ) -> Arc<dyn nazo_key_management::SigningKeyRepository> {
        self.repository.clone()
    }

    fn controller_registry(&self) -> Arc<dyn nazo_persistence::ControllerRegistryPort> {
        unimplemented!("keyctl tests do not use the controller registry")
    }

    fn recovery_invalidations(&self) -> Arc<dyn nazo_persistence::RecoveryInvalidationStore> {
        unimplemented!("keyctl tests do not use recovery invalidations")
    }

    fn admin_clients(&self) -> Arc<dyn nazo_auth::AdminClientRepositoryPort> {
        unimplemented!("keyctl tests do not use admin clients")
    }

    fn tenant_resource_executor(
        &self,
        _tenant: nazo_identity::TenantContext,
        _data_encryption_key: Option<[u8; 32]>,
        _preparation: Arc<dyn nazo_persistence::tenant_resources::TenantResourcePreparation>,
    ) -> Arc<dyn nazo_persistence::tenant_resources::TenantResourceExecutorPort> {
        unimplemented!("keyctl tests do not use tenant resources")
    }

    fn tenant_directory_executor(
        &self,
    ) -> Arc<dyn nazo_persistence::directory_control::TenantDirectoryControlPort> {
        unimplemented!("keyctl tests do not use tenant directory execution")
    }

    fn tenant_directory(&self) -> Arc<dyn nazo_persistence::TenantDirectoryStore> {
        unimplemented!("keyctl tests do not use tenant directory lookup")
    }

    fn run_migrations(&self) -> crate::operator_task::OperatorBackendFuture<'_, bool> {
        unimplemented!("keyctl tests do not run migrations")
    }

    fn initialize_tenant_directory(
        &self,
        _binding: nazo_identity::TenantDirectoryBinding,
    ) -> crate::operator_task::OperatorBackendFuture<'_, bool> {
        unimplemented!("keyctl tests do not initialize tenant directories")
    }
}

fn temporary_directory(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("nazoauth-keyctl-{label}-{}", Uuid::now_v7()))
}

fn tenant_binding(issuer: &str) -> nazo_identity::TenantDirectoryBinding {
    let tenant_id = Uuid::now_v7();
    let realm_id = Uuid::now_v7();
    let organization_id = Uuid::now_v7();
    let tenant = nazo_identity::TenantContext {
        tenant_id: nazo_identity::TenantId::new(tenant_id).expect("tenant id"),
        realm_id: nazo_identity::RealmId::new(realm_id).expect("realm id"),
        organization_id: nazo_identity::OrganizationId::new(organization_id)
            .expect("organization id"),
    };
    let host = Url::parse(issuer)
        .expect("issuer URL")
        .host_str()
        .expect("issuer host")
        .to_owned();
    nazo_identity::TenantDirectoryBinding {
        tenant,
        runtime_revision: 1,
        issuer: issuer.to_owned(),
        external_host: host,
    }
}

fn database_config(data_dir: &Path) -> ConfigSource {
    ConfigSource::from_owned_pairs_for_test([
        ("DATA_DIR".to_owned(), data_dir.display().to_string()),
        (
            "SIGNING_KEY_ENCRYPTION_KEY".to_owned(),
            URL_SAFE_NO_PAD.encode([0x42_u8; 32]),
        ),
        (
            "SIGNING_KEY_ENCRYPTION_KEY_ID".to_owned(),
            "keyctl-test-root".to_owned(),
        ),
    ])
}

fn database_key_settings(data_dir: &Path) -> KeySettings {
    KeySettings {
        keys_dir: data_dir.join("keys"),
        external_command: Vec::new(),
        external_timeout: std::time::Duration::from_secs(1),
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::hours(1),
    }
}

fn all_openid4vc_purposes() -> std::collections::BTreeSet<SigningPurpose> {
    [
        SigningPurpose::Credential,
        SigningPurpose::PresentationRequest,
    ]
    .into_iter()
    .collect()
}

fn managed_options() -> GenerateLocalKeyOptions {
    parse_generate_local(
        "ES256",
        &["credential".to_owned(), "presentation_request".to_owned()],
    )
    .expect("managed OpenID4VC options")
}

fn managed_profile(hostname: &str) -> Openid4vcCertificateProfile {
    Openid4vcCertificateProfile {
        hostname: hostname.to_owned(),
        mdoc_profile: Some(MdocCertificateProfile {
            issuing_country: "US".to_owned(),
            issuer_contact_uri: format!("https://{hostname}"),
            crl_distribution_uri: format!("https://{hostname}/.well-known/mdoc"),
        }),
    }
}

fn parse_certificates(pem: &str) -> Vec<CertificateDer<'_>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("certificate PEM")
}

fn iaca_certificates<'a>(
    material: &'a Openid4vcMaterial,
    issuer_id: &str,
) -> Vec<CertificateDer<'a>> {
    parse_certificates(
        material
            .iaca_private_materials
            .get(issuer_id)
            .expect("IACA material"),
    )
}

fn assert_complete_managed_material(material: &Openid4vcMaterial) {
    assert!(!material.public.signing_kid.is_empty());
    assert_eq!(
        parse_certificates(&material.public.certificate_chain_pem).len(),
        2
    );
    assert!(!material.public.trust_anchors_pem.is_empty());
    assert!(!material.iaca_private_materials.is_empty());
    let snapshot = material
        .public
        .revocation_snapshot
        .as_ref()
        .expect("managed revocation snapshot");
    assert!(!snapshot.entries.is_empty());
    for pem in material.iaca_private_materials.values() {
        assert_eq!(parse_certificates(pem).len(), 2);
    }
}

fn assert_same_material(left: &Openid4vcMaterial, right: &Openid4vcMaterial) {
    assert_eq!(left.public.signing_kid, right.public.signing_kid);
    assert_eq!(
        left.public.certificate_chain_pem,
        right.public.certificate_chain_pem
    );
    assert_eq!(
        left.public.trust_anchors_pem,
        right.public.trust_anchors_pem
    );
    assert_eq!(
        left.public.revocation_snapshot,
        right.public.revocation_snapshot
    );
    assert_eq!(left.iaca_private_materials, right.iaca_private_materials);
}

fn assert_same_persisted_record(left: &PersistedSigningKeyset, right: &PersistedSigningKeyset) {
    assert_eq!(left.revision, right.revision);
    assert_eq!(left.public_metadata, right.public_metadata);
    assert_eq!(
        left.encrypted_private_material,
        right.encrypted_private_material
    );
    assert_eq!(left.wrapping_key_id, right.wrapping_key_id);
}

async fn database_manager(
    repository: Arc<MemorySigningKeyRepository>,
    data_dir: &Path,
    tenant_id: Uuid,
) -> KeyManager {
    KeyManager::load_or_create_database(
        database_key_settings(data_dir),
        tenant_id,
        repository,
        SigningKeyWrappingKeyRing::new("keyctl-test-root", [0x42; 32], None)
            .expect("wrapping key ring"),
    )
    .await
    .expect("database key manager")
}

async fn database_manager_with_mdoc_key(
    repository: Arc<MemorySigningKeyRepository>,
    data_dir: &Path,
    tenant_id: Uuid,
) -> (KeyManager, String, KeyPair) {
    let manager = database_manager(repository, data_dir, tenant_id).await;
    let kid = manager
        .database_register_local(LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: all_openid4vc_purposes(),
        })
        .await
        .expect("database mdoc signing key");
    let key = KeyPair::from_pem(
        &manager
            .database_local_private_key_pem(&kid)
            .expect("database mdoc signing key material"),
    )
    .expect("database mdoc signing key PEM");
    (manager, kid, key)
}

async fn write_mdoc_import_fixture(
    source: &Path,
    active_key: &KeyPair,
    profile: &Openid4vcCertificateProfile,
    include_iaca_directory: bool,
) -> anyhow::Result<Openid4vcMaterial> {
    let active = build_managed_material(active_key, profile, None)?;
    tokio::fs::create_dir_all(source).await?;
    tokio::fs::write(
        source.join("certificate-bundle.pem"),
        &active.public.certificate_chain_pem,
    )
    .await?;
    tokio::fs::write(
        source.join("revocation-snapshot.json"),
        serde_json::to_vec(
            active
                .public
                .revocation_snapshot
                .as_ref()
                .expect("snapshot"),
        )?,
    )
    .await?;
    if include_iaca_directory {
        let iaca_directory = source.join("iaca-keys");
        tokio::fs::create_dir_all(&iaca_directory).await?;
        for (issuer_id, pem) in &active.iaca_private_materials {
            tokio::fs::write(iaca_directory.join(format!("{issuer_id}.pem")), pem).await?;
        }
    }
    Ok(active)
}

#[test]
fn parses_the_closed_purpose_scoped_key_operation() {
    let options = parse_generate_local(
        "ES256",
        &["credential".to_owned(), "presentation_request".to_owned()],
    )
    .unwrap();
    assert_eq!(options.alg, jsonwebtoken::Algorithm::ES256);
    assert_eq!(options.purposes.len(), 2);
}

#[test]
fn rejects_empty_duplicate_or_runtime_signing_purposes() {
    assert!(parse_generate_local("ES256", &[]).is_err());
    assert!(
        parse_generate_local("ES256", &["credential".to_owned(), "credential".to_owned()]).is_err()
    );
    assert!(parse_generate_local("ES256", &["access_token".to_owned()]).is_err());
}

#[test]
fn rejects_unsupported_algorithms() {
    assert!(parse_generate_local("none", &["credential".to_owned()]).is_err());
}

#[test]
fn database_certificate_profile_requires_the_managed_shape() {
    let config = ConfigSource::default();
    let binding = tenant_binding("https://tenant.example");
    let single_purpose = parse_generate_local("ES256", &["credential".to_owned()]).unwrap();
    assert!(
        database_certificate_profile(&binding, &config, &single_purpose)
            .unwrap()
            .is_none()
    );

    let managed = managed_options();
    let profile = database_certificate_profile(&binding, &config, &managed)
        .unwrap()
        .expect("managed certificate profile");
    assert_eq!(profile.hostname, "tenant.example");
    assert!(profile.mdoc_profile.is_none());

    let unsupported = parse_generate_local(
        "EdDSA",
        &["credential".to_owned(), "presentation_request".to_owned()],
    )
    .unwrap();
    assert!(database_certificate_profile(&binding, &config, &unsupported).is_err());

    let ip_binding = tenant_binding("https://127.0.0.1");
    let error = database_certificate_profile(&ip_binding, &config, &managed).unwrap_err();
    assert!(error.to_string().contains("DNS hostname"));

    let mdoc = ConfigSource::from_owned_pairs_for_test([
        (
            "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON".to_owned(),
            r#"{"mdl":{"format":"mso_mdoc","scope":"mdl","cryptographic_binding_methods_supported":["jwk"],"credential_signing_alg_values_supported":["ES256"],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}},"doctype":"org.iso.18013.5.1.mDL"}}"#.to_owned(),
        ),
        (
            "OPENID4VC_MDOC_ISSUING_COUNTRY".to_owned(),
            "US".to_owned(),
        ),
    ]);
    let profile = database_certificate_profile(&binding, &mdoc, &managed)
        .unwrap()
        .expect("mDoc certificate profile");
    let mdoc_profile = profile.mdoc_profile.expect("mDoc profile details");
    assert_eq!(mdoc_profile.issuing_country, "US");
    assert_eq!(mdoc_profile.issuer_contact_uri, "https://tenant.example");
    assert_eq!(
        mdoc_profile.crl_distribution_uri,
        "https://tenant.example/.well-known/mdoc"
    );
}

#[tokio::test]
async fn database_operator_keyctl_roundtrip_keeps_keys_in_the_repository() {
    let data_dir = temporary_directory("database-roundtrip");
    let config = database_config(&data_dir);
    let binding = tenant_binding("http://127.0.0.1:43123");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let persistence = MemoryOperatorPersistence {
        repository: repository.clone(),
    };

    let (first_kid, first_revision, certificate_chain) =
        operator_generate_local_database_for_tenant(
            &config,
            &binding,
            &persistence,
            "ES256",
            &["credential".to_owned()],
        )
        .await
        .expect("database local key generation");
    assert!(!first_kid.is_empty());
    assert!(!first_revision.is_empty());
    assert!(certificate_chain.is_none());
    assert!(!data_dir.exists());

    let (second_kid, second_revision, certificate_chain) =
        operator_generate_local_database_for_tenant(
            &config,
            &binding,
            &persistence,
            "ES256",
            &["credential".to_owned()],
        )
        .await
        .expect("repeated database local key generation");
    assert_eq!(second_kid, first_kid);
    assert_eq!(second_revision, first_revision);
    assert!(certificate_chain.is_none());

    let listed_revision = operator_list_database_for_tenant(&config, &binding, &persistence)
        .await
        .expect("database key listing");
    assert_eq!(listed_revision, first_revision);
    let validated_revision = operator_validate_database_for_tenant(&config, &binding, &persistence)
        .await
        .expect("database key validation");
    assert_eq!(validated_revision, first_revision);

    let external_registration = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "y": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "kid": "external-key",
        "use": "sig",
        "alg": "ES256"
    });
    let external_revision = operator_register_external_database_for_tenant(
        &config,
        &binding,
        &persistence,
        "external-key",
        "ES256",
        "kms://unit/external-key",
        &serde_json::to_vec(&external_registration).unwrap(),
    )
    .await
    .expect("external database key registration");
    assert_ne!(external_revision, first_revision);

    let persisted = repository
        .load()
        .await
        .expect("repository load")
        .expect("persisted database keyset");
    assert!(
        persisted.public_metadata["keys"]
            .as_array()
            .expect("key metadata array")
            .iter()
            .any(|key| {
                key["kid"] == "external-key"
                    && key["backend"] == "external-command"
                    && key["key_ref"] == "kms://unit/external-key"
            })
    );
    assert!(!data_dir.exists());
}

#[tokio::test]
async fn database_import_preserves_legacy_kid_as_an_explicit_operation() {
    let data_dir = temporary_directory("database-import");
    let legacy_dir = data_dir.join("legacy");
    let legacy = KeyManager::load_or_create(database_key_settings(&legacy_dir))
        .await
        .expect("legacy keyset generation");
    let expected_kid = legacy.snapshot().active_kid.clone();
    let config = database_config(&data_dir);
    let binding = tenant_binding("http://127.0.0.1:43124");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let persistence = MemoryOperatorPersistence {
        repository: repository.clone(),
    };

    let revision = operator_import_legacy_file_keyset(
        &config,
        &binding,
        &persistence,
        legacy_dir.join("keys"),
    )
    .await
    .expect("explicit legacy keyset import");
    assert!(!revision.is_empty());
    assert!(legacy_dir.join("keys").join("keyset.json").exists());
    assert!(!data_dir.join("keys").exists());

    let persisted = repository
        .load()
        .await
        .expect("repository load")
        .expect("imported keyset");
    assert_eq!(persisted.public_metadata["active_kid"], expected_kid);

    tokio::fs::remove_dir_all(data_dir)
        .await
        .expect("legacy import fixture cleanup");
}

#[tokio::test]
async fn managed_generation_is_idempotent_and_never_writes_files() {
    let data_dir = temporary_directory("managed-idempotent");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let manager = database_manager(repository, &data_dir, Uuid::now_v7()).await;
    let profile = managed_profile("tenant.example");

    let first_kid =
        generate_local_with_database_manager(&manager, Some(&profile), managed_options())
            .await
            .expect("managed generation");
    let first_state = manager
        .database_openid4vc_state()
        .await
        .expect("managed state");
    let first_material = first_state.material.expect("managed material");
    assert_eq!(first_kid, first_material.public.signing_kid);
    assert_complete_managed_material(&first_material);
    assert!(!data_dir.exists());

    let second_kid =
        generate_local_with_database_manager(&manager, Some(&profile), managed_options())
            .await
            .expect("idempotent managed generation");
    let second_state = manager
        .database_openid4vc_state()
        .await
        .expect("reloaded managed state");
    let second_material = second_state.material.expect("retained managed material");
    assert_eq!(second_kid, first_kid);
    assert_eq!(second_state.revision, first_state.revision);
    assert_same_material(&first_material, &second_material);
    assert!(!data_dir.exists());
}

#[tokio::test]
async fn concurrent_managed_initialization_converges_on_one_complete_generation() {
    let data_dir = temporary_directory("managed-concurrent");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let first = database_manager(repository.clone(), &data_dir, tenant_id).await;
    let second = database_manager(repository.clone(), &data_dir, tenant_id).await;
    let third = database_manager(repository.clone(), &data_dir, tenant_id).await;
    let fourth = database_manager(repository.clone(), &data_dir, tenant_id).await;
    let profile = managed_profile("tenant.example");

    let (first_kid, second_kid, third_kid, fourth_kid) = tokio::join!(
        generate_local_with_database_manager(&first, Some(&profile), managed_options()),
        generate_local_with_database_manager(&second, Some(&profile), managed_options()),
        generate_local_with_database_manager(&third, Some(&profile), managed_options()),
        generate_local_with_database_manager(&fourth, Some(&profile), managed_options()),
    );
    let first_kid = first_kid.expect("first concurrent initialization");
    let second_kid = second_kid.expect("second concurrent initialization");
    let third_kid = third_kid.expect("third concurrent initialization");
    let fourth_kid = fourth_kid.expect("fourth concurrent initialization");
    assert_eq!(first_kid, second_kid);
    assert_eq!(first_kid, third_kid);
    assert_eq!(first_kid, fourth_kid);

    let winner = database_manager(repository, &data_dir, tenant_id).await;
    let state = winner
        .database_openid4vc_state()
        .await
        .expect("concurrent managed state");
    let material = state.material.expect("complete concurrent material");
    assert_eq!(material.public.signing_kid, first_kid);
    assert_complete_managed_material(&material);
    assert!(!data_dir.exists());
}

#[tokio::test]
async fn failed_managed_cas_does_not_leave_partial_material() {
    let data_dir = temporary_directory("managed-cas");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let manager = database_manager(repository.clone(), &data_dir, Uuid::now_v7()).await;
    let profile = managed_profile("tenant.example");

    generate_local_with_database_manager(&manager, Some(&profile), managed_options())
        .await
        .expect("initial managed generation");
    let initial_state = manager
        .database_openid4vc_state()
        .await
        .expect("initial managed state");
    let stale_revision = initial_state.revision;
    rotate_managed_material(&manager, &profile)
        .await
        .expect("winning managed rotation");
    let winner_state = manager
        .database_openid4vc_state()
        .await
        .expect("rotated managed state");
    assert!(winner_state.revision > stale_revision);
    let winner_material = winner_state.material.clone().expect("rotated material");
    let before = repository
        .load()
        .await
        .expect("repository before stale CAS")
        .expect("record before stale CAS");

    let rejected_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let rejected_material =
        build_managed_material(&rejected_key, &profile, Some(winner_material.clone()))
            .expect("candidate managed material");
    assert!(
        manager
            .database_commit_openid4vc(
                stale_revision,
                rejected_material,
                Some(rejected_key.serialize_pem()),
            )
            .await
            .is_err()
    );

    let after = repository
        .load()
        .await
        .expect("repository after stale CAS")
        .expect("record after stale CAS");
    assert_same_persisted_record(&before, &after);
    let state_after = manager
        .database_openid4vc_state()
        .await
        .expect("state after stale CAS");
    assert_same_material(
        &winner_material,
        state_after.material.as_ref().expect("winner retained"),
    );
    assert!(!data_dir.exists());
}

#[tokio::test]
async fn restart_with_a_different_key_manager_still_serves_database_backed_crl() {
    let data_dir = temporary_directory("managed-restart-crl");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let manager = database_manager(repository.clone(), &data_dir, tenant_id).await;
    let profile = managed_profile("tenant.example");
    generate_local_with_database_manager(&manager, Some(&profile), managed_options())
        .await
        .expect("managed generation");
    let state = manager
        .database_openid4vc_state()
        .await
        .expect("managed state");
    let material = state.material.expect("managed material");
    let issuer_id = material
        .iaca_private_materials
        .keys()
        .next()
        .expect("IACA issuer")
        .clone();
    let iaca = iaca_certificates(&material, &issuer_id);

    let restarted = database_manager(repository, &data_dir, tenant_id).await;
    let source = MdocCrlSource {
        keyset: restarted,
        issuer_contact_uri: profile
            .mdoc_profile
            .as_ref()
            .expect("mDoc profile")
            .issuer_contact_uri
            .clone(),
    };
    let crl = signed_mdoc_crl(&source, &issuer_id)
        .await
        .expect("database-backed CRL")
        .expect("CRL for persisted IACA");
    let (_, parsed_crl) = x509_parser::parse_x509_crl(&crl).expect("parse CRL");
    let (_, ca) = x509_parser::parse_x509_certificate(iaca[1].as_ref()).expect("parse IACA");
    assert!(parsed_crl.verify_signature(ca.public_key()).is_ok());
    assert_eq!(parsed_crl.iter_revoked_certificates().count(), 0);
    let response = crate::http::well_known::mdoc_crl(
        Some(actix_web::web::Data::new(source.clone())),
        issuer_id.clone().into(),
    )
    .await;
    assert_eq!(response.status(), actix_web::http::StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/pkix-crl"
    );
    assert!(!data_dir.exists());
}

#[tokio::test]
async fn mdoc_import_preserves_kid_iaca_history_and_rejects_overwrite() {
    let data_dir = temporary_directory("mdoc-import");
    let source = temporary_directory("mdoc-import-source");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let profile = managed_profile("tenant.example");
    let (manager, kid, signing_key) =
        database_manager_with_mdoc_key(repository.clone(), &data_dir, tenant_id).await;

    let active = write_mdoc_import_fixture(&source, &signing_key, &profile, true)
        .await
        .expect("active import fixture");
    let historical_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let historical = build_managed_material(&historical_key, &profile, None)
        .expect("historical import material");
    let historical_id = historical
        .iaca_private_materials
        .keys()
        .next()
        .expect("historical IACA")
        .clone();
    let historical_entry = historical
        .public
        .revocation_snapshot
        .as_ref()
        .expect("historical snapshot")
        .entries
        .first()
        .expect("historical status")
        .clone();
    let mut imported_snapshot = active
        .public
        .revocation_snapshot
        .clone()
        .expect("active snapshot");
    imported_snapshot.this_update -= chrono::Duration::hours(1);
    let mut revoked_historical_entry = historical_entry;
    revoked_historical_entry.status =
        nazo_digital_credentials::CertificateRevocationStatus::Revoked;
    let revoked_historical_certificate = revoked_historical_entry.certificate.clone();
    imported_snapshot.entries.push(revoked_historical_entry);
    tokio::fs::write(
        source.join("revocation-snapshot.json"),
        serde_json::to_vec(&imported_snapshot).unwrap(),
    )
    .await
    .unwrap();
    let historical_pem = historical
        .iaca_private_materials
        .get(&historical_id)
        .expect("historical IACA material");
    tokio::fs::write(
        source
            .join("iaca-keys")
            .join(format!("{historical_id}.pem")),
        historical_pem,
    )
    .await
    .unwrap();

    let imported_revision = import_mdoc_directory(&manager, &profile, &source)
        .await
        .expect("explicit mDoc import");
    assert!(!imported_revision.is_empty());
    let imported_state = manager
        .database_openid4vc_state()
        .await
        .expect("imported state");
    let imported = imported_state.material.expect("imported material");
    assert_eq!(imported.public.signing_kid, kid);
    assert_eq!(imported.iaca_private_materials.len(), 2);
    assert!(imported.iaca_private_materials.contains_key(&historical_id));
    assert_complete_managed_material(&imported);
    assert!(
        imported
            .public
            .revocation_snapshot
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .any(|entry| entry.certificate == revoked_historical_certificate
                && entry.status == nazo_digital_credentials::CertificateRevocationStatus::Revoked)
    );

    let historical_certs = iaca_certificates(&imported, &historical_id);
    let source_after_import = MdocCrlSource {
        keyset: manager.clone(),
        issuer_contact_uri: profile
            .mdoc_profile
            .as_ref()
            .expect("mDoc profile")
            .issuer_contact_uri
            .clone(),
    };
    let historical_crl = signed_mdoc_crl(&source_after_import, &historical_id)
        .await
        .expect("historical CRL")
        .expect("historical CRL present");
    let (_, parsed_historical_crl) =
        x509_parser::parse_x509_crl(&historical_crl).expect("parse historical CRL");
    let (_, historical_ca) =
        x509_parser::parse_x509_certificate(historical_certs[1].as_ref()).expect("historical CA");
    assert!(
        parsed_historical_crl
            .verify_signature(historical_ca.public_key())
            .is_ok()
    );
    assert_eq!(parsed_historical_crl.iter_revoked_certificates().count(), 1);
    let expected_revocation_time = imported_snapshot.this_update.timestamp();
    assert_eq!(
        parsed_historical_crl
            .iter_revoked_certificates()
            .next()
            .unwrap()
            .revocation_date
            .timestamp(),
        expected_revocation_time
    );
    rotate_managed_material(&manager, &profile)
        .await
        .expect("rotation after imported revocation");
    let refreshed_crl = signed_mdoc_crl(&source_after_import, &historical_id)
        .await
        .unwrap()
        .unwrap();
    let (_, refreshed) = x509_parser::parse_x509_crl(&refreshed_crl).unwrap();
    assert_eq!(
        refreshed
            .iter_revoked_certificates()
            .next()
            .unwrap()
            .revocation_date
            .timestamp(),
        expected_revocation_time
    );

    assert!(
        import_mdoc_directory(&manager, &profile, &source)
            .await
            .expect_err("managed import must not overwrite")
            .to_string()
            .contains("already exists")
    );
    assert!(!data_dir.exists());

    tokio::fs::remove_dir_all(source)
        .await
        .expect("mDoc import fixture cleanup");
}

#[tokio::test]
async fn mdoc_import_fails_explicitly_when_iaca_material_is_missing() {
    let data_dir = temporary_directory("mdoc-import-missing-iaca");
    let source = temporary_directory("mdoc-import-missing-iaca-source");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let profile = managed_profile("tenant.example");
    let (manager, _kid, signing_key) =
        database_manager_with_mdoc_key(repository, &data_dir, tenant_id).await;
    write_mdoc_import_fixture(&source, &signing_key, &profile, false)
        .await
        .expect("missing-IACA import fixture");

    let error = import_mdoc_directory(&manager, &profile, &source)
        .await
        .expect_err("missing IACA must fail");
    assert!(error.to_string().contains("iaca-keys"));
    let state = manager
        .database_openid4vc_state()
        .await
        .expect("state after rejected import");
    assert!(state.material.is_none());
    assert!(
        generate_local_with_database_manager(&manager, Some(&profile), managed_options())
            .await
            .expect_err("failed import must not silently regenerate")
            .to_string()
            .contains("explicit mdoc-import")
    );
    assert!(!data_dir.exists());

    tokio::fs::remove_dir_all(source)
        .await
        .expect("missing-IACA fixture cleanup");
}

#[tokio::test]
async fn rotation_retains_old_and_new_ca_crls_and_trust_anchors() {
    let data_dir = temporary_directory("mdoc-rotation");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let manager = database_manager(repository.clone(), &data_dir, tenant_id).await;
    let profile = managed_profile("tenant.example");
    generate_local_with_database_manager(&manager, Some(&profile), managed_options())
        .await
        .expect("initial managed generation");
    let before = manager
        .database_openid4vc_state()
        .await
        .expect("pre-rotation state");
    let old_material = before.material.expect("pre-rotation material");
    let old_issuer_id = old_material
        .iaca_private_materials
        .keys()
        .next()
        .expect("old IACA")
        .clone();
    let old_iaca = iaca_certificates(&old_material, &old_issuer_id);
    let old_ca_pem = pem_certificate(old_iaca[1].as_ref());

    rotate_managed_material(&manager, &profile)
        .await
        .expect("managed rotation");
    let after = manager
        .database_openid4vc_state()
        .await
        .expect("post-rotation state");
    assert!(after.revision > before.revision);
    let new_material = after.material.expect("post-rotation material");
    assert_complete_managed_material(&new_material);
    assert_ne!(
        old_material.public.signing_kid,
        new_material.public.signing_kid
    );
    assert!(
        new_material
            .iaca_private_materials
            .contains_key(&old_issuer_id)
    );
    assert!(new_material.public.trust_anchors_pem.contains(&old_ca_pem));

    let new_issuer_id = new_material
        .iaca_private_materials
        .keys()
        .find(|issuer_id| *issuer_id != &old_issuer_id)
        .expect("new IACA")
        .clone();
    let new_iaca = iaca_certificates(&new_material, &new_issuer_id);
    let new_ca_pem = pem_certificate(new_iaca[1].as_ref());
    assert!(new_material.public.trust_anchors_pem.contains(&new_ca_pem));

    let restarted = database_manager(repository, &data_dir, tenant_id).await;
    let source = MdocCrlSource {
        keyset: restarted,
        issuer_contact_uri: profile
            .mdoc_profile
            .as_ref()
            .expect("mDoc profile")
            .issuer_contact_uri
            .clone(),
    };
    for (issuer_id, ca) in [
        (&old_issuer_id, &old_iaca[1]),
        (&new_issuer_id, &new_iaca[1]),
    ] {
        let crl = signed_mdoc_crl(&source, issuer_id)
            .await
            .expect("rotated CRL")
            .expect("retained CRL");
        let (_, parsed_crl) = x509_parser::parse_x509_crl(&crl).expect("parse rotated CRL");
        let (_, ca) = x509_parser::parse_x509_certificate(ca.as_ref()).expect("parse rotated CA");
        assert!(parsed_crl.verify_signature(ca.public_key()).is_ok());
        assert_eq!(parsed_crl.iter_revoked_certificates().count(), 0);
    }
    assert!(!data_dir.exists());
}
