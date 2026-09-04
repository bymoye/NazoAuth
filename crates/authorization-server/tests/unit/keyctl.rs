use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_key_management::{
    KeyManager, KeySettings, PersistedSigningKeyset, SigningKeyRepository,
    SigningKeyRepositoryFuture, SigningKeyWrappingKeyRing, SigningKeysetCompareAndSwapResult,
    SigningKeysetCreateResult,
};
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

fn all_openid4vc_purposes() -> Vec<String> {
    vec!["credential".to_owned(), "presentation_request".to_owned()]
}

#[test]
fn database_certificate_paths_require_atomic_trust_storage_and_tenant_dns() {
    let config = ConfigSource::default();
    let mut settings = Settings::from_config(&config).expect("default settings");
    let binding = tenant_binding("https://tenant.example");
    let options = parse_generate_local("ES256", &["presentation_request".to_owned()])
        .expect("valid purpose-scoped options");

    assert!(
        database_certificate_paths(&settings, &binding, &config, &options)
            .expect("disabled OpenID4VC")
            .is_none()
    );

    settings.openid4vc.signing_certificate_chain_file =
        Some(PathBuf::from("runtime/certificate-bundle.pem"));
    settings.openid4vc.trust_anchors_file = Some(PathBuf::from("runtime/other-anchors.pem"));
    let paths = database_certificate_paths(&settings, &binding, &config, &options)
        .expect("certificate paths")
        .expect("configured certificate paths");
    assert_eq!(paths.chain, PathBuf::from("runtime/certificate-bundle.pem"));
    assert_eq!(paths.anchors, PathBuf::from("runtime/other-anchors.pem"));
    assert_eq!(paths.hostname, "tenant.example");
    assert!(paths.mdoc_profile.is_none());

    settings.openid4vc.trust_anchors_file = None;
    let error = database_certificate_paths(&settings, &binding, &config, &options)
        .expect_err("certificate generation without trust storage must fail");
    assert!(error.to_string().contains("trust storage"));

    settings.openid4vc.trust_anchors_file = Some(PathBuf::from("runtime/anchors.pem"));
    let ipv4_binding = tenant_binding("https://127.0.0.1");
    let error = database_certificate_paths(&settings, &ipv4_binding, &config, &options)
        .expect_err("tenant certificate generation requires a DNS hostname");
    assert!(error.to_string().contains("DNS hostname"));
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

#[tokio::test]
async fn database_operator_keyctl_roundtrip_keeps_keys_in_the_repository() {
    let data_dir = temporary_directory("database-roundtrip");
    let config = database_config(&data_dir);
    let binding = tenant_binding("http://127.0.0.1:43123");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let persistence = MemoryOperatorPersistence {
        repository: repository.clone(),
    };
    let purposes = all_openid4vc_purposes();

    let (first_kid, first_revision, certificate_chain) =
        operator_generate_local_database_for_tenant(
            &config,
            &binding,
            &persistence,
            "ES256",
            &purposes,
        )
        .await
        .expect("database local key generation");
    assert!(!first_kid.is_empty());
    assert!(!first_revision.is_empty());
    assert!(certificate_chain.is_none());
    assert!(
        !data_dir.join("keys").exists(),
        "database key management must not create a local key directory"
    );

    let (second_kid, second_revision, certificate_chain) =
        operator_generate_local_database_for_tenant(
            &config,
            &binding,
            &persistence,
            "ES256",
            &purposes,
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

    let repeated_external_revision = operator_register_external_database_for_tenant(
        &config,
        &binding,
        &persistence,
        "external-key",
        "ES256",
        "kms://unit/external-key",
        &serde_json::to_vec(&external_registration).unwrap(),
    )
    .await
    .expect("repeated external database key registration");
    assert_eq!(repeated_external_revision, external_revision);

    assert!(
        operator_register_external_database_for_tenant(
            &config,
            &binding,
            &persistence,
            "invalid",
            "none",
            "kms://unit/invalid",
            br"{}",
        )
        .await
        .is_err()
    );
    assert!(
        operator_register_external_database_for_tenant(
            &config,
            &binding,
            &persistence,
            "invalid",
            "ES256",
            "kms://unit/invalid",
            b"not-json",
        )
        .await
        .is_err()
    );

    let _ = tokio::fs::remove_dir_all(&data_dir).await;
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

    let _ = tokio::fs::remove_dir_all(&data_dir).await;
}

#[tokio::test]
async fn database_certificate_generation_is_idempotent_and_requires_both_purposes() {
    let data_dir = temporary_directory("database-certificate");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let ring = SigningKeyWrappingKeyRing::new("certificate-root", [0x43; 32], None)
        .expect("wrapping key ring");
    let manager = KeyManager::load_or_create_database(
        database_key_settings(&data_dir),
        Uuid::now_v7(),
        repository,
        ring,
    )
    .await
    .expect("database key manager");
    let certificate = data_dir.join("openid4vc").join("certificate-bundle.pem");
    let paths = Openid4vcCertificatePaths {
        chain: certificate.clone(),
        anchors: certificate.clone(),
        revocation_snapshot: None,
        hostname: "tenant.example".to_owned(),
        mdoc_profile: None,
    };

    let error = generate_local_with_database_manager(
        &manager,
        Some(&paths),
        parse_generate_local("ES256", &["credential".to_owned()]).unwrap(),
    )
    .await
    .expect_err("certificate generation must require both OpenID4VC purposes");
    assert!(
        error
            .to_string()
            .contains("both credential and presentation_request")
    );

    let options = parse_generate_local("ES256", &all_openid4vc_purposes()).unwrap();
    let kid = generate_local_with_database_manager(&manager, Some(&paths), options)
        .await
        .expect("database certificate generation");
    assert!(certificate.is_file());
    let contents = tokio::fs::read_to_string(&certificate)
        .await
        .expect("generated certificate bundle");
    assert_eq!(contents.matches("BEGIN CERTIFICATE").count(), 2);

    let repeated_kid = generate_local_with_database_manager(
        &manager,
        Some(&paths),
        parse_generate_local("ES256", &all_openid4vc_purposes()).unwrap(),
    )
    .await
    .expect("repeated database certificate generation");
    assert_eq!(repeated_kid, kid);
    assert_eq!(
        tokio::fs::read_to_string(&certificate)
            .await
            .expect("retained certificate bundle"),
        contents
    );

    let _ = tokio::fs::remove_dir_all(&data_dir).await;
}

#[tokio::test]
async fn mdoc_certificate_profile_persists_a_matching_iaca_key_and_serves_snapshot_backed_crls() {
    let directory = std::env::temp_dir().join(format!(
        "nazoauth-mdoc-certificate-{}",
        uuid::Uuid::now_v7()
    ));
    let certificate = directory.join("certificate-bundle.pem");
    let revocation_snapshot = directory.join("revocation-snapshot.json");
    let profile = MdocCertificateProfile {
        issuing_country: "US".to_owned(),
        issuer_contact_uri: "https://auth.example".to_owned(),
        crl_distribution_uri: "https://auth.example/.well-known/mdoc".to_owned(),
    };
    let paths = Openid4vcCertificatePaths {
        chain: certificate.clone(),
        anchors: certificate.clone(),
        revocation_snapshot: Some(revocation_snapshot.clone()),
        hostname: "auth.example".to_owned(),
        mdoc_profile: Some(profile),
    };
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let bundle = build_openid4vc_certificate_bundle(
        &signing_key,
        "auth.example",
        paths.mdoc_profile.as_ref(),
    )
    .unwrap();
    activate_openid4vc_certificate_bundle(&paths, &bundle)
        .await
        .unwrap();
    initialize_mdoc_revocation_snapshot(
        &paths,
        bundle.mdoc_material.as_ref().expect("mdoc material"),
    )
    .await
    .unwrap();

    assert!(
        existing_openid4vc_bundle_matches(&paths, &signing_key)
            .await
            .unwrap()
    );
    let chain = tokio::fs::read(&certificate).await.unwrap();
    let certificates = CertificateDer::pem_slice_iter(&chain)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(&certificates[0]).unwrap();
    let (_, ca) = x509_parser::parse_x509_certificate(&certificates[1]).unwrap();
    assert!(mdoc_certificate_profile_matches(
        &leaf,
        &ca,
        paths.mdoc_profile.as_ref().unwrap()
    ));
    let key_path = iaca_private_key_path(&certificate, certificates[1].as_ref()).unwrap();
    assert!(tokio::fs::try_exists(&key_path).await.unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(
            std::fs::metadata(key_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    let source = MdocCrlSource {
        certificate_bundle: certificate.clone(),
        revocation_snapshot: revocation_snapshot.clone(),
        issuer_contact_uri: "https://auth.example".to_owned(),
    };
    let issuer_id = sha256_hex(certificates[1].as_ref());
    let crl = signed_mdoc_crl(&source, &issuer_id)
        .await
        .unwrap()
        .expect("mdoc CRL");
    let (_, parsed_crl) = x509_parser::parse_x509_crl(&crl).unwrap();
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
    assert_eq!(
        crate::http::well_known::mdoc_crl(None, issuer_id.clone().into())
            .await
            .status(),
        actix_web::http::StatusCode::NOT_FOUND
    );

    let mut snapshot = nazo_digital_credentials::CertificateRevocationSnapshot::from_json(
        &tokio::fs::read(&revocation_snapshot).await.unwrap(),
    )
    .unwrap();
    assert_eq!(
        parsed_crl.last_update().timestamp(),
        snapshot.this_update.timestamp()
    );
    assert_eq!(
        parsed_crl.next_update().unwrap().timestamp(),
        snapshot.next_update.timestamp()
    );
    snapshot.entries[0].status = nazo_digital_credentials::CertificateRevocationStatus::Revoked;
    snapshot.this_update = chrono::Utc::now();
    tokio::fs::write(&revocation_snapshot, serde_json::to_vec(&snapshot).unwrap())
        .await
        .unwrap();
    let revoked_crl = signed_mdoc_crl(&source, &issuer_id)
        .await
        .unwrap()
        .expect("revoked mdoc CRL");
    let (_, parsed_revoked_crl) = x509_parser::parse_x509_crl(&revoked_crl).unwrap();
    assert!(parsed_revoked_crl.verify_signature(ca.public_key()).is_ok());
    let revoked = parsed_revoked_crl
        .iter_revoked_certificates()
        .collect::<Vec<_>>();
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].raw_serial(), leaf.raw_serial());

    assert!(
        existing_openid4vc_bundle_matches(&paths, &signing_key)
            .await
            .unwrap()
    );
    initialize_mdoc_revocation_snapshot(&paths, bundle.mdoc_material.as_ref().unwrap())
        .await
        .unwrap();
    let preserved = nazo_digital_credentials::CertificateRevocationSnapshot::from_json(
        &tokio::fs::read(&revocation_snapshot).await.unwrap(),
    )
    .unwrap();
    assert_eq!(
        preserved.entries[0].status,
        nazo_digital_credentials::CertificateRevocationStatus::Revoked
    );

    let rotated = build_openid4vc_certificate_bundle(
        &signing_key,
        "auth.example",
        paths.mdoc_profile.as_ref(),
    )
    .unwrap();
    activate_openid4vc_certificate_bundle(&paths, &rotated)
        .await
        .unwrap();
    let rotated_material = rotated.mdoc_material.as_ref().unwrap();
    initialize_mdoc_revocation_snapshot(&paths, rotated_material)
        .await
        .unwrap();
    let old_crl = signed_mdoc_crl(&source, &issuer_id).await.unwrap().unwrap();
    let (_, old_crl) = x509_parser::parse_x509_crl(&old_crl).unwrap();
    assert!(old_crl.verify_signature(ca.public_key()).is_ok());
    assert_eq!(
        old_crl
            .iter_revoked_certificates()
            .next()
            .unwrap()
            .raw_serial(),
        leaf.raw_serial()
    );
    let new_crl = signed_mdoc_crl(&source, &sha256_hex(&rotated_material.ca_der))
        .await
        .unwrap()
        .unwrap();
    let (_, new_crl) = x509_parser::parse_x509_crl(&new_crl).unwrap();
    let (_, new_ca) = x509_parser::parse_x509_certificate(&rotated_material.ca_der).unwrap();
    assert!(new_crl.verify_signature(new_ca.public_key()).is_ok());
    assert_eq!(new_crl.iter_revoked_certificates().count(), 0);
    assert!(
        signed_mdoc_crl(&source, "../other-tenant")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        signed_mdoc_crl(&source, &"0".repeat(64))
            .await
            .unwrap()
            .is_none()
    );

    let fresh_next_update = snapshot.next_update;
    snapshot.this_update = chrono::Utc::now() - chrono::Duration::hours(2);
    snapshot.next_update = chrono::Utc::now() - chrono::Duration::hours(1);
    tokio::fs::write(&revocation_snapshot, serde_json::to_vec(&snapshot).unwrap())
        .await
        .unwrap();
    assert!(signed_mdoc_crl(&source, &issuer_id).await.is_err());
    snapshot.next_update = fresh_next_update;
    snapshot.entries.clear();
    tokio::fs::write(&revocation_snapshot, serde_json::to_vec(&snapshot).unwrap())
        .await
        .unwrap();
    assert!(signed_mdoc_crl(&source, &issuer_id).await.is_err());
    assert_eq!(
        crate::http::well_known::mdoc_crl(
            Some(actix_web::web::Data::new(source)),
            issuer_id.clone().into()
        )
        .await
        .status(),
        actix_web::http::StatusCode::SERVICE_UNAVAILABLE
    );

    tokio::fs::write(
        iaca_private_key_path(&certificate, &rotated_material.ca_der).unwrap(),
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .unwrap()
            .serialize_pem(),
    )
    .await
    .unwrap();
    assert!(
        !existing_openid4vc_bundle_matches(&paths, &signing_key)
            .await
            .unwrap()
    );

    tokio::fs::remove_dir_all(directory).await.unwrap();
}

#[test]
fn mdoc_crl_source_and_certificate_profile_follow_runtime_configuration() {
    let defaults = Settings::from_config(&ConfigSource::default()).unwrap();
    assert!(MdocCrlSource::from_settings(&defaults).is_none());

    let chain_only = ConfigSource::from_owned_pairs_for_test([(
        "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE".to_owned(),
        "runtime/openid4vc-chain.pem".to_owned(),
    )]);
    let chain_only_settings = Settings::from_config(&chain_only).unwrap();
    assert!(MdocCrlSource::from_settings(&chain_only_settings).is_none());

    let configured = ConfigSource::from_owned_pairs_for_test([
        (
            "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE".to_owned(),
            "runtime/openid4vc-chain.pem".to_owned(),
        ),
        (
            "OPENID4VC_REVOCATION_SNAPSHOT_FILE".to_owned(),
            "runtime/openid4vc-revocation.json".to_owned(),
        ),
        ("ISSUER".to_owned(), "http://127.0.0.1:8000".to_owned()),
    ]);
    let settings = Settings::from_config(&configured).unwrap();
    let source = MdocCrlSource::from_settings(&settings).expect("configured CRL source");
    assert_eq!(
        source.certificate_bundle,
        PathBuf::from("runtime/openid4vc-chain.pem")
    );
    assert_eq!(
        source.revocation_snapshot,
        PathBuf::from("runtime/openid4vc-revocation.json")
    );
    assert_eq!(source.issuer_contact_uri, "http://127.0.0.1:8000");

    let no_mdoc = ConfigSource::default();
    assert!(
        mdoc_certificate_profile(&no_mdoc, &Url::parse("https://auth.example/").unwrap())
            .unwrap()
            .is_none()
    );

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
    let profile = mdoc_certificate_profile(&mdoc, &Url::parse("https://auth.example/").unwrap())
        .unwrap()
        .expect("mDoc profile");
    assert_eq!(profile.issuing_country, "US");
    assert_eq!(profile.issuer_contact_uri, "https://auth.example");
    assert_eq!(
        profile.crl_distribution_uri,
        "https://auth.example/.well-known/mdoc"
    );
}

#[tokio::test]
async fn signed_mdoc_crl_rejects_invalid_material_and_preserves_key_ownership() {
    let directory = std::env::temp_dir().join(format!(
        "nazoauth-mdoc-crl-boundaries-{}",
        uuid::Uuid::now_v7()
    ));
    let certificate = directory.join("certificate-bundle.pem");
    let snapshot_path = directory.join("revocation-snapshot.json");
    let profile = MdocCertificateProfile {
        issuing_country: "US".to_owned(),
        issuer_contact_uri: "https://auth.example".to_owned(),
        crl_distribution_uri: "https://auth.example/.well-known/mdoc".to_owned(),
    };
    let paths = Openid4vcCertificatePaths {
        chain: certificate.clone(),
        anchors: certificate.clone(),
        revocation_snapshot: Some(snapshot_path.clone()),
        hostname: "auth.example".to_owned(),
        mdoc_profile: Some(profile),
    };
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let bundle = build_openid4vc_certificate_bundle(
        &signing_key,
        "auth.example",
        paths.mdoc_profile.as_ref(),
    )
    .unwrap();
    activate_openid4vc_certificate_bundle(&paths, &bundle)
        .await
        .unwrap();
    initialize_mdoc_revocation_snapshot(
        &paths,
        bundle.mdoc_material.as_ref().expect("mDoc material"),
    )
    .await
    .unwrap();

    let chain = tokio::fs::read(&certificate).await.unwrap();
    let certificates = CertificateDer::pem_slice_iter(&chain)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let issuer_id = sha256_hex(certificates[1].as_ref());
    let source = MdocCrlSource {
        certificate_bundle: certificate.clone(),
        revocation_snapshot: snapshot_path.clone(),
        issuer_contact_uri: "https://auth.example".to_owned(),
    };
    let material = bundle.mdoc_material.as_ref().unwrap();
    let key_path = iaca_private_key_path(&certificate, certificates[1].as_ref()).unwrap();
    let original_material = tokio::fs::read(&key_path).await.unwrap();
    persist_iaca_private_key(&paths, material).await.unwrap();
    assert_eq!(tokio::fs::read(&key_path).await.unwrap(), original_material);
    let wrong_id = if issuer_id == "f".repeat(64) {
        "e".repeat(64)
    } else {
        "f".repeat(64)
    };
    tokio::fs::write(
        directory.join("iaca-keys").join(format!("{wrong_id}.pem")),
        &material.issuer_material_pem,
    )
    .await
    .unwrap();
    let error = signed_mdoc_crl(&source, &wrong_id).await.unwrap_err();
    assert!(error.to_string().contains("does not match requested IACA"));

    let chain_pem = String::from_utf8(bundle.contents.clone()).unwrap();
    let first_certificate_end = chain_pem
        .find("-----END CERTIFICATE-----")
        .expect("leaf PEM terminator")
        + "-----END CERTIFICATE-----".len();
    tokio::fs::write(&key_path, &chain_pem[..first_certificate_end])
        .await
        .unwrap();
    let error = signed_mdoc_crl(&source, &issuer_id).await.unwrap_err();
    assert!(error.to_string().contains("must contain a DS and IACA"));

    tokio::fs::write(&key_path, &material.issuer_material_pem)
        .await
        .unwrap();
    let wrong_private_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    tokio::fs::write(
        &key_path,
        format!("{}{}", wrong_private_key.serialize_pem(), chain_pem),
    )
    .await
    .unwrap();
    let error = signed_mdoc_crl(&source, &issuer_id).await.unwrap_err();
    assert!(error.to_string().contains("private key does not match"));
    let conflicting_material = tokio::fs::read(&key_path).await.unwrap();
    let error = persist_iaca_private_key(&paths, material)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not match certificate"));
    assert_eq!(
        tokio::fs::read(&key_path).await.unwrap(),
        conflicting_material
    );

    tokio::fs::write(&key_path, &material.issuer_material_pem)
        .await
        .unwrap();
    tokio::fs::remove_file(&key_path).await.unwrap();
    assert!(
        !existing_openid4vc_bundle_matches(&paths, &signing_key)
            .await
            .unwrap()
    );
    tokio::fs::write(&key_path, b"not a PKCS#8 key")
        .await
        .unwrap();
    assert!(
        !existing_openid4vc_bundle_matches(&paths, &signing_key)
            .await
            .unwrap()
    );

    let plain_directory = directory.join("plain");
    let plain_certificate = plain_directory.join("certificate-bundle.pem");
    let plain_snapshot = plain_directory.join("revocation-snapshot.json");
    tokio::fs::create_dir_all(plain_directory.join("iaca-keys"))
        .await
        .unwrap();
    let plain_bundle =
        build_openid4vc_certificate_bundle(&signing_key, "auth.example", None).unwrap();
    tokio::fs::write(&plain_certificate, &plain_bundle.contents)
        .await
        .unwrap();
    let plain_certificates = CertificateDer::pem_slice_iter(&plain_bundle.contents)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let plain_id = sha256_hex(plain_certificates[1].as_ref());
    tokio::fs::write(
        plain_directory
            .join("iaca-keys")
            .join(format!("{plain_id}.pem")),
        &plain_bundle.contents,
    )
    .await
    .unwrap();
    let now = chrono::Utc::now();
    let plain_snapshot_value = nazo_digital_credentials::CertificateRevocationSnapshot {
        version: nazo_digital_credentials::CertificateRevocationSnapshot::VERSION,
        this_update: now - chrono::Duration::minutes(1),
        next_update: now + chrono::Duration::hours(1),
        entries: Vec::new(),
    };
    tokio::fs::write(
        &plain_snapshot,
        serde_json::to_vec(&plain_snapshot_value).unwrap(),
    )
    .await
    .unwrap();
    let plain_source = MdocCrlSource {
        certificate_bundle: plain_certificate,
        revocation_snapshot: plain_snapshot,
        issuer_contact_uri: "https://auth.example".to_owned(),
    };
    assert!(
        signed_mdoc_crl(&plain_source, &plain_id)
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(
        crate::http::well_known::mdoc_crl(
            Some(actix_web::web::Data::new(source.clone())),
            "not-an-issuer".to_owned().into(),
        )
        .await
        .status(),
        actix_web::http::StatusCode::NOT_FOUND
    );

    tokio::fs::remove_file(&key_path).await.unwrap();
    tokio::fs::create_dir(&key_path).await.unwrap();
    assert!(signed_mdoc_crl(&source, &issuer_id).await.is_err());
    let error = persist_iaca_private_key(&paths, material)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("must be a regular file"));

    tokio::fs::remove_dir_all(directory).await.unwrap();
}

#[tokio::test]
async fn mdoc_snapshot_initialization_without_storage_is_a_noop() {
    let paths = Openid4vcCertificatePaths {
        chain: PathBuf::from("runtime/certificate-bundle.pem"),
        anchors: PathBuf::from("runtime/certificate-bundle.pem"),
        revocation_snapshot: None,
        hostname: "auth.example".to_owned(),
        mdoc_profile: Some(MdocCertificateProfile {
            issuing_country: "US".to_owned(),
            issuer_contact_uri: "https://auth.example".to_owned(),
            crl_distribution_uri: "https://auth.example/.well-known/mdoc".to_owned(),
        }),
    };
    let material = MdocCertificateMaterial {
        leaf_der: Vec::new(),
        ca_der: Vec::new(),
        issuer_material_pem: String::new(),
    };
    initialize_mdoc_revocation_snapshot(&paths, &material)
        .await
        .unwrap();
}
