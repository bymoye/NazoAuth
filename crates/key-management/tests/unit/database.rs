use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::SigningPurpose;
use nazo_digital_credentials::{
    CertificateRevocationEntry, CertificateRevocationSnapshot, CertificateRevocationStatus,
    certificate_identity,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{KeyManager, Openid4vcPublicMaterial, SigningKeyRepositoryFuture};

use super::*;

#[derive(Default)]
struct TestRepository(Mutex<Option<PersistedSigningKeyset>>);

impl SigningKeyRepository for TestRepository {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>> {
        Box::pin(async move { Ok(self.0.lock().unwrap().clone()) })
    }

    fn create_if_absent(
        &self,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        Box::pin(async move {
            let mut record = self.0.lock().unwrap();
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
            let mut record = self.0.lock().unwrap();
            let current = record.clone().expect("keyset exists before CAS");
            Ok(if current.revision == expected_revision {
                *record = Some(candidate.clone());
                SigningKeysetCompareAndSwapResult::Applied(candidate)
            } else {
                SigningKeysetCompareAndSwapResult::Conflict(current)
            })
        })
    }
}

async fn database_fixture() -> (
    KeyManager,
    Arc<TestRepository>,
    Uuid,
    SigningKeyWrappingKeyRing,
) {
    let repository = Arc::new(TestRepository::default());
    let tenant_id = Uuid::now_v7();
    let wrapping_keys = SigningKeyWrappingKeyRing::new(
        "openid4vc-test-root",
        [0x52_u8; 32],
        Some(("openid4vc-test-previous".to_owned(), [0x33_u8; 32])),
    )
    .unwrap();
    let manager = KeyManager::load_or_create_database(
        settings(Vec::new()),
        tenant_id,
        repository.clone(),
        wrapping_keys.clone(),
    )
    .await
    .unwrap();
    (manager, repository, tenant_id, wrapping_keys)
}

struct Openid4vcFixture {
    material: Openid4vcMaterial,
    private_key_pem: String,
}

fn openid4vc_fixture(status: Option<CertificateRevocationStatus>, stale: bool) -> Openid4vcFixture {
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let now = time::OffsetDateTime::now_utc();

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = now - time::Duration::minutes(1);
    ca_params.not_after = now + time::Duration::hours(1);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let mut leaf_params = CertificateParams::new(vec!["issuer.test".to_owned()]).unwrap();
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = now - time::Duration::minutes(1);
    leaf_params.not_after = now + time::Duration::hours(1);
    let leaf = leaf_params.signed_by(&signing_key, &ca).unwrap();

    let leaf_der = leaf.der().to_vec();
    let snapshot = status.map(|status| CertificateRevocationSnapshot {
        version: CertificateRevocationSnapshot::VERSION,
        this_update: chrono::Utc::now() - chrono::Duration::hours(1),
        next_update: chrono::Utc::now() + chrono::Duration::hours(1),
        entries: vec![CertificateRevocationEntry {
            issuer: "https://issuer.test".to_owned(),
            certificate: certificate_identity(&leaf_der),
            status,
            revoked_at: (status == CertificateRevocationStatus::Revoked)
                .then_some(chrono::Utc::now()),
        }],
    });
    let snapshot = if stale {
        Some(CertificateRevocationSnapshot {
            version: CertificateRevocationSnapshot::VERSION,
            this_update: chrono::Utc::now() - chrono::Duration::hours(2),
            next_update: chrono::Utc::now() - chrono::Duration::minutes(1),
            entries: Vec::new(),
        })
    } else {
        snapshot
    };
    let ca_pem = ca.pem();
    let leaf_pem = leaf.pem();
    let ca_id = hex_sha256(ca.der());
    Openid4vcFixture {
        material: Openid4vcMaterial {
            public: Openid4vcPublicMaterial {
                signing_kid: format!("openid4vc-{}", Uuid::now_v7()),
                certificate_chain_pem: format!("{leaf_pem}{ca_pem}"),
                trust_anchors_pem: ca_pem.clone(),
                revocation_snapshot: snapshot,
            },
            iaca_private_materials: [(
                ca_id,
                format!("{}{}{}", ca.key().serialize_pem(), leaf_pem, ca_pem),
            )]
            .into_iter()
            .collect(),
        },
        private_key_pem: signing_key.serialize_pem(),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn settings(external_command: Vec<String>) -> KeySettings {
    KeySettings {
        keys_dir: std::env::temp_dir().join(format!("nazoauth-database-test-{}", Uuid::now_v7())),
        external_command,
        external_timeout: std::time::Duration::from_secs(1),
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    }
}

fn valid_payload() -> Value {
    initial_payload().expect("database fixture keyset should generate")
}

fn active_entry_mut(payload: &mut Value) -> &mut Value {
    let active_kid = payload["active_kid"].as_str().unwrap().to_owned();
    payload["keys"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry["kid"] == active_kid)
        .unwrap()
}

fn external_entry_from_active(payload: &Value, kid: &str) -> Value {
    let mut entry = payload["keys"][0].clone();
    entry["kid"] = json!(kid);
    entry["backend"] = json!("external-command");
    entry["key_ref"] = json!("kms://test/external");
    entry.as_object_mut().unwrap().remove("private_pkcs8_der");
    entry["public_jwk"]["kid"] = json!(kid);
    entry
}

#[test]
fn import_identity_requires_backend_specific_private_material() {
    let local = json!({
        "kid":"local",
        "alg":"RS256",
        "backend":"local-db",
        "purposes":null,
        "public_jwk":null,
        "private_pkcs8_der":"private"
    });
    assert_eq!(import_identity(&local).unwrap()["kid"], "local");

    let external = json!({
        "kid":"external",
        "alg":"RS256",
        "backend":"external-command",
        "purposes":null,
        "public_jwk":null,
        "key_ref":"kms://test/external"
    });
    assert_eq!(
        import_identity(&external).unwrap()["key_ref"],
        "kms://test/external"
    );

    let mut missing_local = local.clone();
    missing_local
        .as_object_mut()
        .unwrap()
        .remove("private_pkcs8_der");
    assert!(import_identity(&missing_local).is_err());

    let mut missing_external = external.clone();
    missing_external.as_object_mut().unwrap().remove("key_ref");
    assert!(import_identity(&missing_external).is_err());
    assert!(import_identity(&json!({"backend":"unsupported"})).is_err());
    assert!(import_identity(&json!({})).is_err());
}

#[test]
fn import_compatibility_rejects_missing_or_changed_generation_members() {
    let local = json!({
        "kid":"local",
        "alg":"RS256",
        "backend":"local-db",
        "purposes":null,
        "public_jwk":{"kid":"local"},
        "private_pkcs8_der":"private"
    });
    let imported = json!({
        "request_object_private_pem":"request",
        "keys":[local.clone()]
    });
    let existing = imported.clone();
    assert!(ensure_import_is_compatible(&imported, &existing).is_ok());

    let mut changed_request = existing.clone();
    changed_request["request_object_private_pem"] = json!("changed");
    assert!(ensure_import_is_compatible(&imported, &changed_request).is_err());
    assert!(
        ensure_import_is_compatible(&imported, &json!({"request_object_private_pem":"request"}))
            .is_err()
    );
    assert!(
        ensure_import_is_compatible(&json!({"request_object_private_pem":"request"}), &existing)
            .is_err()
    );

    let mut missing_kid = imported.clone();
    missing_kid["keys"][0]
        .as_object_mut()
        .unwrap()
        .remove("kid");
    assert!(ensure_import_is_compatible(&missing_kid, &existing).is_err());

    let mut missing_existing_key = existing.clone();
    missing_existing_key["keys"] = json!([]);
    assert!(ensure_import_is_compatible(&imported, &missing_existing_key).is_err());

    let mut changed_private = existing.clone();
    changed_private["keys"][0]["private_pkcs8_der"] = json!("changed");
    assert!(ensure_import_is_compatible(&imported, &changed_private).is_err());

    let external = json!({
        "kid":"external",
        "alg":"RS256",
        "backend":"external-command",
        "purposes":null,
        "public_jwk":{"kid":"external"},
        "key_ref":"kms://test/external"
    });
    assert!(
        ensure_import_is_compatible(
            &json!({"request_object_private_pem":"request","keys":[external.clone()]}),
            &json!({"request_object_private_pem":"request","keys":[external]})
        )
        .is_ok()
    );
}

#[test]
fn decrypt_payload_rejects_invalid_revision_ciphertext_and_projection() {
    let tenant = Uuid::now_v7();
    let ring = SigningKeyWrappingKeyRing::new("current", [31_u8; 32], None).unwrap();
    let payload = valid_payload();
    let record = persist_payload(tenant, 1, payload, &ring).unwrap();

    let mut invalid_revision = record.clone();
    invalid_revision.revision = 0;
    assert!(decrypt_payload(tenant, &ring, &invalid_revision).is_err());

    let mut invalid_ciphertext = record.clone();
    invalid_ciphertext.encrypted_private_material.clear();
    assert!(decrypt_payload(tenant, &ring, &invalid_ciphertext).is_err());

    let mut mismatched_projection = record;
    mismatched_projection.public_metadata["active_kid"] = json!("different");
    assert!(decrypt_payload(tenant, &ring, &mismatched_projection).is_err());
}

#[test]
fn load_payload_rejects_tampered_local_and_generation_metadata() {
    let base = valid_payload();

    let mut schema = base.clone();
    schema["schema_version"] = json!("legacy");
    assert!(load_payload(&settings(Vec::new()), &schema).is_err());

    let mut missing_active = base.clone();
    missing_active.as_object_mut().unwrap().remove("active_kid");
    assert!(load_payload(&settings(Vec::new()), &missing_active).is_err());

    let mut invalid_request = base.clone();
    invalid_request["request_object_private_pem"] = json!(URL_SAFE_NO_PAD.encode([1_u8]));
    assert!(load_payload(&settings(Vec::new()), &invalid_request).is_err());

    let mut missing_private = base.clone();
    active_entry_mut(&mut missing_private)
        .as_object_mut()
        .unwrap()
        .remove("private_pkcs8_der");
    assert!(load_payload(&settings(Vec::new()), &missing_private).is_err());

    let mut mismatched_public = base.clone();
    active_entry_mut(&mut mismatched_public)["public_jwk"] = json!({
        "kid": mismatched_public["active_kid"],
        "alg":"RS256",
        "use":"sig",
        "n":"AQ",
        "e":"AQAB"
    });
    assert!(load_payload(&settings(Vec::new()), &mismatched_public).is_err());

    let mut duplicate_kid = base.clone();
    let duplicate = duplicate_kid["keys"][0].clone();
    duplicate_kid["keys"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(load_payload(&settings(Vec::new()), &duplicate_kid).is_err());

    let mut unsupported_backend = base.clone();
    active_entry_mut(&mut unsupported_backend)["backend"] = json!("unsupported");
    assert!(load_payload(&settings(Vec::new()), &unsupported_backend).is_err());

    let mut active_purpose = base.clone();
    active_entry_mut(&mut active_purpose)["purposes"] = json!(["credential"]);
    assert!(load_payload(&settings(Vec::new()), &active_purpose).is_err());

    let mut active_retired = base.clone();
    active_entry_mut(&mut active_retired)["retire_at"] = json!(
        (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    assert!(load_payload(&settings(Vec::new()), &active_retired).is_err());
}

#[test]
fn load_payload_handles_external_keys_with_and_without_a_signer_command() {
    let base = valid_payload();
    let mut non_active = base.clone();
    non_active["keys"]
        .as_array_mut()
        .unwrap()
        .push(external_entry_from_active(&base, "external"));
    let loaded = load_payload(&settings(Vec::new()), &non_active).unwrap();
    assert!(loaded.verification_keys.iter().any(|entry| {
        entry.managed.kid == "external"
            && matches!(entry.managed.handle, KeyHandle::External { .. })
    }));

    let mut missing_ref = non_active.clone();
    missing_ref["keys"][2]
        .as_object_mut()
        .unwrap()
        .remove("key_ref");
    assert!(load_payload(&settings(Vec::new()), &missing_ref).is_err());

    let mut active_external = base.clone();
    let active = active_entry_mut(&mut active_external);
    active["backend"] = json!("external-command");
    active["key_ref"] = json!("kms://test/active");
    active.as_object_mut().unwrap().remove("private_pkcs8_der");
    assert!(load_payload(&settings(Vec::new()), &active_external).is_err());
    let loaded = load_payload(&settings(vec!["test-signer".to_owned()]), &active_external)
        .expect("an active external key needs only an explicit command");
    assert!(matches!(
        loaded.active_signing_key,
        ActiveSigningKey::ExternalCommand(_)
    ));
}

#[test]
fn maintain_payload_prepublishes_rotates_and_repairs_protocol_keys() {
    let mut candidate = valid_payload();
    let due = settings(Vec::new());
    let mut due = KeySettings {
        rotation_interval: chrono::Duration::seconds(-1),
        prepublish_window: chrono::Duration::days(1),
        ..due
    };
    assert!(maintain_payload(&mut candidate, &due).unwrap());
    assert!(!maintain_payload(&mut candidate, &due).unwrap());

    let mut activate_now = valid_payload();
    due.prepublish_window = chrono::Duration::zero();
    assert!(maintain_payload(&mut activate_now, &due).unwrap());
    assert!(maintain_payload(&mut activate_now, &due).unwrap());
    assert_ne!(
        activate_now["active_kid"],
        valid_payload()["active_kid"],
        "a mature prepublished candidate should become active"
    );

    let mut missing_protocol = valid_payload();
    missing_protocol["keys"]
        .as_array_mut()
        .unwrap()
        .retain(|entry| entry["alg"] != "PS256");
    let stable = settings(Vec::new());
    assert!(maintain_payload(&mut missing_protocol, &stable).unwrap());
    assert!(
        missing_protocol["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["alg"] == "PS256")
    );

    let mut external_active = valid_payload();
    let active = active_entry_mut(&mut external_active);
    active["backend"] = json!("external-command");
    assert!(!maintain_payload(&mut external_active, &stable).unwrap());
}

#[test]
fn records_report_each_persisted_key_lifecycle_state() {
    let mut payload = valid_payload();
    let now = chrono::Utc::now();
    let keys = payload["keys"].as_array_mut().unwrap();
    keys.extend([
        json!({
            "kid":"future-grace", "alg":"RS256", "backend":"local-db",
            "created_at":now.to_rfc3339(),
            "retire_at":(now + chrono::Duration::hours(1)).to_rfc3339()
        }),
        json!({
            "kid":"expired", "alg":"RS256", "backend":"local-db",
            "created_at":now.to_rfc3339(),
            "retire_at":(now - chrono::Duration::hours(1)).to_rfc3339()
        }),
        json!({
            "kid":"purpose", "alg":"ES256", "backend":"local-db",
            "purposes":["credential"], "created_at":now.to_rfc3339(), "retire_at":null
        }),
        json!({
            "kid":"next", "alg":"RS256", "backend":"local-db",
            "created_at":now.to_rfc3339(), "retire_at":null
        }),
    ]);
    let records = records(&payload).unwrap();
    let status = |kid: &str| {
        records
            .iter()
            .find(|record| record.kid == kid)
            .unwrap()
            .status
    };
    assert_eq!(status("future-grace"), KeyRecordStatus::Grace);
    assert_eq!(status("expired"), KeyRecordStatus::Retired);
    assert_eq!(status("purpose"), KeyRecordStatus::PurposeScoped);
    assert_eq!(status("next"), KeyRecordStatus::Prepublished);
}

#[test]
fn registration_validation_rejects_ambiguous_or_unsafe_inputs() {
    assert!(
        validate_local_registration(&LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: BTreeSet::new(),
        })
        .is_err()
    );
    assert!(
        validate_local_registration(&LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: [SigningPurpose::AccessToken].into_iter().collect(),
        })
        .is_err()
    );
    assert!(
        validate_local_registration(&LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::HS256,
            purposes: [SigningPurpose::Credential].into_iter().collect(),
        })
        .is_err()
    );

    assert!(
        validate_external_registration(&ExternalKeyRegistration {
            kid: " ".to_owned(),
            algorithm: jsonwebtoken::Algorithm::RS256,
            key_ref: "kms://test".to_owned(),
            public_jwk: json!({}),
        })
        .is_err()
    );
    assert!(
        validate_external_registration(&ExternalKeyRegistration {
            kid: "external".to_owned(),
            algorithm: jsonwebtoken::Algorithm::HS256,
            key_ref: "kms://test".to_owned(),
            public_jwk: json!({}),
        })
        .is_err()
    );

    let payload = valid_payload();
    let public_jwk = payload["keys"][0]["public_jwk"].clone();
    assert!(
        validate_external_registration(&ExternalKeyRegistration {
            kid: payload["keys"][0]["kid"].as_str().unwrap().to_owned(),
            algorithm: jsonwebtoken::Algorithm::RS256,
            key_ref: "kms://test".to_owned(),
            public_jwk,
        })
        .is_ok()
    );
}

#[test]
fn local_private_key_export_requires_a_local_database_key() {
    let payload = valid_payload();
    let loaded = load_payload(&settings(Vec::new()), &payload).unwrap();
    let kid = loaded.active_kid.clone();
    assert!(
        local_private_key_pem(&loaded, &kid)
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
    assert!(local_private_key_pem(&loaded, "missing").is_err());

    let mut with_external = payload;
    let external = external_entry_from_active(&with_external, "external");
    with_external["keys"].as_array_mut().unwrap().push(external);
    let loaded = load_payload(&settings(Vec::new()), &with_external).unwrap();
    assert!(local_private_key_pem(&loaded, "external").is_err());
}

#[tokio::test]
async fn openid4vc_wrong_leaf_is_rejected_before_cas() {
    let (manager, repository, tenant_id, wrapping_keys) = database_fixture().await;
    let expected = manager.database_openid4vc_state().await.unwrap();
    let fixture = openid4vc_fixture(None, false);
    let other = openid4vc_fixture(None, false);
    let mut material = fixture.material.clone();
    material.public.certificate_chain_pem = other.material.public.certificate_chain_pem;

    let error = manager
        .database_commit_openid4vc(expected.revision, material, Some(fixture.private_key_pem))
        .await
        .expect_err("certificate/key mismatch must fail before CAS");
    assert!(error.to_string().contains("does not match its managed key"));
    let record = repository.load().await.unwrap().unwrap();
    assert_eq!(record.revision, expected.revision);
    assert!(
        manager
            .database_openid4vc_state()
            .await
            .unwrap()
            .material
            .is_none()
    );
    assert!(decrypt_payload(tenant_id, &wrapping_keys, &record).is_ok());
}

#[tokio::test]
async fn openid4vc_revision_conflict_does_not_publish_material() {
    let (manager, repository, _tenant_id, _wrapping_keys) = database_fixture().await;
    let expected = manager.database_openid4vc_state().await.unwrap();
    let fixture = openid4vc_fixture(None, false);
    let error = manager
        .database_commit_openid4vc(
            expected.revision - 1,
            fixture.material,
            Some(fixture.private_key_pem),
        )
        .await
        .expect_err("a stale expected revision must conflict");
    assert!(error.to_string().contains("revision conflict"));
    let record = repository.load().await.unwrap().unwrap();
    assert_eq!(record.revision, expected.revision);
    assert!(
        manager
            .database_openid4vc_state()
            .await
            .unwrap()
            .material
            .is_none()
    );
}

#[tokio::test]
async fn openid4vc_public_projection_redacts_iaca_and_reload_rebases_observation() {
    let (manager, repository, tenant_id, wrapping_keys) = database_fixture().await;
    let expected = manager.database_openid4vc_state().await.unwrap();
    let fixture = openid4vc_fixture(None, true);
    let private_material = fixture
        .material
        .iaca_private_materials
        .values()
        .next()
        .unwrap()
        .clone();
    manager
        .database_commit_openid4vc(
            expected.revision,
            fixture.material.clone(),
            Some(fixture.private_key_pem),
        )
        .await
        .unwrap();

    let record = repository.load().await.unwrap().unwrap();
    assert_eq!(record.wrapping_key_id, wrapping_keys.current_id());
    let public_json = serde_json::to_string(&record.public_metadata).unwrap();
    assert!(!public_json.contains("PRIVATE KEY"));
    assert!(!format!("{:?}", fixture.material).contains("PRIVATE KEY"));
    assert!(
        record.public_metadata["openid4vc"]
            .get("iaca_private_materials")
            .is_none()
    );
    let encrypted_payload = decrypt_payload(tenant_id, &wrapping_keys, &record).unwrap();
    assert!(decrypt_payload(Uuid::now_v7(), &wrapping_keys, &record).is_err());
    assert_eq!(
        encrypted_payload["openid4vc"]["iaca_private_materials"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .and_then(Value::as_str),
        Some(private_material.as_str())
    );

    let state = manager.database_openid4vc_state().await.unwrap();
    let persisted_next_update = state
        .material
        .as_ref()
        .unwrap()
        .public
        .revocation_snapshot
        .as_ref()
        .unwrap()
        .next_update;
    assert!(persisted_next_update < chrono::Utc::now());
    let loaded_snapshot = manager
        .openid4vc_public_material()
        .unwrap()
        .revocation_snapshot
        .clone()
        .unwrap();
    assert!(loaded_snapshot.this_update <= chrono::Utc::now());
    assert!(loaded_snapshot.next_update > chrono::Utc::now());
    assert_eq!(
        loaded_snapshot.next_update - loaded_snapshot.this_update,
        chrono::Duration::seconds(crate::lifecycle::OPENID4VC_REVOCATION_MAX_STALE_SECONDS)
    );

    let reloaded = KeyManager::load_or_create_database(
        settings(Vec::new()),
        tenant_id,
        repository.clone(),
        wrapping_keys,
    )
    .await
    .unwrap();
    let reloaded_snapshot = reloaded
        .openid4vc_public_material()
        .unwrap()
        .revocation_snapshot
        .clone()
        .unwrap();
    assert!(reloaded_snapshot.next_update > chrono::Utc::now());
    assert_eq!(
        reloaded_snapshot.next_update - reloaded_snapshot.this_update,
        chrono::Duration::seconds(crate::lifecycle::OPENID4VC_REVOCATION_MAX_STALE_SECONDS)
    );
}

#[tokio::test]
async fn openid4vc_revoked_active_leaf_cannot_prepare_signing() {
    let (manager, _repository, _tenant_id, _wrapping_keys) = database_fixture().await;
    let expected = manager.database_openid4vc_state().await.unwrap();
    let fixture = openid4vc_fixture(Some(CertificateRevocationStatus::Good), false);
    manager
        .database_commit_openid4vc(
            expected.revision,
            fixture.material.clone(),
            Some(fixture.private_key_pem),
        )
        .await
        .unwrap();
    let expected = manager.database_openid4vc_state().await.unwrap();
    let mut revoked = fixture.material;
    revoked.public.revocation_snapshot.as_mut().unwrap().entries[0].status =
        CertificateRevocationStatus::Revoked;
    revoked.public.revocation_snapshot.as_mut().unwrap().entries[0].revoked_at =
        Some(chrono::Utc::now());
    manager
        .database_commit_openid4vc(expected.revision, revoked, None)
        .await
        .unwrap();
    let error = manager
        .prepare_openid4vc_signing()
        .err()
        .expect("revoked active DS must not sign");
    assert!(error.to_string().contains("revoked"));
}
