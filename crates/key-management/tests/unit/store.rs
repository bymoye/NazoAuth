use std::path::PathBuf;

use super::*;

fn settings(keys_dir: PathBuf) -> KeySettings {
    KeySettings {
        keys_dir,
        external_command: Vec::new(),
        external_timeout: std::time::Duration::from_secs(2),
        rotation_interval: chrono::Duration::seconds(3_600),
        prepublish_window: chrono::Duration::seconds(1_800),
        verification_grace: chrono::Duration::seconds(600),
    }
}

#[tokio::test]
async fn atomic_json_write_leaves_only_complete_target() {
    let directory = std::env::temp_dir().join(format!("nazo-key-atomic-{}", Uuid::now_v7()));
    let path = directory.join("keyset.json");
    write_json_atomic(&path, &json!({"active_kid":"new","keys":[]}))
        .await
        .expect("atomic write should succeed");

    let parsed: Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.expect("target should exist"))
            .expect("target must contain complete JSON");
    assert_eq!(parsed["active_kid"], "new");
    let files = std::fs::read_dir(&directory)
        .expect("directory should exist")
        .map(|entry| entry.expect("entry should be readable").file_name())
        .collect::<Vec<_>>();
    assert_eq!(files, vec![std::ffi::OsString::from("keyset.json")]);
    tokio::fs::remove_dir_all(directory)
        .await
        .expect("cleanup should succeed");
}

#[tokio::test]
async fn lifecycle_prepublishes_then_activates_with_grace() {
    let directory = std::env::temp_dir().join(format!("nazo-key-lifecycle-{}", Uuid::now_v7()));
    let settings = settings(directory.clone());
    create_new_keyset(&settings)
        .await
        .expect("initial keyset should be created");
    let path = directory.join("keyset.json");
    let mut payload: Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    let original_kid = payload["active_kid"].as_str().unwrap().to_owned();
    payload["keys"][0]["created_at"] =
        json!(timestamp(Utc::now() - chrono::Duration::seconds(2_000)));
    write_json_atomic(&path, &payload).await.unwrap();

    maintain_keyset_lifecycle(&settings, &path).await.unwrap();
    let mut payload: Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    assert_eq!(payload["active_kid"], original_kid);
    assert_eq!(payload["keys"].as_array().unwrap().len(), 3);
    payload["keys"][0]["created_at"] =
        json!(timestamp(Utc::now() - chrono::Duration::seconds(4_000)));
    let candidate = payload["keys"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|key| key["kid"] != original_kid && key["alg"] == "RS256")
        .unwrap();
    candidate["created_at"] = json!(timestamp(Utc::now() - chrono::Duration::seconds(2_000)));
    let candidate_kid = candidate["kid"].as_str().unwrap().to_owned();
    write_json_atomic(&path, &payload).await.unwrap();

    maintain_keyset_lifecycle(&settings, &path).await.unwrap();
    let payload: Value = serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    assert_eq!(payload["active_kid"], candidate_kid);
    let previous = payload["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["kid"] == original_kid)
        .unwrap();
    assert!(previous["retire_at"].as_str().is_some());
    tokio::fs::remove_dir_all(directory).await.unwrap();
}

#[tokio::test]
async fn lifecycle_upgrades_legacy_protocol_response_keys_for_signed_introspection() {
    let directory = std::env::temp_dir().join(format!(
        "nazo-key-introspection-purpose-upgrade-{}",
        Uuid::now_v7()
    ));
    let settings = settings(directory.clone());
    create_new_keyset(&settings).await.unwrap();
    let path = directory.join("keyset.json");
    let mut payload: Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    payload["keys"][0]["created_at"] =
        json!(timestamp(Utc::now() - chrono::Duration::seconds(2_000)));
    write_json_atomic(&path, &payload).await.unwrap();
    maintain_keyset_lifecycle(&settings, &path).await.unwrap();
    let mut payload: Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    for key in payload["keys"].as_array_mut().unwrap() {
        if let Some(purposes) = key.get_mut("purposes").and_then(Value::as_array_mut) {
            purposes.retain(|purpose| purpose != "introspection");
        }
    }
    write_json_atomic(&path, &payload).await.unwrap();

    maintain_keyset_lifecycle(&settings, &path).await.unwrap();

    let upgraded: Value = serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    for key in upgraded["keys"].as_array().unwrap() {
        if let Some(purposes) = key["purposes"].as_array()
            && purposes.iter().any(|purpose| purpose == "id_token")
            && purposes.iter().any(|purpose| purpose == "jarm")
        {
            assert!(purposes.iter().any(|purpose| purpose == "introspection"));
        }
    }
    tokio::fs::remove_dir_all(directory).await.unwrap();
}

#[tokio::test]
async fn key_manager_lists_persisted_key_states_without_server_schema_logic() {
    let directory = std::env::temp_dir().join(format!("nazo-key-list-{}", Uuid::now_v7()));
    let settings = settings(directory.clone());
    let now = Utc::now();
    write_json_atomic(
        &directory.join("keyset.json"),
        &json!({
            "active_kid":"active",
            "keys":[
                {"kid":"active","alg":"EdDSA","file":"active.pem","retire_at":null},
                {"kid":"candidate","alg":"EdDSA","file":"candidate.pem","retire_at":null},
                {"kid":"grace","alg":"RS256","file":"grace.pem","retire_at":timestamp(now + chrono::Duration::minutes(5))},
                {"kid":"retired","alg":"RS256","file":"retired.pem","retire_at":timestamp(now - chrono::Duration::minutes(5))}
            ]
        }),
    )
    .await
    .unwrap();

    let records = crate::KeyManager::list_keys(&settings).await.unwrap();
    assert_eq!(
        records
            .iter()
            .map(|record| (record.kid.as_str(), record.status))
            .collect::<Vec<_>>(),
        vec![
            ("active", KeyRecordStatus::Active),
            ("candidate", KeyRecordStatus::Prepublished),
            ("grace", KeyRecordStatus::Grace),
            ("retired", KeyRecordStatus::Retired),
        ]
    );
    tokio::fs::remove_dir_all(directory).await.unwrap();
}

#[tokio::test]
async fn key_manager_registers_exact_external_key_schema_atomically() {
    let directory = std::env::temp_dir().join(format!("nazo-key-register-{}", Uuid::now_v7()));
    let settings = settings(directory.clone());
    let public_jwk_file = directory.join("external-public.jwk.json");
    tokio::fs::create_dir_all(&directory).await.unwrap();
    let material = generate_key_material(jsonwebtoken::Algorithm::EdDSA).unwrap();
    let public_jwk = public_jwk_from_private_der(
        "external",
        jsonwebtoken::Algorithm::EdDSA,
        &material.private_pkcs8_der,
    )
    .unwrap();
    tokio::fs::write(&public_jwk_file, serde_json::to_vec(&public_jwk).unwrap())
        .await
        .unwrap();

    crate::KeyManager::register_external(
        &settings,
        crate::ExternalKeyRegistration {
            kid: "external".to_owned(),
            algorithm: jsonwebtoken::Algorithm::EdDSA,
            key_ref: "kms://key/1".to_owned(),
            public_jwk_file: public_jwk_file.clone(),
        },
    )
    .await
    .unwrap();

    crate::KeyManager::register_external(
        &settings,
        crate::ExternalKeyRegistration {
            kid: "external".to_owned(),
            algorithm: jsonwebtoken::Algorithm::EdDSA,
            key_ref: "kms://key/1".to_owned(),
            public_jwk_file: public_jwk_file.clone(),
        },
    )
    .await
    .expect("an exact retry must be idempotent");
    let conflict = crate::KeyManager::register_external(
        &settings,
        crate::ExternalKeyRegistration {
            kid: "external".to_owned(),
            algorithm: jsonwebtoken::Algorithm::EdDSA,
            key_ref: "kms://different-key".to_owned(),
            public_jwk_file,
        },
    )
    .await
    .unwrap_err();
    assert!(conflict.to_string().contains("different material"));

    let payload: Value = serde_json::from_slice(
        &tokio::fs::read(directory.join("keyset.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(payload["active_kid"], "external");
    let entry = &payload["keys"][0];
    assert_eq!(entry["kid"], "external");
    assert_eq!(entry["alg"], "EdDSA");
    assert_eq!(entry["backend"], "external-command");
    assert_eq!(entry["key_ref"], "kms://key/1");
    assert_eq!(entry["retire_at"], Value::Null);
    assert!(entry["created_at"].as_str().is_some());
    assert_eq!(entry["public_jwk"]["kid"], "external");
    tokio::fs::remove_dir_all(directory).await.unwrap();
}

#[tokio::test]
async fn external_key_registration_rejects_unusable_algorithm_material() {
    let off_curve_coordinate = URL_SAFE_NO_PAD.encode([0_u8; 32]);
    for (label, algorithm, public_jwk) in [
        (
            "rsa",
            jsonwebtoken::Algorithm::RS256,
            json!({
                "kty":"RSA","kid":"external","alg":"RS256","use":"sig",
                "n":"not-base64url","e":"AQAB"
            }),
        ),
        (
            "ec",
            jsonwebtoken::Algorithm::ES256,
            json!({
                "kty":"EC","crv":"P-256","kid":"external","alg":"ES256","use":"sig",
                "x":"AQ","y":"AQ"
            }),
        ),
        (
            "ec-off-curve",
            jsonwebtoken::Algorithm::ES256,
            json!({
                "kty":"EC","crv":"P-256","kid":"external","alg":"ES256","use":"sig",
                "x":off_curve_coordinate.clone(),"y":off_curve_coordinate
            }),
        ),
        (
            "ed25519",
            jsonwebtoken::Algorithm::EdDSA,
            json!({
                "kty":"OKP","crv":"Ed25519","kid":"external","alg":"EdDSA","use":"sig"
            }),
        ),
    ] {
        let directory = std::env::temp_dir().join(format!(
            "nazo-key-register-invalid-{label}-{}",
            Uuid::now_v7()
        ));
        let settings = settings(directory.clone());
        let public_jwk_file = directory.join("external-public.jwk.json");
        tokio::fs::create_dir_all(&directory).await.unwrap();
        tokio::fs::write(&public_jwk_file, serde_json::to_vec(&public_jwk).unwrap())
            .await
            .unwrap();

        let error = crate::KeyManager::register_external(
            &settings,
            crate::ExternalKeyRegistration {
                kid: "external".to_owned(),
                algorithm,
                key_ref: format!("kms://invalid/{label}"),
                public_jwk_file,
            },
        )
        .await
        .expect_err("unusable public key material must fail before keyset publication");
        assert!(error.to_string().contains("not usable"));
        assert!(
            !directory.join("keyset.json").exists(),
            "a rejected external key must not become the active keyset"
        );
        tokio::fs::remove_dir_all(directory).await.unwrap();
    }
}
