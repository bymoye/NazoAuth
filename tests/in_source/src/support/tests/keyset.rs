use super::*;
use proptest::prelude::*;
use std::path::{Path, PathBuf};

use crate::domain::KeysetStore;
use crate::settings::{EmailDelivery, EmailSettings, RateLimitSettings};
use crate::support::ClientIpHeaderMode;

#[test]
fn jwks_publishes_active_and_previous_verification_keys() {
    let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    let previous_der = ed25519_pkcs8_private_der(&[2u8; 32]);
    let keyset = Keyset {
        active_kid: "active".to_owned(),
        active_alg: jsonwebtoken::Algorithm::EdDSA,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(active_der.clone()),
        verification_keys: vec![
            VerificationKey {
                kid: "active".to_owned(),
                public_jwk: public_jwk_from_private_der(
                    "active",
                    jsonwebtoken::Algorithm::EdDSA,
                    &active_der,
                )
                .unwrap(),
                local_signing_key: None,
            },
            VerificationKey {
                kid: "previous".to_owned(),
                public_jwk: public_jwk_from_private_der(
                    "previous",
                    jsonwebtoken::Algorithm::EdDSA,
                    &previous_der,
                )
                .unwrap(),
                local_signing_key: None,
            },
        ],
    };

    let jwks = keyset.jwks();
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 2);
    assert!(keyset.verification_key("previous").is_some());
}

#[test]
fn response_signing_capabilities_include_only_active_or_locally_signable_keys() {
    let rs256 = generate_key_material(jsonwebtoken::Algorithm::RS256).unwrap();
    let ps256 = generate_key_material(jsonwebtoken::Algorithm::PS256).unwrap();
    let keyset = Keyset {
        active_kid: "active-eddsa".to_owned(),
        active_alg: jsonwebtoken::Algorithm::EdDSA,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
        verification_keys: vec![
            VerificationKey {
                kid: "local-rs256".to_owned(),
                public_jwk: public_jwk_from_private_der(
                    "local-rs256",
                    jsonwebtoken::Algorithm::RS256,
                    &rs256.private_pkcs8_der,
                )
                .unwrap(),
                local_signing_key: Some(rs256.private_pkcs8_der.clone()),
            },
            VerificationKey {
                kid: "public-only-ps256".to_owned(),
                public_jwk: public_jwk_from_private_der(
                    "public-only-ps256",
                    jsonwebtoken::Algorithm::PS256,
                    &ps256.private_pkcs8_der,
                )
                .unwrap(),
                local_signing_key: None,
            },
        ],
    };

    assert_eq!(
        keyset.response_signing_alg_values_supported(),
        vec!["EdDSA", "RS256"]
    );
    let (kid, private_key) = keyset
        .local_response_signing_key(jsonwebtoken::Algorithm::RS256)
        .expect("locally signable auxiliary key should be selectable");
    assert_eq!(kid, "local-rs256");
    assert_eq!(private_key, rs256.private_pkcs8_der.as_slice());
    assert!(
        keyset
            .local_response_signing_key(jsonwebtoken::Algorithm::PS256)
            .is_none(),
        "verification-only keys must not be advertised as signing capabilities"
    );
}

#[test]
fn keyset_store_replaces_runtime_signing_snapshot() {
    let first = Keyset {
        active_kid: "first".to_owned(),
        active_alg: jsonwebtoken::Algorithm::EdDSA,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(ed25519_pkcs8_private_der(&[1u8; 32])),
        verification_keys: Vec::new(),
    };
    let second = Keyset {
        active_kid: "second".to_owned(),
        active_alg: jsonwebtoken::Algorithm::RS256,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
        verification_keys: Vec::new(),
    };

    let store = KeysetStore::new(first);
    assert_eq!(store.snapshot().active_kid, "first");

    store.replace(second);

    let snapshot = store.snapshot();
    assert_eq!(snapshot.active_kid, "second");
    assert_eq!(snapshot.active_alg, jsonwebtoken::Algorithm::RS256);
}

#[test]
fn retired_non_active_key_entries_are_detected() {
    let retired = json!({"retire_at": "2000-01-01T00:00:00Z"});
    let live = json!({"retire_at": "2999-01-01T00:00:00Z"});
    let missing = json!({});

    assert!(
        key_entry_retire_at(&retired)
            .unwrap()
            .is_some_and(|retire_at| retire_at <= Utc::now())
    );
    assert!(
        key_entry_retire_at(&live)
            .unwrap()
            .is_none_or(|retire_at| retire_at > Utc::now())
    );
    assert!(
        key_entry_retire_at(&missing).unwrap().is_none(),
        "missing retire_at should mean the key is still publishable"
    );
}

proptest! {
    #[test]
    fn ed25519_pkcs8_seed_roundtrips_through_der(seed in any::<[u8; 32]>()) {
        let der = ed25519_pkcs8_private_der(&seed);

        prop_assert_eq!(ed25519_seed_from_pkcs8(&der), Some(seed));
        prop_assert!(public_jwk_from_private_der(
            "kid-1",
            jsonwebtoken::Algorithm::EdDSA,
            &der
        ).is_ok());
    }

    #[test]
    fn pem_der_roundtrip_preserves_key_material(seed in any::<[u8; 32]>()) {
        let der = ed25519_pkcs8_private_der(&seed);
        let pem = der_to_pem(&der, "PRIVATE KEY");
        let decoded = pem_to_der(&pem);

        prop_assert_eq!(decoded.as_deref(), Some(der.as_slice()));
    }

    #[test]
    fn unsupported_keyset_algorithms_are_rejected(alg in "[A-Z0-9]{1,12}") {
        prop_assume!(!matches!(alg.as_str(), "EdDSA" | "RS256" | "ES256" | "PS256"));
        let entry = json!({"alg": alg});

        prop_assert!(key_entry_algorithm(&entry).is_err());
    }
}

#[tokio::test]
async fn missing_keyset_file_allows_initial_creation() {
    let keys_dir = temp_keys_dir("missing");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let result = try_load_keyset(&settings, &keyset_path).await.unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert!(result.is_none());
}

#[tokio::test]
async fn load_or_create_keyset_creates_keyset_when_no_keyset_exists() {
    let keys_dir = temp_keys_dir("load_or_create_missing");
    let settings = test_settings(keys_dir.clone());

    let keyset = load_or_create_keyset(&settings).await.unwrap();
    let keyset_json = tokio::fs::read_to_string(keys_dir.join("keyset.json"))
        .await
        .unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert_eq!(keyset.active_alg, jsonwebtoken::Algorithm::RS256);
    assert!(
        keyset_json.contains(&keyset.active_kid),
        "persisted keyset should contain the active kid"
    );
}

#[tokio::test]
async fn load_or_create_keyset_prepublishes_next_local_key_before_rotation_deadline() {
    let keys_dir = temp_keys_dir("automatic_prepublish");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let mut settings = test_settings(keys_dir.clone());
    settings.signing_key_rotation_interval_seconds = 10;
    settings.signing_key_prepublish_seconds = 3;
    write_local_key_entry(
        &keys_dir,
        "active",
        "RS256",
        "active.pem",
        Utc::now() - chrono::Duration::seconds(8),
    )
    .await;
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [{
                "kid": "active",
                "alg": "RS256",
                "file": "active.pem",
                "created_at": timestamp(Utc::now() - chrono::Duration::seconds(8)),
                "retire_at": null
            }]
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    let keyset = load_or_create_keyset(&settings).await.unwrap();
    let payload: Value = serde_json::from_str(
        &tokio::fs::read_to_string(keys_dir.join("keyset.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert_eq!(keyset.active_kid, "active");
    let keys = payload["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    let prepublished = keys.iter().find(|key| key["kid"] != "active").unwrap();
    assert_eq!(prepublished["alg"], "RS256");
    assert!(prepublished["file"].as_str().unwrap().starts_with("rs256-"));
    assert_eq!(keyset.verification_keys.len(), 2);
}

#[tokio::test]
async fn load_or_create_keyset_records_missing_active_created_at_without_rotating() {
    let keys_dir = temp_keys_dir("automatic_missing_created_at");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let mut settings = test_settings(keys_dir.clone());
    settings.signing_key_rotation_interval_seconds = 10;
    settings.signing_key_prepublish_seconds = 3;
    write_local_key_entry(&keys_dir, "active", "RS256", "active.pem", Utc::now()).await;
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [{
                "kid": "active",
                "alg": "RS256",
                "file": "active.pem",
                "retire_at": null
            }]
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    let keyset = load_or_create_keyset(&settings).await.unwrap();
    let payload: Value = serde_json::from_str(
        &tokio::fs::read_to_string(keys_dir.join("keyset.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert_eq!(keyset.active_kid, "active");
    assert!(payload["keys"][0]["created_at"].as_str().is_some());
    assert_eq!(payload["keys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn load_or_create_keyset_due_without_candidate_prepublishes_without_activation() {
    let keys_dir = temp_keys_dir("automatic_due_no_candidate");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let mut settings = test_settings(keys_dir.clone());
    settings.signing_key_rotation_interval_seconds = 10;
    settings.signing_key_prepublish_seconds = 3;
    write_local_key_entry(
        &keys_dir,
        "active",
        "RS256",
        "active.pem",
        Utc::now() - chrono::Duration::seconds(11),
    )
    .await;
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [{
                "kid": "active",
                "alg": "RS256",
                "file": "active.pem",
                "created_at": timestamp(Utc::now() - chrono::Duration::seconds(11)),
                "retire_at": null
            }]
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    let keyset = load_or_create_keyset(&settings).await.unwrap();
    let payload: Value = serde_json::from_str(
        &tokio::fs::read_to_string(keys_dir.join("keyset.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert_eq!(keyset.active_kid, "active");
    assert_eq!(payload["active_kid"], "active");
    assert_eq!(payload["keys"].as_array().unwrap().len(), 2);
    assert!(
        payload["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key["kid"] != "active" && key["alg"] == "RS256")
    );
}

#[tokio::test]
async fn load_or_create_keyset_activates_prepublished_key_after_window_and_graces_old_active() {
    let keys_dir = temp_keys_dir("automatic_activate");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let mut settings = test_settings(keys_dir.clone());
    settings.signing_key_rotation_interval_seconds = 10;
    settings.signing_key_prepublish_seconds = 3;
    write_local_key_entry(
        &keys_dir,
        "active",
        "RS256",
        "active.pem",
        Utc::now() - chrono::Duration::seconds(11),
    )
    .await;
    write_local_key_entry(
        &keys_dir,
        "next",
        "RS256",
        "next.pem",
        Utc::now() - chrono::Duration::seconds(4),
    )
    .await;
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [
                {
                    "kid": "active",
                    "alg": "RS256",
                    "file": "active.pem",
                    "created_at": timestamp(Utc::now() - chrono::Duration::seconds(11)),
                    "retire_at": null
                },
                {
                    "kid": "next",
                    "alg": "RS256",
                    "file": "next.pem",
                    "created_at": timestamp(Utc::now() - chrono::Duration::seconds(4)),
                    "retire_at": null
                }
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    let before_activation = Utc::now() - chrono::Duration::seconds(1);
    let keyset = load_or_create_keyset(&settings).await.unwrap();
    let payload: Value = serde_json::from_str(
        &tokio::fs::read_to_string(keys_dir.join("keyset.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert_eq!(keyset.active_kid, "next");
    assert_eq!(payload["active_kid"], "next");
    let old_active = payload["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["kid"] == "active")
        .unwrap();
    let retire_at = DateTime::parse_from_rfc3339(old_active["retire_at"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    assert!(retire_at >= before_activation + chrono::Duration::seconds(600));
    assert!(retire_at <= Utc::now() + chrono::Duration::seconds(601));
    assert_eq!(keyset.verification_keys.len(), 2);
}

#[tokio::test]
async fn load_or_create_keyset_activates_oldest_local_candidate_and_ignores_external_without_signer()
 {
    let keys_dir = temp_keys_dir("automatic_candidate_selection");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let mut settings = test_settings(keys_dir.clone());
    settings.signing_key_rotation_interval_seconds = 10;
    settings.signing_key_prepublish_seconds = 3;
    write_local_key_entry(
        &keys_dir,
        "active",
        "RS256",
        "active.pem",
        Utc::now() - chrono::Duration::seconds(11),
    )
    .await;
    write_local_key_entry(
        &keys_dir,
        "next-old",
        "RS256",
        "next-old.pem",
        Utc::now() - chrono::Duration::seconds(5),
    )
    .await;
    write_local_key_entry(
        &keys_dir,
        "next-new",
        "RS256",
        "next-new.pem",
        Utc::now() - chrono::Duration::seconds(4),
    )
    .await;
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [
                {
                    "kid": "active",
                    "alg": "RS256",
                    "file": "active.pem",
                    "created_at": timestamp(Utc::now() - chrono::Duration::seconds(11)),
                    "retire_at": null
                },
                {
                    "kid": "external-next",
                    "alg": "RS256",
                    "backend": "external-command",
                    "key_ref": "kms://prod/oauth/external-next",
                    "public_jwk": public_jwk_from_private_der(
                        "external-next",
                        jsonwebtoken::Algorithm::RS256,
                        &generate_key_material(jsonwebtoken::Algorithm::RS256).unwrap().private_pkcs8_der
                    ).unwrap(),
                    "created_at": timestamp(Utc::now() - chrono::Duration::seconds(6)),
                    "retire_at": null
                },
                {
                    "kid": "next-old",
                    "alg": "RS256",
                    "file": "next-old.pem",
                    "created_at": timestamp(Utc::now() - chrono::Duration::seconds(5)),
                    "retire_at": null
                },
                {
                    "kid": "next-new",
                    "alg": "RS256",
                    "file": "next-new.pem",
                    "created_at": timestamp(Utc::now() - chrono::Duration::seconds(4)),
                    "retire_at": null
                }
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    let keyset = load_or_create_keyset(&settings).await.unwrap();
    let payload: Value = serde_json::from_str(
        &tokio::fs::read_to_string(keys_dir.join("keyset.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert_eq!(keyset.active_kid, "next-old");
    assert_eq!(payload["active_kid"], "next-old");
    let next_new = payload["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["kid"] == "next-new")
        .unwrap();
    assert!(next_new["retire_at"].is_null());
}

#[tokio::test]
async fn load_or_create_keyset_does_not_activate_fresh_prepublished_key() {
    let keys_dir = temp_keys_dir("automatic_fresh_candidate");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let mut settings = test_settings(keys_dir.clone());
    settings.signing_key_rotation_interval_seconds = 10;
    settings.signing_key_prepublish_seconds = 3;
    write_local_key_entry(
        &keys_dir,
        "active",
        "RS256",
        "active.pem",
        Utc::now() - chrono::Duration::seconds(11),
    )
    .await;
    write_local_key_entry(
        &keys_dir,
        "next",
        "RS256",
        "next.pem",
        Utc::now() - chrono::Duration::seconds(1),
    )
    .await;
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [
                {
                    "kid": "active",
                    "alg": "RS256",
                    "file": "active.pem",
                    "created_at": timestamp(Utc::now() - chrono::Duration::seconds(11)),
                    "retire_at": null
                },
                {
                    "kid": "next",
                    "alg": "RS256",
                    "file": "next.pem",
                    "created_at": timestamp(Utc::now() - chrono::Duration::seconds(1)),
                    "retire_at": null
                }
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    let keyset = load_or_create_keyset(&settings).await.unwrap();
    let payload: Value = serde_json::from_str(
        &tokio::fs::read_to_string(keys_dir.join("keyset.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert_eq!(keyset.active_kid, "active");
    assert_eq!(payload["active_kid"], "active");
    assert_eq!(payload["keys"].as_array().unwrap().len(), 2);
    let old_active = payload["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["kid"] == "active")
        .unwrap();
    assert!(old_active["retire_at"].is_null());
}

#[tokio::test]
async fn keyset_read_and_json_parse_failures_are_reported() {
    let read_error_dir = temp_keys_dir("read_error");
    tokio::fs::create_dir_all(&read_error_dir).await.unwrap();
    let settings = test_settings(read_error_dir.clone());
    let read_error = match try_load_keyset(&settings, &read_error_dir).await {
        Ok(_) => panic!("a directory in place of keyset.json must be a read error"),
        Err(error) => error,
    };
    assert!(
        format!("{read_error:#}").contains("failed to read"),
        "unexpected read error: {read_error:#}"
    );
    let _ = tokio::fs::remove_dir_all(&read_error_dir).await;

    let parse_error_dir = temp_keys_dir("parse_error");
    tokio::fs::create_dir_all(&parse_error_dir).await.unwrap();
    let keyset_path = parse_error_dir.join("keyset.json");
    tokio::fs::write(&keyset_path, "not-json").await.unwrap();
    let settings = test_settings(parse_error_dir.clone());
    let parse_error = match try_load_keyset(&settings, &keyset_path).await {
        Ok(_) => panic!("malformed keyset.json must not be accepted"),
        Err(error) => error,
    };
    let _ = tokio::fs::remove_dir_all(&parse_error_dir).await;

    assert!(
        format!("{parse_error:#}").contains("failed to parse"),
        "unexpected parse error: {parse_error:#}"
    );
}

#[tokio::test]
async fn keyset_schema_requires_active_kid_keys_and_entry_kid() {
    let cases = [
        (
            "missing_active_kid",
            json!({"keys": []}),
            "missing active_kid",
        ),
        (
            "missing_keys",
            json!({"active_kid": "active"}),
            "missing keys array",
        ),
        (
            "missing_entry_kid",
            json!({"active_kid": "active", "keys": [{"file": "active.pem"}]}),
            "entry missing kid",
        ),
    ];

    for (label, payload, expected) in cases {
        let keys_dir = temp_keys_dir(label);
        tokio::fs::create_dir_all(&keys_dir).await.unwrap();
        let keyset_path = keys_dir.join("keyset.json");
        tokio::fs::write(
            &keyset_path,
            serde_json::to_string_pretty(&payload).unwrap(),
        )
        .await
        .unwrap();
        let settings = test_settings(keys_dir.clone());

        let error = match try_load_keyset(&settings, &keyset_path).await {
            Ok(_) => panic!("invalid keyset schema must fail closed"),
            Err(error) => error,
        };
        let _ = tokio::fs::remove_dir_all(&keys_dir).await;

        assert!(
            format!("{error:#}").contains(expected),
            "unexpected schema error for {label}: {error:#}"
        );
    }
}

#[tokio::test]
async fn created_keyset_uses_oidc_mandatory_default_signing_alg() {
    let keys_dir = temp_keys_dir("create_default_alg");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let settings = test_settings(keys_dir.clone());

    let keyset = create_new_keyset(&settings).await.unwrap();
    let keyset_json = tokio::fs::read_to_string(keys_dir.join("keyset.json"))
        .await
        .unwrap();
    let payload: Value = serde_json::from_str(&keyset_json).unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert!(keyset.active_kid.starts_with("rs256-"));
    assert_eq!(keyset.active_alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(payload["keys"][0]["alg"], "RS256");
    assert_eq!(keyset.jwks()["keys"][0]["alg"], "RS256");
}

#[tokio::test]
async fn load_or_create_keyset_backfills_oidc_default_rs256_signing_key() {
    let keys_dir = temp_keys_dir("backfill_rs256_default");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    write_local_key_entry(
        &keys_dir,
        "active-ps256",
        "PS256",
        "active-ps256.pem",
        Utc::now(),
    )
    .await;
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active-ps256",
            "keys": [{
                "kid": "active-ps256",
                "alg": "PS256",
                "file": "active-ps256.pem",
                "created_at": timestamp(Utc::now()),
                "retire_at": null
            }]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());

    let keyset = load_or_create_keyset(&settings).await.unwrap();
    let keyset_json = tokio::fs::read_to_string(keys_dir.join("keyset.json"))
        .await
        .unwrap();
    let payload: Value = serde_json::from_str(&keyset_json).unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert_eq!(keyset.active_kid, "active-ps256");
    assert_eq!(keyset.active_alg, jsonwebtoken::Algorithm::PS256);
    let keys = payload["keys"].as_array().unwrap();
    assert!(
        keys.iter()
            .any(|key| key["kid"] == "active-ps256" && key["alg"] == "PS256")
    );
    assert!(
        keys.iter().any(|key| key["alg"] == "RS256"
            && key["file"]
                .as_str()
                .is_some_and(|file| file.starts_with("rs256-"))
            && key["retire_at"].is_null()),
        "RS256 must be available for clients relying on the OpenID Connect default id_token alg"
    );
    assert!(
        keyset.jwks()["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key["alg"] == "RS256")
    );
    assert_eq!(
        keyset.response_signing_alg_values_supported(),
        vec!["RS256", "PS256"]
    );
    assert!(
        keyset
            .local_response_signing_key(jsonwebtoken::Algorithm::RS256)
            .is_some(),
        "the backfilled RS256 private key must remain available in the loaded snapshot"
    );
}

#[tokio::test]
async fn duplicate_keyset_kids_are_rejected() {
    let keys_dir = temp_keys_dir("duplicate_kid");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let first_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    let second_der = ed25519_pkcs8_private_der(&[2u8; 32]);
    tokio::fs::write(
        keys_dir.join("first.pem"),
        der_to_pem(&first_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("second.pem"),
        der_to_pem(&second_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "duplicate",
            "keys": [
                {"kid": "duplicate", "file": "first.pem", "retire_at": null},
                {"kid": "duplicate", "file": "second.pem", "retire_at": null}
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let result = try_load_keyset(&settings, &keyset_path).await;
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    match result {
        Ok(_) => panic!("duplicate keyset kid should be rejected"),
        Err(error) => assert!(format!("{error:#}").contains("duplicate kid duplicate")),
    }
}

#[tokio::test]
async fn live_previous_key_entry_must_load_successfully() {
    let keys_dir = temp_keys_dir("missing_previous");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    tokio::fs::write(
        keys_dir.join("active.pem"),
        der_to_pem(&active_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [
                {"kid": "active", "file": "active.pem", "retire_at": null},
                {"kid": "previous", "file": "missing.pem", "retire_at": null}
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let result = try_load_keyset(&settings, &keyset_path).await;
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn retired_previous_key_entry_is_skipped() {
    let keys_dir = temp_keys_dir("retired_previous");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    tokio::fs::write(
        keys_dir.join("active.pem"),
        der_to_pem(&active_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [
                {"kid": "active", "file": "active.pem", "retire_at": null},
                {
                    "kid": "previous",
                    "file": "missing.pem",
                    "retire_at": "2000-01-01T00:00:00Z"
                }
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let keyset = try_load_keyset(&settings, &keyset_path)
        .await
        .unwrap()
        .unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert_eq!(keyset.active_kid, "active");
    assert_eq!(keyset.verification_keys.len(), 1);
}

#[tokio::test]
async fn malformed_retire_at_in_keyset_fails_closed() {
    let keys_dir = temp_keys_dir("malformed_retire_at");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    let previous_der = ed25519_pkcs8_private_der(&[2u8; 32]);
    tokio::fs::write(
        keys_dir.join("active.pem"),
        der_to_pem(&active_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("previous.pem"),
        der_to_pem(&previous_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [
                {"kid": "active", "file": "active.pem", "retire_at": null},
                {"kid": "previous", "file": "previous.pem", "retire_at": "not-rfc3339"}
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let error = match try_load_keyset(&settings, &keyset_path).await {
        Ok(_) => panic!("malformed key retirement metadata must fail closed"),
        Err(error) => error,
    };
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert!(
        format!("{error:#}").contains("retire_at"),
        "unexpected malformed retire_at error: {error:#}"
    );
}

#[tokio::test]
async fn retired_active_key_entry_is_rejected() {
    let keys_dir = temp_keys_dir("retired_active");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    tokio::fs::write(
        keys_dir.join("active.pem"),
        der_to_pem(&active_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [
                {
                    "kid": "active",
                    "file": "active.pem",
                    "retire_at": "2000-01-01T00:00:00Z"
                }
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let result = try_load_keyset(&settings, &keyset_path).await;
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn active_key_with_future_retirement_metadata_is_rejected() {
    let keys_dir = temp_keys_dir("active_future_retire_at");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    tokio::fs::write(
        keys_dir.join("active.pem"),
        der_to_pem(&active_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [
                {
                    "kid": "active",
                    "file": "active.pem",
                    "retire_at": "2999-01-01T00:00:00Z"
                }
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let error = match try_load_keyset(&settings, &keyset_path).await {
        Ok(_) => panic!("active signing key must not carry retirement metadata"),
        Err(error) => error,
    };
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert!(
        format!("{error:#}").contains("active key active cannot have retire_at"),
        "unexpected active-key retirement error: {error:#}"
    );
}

#[tokio::test]
async fn active_kid_must_reference_a_live_signing_key() {
    let keys_dir = temp_keys_dir("active_missing");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let previous_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    tokio::fs::write(
        keys_dir.join("previous.pem"),
        der_to_pem(&previous_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "missing-active",
            "keys": [
                {"kid": "previous", "file": "previous.pem", "retire_at": null}
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let error = match try_load_keyset(&settings, &keyset_path).await {
        Ok(_) => panic!("active_kid must identify the live signing key"),
        Err(error) => error,
    };
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert!(
        format!("{error:#}").contains("active_kid does not reference a live key"),
        "unexpected active kid error: {error:#}"
    );
}

#[tokio::test]
async fn local_key_entry_rejects_invalid_pem_and_algorithm_mismatch() {
    let cases = [
        (
            "invalid_pem",
            "not a pem".to_owned(),
            jsonwebtoken::Algorithm::EdDSA,
            "not valid PEM",
        ),
        (
            "algorithm_mismatch",
            der_to_pem(&ed25519_pkcs8_private_der(&[3u8; 32]), "PRIVATE KEY"),
            jsonwebtoken::Algorithm::RS256,
            "private key does not match alg",
        ),
    ];

    for (label, pem, alg, expected) in cases {
        let keys_dir = temp_keys_dir(label);
        tokio::fs::create_dir_all(&keys_dir).await.unwrap();
        tokio::fs::write(keys_dir.join("active.pem"), pem)
            .await
            .unwrap();
        tokio::fs::write(
            keys_dir.join("keyset.json"),
            serde_json::to_string_pretty(&json!({
                "active_kid": "active",
                "keys": [{
                    "kid": "active",
                    "alg": signing_algorithm_name(alg).unwrap(),
                    "file": "active.pem",
                    "retire_at": null
                }]
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let settings = test_settings(keys_dir.clone());
        let keyset_path = keys_dir.join("keyset.json");

        let error = match try_load_keyset(&settings, &keyset_path).await {
            Ok(_) => panic!("invalid local signing material must fail closed"),
            Err(error) => error,
        };
        let _ = tokio::fs::remove_dir_all(&keys_dir).await;

        assert!(
            format!("{error:#}").contains(expected),
            "unexpected local key error for {label}: {error:#}"
        );
    }
}

#[tokio::test]
async fn active_external_command_key_requires_signer_command() {
    let keys_dir = temp_keys_dir("external_missing_command");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .unwrap()
        .private_pkcs8_der;
    let public_jwk = public_jwk_from_private_der(
        "external-active",
        jsonwebtoken::Algorithm::RS256,
        &active_der,
    )
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "external-active",
            "keys": [{
                "kid": "external-active",
                "alg": "RS256",
                "backend": "external-command",
                "key_ref": "kms://tenant/signing/external-active",
                "public_jwk": public_jwk,
                "retire_at": null
            }]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let result = try_load_keyset(&settings, &keyset_path).await;
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    match result {
        Ok(_) => panic!("active external-command key without command should fail"),
        Err(error) => assert!(format!("{error:#}").contains("SIGNING_EXTERNAL_COMMAND")),
    }
}

#[tokio::test]
async fn external_public_jwk_metadata_is_bound_to_keyset_entry() {
    let active_der = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .unwrap()
        .private_pkcs8_der;
    let mut public_jwk = public_jwk_from_private_der(
        "external-active",
        jsonwebtoken::Algorithm::RS256,
        &active_der,
    )
    .unwrap();
    let object = public_jwk.as_object_mut().unwrap();
    object.remove("kid");
    object.remove("alg");
    object.remove("use");

    let inherited = external_public_jwk(&json!({
        "kid": "external-active",
        "alg": "RS256",
        "public_jwk": public_jwk
    }))
    .unwrap();
    assert_eq!(inherited["kid"], "external-active");
    assert_eq!(inherited["alg"], "RS256");
    assert_eq!(inherited["use"], "sig");

    for (label, public_jwk, expected) in [
        (
            "kid_mismatch",
            json!({"kid": "other", "alg": "RS256", "use": "sig"}),
            "kid does not match",
        ),
        (
            "alg_mismatch",
            json!({"kid": "external-active", "alg": "PS256", "use": "sig"}),
            "alg does not match",
        ),
        (
            "wrong_use",
            json!({"kid": "external-active", "alg": "RS256", "use": "enc"}),
            "use must be sig",
        ),
    ] {
        let error = external_public_jwk(&json!({
            "kid": "external-active",
            "alg": "RS256",
            "public_jwk": public_jwk
        }))
        .expect_err("external public JWK metadata must match the keyset entry");
        assert!(
            format!("{error:#}").contains(expected),
            "unexpected external public JWK error for {label}: {error:#}"
        );
    }
}

#[tokio::test]
async fn external_public_jwk_rejects_private_or_symmetric_key_material() {
    for private_member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let mut public_jwk = json!({
            "kty": "RSA",
            "kid": "external-active",
            "alg": "RS256",
            "use": "sig",
            "n": "modulus",
            "e": "AQAB"
        });
        public_jwk[private_member] = json!("secret");

        let error = external_public_jwk(&json!({
            "kid": "external-active",
            "alg": "RS256",
            "public_jwk": public_jwk
        }))
        .expect_err("private JWK members must not be accepted for public JWKS publication");

        assert!(
            format!("{error:#}").contains("private or symmetric key material"),
            "unexpected external public JWK error for {private_member}: {error:#}"
        );
    }
}

#[tokio::test]
async fn external_command_signer_produces_verifiable_jwt() {
    let keys_dir = temp_keys_dir("external_signer");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .unwrap()
        .private_pkcs8_der;
    let private_pem = der_to_pem(&active_der, "RSA PRIVATE KEY");
    let public_jwk = public_jwk_from_private_der(
        "external-active",
        jsonwebtoken::Algorithm::RS256,
        &active_der,
    )
    .unwrap();
    let private_key_path = keys_dir.join("external-active.pem");
    tokio::fs::write(&private_key_path, &private_pem)
        .await
        .unwrap();
    let signer_command = external_rsa_signer_command(&keys_dir, &private_key_path).await;
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "external-active",
            "keys": [{
                "kid": "external-active",
                "alg": "RS256",
                "backend": "external-command",
                "key_ref": "test-ed25519",
                "public_jwk": public_jwk,
                "retire_at": null
            }]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let mut settings = test_settings(keys_dir.clone());
    settings.signing_external_command = signer_command;
    let keyset_path = keys_dir.join("keyset.json");
    let keyset = try_load_keyset(&settings, &keyset_path)
        .await
        .unwrap()
        .unwrap();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("external-active".to_owned());
    let claims = json!({"sub": "subject-1", "exp": 4_102_444_800_i64});

    let token = keyset.sign_jwt(&header, &claims).await.unwrap();
    let decoding_key =
        crate::support::jwt_decoding_key_from_jwk(&keyset.jwks()["keys"][0], header.alg).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_exp = false;
    let decoded = jsonwebtoken::decode::<Value>(&token, &decoding_key, &validation).unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert_eq!(decoded.claims["sub"], "subject-1");
}

#[tokio::test]
async fn external_command_signer_signature_must_match_active_public_jwk() {
    let keys_dir = temp_keys_dir("external_signer_bad_signature");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .unwrap()
        .private_pkcs8_der;
    let wrong_der = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .unwrap()
        .private_pkcs8_der;
    let wrong_private_pem = der_to_pem(&wrong_der, "RSA PRIVATE KEY");
    let public_jwk = public_jwk_from_private_der(
        "external-active",
        jsonwebtoken::Algorithm::RS256,
        &active_der,
    )
    .unwrap();
    let wrong_private_key_path = keys_dir.join("wrong-external-active.pem");
    tokio::fs::write(&wrong_private_key_path, &wrong_private_pem)
        .await
        .unwrap();
    let signer_command = external_rsa_signer_command(&keys_dir, &wrong_private_key_path).await;
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "external-active",
            "keys": [{
                "kid": "external-active",
                "alg": "RS256",
                "backend": "external-command",
                "key_ref": "kms://tenant/signing/external-active",
                "public_jwk": public_jwk,
                "retire_at": null
            }]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let mut settings = test_settings(keys_dir.clone());
    settings.signing_external_command = signer_command;
    let keyset_path = keys_dir.join("keyset.json");
    let keyset = try_load_keyset(&settings, &keyset_path)
        .await
        .unwrap()
        .unwrap();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("external-active".to_owned());
    let claims = json!({"sub": "subject-1", "exp": 4_102_444_800_i64});

    let result = keyset.sign_jwt(&header, &claims).await;
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    match result {
        Ok(_) => panic!("external signer signature mismatch should fail"),
        Err(error) => assert!(format!("{error}").contains("does not verify")),
    }
}

#[test]
fn key_material_helpers_reject_unsupported_or_malformed_inputs() {
    assert!(generate_key_material(jsonwebtoken::Algorithm::HS256).is_err());
    assert!(
        public_jwk_from_private_der("kid", jsonwebtoken::Algorithm::EdDSA, b"not-ed25519-pkcs8")
            .is_err()
    );
    assert!(
        public_jwk_from_private_der(
            "kid",
            jsonwebtoken::Algorithm::HS256,
            &ed25519_pkcs8_private_der(&[4u8; 32])
        )
        .is_err()
    );
    assert!(
        pem_to_der("-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----").is_none()
    );
}

#[tokio::test]
async fn sign_jwt_requires_active_algorithm_and_kid() {
    let active_der = ed25519_pkcs8_private_der(&[5u8; 32]);
    let keyset = Keyset {
        active_kid: "active".to_owned(),
        active_alg: jsonwebtoken::Algorithm::EdDSA,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(active_der),
        verification_keys: Vec::new(),
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("active".to_owned());

    let error = keyset
        .sign_jwt(&header, &json!({"sub": "subject-1"}))
        .await
        .expect_err("JWT signing must reject headers that do not match the active key");

    assert!(matches!(
        error.kind(),
        jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
    ));
}

#[tokio::test]
async fn local_signing_rejects_algorithms_outside_server_allowlist() {
    let keyset = Keyset {
        active_kid: "active".to_owned(),
        active_alg: jsonwebtoken::Algorithm::HS256,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(vec![1, 2, 3]),
        verification_keys: Vec::new(),
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("active".to_owned());

    let error = keyset
        .sign_jwt(&header, &json!({"sub": "subject-1"}))
        .await
        .expect_err("local JWT signing must reject symmetric algorithms");

    assert!(matches!(
        error.kind(),
        jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
    ));
}

fn temp_keys_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "nazo_keyset_{label}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[cfg(unix)]
async fn external_rsa_signer_command(keys_dir: &Path, private_key_path: &Path) -> Vec<String> {
    let signer = keys_dir.join("signer.sh");
    tokio::fs::write(
        &signer,
        r#"#!/bin/sh
set -eu
key_file="$1"
request=$(cat)
signing_input=$(printf '%s' "$request" | sed -n 's/.*"signing_input":"\([^"]*\)".*/\1/p')
signature=$(printf '%s' "$signing_input" | openssl dgst -sha256 -sign "$key_file" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
printf '{"signature":"%s"}' "$signature"
"#,
    )
    .await
    .unwrap();
    vec![
        "sh".to_owned(),
        signer.display().to_string(),
        private_key_path.display().to_string(),
    ]
}

#[cfg(windows)]
async fn external_rsa_signer_command(keys_dir: &Path, private_key_path: &Path) -> Vec<String> {
    let signer = keys_dir.join("signer.ps1");
    tokio::fs::write(
        &signer,
        r#"$ErrorActionPreference = 'Stop'
$keyFile = $args[0]
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$inputPath = [System.IO.Path]::GetTempFileName()
$signaturePath = [System.IO.Path]::GetTempFileName()
try {
  [System.IO.File]::WriteAllText($inputPath, [string]$request.signing_input, [System.Text.Encoding]::ASCII)
  & openssl dgst -sha256 -sign $keyFile -binary -out $signaturePath $inputPath | Out-Null
  $signature = (& openssl base64 -A -in $signaturePath).Trim().Replace('+', '-').Replace('/', '_').TrimEnd('=')
  [Console]::Out.Write("{""signature"":""$signature""}")
} finally {
  Remove-Item -LiteralPath $inputPath, $signaturePath -ErrorAction SilentlyContinue
}
"#,
    )
    .await
    .unwrap();
    vec![
        "pwsh".to_owned(),
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-File".to_owned(),
        signer.display().to_string(),
        private_key_path.display().to_string(),
    ]
}

async fn write_local_key_entry(
    keys_dir: &Path,
    _kid: &str,
    alg: &str,
    file_name: &str,
    _created_at: DateTime<Utc>,
) {
    let alg = signing_algorithm_from_name(alg).unwrap();
    let private_pkcs8_der = generate_key_material(alg).unwrap().private_pkcs8_der;
    tokio::fs::write(
        keys_dir.join(file_name),
        der_to_pem(&private_pkcs8_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn test_settings(jwk_keys_dir: PathBuf) -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://issuer.example".to_owned(),
        frontend_base_url: "https://frontend.example".to_owned(),
        cors_allowed_origins: vec!["https://frontend.example".to_owned()],
        default_audience: "resource://default".to_owned(),
        protected_resource_identifier: "https://issuer.example/fapi/resource".to_owned(),
        authorization_server_profile: crate::settings::AuthorizationServerProfile::Oauth2Baseline,
        ciba_security_profile:
            crate::settings::CibaSecurityProfile::FapiCibaId1PlainPrivateKeyJwtPoll,
        dpop_nonce_policy: crate::settings::DpopNoncePolicy::Required,
        request_object_jti_policy: crate::settings::RequestObjectJtiPolicy::Optional,
        session_cookie_name: "session".to_owned(),
        csrf_cookie_name: "csrf".to_owned(),
        cookie_secure: true,
        session_ttl_seconds: 28_800,
        auth_code_ttl_seconds: 300,
        access_token_ttl_seconds: 300,
        id_token_ttl_seconds: 600,
        refresh_token_ttl_seconds: 2_592_000,
        avatar_max_bytes: 2_097_152,
        client_delivery_ttl_seconds: 86_400,
        client_secret_pepper: "client-secret-pepper-for-tests-000000000001".to_owned(),
        rate_limit: RateLimitSettings {
            window_seconds: 60,
            auth_max_requests: 30,
            token_max_requests: 60,
            token_management_max_requests: 120,
            login_failure_window_seconds: 900,
            login_failure_email_max_attempts: 50,
            login_failure_ip_email_max_attempts: 5,
        },
        email: EmailSettings {
            delivery: EmailDelivery::Disabled,
            code_ttl_seconds: 900,
            send_cooldown_seconds: 60,
            send_peer_cooldown_seconds: 5,
        },
        email_code_dev_response_enabled: false,
        avatar_storage_dir: jwk_keys_dir.join("avatars"),
        jwk_keys_dir,
        signing_external_command: Vec::new(),
        signing_external_timeout_ms: 2_000,
        signing_key_rotation_interval_seconds: 7_776_000,
        signing_key_prepublish_seconds: 86_400,
        trusted_proxy_cidrs: Vec::new(),
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: crate::settings::SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: false,
        scim_bearer_token: None,
        passkey: crate::settings::PasskeySettings {
            rp_id: "issuer.example".to_owned(),
            rp_name: "Nazo OAuth".to_owned(),
            origin: "https://issuer.example".to_owned(),
            require_user_verification: true,
            require_user_handle: true,
            strict_base64: true,
        },
        federation: crate::settings::FederationSettings {
            providers: crate::settings::FederationProviderRegistry::default(),
            saml_gateway: None,
        },
        enable_request_object: false,
        enable_request_uri_parameter: false,
        enable_par_request_object: false,
        enable_authorization_details: false,
        enable_legacy_audience_param: false,
        enable_device_authorization_grant: false,
        enable_dynamic_client_registration: false,
        enable_frontchannel_logout: false,
        enable_session_management: false,
        enable_ciba: false,
        enable_native_sso: false,
        dynamic_client_registration_initial_access_token: None,
        device_authorization_ttl_seconds: 600,
        device_authorization_poll_interval_seconds: 5,
        ciba_auth_req_id_ttl_seconds: 600,
        ciba_poll_interval_seconds: 5,
        ciba_automated_decision_token: None,
    }
}
