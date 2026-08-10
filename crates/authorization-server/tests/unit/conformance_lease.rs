use super::*;

#[test]
fn built_in_conformance_matrix_is_the_authoritative_44_plan_descriptor() {
    let descriptor = load_matrix_descriptor().expect("built-in matrix must validate");
    assert_eq!(descriptor.groups.len(), 11);
    assert_eq!(
        descriptor
            .groups
            .iter()
            .map(|group| group.plans.len())
            .sum::<usize>(),
        44
    );
    assert_eq!(
        descriptor
            .groups
            .iter()
            .map(|group| group.plans.len())
            .sum::<usize>(),
        44
    );
    assert_eq!(
        descriptor
            .groups
            .iter()
            .filter(|group| group.profile != "openid4vc")
            .map(|group| group.plans.len())
            .sum::<usize>(),
        27
    );
    assert_eq!(
        descriptor
            .groups
            .iter()
            .filter(|group| group.profile == "openid4vc")
            .map(|group| group.plans.len())
            .sum::<usize>(),
        17
    );
    let encoded = serde_json::to_string(&descriptor).expect("matrix serialization");
    let value: serde_json::Value = serde_json::from_str(&encoded).expect("matrix JSON");
    assert!(encoded.contains("{{generated.dynamic_registration_initial_access_token}}"));
    assert!(encoded.contains("{{generated.ciba_automated_decision_token}}"));
    assert!(!encoded.contains("$secret"));
    assert_no_embedded_sensitive_values(&value);
}

fn assert_no_embedded_sensitive_values(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                if matches!(
                    key.as_str(),
                    "password"
                        | "token"
                        | "access_token"
                        | "refresh_token"
                        | "password_hash"
                        | "client_secret"
                        | "private_key"
                        | "private_jwk"
                        | "d"
                        | "p"
                        | "q"
                        | "dp"
                        | "dq"
                        | "qi"
                        | "oth"
                        | "k"
                ) {
                    assert!(
                        child
                            .as_str()
                            .is_some_and(|text| { text.starts_with("{{") && text.ends_with("}}") }),
                        "sensitive descriptor value must be a placeholder"
                    );
                }
                assert_no_embedded_sensitive_values(child);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                assert_no_embedded_sensitive_values(child);
            }
        }
        _ => {}
    }
}

fn database_is_available() -> bool {
    if std::env::var_os("DATABASE_URL").is_some() {
        true
    } else if std::env::var_os("CI").is_some() {
        panic!("CI requires DATABASE_URL for conformance lease lifecycle coverage")
    } else {
        false
    }
}

#[tokio::test]
async fn operator_lifecycle_uses_the_authoritative_tenant_lease() {
    if !database_is_available() {
        return;
    }
    let nonce = Uuid::now_v7().simple().to_string();
    let profile = format!("coverage-{nonce}");
    let material_sha256 = format!("{nonce}{nonce}");
    let created = operator_create(&profile, &material_sha256, None, None, None, 60)
        .await
        .unwrap();
    let lease_id = match created {
        TaskResult::ConformanceLeaseCreated { lease } => {
            assert_eq!(lease.profile, profile);
            assert_eq!(lease.material_sha256, material_sha256);
            assert!(lease.expires_at > lease.created_at);
            assert!(lease.revoked_at.is_none());
            assert!(lease.cleaned_at.is_none());
            lease.lease_id
        }
        other => panic!("unexpected create result: {other:?}"),
    };

    let leases = match operator_list().await.unwrap() {
        TaskResult::ConformanceLeaseList { leases } => leases,
        other => panic!("unexpected list result: {other:?}"),
    };
    assert!(leases.iter().any(|lease| lease.lease_id == lease_id));

    let revoked = operator_revoke(&lease_id).await.unwrap();
    assert_eq!(
        revoked,
        TaskResult::ConformanceLeaseRevoked {
            lease_id: lease_id.clone(),
            deactivated_clients: 0,
        }
    );
    assert!(matches!(
        operator_cleanup().await.unwrap(),
        TaskResult::ConformanceLeaseCleaned { .. }
    ));

    let leases = match operator_list().await.unwrap() {
        TaskResult::ConformanceLeaseList { leases } => leases,
        other => panic!("unexpected final list result: {other:?}"),
    };
    let tombstone = leases
        .iter()
        .find(|lease| lease.lease_id == lease_id)
        .unwrap();
    assert!(tombstone.revoked_at.is_some());
    assert!(tombstone.cleaned_at.is_some());
}

#[tokio::test]
async fn operator_rejects_invalid_identifiers_and_ttl_overflow() {
    assert!(operator_revoke("not-a-uuid").await.is_err());
    assert!(
        operator_create(
            "oidf-full",
            &"a".repeat(64),
            Some(&"b".repeat(64)),
            None,
            None,
            60,
        )
        .await
        .is_err()
    );
    assert!(
        operator_create(
            "oidc-fapi-ciba",
            &"a".repeat(64),
            Some(&"B".repeat(64)),
            None,
            None,
            60,
        )
        .await
        .is_err()
    );
    assert!(
        operator_create(
            "oidc-fapi-ciba",
            &"a".repeat(64),
            None,
            Some(&"C".repeat(64)),
            None,
            60,
        )
        .await
        .is_err()
    );
    if database_is_available() {
        assert!(
            operator_create(
                "coverage-overflow",
                &"a".repeat(64),
                None,
                None,
                None,
                u64::MAX,
            )
            .await
            .is_err()
        );
    }
}
