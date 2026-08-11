use super::*;

use nazo_auth::{
    AdminClientFuture, AdminClientPortError, AdminClientRepositoryPort, OAuthClient,
    SectorIdentifierFuture, SectorIdentifierResolverPort,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

#[test]
fn empty_optional_mtls_selectors_do_not_require_a_trust_anchor() {
    let baseline = serde_json::json!({
        "token_endpoint_auth_method": "client_secret_basic",
        "require_mtls_bound_tokens": false,
        "tls_client_auth_subject_dn": null,
        "tls_client_auth_cert_sha256": null,
        "tls_client_auth_san_dns": [],
        "tls_client_auth_san_uri": [],
        "tls_client_auth_san_ip": [],
        "tls_client_auth_san_email": []
    });
    assert!(!registration_requires_mtls_anchor(&baseline));

    let mut mtls = baseline.clone();
    mtls["require_mtls_bound_tokens"] = serde_json::json!(true);
    assert!(registration_requires_mtls_anchor(&mtls));

    let mut san_bound = baseline;
    san_bound["tls_client_auth_san_dns"] = serde_json::json!(["client.example"]);
    assert!(registration_requires_mtls_anchor(&san_bound));
}

#[cfg(unix)]
fn secure_material_fixture(name: &str, mode: u32) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!("nazoauth-{name}-{}", Uuid::now_v7()));
    fs::create_dir(&directory).expect("create secure material directory");
    let path = directory.join("material.json");
    fs::write(&path, b"{}\n").expect("write secure material");
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("set secure material mode");
    path
}

#[cfg(unix)]
#[test]
fn secure_material_accepts_owner_and_service_group_read_only_modes() {
    for mode in [0o400, 0o440] {
        let path = secure_material_fixture("accepted-mode", mode);
        let metadata = fs::metadata(&path).expect("material metadata");
        assert_eq!(metadata.gid(), rustix::process::getegid().as_raw());
        assert_eq!(read_fixed_material(&path, 16).unwrap(), b"{}\n");
        fs::remove_dir_all(path.parent().unwrap()).expect("remove fixture");
    }
}

#[cfg(unix)]
#[test]
fn secure_material_rejects_broad_permissions_and_hard_links() {
    let broad = secure_material_fixture("broad-mode", 0o640);
    assert!(read_fixed_material(&broad, 16).is_err());
    fs::remove_dir_all(broad.parent().unwrap()).expect("remove broad fixture");

    let linked = secure_material_fixture("hard-link", 0o400);
    fs::hard_link(&linked, linked.with_extension("alias")).expect("create hard link");
    assert!(read_fixed_material(&linked, 16).is_err());
    fs::remove_dir_all(linked.parent().unwrap()).expect("remove linked fixture");
}

#[cfg(unix)]
#[test]
fn fixed_policy_secret_accepts_owner_only_source_without_weakening_bundle_mode() {
    let path = secure_material_fixture("owner-secret", 0o600);
    assert!(read_fixed_material(&path, 16).is_err());
    assert_eq!(
        read_fixed_secret_string(&path, "policy secret").unwrap(),
        "{}"
    );
    fs::remove_dir_all(path.parent().unwrap()).expect("remove owner secret fixture");
}

#[test]
fn built_in_conformance_matrix_is_the_authoritative_44_plan_descriptor() {
    let descriptor = load_matrix_descriptor().expect("built-in matrix must validate");
    assert_eq!(descriptor.groups.len(), 11);
    assert!(
        descriptor
            .groups
            .iter()
            .all(|group| group.variant.values.is_empty()),
        "presentation-only group variants must not leak into official Suite requests"
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
    assert!(descriptor_requires_reference(
        &descriptor,
        "generated.dynamic_registration_initial_access_token"
    ));
    assert!(!descriptor_requires_reference(
        &descriptor,
        "generated.ciba_automated_decision_token"
    ));
    assert!(descriptor_requires_reference(
        &descriptor,
        "target.ciba_automated_decision_url"
    ));
    assert!(!encoded.contains("$secret"));
    assert_no_embedded_sensitive_values(&value);
    for group in &descriptor.groups {
        for plan in &group.plans {
            for role in group.required_roles.iter().chain(&plan.required_roles) {
                let Some(template) = role.registration_template.as_ref() else {
                    continue;
                };
                let mut deserializable = template.clone();
                if deserializable
                    .get("jwks")
                    .is_some_and(serde_json::Value::is_string)
                {
                    deserializable["jwks"] = serde_json::json!({ "keys": [] });
                }
                serde_json::from_value::<nazo_auth::CreateClientRequest>(deserializable)
                    .unwrap_or_else(|error| {
                        panic!(
                            "{} / {} / {} is not a CreateClientRequest: {error}",
                            group.id, plan.id, role.role
                        )
                    });
                let scopes = template["scopes"]
                    .as_array()
                    .expect("registration scopes must be an array");
                let grants = template["grant_types"]
                    .as_array()
                    .expect("registration grant_types must be an array");
                if scopes.iter().any(|scope| scope == "offline_access") {
                    assert!(
                        grants.iter().any(|grant| grant == "refresh_token"),
                        "{} / {} / {} enables offline_access without refresh_token",
                        group.id,
                        plan.id,
                        role.role
                    );
                }
                if template
                    .get("backchannel_authentication_request_signing_alg")
                    .is_some_and(|value| !value.is_null())
                {
                    assert!(
                        template.get("jwks").is_some_and(|value| !value.is_null()),
                        "{} / {} / {} signs CIBA requests without a client JWKS",
                        group.id,
                        plan.id,
                        role.role
                    );
                }
                for grant in grants.iter().filter_map(serde_json::Value::as_str) {
                    assert_ne!(
                        grant, "urn:openid:params:oauth:grant-type:ciba",
                        "{} / {} / {} uses the non-canonical CIBA grant URI",
                        group.id, plan.id, role.role
                    );
                }
            }
        }
    }
}

#[test]
fn onboarding_mapping_preserves_the_public_oauth_client_id() {
    let mappings = map_persistence_client_mappings(vec![nazo_postgres::ConformanceClientMapping {
        logical_client_id: "fapi-rp".to_owned(),
        client_id: "client-fapi-rp".to_owned(),
    }]);

    assert_eq!(
        mappings,
        vec![("fapi-rp".to_owned(), "client-fapi-rp".to_owned())]
    );
}

#[derive(Clone, Copy)]
struct UnusedClientRepository;

impl AdminClientRepositoryPort for UnusedClientRepository {
    fn page(&self, _offset: i64, _limit: i64) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)> {
        Box::pin(async { Err(AdminClientPortError::Unexpected) })
    }

    fn by_client_id<'a>(
        &'a self,
        _tenant_id: Uuid,
        _client_id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>> {
        Box::pin(async { Err(AdminClientPortError::Unexpected) })
    }

    fn insert<'a>(
        &'a self,
        _client: &'a OAuthClient,
        _client_secret_hash: Option<&'a str>,
        _registration_access_token_blake3: Option<&'a str>,
        _conformance_lease_id: Option<Uuid>,
    ) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async { Err(AdminClientPortError::Unexpected) })
    }

    fn update<'a>(&'a self, _client: &'a OAuthClient) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async { Err(AdminClientPortError::Unexpected) })
    }
}

#[derive(Clone, Copy)]
struct UnusedSectorIdentifierResolver;

impl SectorIdentifierResolverPort for UnusedSectorIdentifierResolver {
    fn resolve<'a>(&'a self, _uri: &'a str) -> SectorIdentifierFuture<'a> {
        Box::pin(async { Err("unexpected sector identifier lookup".to_owned()) })
    }
}

fn materialize_registration_fixture(
    value: &mut serde_json::Value,
    rsa_jwks: &serde_json::Value,
    ec_jwks: &serde_json::Value,
) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                materialize_registration_fixture(value, rsa_jwks, ec_jwks);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                materialize_registration_fixture(value, rsa_jwks, ec_jwks);
            }
        }
        serde_json::Value::String(text) if text.starts_with("{{client.") => {
            if text.ends_with(".rsa.public_jwks}}") {
                *value = rsa_jwks.clone();
            } else if text.ends_with(".ec.public_jwks}}") {
                *value = ec_jwks.clone();
            } else if text.ends_with(".mtls.cert_sha256}}") {
                *text = "a".repeat(64);
            } else {
                panic!("unsupported client registration placeholder: {text}");
            }
        }
        serde_json::Value::String(text) if text == "{{target.issuer}}" => {
            *text = "https://server.example".to_owned();
        }
        serde_json::Value::String(text) if text.starts_with("{{target.url.") => {
            let path = text
                .strip_prefix("{{target.url.")
                .and_then(|value| value.strip_suffix("}}"))
                .expect("target URL placeholder");
            *text = format!("https://server.example{path}");
        }
        serde_json::Value::String(text)
            if text.starts_with("{{suite.test.") || text.starts_with("{{suite.test_query.") =>
        {
            *text = "https://suite.example/test/a/callback".to_owned();
        }
        serde_json::Value::String(text) if text.starts_with("{{") => {
            panic!("unsupported registration placeholder: {text}");
        }
        _ => {}
    }
}

#[actix_web::test]
async fn built_in_registration_templates_pass_the_real_admin_policy() {
    let descriptor = load_matrix_descriptor().expect("built-in matrix must validate");
    let rsa = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let ec = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let rsa_jwks = serde_json::json!({"keys": [rsa.public_jwk("matrix-rsa")]});
    let ec_jwks = serde_json::json!({"keys": [ec.public_jwk("matrix-ec")]});
    let service = nazo_auth::AdminClientService::new(
        UnusedClientRepository,
        UnusedSectorIdentifierResolver,
        crate::http::admin::clients::ServerAdminClientCrypto::for_policy_validation(),
        nazo_auth::AdminClientPolicy {
            tenant: nazo_identity::TenantContext::default_system(),
            pairwise_subject_secret: Some("test-pairwise-subject-secret".to_owned()),
            client_secret_pepper: "test-client-secret-pepper".to_owned(),
        },
    );

    for group in &descriptor.groups {
        for plan in &group.plans {
            for role in group.required_roles.iter().chain(&plan.required_roles) {
                let Some(mut template) = role.registration_template.clone() else {
                    continue;
                };
                materialize_registration_fixture(&mut template, &rsa_jwks, &ec_jwks);
                canonicalize_conformance_registration_sets(&mut template)
                    .expect("registration set canonicalization");
                let request = serde_json::from_value(template).unwrap_or_else(|error| {
                    panic!(
                        "{} / {} / {} is not a CreateClientRequest: {error}",
                        group.id, plan.id, role.role
                    )
                });
                service
                    .prepare_registration(request)
                    .await
                    .unwrap_or_else(|error| {
                        panic!(
                            "{} / {} / {} fails admin policy: {error}",
                            group.id, plan.id, role.role
                        )
                    });
            }
        }
    }
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
