use super::*;

use nazo_auth::{
    AdminClientFuture, AdminClientPortError, AdminClientRepositoryPort, OAuthClient,
    SectorIdentifierFuture, SectorIdentifierResolverPort,
};

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

#[test]
fn secret_text_deserializes_and_wipes_owned_material() {
    let secret: SecretText = serde_json::from_value(serde_json::json!("bundle-secret"))
        .expect("secret text deserialization");
    assert_eq!(secret.as_str(), "bundle-secret");

    let mut value = "sensitive-value".to_owned();
    wipe_secret_string(&mut value);
    assert!(value.is_empty());
}

#[test]
fn mtls_registration_selectors_all_require_a_trust_anchor() {
    for request in [
        serde_json::json!({
            "token_endpoint_auth_method": "tls_client_auth"
        }),
        serde_json::json!({
            "token_endpoint_auth_method": "self_signed_tls_client_auth"
        }),
        serde_json::json!({
            "tls_client_auth_subject_dn": "CN=conformance-client"
        }),
        serde_json::json!({
            "tls_client_auth_cert_sha256": "a".repeat(64)
        }),
        serde_json::json!({
            "tls_client_auth_san_dns": ["client.example"]
        }),
        serde_json::json!({
            "tls_client_auth_san_uri": ["spiffe://example.test/client"]
        }),
        serde_json::json!({
            "tls_client_auth_san_ip": ["127.0.0.1"]
        }),
        serde_json::json!({
            "tls_client_auth_san_email": ["client@example.test"]
        }),
    ] {
        assert!(registration_requires_mtls_anchor(&request), "{request}");
    }
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

    let symlinked = secure_material_fixture("symlink", 0o400);
    let target = symlinked.with_extension("target");
    fs::rename(&symlinked, &target).expect("move symlink target");
    std::os::unix::fs::symlink(&target, &symlinked).expect("create secure-material symlink");
    assert!(read_fixed_material(&symlinked, 16).is_err());
    fs::remove_dir_all(symlinked.parent().unwrap()).expect("remove symlink fixture");

    let empty = secure_material_fixture("empty-material", 0o600);
    fs::write(&empty, b"").expect("truncate material");
    fs::set_permissions(&empty, fs::Permissions::from_mode(0o400)).expect("lock empty material");
    assert!(read_fixed_material(&empty, 16).is_err());
    fs::remove_dir_all(empty.parent().unwrap()).expect("remove empty fixture");

    let oversized = secure_material_fixture("oversized-material", 0o600);
    fs::write(&oversized, b"0123456789abcdefg").expect("write oversized material");
    fs::set_permissions(&oversized, fs::Permissions::from_mode(0o400))
        .expect("lock oversized material");
    assert!(read_fixed_material(&oversized, 16).is_err());
    fs::remove_dir_all(oversized.parent().unwrap()).expect("remove oversized fixture");
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

#[cfg(unix)]
#[test]
fn fixed_secret_reader_rejects_empty_control_and_non_utf8_values() {
    let path = secure_material_fixture("invalid-secret", 0o600);
    fs::write(&path, b" \n").expect("write empty secret");
    assert!(read_fixed_secret_string(&path, "policy secret").is_err());
    fs::write(&path, b"valid\0secret\n").expect("write control secret");
    assert!(read_fixed_secret_string(&path, "policy secret").is_err());
    fs::write(&path, [0xff, 0xfe]).expect("write non-UTF8 secret");
    assert!(read_fixed_secret_string(&path, "policy secret").is_err());
    fs::remove_dir_all(path.parent().unwrap()).expect("remove invalid secret fixture");
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
    assert_eq!(descriptor.openid4vc_credential_datasets.len(), 2);
    assert!(
        descriptor
            .openid4vc_credential_datasets
            .get("eu.europa.ec.eudi.pid.1")
            .is_some_and(
                |claims| claims.get("email").and_then(serde_json::Value::as_str)
                    == Some("credential-holder@example.test")
            )
    );
    assert!(
        descriptor
            .openid4vc_credential_datasets
            .get("org.iso.18013.5.1.mDL")
            .is_some_and(|claims| claims
                .get("org.iso.18013.5.1")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|claims| claims.get("document_number")
                    == Some(&serde_json::json!("SPECIMEN-0001"))))
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
fn suite_origin_is_canonical_and_cannot_alias_the_issuer_origin() {
    assert_eq!(
        validate_suite_origin("https://Suite.Example:443/path", "https://issuer.example")
            .expect("suite origin should canonicalize"),
        "https://suite.example"
    );
    assert!(
        validate_suite_origin("https://issuer.example:443", "https://issuer.example/").is_err(),
        "default-port and trailing-slash aliases must not bypass the issuer-origin boundary"
    );
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

fn trust_material_fixture() -> Openid4vcConformanceTrust {
    Openid4vcConformanceTrust {
        schema: 1,
        client_attestation_issuer: "https://suite.example/".to_owned(),
        client_attestation_jwks: serde_json::json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "y": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }]
        }),
        key_attestation_jwks: serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "kid": "holder"
            }]
        }),
        credential_trust_anchor_pem:
            "-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----\n".to_owned(),
    }
}

#[test]
fn conformance_trust_material_is_bound_to_the_suite_origin() {
    let mut material = trust_material_fixture();
    material.client_attestation_issuer = "https://other-suite.example/".to_owned();
    assert!(validate_conformance_trust_material(&material, "https://suite.example").is_err());
}

#[test]
fn conformance_trust_material_rejects_private_or_unsupported_keys() {
    let mut private = trust_material_fixture();
    private.client_attestation_jwks["keys"][0]["d"] = serde_json::json!("private");
    assert!(validate_conformance_trust_material(&private, "https://suite.example").is_err());

    let mut unsupported = trust_material_fixture();
    unsupported.key_attestation_jwks["keys"][0]["kty"] = serde_json::json!("RSA");
    assert!(validate_conformance_trust_material(&unsupported, "https://suite.example").is_err());
}

#[test]
fn checked_in_matrix_pins_one_current_suite_mdoc_ca() {
    let descriptor = load_matrix_descriptor().expect("checked-in Matrix descriptor");
    let anchors = crate::domain::parse_conformance_credential_trust_anchors(
        &descriptor.openid4vc_suite_mdoc_trust_anchor_pem,
    )
    .expect("current Suite mdoc trust anchor");
    assert_eq!(anchors.len(), 1);
}

#[test]
fn matrix_suite_mdoc_anchor_policy_rejects_ambiguous_matrix_pins() {
    let base = load_matrix_descriptor().expect("checked-in Matrix descriptor");
    let mut descriptor = base.clone();
    descriptor.openid4vc_suite_mdoc_trust_anchor_pem = format!(
        "{}\n{}\n",
        base.openid4vc_suite_mdoc_trust_anchor_pem.trim_end(),
        base.openid4vc_suite_mdoc_trust_anchor_pem.trim_end()
    );
    let material = valid_conformance_trust(&base);
    let error = validate_matrix_suite_mdoc_anchor(&material, &descriptor)
        .expect_err("Matrix must pin exactly one Suite mdoc trust anchor");
    assert!(error.to_string().contains("Matrix Suite mdoc trust anchor"));
}

#[test]
fn matrix_suite_mdoc_anchor_policy_requires_exact_membership() {
    let descriptor = load_matrix_descriptor().expect("built-in matrix descriptor");
    let mut material = valid_conformance_trust(&descriptor);
    let unrelated = || {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("unrelated trust key");
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let pem = params
            .self_signed(&key)
            .expect("unrelated trust anchor")
            .pem();
        let pem = pem.replace("\r\n", "\n");
        format!("{}\n", pem.trim_end())
    };
    material.credential_trust_anchor_pem = format!("{}{}", unrelated(), unrelated());
    let error = validate_matrix_suite_mdoc_anchor(&material, &descriptor)
        .expect_err("the trust set must include the exact Matrix Suite anchor");
    assert!(error.to_string().contains("does not contain the Matrix"));
}

#[derive(Clone, Copy)]
struct UnusedClientRepository;

impl AdminClientRepositoryPort for UnusedClientRepository {
    fn page(
        &self,
        _tenant_id: Uuid,
        _offset: i64,
        _limit: i64,
    ) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)> {
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

fn valid_conformance_trust(descriptor: &ConformanceMatrixDescriptor) -> Openid4vcConformanceTrust {
    let key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("deployment trust key");
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let deployment_anchor = params
        .self_signed(&key)
        .expect("deployment trust anchor")
        .pem();
    let deployment_anchor = deployment_anchor.replace("\r\n", "\n");
    let deployment_anchor = format!("{}\n", deployment_anchor.trim_end());
    let client_attestation =
        crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let key_attestation =
        crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let material = Openid4vcConformanceTrust {
        schema: 1,
        client_attestation_issuer: "https://suite.example/".to_owned(),
        client_attestation_jwks: serde_json::json!({
            "keys": [client_attestation.public_jwk("client-attestation")]
        }),
        key_attestation_jwks: serde_json::json!({
            "keys": [key_attestation.public_jwk("key-attestation")]
        }),
        credential_trust_anchor_pem: format!(
            "{}{}\n",
            deployment_anchor,
            descriptor.openid4vc_suite_mdoc_trust_anchor_pem.trim_end()
        ),
    };
    nazo_operator_protocol::validate_openid4vc_conformance_trust(&material)
        .expect("generated conformance trust material");
    material
}

fn onboarding_clients_fixture(
    descriptor: &ConformanceMatrixDescriptor,
) -> Vec<ConformanceClientBundle> {
    let rsa = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let ec = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let rsa_jwks = serde_json::json!({"keys": [rsa.public_jwk("matrix-rsa")]});
    let ec_jwks = serde_json::json!({"keys": [ec.public_jwk("matrix-ec")]});
    let mut clients = BTreeMap::new();

    for group in &descriptor.groups {
        for plan in &group.plans {
            for role in group.required_roles.iter().chain(&plan.required_roles) {
                let Some(mut request) = role.registration_template.clone() else {
                    continue;
                };
                let logical_client_id = role
                    .logical_client_id
                    .as_deref()
                    .unwrap_or(&role.role)
                    .to_owned();
                if clients.contains_key(&logical_client_id) {
                    continue;
                }
                materialize_registration_fixture(&mut request, &rsa_jwks, &ec_jwks);
                let auth_method = request
                    .get("token_endpoint_auth_method")
                    .and_then(serde_json::Value::as_str)
                    .expect("matrix registration auth method");
                let client_secret =
                    matches!(auth_method, "client_secret_basic" | "client_secret_post")
                        .then(|| SecretText(format!("secret-{logical_client_id}")));
                let mtls_trust_anchor_pem = registration_requires_mtls_anchor(&request)
                    .then(|| descriptor.openid4vc_suite_mdoc_trust_anchor_pem.clone());
                clients.insert(
                    logical_client_id.clone(),
                    ConformanceClientBundle {
                        logical_client_id,
                        request,
                        client_secret,
                        mtls_trust_anchor_pem,
                    },
                );
            }
        }
    }

    clients.into_values().collect()
}

fn onboarding_bundle_fixture() -> (SignedOnboardingClaims<'static>, ConformanceOnboardingBundle) {
    const TASK_JTI: &str = "request-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PROFILE: &str = "nazoauth-full";
    const BUNDLE_SHA256: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let descriptor = load_matrix_descriptor().expect("built-in matrix");
    let matrix_sha256 = digest_hex(CONFORMANCE_MATRIX_BYTES);
    let clients = onboarding_clients_fixture(&descriptor);
    let client_count = u32::try_from(clients.len()).expect("bounded client count");
    let claims = SignedOnboardingClaims {
        task_jti: TASK_JTI,
        profile: PROFILE,
        bundle_schema: 3,
        bundle_sha256: BUNDLE_SHA256,
        matrix_sha256: Box::leak(matrix_sha256.clone().into_boxed_str()),
        client_count,
        ttl_seconds: 300,
    };
    let bundle = ConformanceOnboardingBundle {
        schema: 3,
        request_jti: TASK_JTI.to_owned(),
        matrix_sha256,
        profile: PROFILE.to_owned(),
        target_issuer: configured_issuer().expect("configured issuer"),
        suite_base_url: "https://suite.example/test/a/plan".to_owned(),
        openid4vc_conformance_trust: valid_conformance_trust(&descriptor),
        applicant: ConformanceApplicantBundle {
            email: "credential-holder@example.test".to_owned(),
            password: SecretText(format!("bundle-password-{}", Uuid::now_v7())),
        },
        dynamic_registration_initial_access_token: Some(SecretText(
            "dynamic-registration-token".to_owned(),
        )),
        ciba_automated_decision_token: Some(SecretText("ciba-decision-token".to_owned())),
        clients,
        openid4vc_credential_datasets: descriptor.openid4vc_credential_datasets,
    };
    (claims, bundle)
}

#[actix_web::test]
async fn onboarding_bundle_rejects_unknown_runtime_credential_configuration() {
    let (claims, bundle) = onboarding_bundle_fixture();
    let error = validate_bundle(claims, bundle)
        .await
        .err()
        .expect("unknown runtime credential configuration must fail");
    assert!(
        error
            .to_string()
            .contains("conformance credential configuration is unknown"),
        "unexpected credential-configuration error: {error:#}"
    );
}

async fn assert_onboarding_bundle_error(
    claims: SignedOnboardingClaims<'_>,
    bundle: ConformanceOnboardingBundle,
    expected: &str,
) {
    let error = validate_bundle(claims, bundle)
        .await
        .err()
        .expect("invalid onboarding bundle must fail");
    assert!(
        error.to_string().contains(expected),
        "expected {expected:?}, got {error:#}"
    );
}

#[actix_web::test]
async fn onboarding_bundle_rejects_signed_binding_and_secret_material_drift() {
    let (mut claims, bundle) = onboarding_bundle_fixture();
    claims.task_jti = "request-not-hex";
    assert_onboarding_bundle_error(claims, bundle, "idempotency binding is invalid").await;

    let (mut claims, bundle) = onboarding_bundle_fixture();
    claims.bundle_schema = 2;
    assert_onboarding_bundle_error(claims, bundle, "schema does not match").await;

    let (claims, mut bundle) = onboarding_bundle_fixture();
    bundle.request_jti = "request-cccccccccccccccccccccccccccccccc".to_owned();
    assert_onboarding_bundle_error(claims, bundle, "task binding does not match").await;

    let (claims, mut bundle) = onboarding_bundle_fixture();
    bundle.matrix_sha256 = "c".repeat(64);
    assert_onboarding_bundle_error(claims, bundle, "matrix digest does not match").await;

    let (mut claims, bundle) = onboarding_bundle_fixture();
    claims.profile = "unsupported";
    assert_onboarding_bundle_error(claims, bundle, "profile does not match").await;

    let (mut claims, bundle) = onboarding_bundle_fixture();
    claims.bundle_sha256 = "INVALID";
    assert_onboarding_bundle_error(claims, bundle, "bundle digest is invalid").await;

    let (mut claims, mut bundle) = onboarding_bundle_fixture();
    claims.matrix_sha256 = "INVALID";
    bundle.matrix_sha256 = "INVALID".to_owned();
    assert_onboarding_bundle_error(claims, bundle, "matrix digest is invalid").await;

    let (mut claims, bundle) = onboarding_bundle_fixture();
    claims.ttl_seconds = 59;
    assert_onboarding_bundle_error(claims, bundle, "ttl is out of bounds").await;

    let (mut claims, bundle) = onboarding_bundle_fixture();
    claims.client_count = 0;
    assert_onboarding_bundle_error(claims, bundle, "client count does not match").await;

    let (claims, mut bundle) = onboarding_bundle_fixture();
    bundle.target_issuer = "https://different-deployment.example".to_owned();
    assert_onboarding_bundle_error(claims, bundle, "does not match this deployment").await;

    let (claims, mut bundle) = onboarding_bundle_fixture();
    bundle.openid4vc_conformance_trust.client_attestation_issuer =
        "https://different-suite.example/".to_owned();
    assert_onboarding_bundle_error(
        claims,
        bundle,
        "client-attestation issuer does not match the Suite origin",
    )
    .await;

    let (claims, mut bundle) = onboarding_bundle_fixture();
    let descriptor = load_matrix_descriptor().expect("built-in matrix");
    bundle
        .openid4vc_conformance_trust
        .credential_trust_anchor_pem = descriptor.openid4vc_suite_mdoc_trust_anchor_pem;
    assert_onboarding_bundle_error(claims, bundle, "does not contain the Matrix").await;
}

#[actix_web::test]
async fn onboarding_bundle_rejects_unsupported_profile_and_invalid_applicant_password() {
    let (mut claims, mut bundle) = onboarding_bundle_fixture();
    claims.profile = "unsupported";
    bundle.profile = "unsupported".to_owned();
    assert_onboarding_bundle_error(claims, bundle, "profile is not supported").await;

    let (claims, mut bundle) = onboarding_bundle_fixture();
    bundle.applicant.password = SecretText(String::new());
    assert_onboarding_bundle_error(claims, bundle, "applicant password is invalid").await;
}

#[test]
fn onboarding_dataset_policy_rejects_shape_size_secret_and_unknown_configuration() {
    let descriptor = load_matrix_descriptor().expect("built-in matrix");
    let mut empty = descriptor.clone();
    empty.openid4vc_credential_datasets =
        BTreeMap::from([("eu.europa.ec.eudi.pid.1".to_owned(), serde_json::json!({}))]);
    assert!(
        validate_onboarding_credential_datasets(&empty.openid4vc_credential_datasets, &empty)
            .is_err()
    );

    let mut oversized = descriptor.clone();
    oversized.openid4vc_credential_datasets = BTreeMap::from([(
        "eu.europa.ec.eudi.pid.1".to_owned(),
        serde_json::json!({
            "email": "x".repeat(MAX_CONFORMANCE_ONBOARDING_CREDENTIAL_DATASET_BYTES)
        }),
    )]);
    assert!(
        validate_onboarding_credential_datasets(
            &oversized.openid4vc_credential_datasets,
            &oversized
        )
        .is_err()
    );

    let mut secret = descriptor.clone();
    secret.openid4vc_credential_datasets = BTreeMap::from([(
        "eu.europa.ec.eudi.pid.1".to_owned(),
        serde_json::json!({"client_secret": "forbidden"}),
    )]);
    assert!(
        validate_onboarding_credential_datasets(&secret.openid4vc_credential_datasets, &secret)
            .is_err()
    );

    let mut unknown = descriptor;
    unknown.openid4vc_credential_datasets = BTreeMap::from([(
        "unknown-credential".to_owned(),
        serde_json::json!({"claim": "value"}),
    )]);
    assert!(
        validate_onboarding_credential_datasets(&unknown.openid4vc_credential_datasets, &unknown)
            .is_err()
    );
}

#[test]
fn onboarding_dataset_policy_enforces_count_and_total_size_before_runtime_lookup() {
    let descriptor = load_matrix_descriptor().expect("built-in matrix");
    let maximum = usize::try_from(MAX_CONFORMANCE_ONBOARDING_CREDENTIAL_DATASETS)
        .expect("dataset count bound");
    let mut too_many = descriptor.clone();
    too_many.openid4vc_credential_datasets = (0..=maximum)
        .map(|index| {
            (
                format!("credential-{index}"),
                serde_json::json!({"claim": "value"}),
            )
        })
        .collect();
    let error =
        validate_onboarding_credential_datasets(&too_many.openid4vc_credential_datasets, &too_many)
            .expect_err("dataset count must be bounded");
    assert!(error.to_string().contains("count is out of bounds"));

    let mut too_large = descriptor.clone();
    too_large.openid4vc_credential_datasets = (0..maximum)
        .map(|index| {
            (
                format!("credential-{index}"),
                serde_json::json!({"claim": "x".repeat(60_000)}),
            )
        })
        .collect();
    let error = validate_onboarding_credential_datasets(
        &too_large.openid4vc_credential_datasets,
        &too_large,
    )
    .expect_err("dataset total size must be bounded");
    assert!(error.to_string().contains("total size is out of bounds"));

    let mut empty = descriptor;
    empty.openid4vc_credential_datasets = BTreeMap::new();
    validate_onboarding_credential_datasets(&empty.openid4vc_credential_datasets, &empty)
        .expect("empty dataset map has no runtime configuration to validate");
}

#[test]
fn onboarding_scalar_and_registration_validators_cover_closed_policy_boundaries() {
    assert_eq!(
        validate_target_issuer(" http://127.0.0.1:8000/ ").unwrap(),
        "http://127.0.0.1:8000"
    );
    for invalid in [
        "http://example.com",
        "https://user@example.com",
        "https://example.com?query=1",
        "https://example.com#fragment",
        "not-a-url",
    ] {
        assert!(validate_target_issuer(invalid).is_err(), "{invalid}");
    }
    for invalid in [
        "http://suite.example",
        "https://user@suite.example",
        "https://suite.example?query=1",
        "https://suite.example#fragment",
        "not-a-url",
    ] {
        assert!(
            validate_suite_origin(invalid, "https://issuer.example").is_err(),
            "{invalid}"
        );
    }
    for invalid in [
        "",
        "missing-at.example",
        "two@@example.test",
        "local@.example",
        "local@example.",
        "white space@example.test",
    ] {
        assert!(validate_email(invalid).is_err(), "{invalid}");
    }
    assert_eq!(
        validate_email(" holder@example.test ").unwrap(),
        "holder@example.test"
    );
    assert!(validate_secret_text("", "test", 8).is_err());
    assert!(validate_secret_text("too-long", "test", 3).is_err());
    assert!(validate_secret_text("bad\nvalue", "test", 32).is_err());
    assert_eq!(validate_secret_text("valid", "test", 8).unwrap(), "valid");

    let descriptor = load_matrix_descriptor().expect("built-in matrix");
    let mut request = onboarding_clients_fixture(&descriptor)
        .into_iter()
        .next()
        .expect("matrix client")
        .request;
    validate_client_request(&request).expect("matrix client request");
    request["unsupported"] = serde_json::json!(true);
    assert!(validate_client_request(&request).is_err());
    request.as_object_mut().unwrap().remove("unsupported");
    request["client_type"] = serde_json::json!("public");
    assert!(validate_client_request(&request).is_err());
    request["client_type"] = serde_json::json!("confidential");
    request["tls_client_auth_cert_sha256"] = serde_json::json!("not-a-digest");
    assert!(validate_client_request(&request).is_err());
    request["tls_client_auth_cert_sha256"] = serde_json::Value::Null;
    request["tls_client_auth_subject_dn"] = serde_json::json!("x".repeat(4097));
    assert!(validate_client_request(&request).is_err());
    request["tls_client_auth_subject_dn"] = serde_json::Value::Null;
    request["jwks"] = serde_json::json!({"keys": [{"k": "secret"}]});
    assert!(validate_client_request(&request).is_err());

    let oversized_request = serde_json::json!({
        "client_name": "x".repeat(MAX_CONFORMANCE_CLIENT_REQUEST_BYTES),
        "client_type": "confidential",
        "redirect_uris": ["https://client.example/cb"],
        "scopes": ["openid"],
        "allowed_audiences": ["https://issuer.example"],
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "client_secret_basic"
    });
    assert!(validate_client_request(&oversized_request).is_err());
    assert!(validate_client_request(&serde_json::json!([])).is_err());
    assert!(
        validate_client_request(&serde_json::json!({
            "client_type": "confidential"
        }))
        .is_err()
    );

    let mut sets = serde_json::json!({
        "redirect_uris": ["https://client.example/cb", "https://client.example/cb"],
        "scopes": ["openid", "openid"]
    });
    canonicalize_conformance_registration_sets(&mut sets).unwrap();
    assert_eq!(sets["redirect_uris"].as_array().unwrap().len(), 1);
    assert_eq!(sets["scopes"].as_array().unwrap().len(), 1);
    assert!(canonicalize_conformance_registration_sets(&mut serde_json::json!([])).is_err());
    assert!(
        canonicalize_conformance_registration_sets(&mut serde_json::json!({"scopes": "openid"}))
            .is_err()
    );
    assert!(
        canonicalize_conformance_registration_sets(
            &mut serde_json::json!({"scopes": ["openid", 1]})
        )
        .is_err()
    );

    assert!(contains_secret_field(
        &serde_json::json!([{"token": "secret"}])
    ));
    assert!(!contains_secret_field(
        &serde_json::json!({"claim": "public"})
    ));
    assert!(is_identifier("nazoauth-full/v1"));
    assert!(!is_identifier("contains space"));
    assert!(is_file_identifier("client_id-1"));
    assert!(!is_file_identifier("client/id"));
    assert!(is_lower_hex(&"a".repeat(64), 64));
    assert!(!is_lower_hex(&"A".repeat(64), 64));
    assert!(value_contains_reference(
        &serde_json::json!({"nested": ["{{target.issuer}}"]}),
        "target.issuer"
    ));
    assert!(!value_contains_reference(
        &serde_json::json!({"nested": ["target.issuer"]}),
        "target.issuer"
    ));
    assert!(descriptor_requires_reference(
        &descriptor,
        "target.ciba_automated_decision_url"
    ));
}

#[test]
fn controller_path_helpers_keep_fixed_defaults_without_environment_overrides() {
    if std::env::var_os("NAZOAUTH_OPERATOR_CLIENT_SECRET_PEPPER_FILE").is_none() {
        assert!(
            conformance_policy_secret_path(
                "NAZOAUTH_OPERATOR_CLIENT_SECRET_PEPPER_FILE",
                CONFORMANCE_CLIENT_SECRET_PEPPER_PATH,
                "client-secret-pepper",
            )
            .is_err()
        );
    }
    if std::env::var_os("NAZOAUTH_OPERATOR_CONFORMANCE_BUNDLE_FILE").is_none() {
        assert_eq!(
            conformance_bundle_path().expect("fixed bundle path"),
            std::path::PathBuf::from(CONFORMANCE_BUNDLE_PATH)
        );
    }
    if std::env::var_os("NAZOAUTH_OPERATOR_OUTPUT_DIRECTORY").is_none() {
        assert_eq!(
            conformance_output_directory().expect("fixed output directory"),
            std::path::PathBuf::from(CONFORMANCE_OUTPUT_DIRECTORY)
        );
    }
}

#[tokio::test]
async fn onboarding_password_hash_uses_the_configured_bounded_worker() {
    let password = format!("coverage-password-{}", Uuid::now_v7());
    let hash = hash_applicant_password(&password)
        .await
        .expect("bounded applicant password hash");
    assert!(hash.into_persistence_value().starts_with("$argon2"));
}

async fn onboarding_adapter_request(
    tenant_id: Uuid,
    bundle_schema: u32,
    client_count: u32,
    ttl_seconds: u64,
) -> ConformanceOnboardingRequest {
    let descriptor = load_matrix_descriptor().expect("built-in matrix");
    let password = format!("adapter-password-{}", Uuid::now_v7());
    ConformanceOnboardingRequest {
        tenant_id,
        task_jti: format!("request-{}", Uuid::now_v7().simple()),
        profile: "nazoauth-full".to_owned(),
        bundle_schema,
        bundle_sha256: "b".repeat(64),
        matrix_sha256: digest_hex(CONFORMANCE_MATRIX_BYTES),
        suite_origin: "https://suite.example".to_owned(),
        public_material: valid_conformance_trust(&descriptor),
        dynamic_registration_initial_access_token_sha256: Some("c".repeat(64)),
        ciba_automated_decision_token_sha256: Some("d".repeat(64)),
        client_count,
        ttl_seconds,
        applicant: ConformanceOnboardingApplicant {
            username: format!("conformance-{}", Uuid::now_v7().simple()),
            email: "credential-holder@example.test".to_owned(),
            password_hash: hash_applicant_password(&password)
                .await
                .expect("applicant password hash"),
            email_verified: true,
            display_name: CONFORMANCE_PROFILE_DISPLAY_NAME.to_owned(),
            given_name: CONFORMANCE_PROFILE_GIVEN_NAME.to_owned(),
            family_name: CONFORMANCE_PROFILE_FAMILY_NAME.to_owned(),
            middle_name: CONFORMANCE_PROFILE_MIDDLE_NAME.to_owned(),
            nickname: CONFORMANCE_PROFILE_NICKNAME.to_owned(),
            profile_url: CONFORMANCE_PROFILE_URL.to_owned(),
            avatar_url: CONFORMANCE_PROFILE_AVATAR_URL.to_owned(),
            website_url: CONFORMANCE_PROFILE_WEBSITE_URL.to_owned(),
            gender: CONFORMANCE_PROFILE_GENDER.to_owned(),
            birthdate: CONFORMANCE_PROFILE_BIRTHDATE.to_owned(),
            zoneinfo: CONFORMANCE_PROFILE_ZONEINFO.to_owned(),
            locale: CONFORMANCE_PROFILE_LOCALE.to_owned(),
            address: nazo_identity::PostalAddress::default(),
            phone_number: CONFORMANCE_PROFILE_PHONE_NUMBER.to_owned(),
            phone_number_verified: true,
        },
        clients: Vec::new(),
        mtls_trust_anchors: Vec::new(),
        openid4vc_credential_datasets: descriptor.openid4vc_credential_datasets,
    }
}

#[tokio::test]
async fn onboarding_adapter_rejects_conversion_boundaries_before_database_access() {
    let pool = nazo_postgres::create_pool("postgresql://postgres:postgres@127.0.0.1:5432/oauth", 1)
        .expect("lazy adapter pool");
    let adapter = PostgresOnboardingRepository::new(ConformanceLeaseRepository::new(pool));

    let request = onboarding_adapter_request(DEFAULT_TENANT_ID, 3, 0, 300).await;
    let pending = adapter.apply_onboarding(request);
    drop(pending);

    let mut request = onboarding_adapter_request(Uuid::now_v7(), 3, 0, 300).await;
    assert!(
        adapter
            .apply_onboarding(request)
            .await
            .expect_err("tenant binding must be checked before persistence")
            .to_string()
            .contains("tenant binding")
    );

    request = onboarding_adapter_request(DEFAULT_TENANT_ID, u32::MAX, 0, 300).await;
    assert!(
        adapter
            .apply_onboarding(request)
            .await
            .expect_err("bundle schema conversion must be bounded")
            .to_string()
            .contains("bundle schema")
    );

    request = onboarding_adapter_request(DEFAULT_TENANT_ID, 3, 0, u64::MAX).await;
    assert!(
        adapter
            .apply_onboarding(request)
            .await
            .expect_err("ttl conversion must be bounded")
            .to_string()
            .contains("ttl")
    );

    request = onboarding_adapter_request(DEFAULT_TENANT_ID, 3, u32::MAX, 300).await;
    assert!(
        adapter
            .apply_onboarding(request)
            .await
            .expect_err("client count conversion must be bounded")
            .to_string()
            .contains("client count")
    );
}

#[tokio::test]
async fn prepare_client_registrations_requires_the_controller_secret_channel() {
    if std::env::var_os("NAZOAUTH_OPERATOR_CLIENT_SECRET_PEPPER_FILE").is_none() {
        let error = match prepare_client_registrations(Vec::new()).await {
            Ok(_) => panic!("client preparation must not proceed without its secret channel"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("NAZOAUTH_OPERATOR_CLIENT_SECRET_PEPPER_FILE")
        );
    }
}

#[tokio::test]
async fn postgres_onboarding_adapter_rejects_invalid_conversion_and_count_boundaries() {
    if !database_is_available() {
        return;
    }
    let adapter = PostgresOnboardingRepository::new(repository().expect("lease repository"));

    let request = onboarding_adapter_request(Uuid::now_v7(), 3, 0, 300).await;
    assert!(adapter.apply_onboarding(request).await.is_err());

    let request = onboarding_adapter_request(DEFAULT_TENANT_ID, u32::MAX, 0, 300).await;
    assert!(adapter.apply_onboarding(request).await.is_err());

    let request = onboarding_adapter_request(DEFAULT_TENANT_ID, 3, 0, u64::MAX).await;
    assert!(adapter.apply_onboarding(request).await.is_err());

    let request = onboarding_adapter_request(DEFAULT_TENANT_ID, 3, u32::MAX, 300).await;
    assert!(adapter.apply_onboarding(request).await.is_err());

    let request = onboarding_adapter_request(DEFAULT_TENANT_ID, 3, 1, 300).await;
    let error = adapter
        .apply_onboarding(request)
        .await
        .expect_err("client count mismatch must fail");
    assert!(error.to_string().contains("consistency"));
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
                        | "private_jwks"
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

#[tokio::test]
async fn operator_create_rejects_invalid_digest_and_trust_before_storage() {
    let error = operator_create(
        "oidc-fapi-ciba",
        &"a".repeat(64),
        Some(&"A".repeat(64)),
        None,
        None,
        60,
    )
    .await
    .expect_err("uppercase digest must fail closed before repository access");
    assert!(error.to_string().contains("lowercase SHA-256"));

    let error = operator_create(
        "oidc-fapi-ciba",
        &"a".repeat(64),
        None,
        None,
        Some(trust_material_fixture()),
        60,
    )
    .await
    .expect_err("invalid trust material must fail closed before repository access");
    assert!(
        error
            .to_string()
            .contains("invalid OpenID4VC conformance credential trust anchor")
    );
}

#[test]
fn policy_secret_path_accepts_only_the_explicit_fixed_mapping() {
    let configured = std::env::var_os("PATH").expect("test process PATH");
    let configured = configured.to_string_lossy();
    assert_eq!(
        conformance_policy_secret_path("PATH", &configured, "unused-credential").unwrap(),
        std::path::PathBuf::from(configured.as_ref())
    );

    let error = conformance_policy_secret_path(
        "PATH",
        "/run/credentials/client-secret-pepper",
        "client-secret-pepper",
    )
    .expect_err("an ambient PATH value must not become a controller credential path");
    assert!(error.to_string().contains("fixed mapping"));
}

#[test]
fn dataset_validation_rejects_maps_that_drift_from_the_signed_matrix() {
    let descriptor = load_matrix_descriptor().expect("built-in matrix");
    let mut datasets = descriptor.openid4vc_credential_datasets.clone();
    datasets.remove("eu.europa.ec.eudi.pid.1");
    let error = validate_onboarding_credential_datasets(&datasets, &descriptor)
        .expect_err("the lease dataset map is signed by the matrix");
    assert!(
        error
            .to_string()
            .contains("do not match the deployment matrix")
    );
}

#[test]
fn matrix_anchor_policy_rejects_multiple_suite_pins_before_membership_check() {
    let descriptor = load_matrix_descriptor().expect("built-in matrix");
    let mut ambiguous = descriptor.clone();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("second Suite trust key");
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let second = params
        .self_signed(&key)
        .expect("second Suite trust anchor")
        .pem();
    ambiguous.openid4vc_suite_mdoc_trust_anchor_pem = format!(
        "{}\n{}\n",
        descriptor.openid4vc_suite_mdoc_trust_anchor_pem.trim_end(),
        second.replace("\r\n", "\n").trim_end()
    );
    let material = valid_conformance_trust(&descriptor);
    let error = validate_matrix_suite_mdoc_anchor(&material, &ambiguous)
        .expect_err("Matrix must pin exactly one Suite mdoc trust anchor");
    assert!(error.to_string().contains("exactly one"));
}

#[tokio::test]
async fn onboarding_apply_requires_the_fixed_bundle_channel_before_database_access() {
    if std::env::var_os("NAZOAUTH_OPERATOR_CONFORMANCE_BUNDLE_FILE").is_some() {
        return;
    }
    let error = operator_onboarding_apply(
        "request-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "nazoauth-full",
        3,
        &"b".repeat(64),
        &digest_hex(CONFORMANCE_MATRIX_BYTES),
        0,
        300,
    )
    .await
    .expect_err("onboarding must fail closed when the bundle channel is absent");
    assert!(error.to_string().contains("onboarding bundle"));
}

#[test]
fn onboarding_repository_requires_the_operator_data_key_channel() {
    if std::env::var_os("NAZOAUTH_OPERATOR_OPENID4VC_DATA_ENCRYPTION_KEY_FILE").is_some() {
        return;
    }
    let error = match repository_for_onboarding() {
        Ok(_) => panic!("onboarding repository must not be built without its data key"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("OPENID4VC"));
}
