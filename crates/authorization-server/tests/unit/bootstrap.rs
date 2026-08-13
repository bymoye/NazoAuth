use super::*;
use actix_web::http::header;
use actix_web::{HttpResponse, test as actix_test};
use chrono::{Duration as ChronoDuration, Utc};
use nazo_digital_credentials::CertificateRevocationSnapshot;

fn write_test_tls_identity(root: &std::path::Path) -> (String, String, String) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let certificate = params.self_signed(&key).unwrap();
    let certificate_path = root.join("server.pem");
    let private_key_path = root.join("server.key");
    let ca_path = root.join("ca.pem");
    std::fs::write(&certificate_path, certificate.pem()).unwrap();
    std::fs::write(&ca_path, certificate.pem()).unwrap();
    std::fs::write(&private_key_path, key.serialize_pem()).unwrap();
    (
        certificate_path.display().to_string(),
        private_key_path.display().to_string(),
        ca_path.display().to_string(),
    )
}

#[test]
fn production_bootstrap_only_publishes_focused_application_data() {
    let source = include_str!("../../src/bootstrap/mod.rs");

    assert!(
        !source.contains("web::Data::new(TestInfrastructure"),
        "production bootstrap must not reconstruct the giant TestInfrastructure"
    );
    assert!(
        !source.contains(".app_data(state"),
        "production Actix app must not publish the giant TestInfrastructure"
    );
}

#[test]
fn transport_tls_features_are_consolidated_on_rustls() {
    let manifest = include_str!("../../Cargo.toml");

    assert!(
        manifest
            .contains(r#"actix-web = { workspace = true, features = ["cookies", "rustls-0_23"] }"#)
    );
    assert!(manifest.contains(
        r#"lettre = { workspace = true, features = ["aws-lc-rs", "builder", "rustls-platform-verifier", "smtp-transport", "tokio1-rustls"] }"#
    ));
    assert!(!manifest.contains("tokio1-native-tls"));
    assert!(!manifest.contains(r#"features = ["native-tls", "rustls"#));
    assert!(!manifest.contains(r#"features = ["cookies", "openssl"]"#));
}

#[actix_web::test]
async fn security_headers_are_added_to_core_responses() {
    let app = actix_test::init_service(App::new().wrap(from_fn(security_headers)).route(
        "/ok",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = actix_test::TestRequest::get().uri("/ok").to_request();
    let response = actix_test::call_service(&app, request).await;
    let headers = response.headers();

    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(headers.get("Referrer-Policy").unwrap(), "no-referrer");
    assert_eq!(
        headers.get("Permissions-Policy").unwrap(),
        "interest-cohort=()"
    );
    assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert!(
        headers
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
}

#[actix_web::test]
async fn bundled_ui_serves_assets_and_spa_routes_without_masking_missing_assets() {
    let root = std::env::temp_dir().join(format!("nazoauth-ui-test-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(root.join("assets")).unwrap();
    std::fs::write(
        root.join("index.html"),
        "<!doctype html><title>NazoAuth</title>",
    )
    .unwrap();
    std::fs::write(root.join("assets/app.js"), "console.log('nazoauth');").unwrap();

    let app = actix_test::init_service(
        App::new()
            .wrap(from_fn(security_headers))
            .service(ui_static_files(root.clone())),
    )
    .await;

    for path in ["/ui/", "/ui/auth", "/ui/assets/app.js"] {
        let response =
            actix_test::call_service(&app, actix_test::TestRequest::get().uri(path).to_request())
                .await;
        assert_eq!(response.status(), actix_web::http::StatusCode::OK, "{path}");
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
    }

    let missing_asset = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/ui/assets/missing.js")
            .to_request(),
    )
    .await;
    assert_eq!(
        missing_asset.status(),
        actix_web::http::StatusCode::NOT_FOUND
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn direct_tls_listener_is_disabled_by_default_and_requires_complete_identity() {
    let disabled = ConfigSource::default();
    let disabled_settings = Settings::from_config(&disabled).unwrap();
    assert!(
        direct_tls_listener(&disabled, &disabled_settings)
            .unwrap()
            .is_none()
    );

    let incomplete = ConfigSource::from_pairs_for_test([("MTLS_CERTIFICATE_SOURCE", "direct-tls")]);
    let incomplete_settings = Settings::from_config(&incomplete).unwrap();
    let error = direct_tls_listener(&incomplete, &incomplete_settings)
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "TLS_BIND is required for direct-tls mTLS"
    );
}

#[test]
fn direct_tls_listener_loads_a_complete_mutual_tls_identity() {
    let root = std::env::temp_dir().join(format!("nazoauth-tls-test-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let (certificate, private_key, client_ca) = write_test_tls_identity(&root);
    let config = ConfigSource::from_owned_pairs_for_test([
        (
            "MTLS_CERTIFICATE_SOURCE".to_owned(),
            "direct-tls".to_owned(),
        ),
        ("TLS_BIND".to_owned(), "127.0.0.1:0".to_owned()),
        ("TLS_CERTIFICATE_FILE".to_owned(), certificate),
        ("TLS_PRIVATE_KEY_FILE".to_owned(), private_key),
        ("TLS_CLIENT_CA_FILE".to_owned(), client_ca),
    ]);
    let settings = Settings::from_config(&config).unwrap();
    let (address, _acceptor) = direct_tls_listener(&config, &settings).unwrap().unwrap();
    assert_eq!(address, "127.0.0.1:0".parse().unwrap());
    std::fs::remove_dir_all(root).unwrap();
}

fn write_fresh_revocation_snapshot(root: &std::path::Path) -> std::path::PathBuf {
    let path = root.join("revocations.json");
    let now = Utc::now();
    let snapshot = CertificateRevocationSnapshot {
        version: CertificateRevocationSnapshot::VERSION,
        this_update: now - ChronoDuration::minutes(1),
        next_update: now + ChronoDuration::minutes(10),
        entries: Vec::new(),
    };
    std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    path
}

fn revocation_settings(
    policy: Openid4vcRevocationPolicy,
    snapshot_file: Option<std::path::PathBuf>,
) -> crate::settings::Openid4vcSettings {
    let mut settings = Settings::from_config(&ConfigSource::default()).unwrap();
    settings.openid4vc.revocation_policy = policy;
    settings.openid4vc.revocation_snapshot_file = snapshot_file;
    settings.openid4vc.revocation_reload_interval_seconds = 3_600;
    settings.openid4vc
}

#[actix_web::test]
async fn revocation_bootstrap_loads_disabled_optional_and_required_policies() {
    let disabled = load_revocation_policy(&revocation_settings(
        Openid4vcRevocationPolicy::Disabled,
        None,
    ))
    .await
    .unwrap();
    assert!(!disabled.is_enabled());
    assert!(disabled.snapshot().is_none());

    let root = std::env::temp_dir().join(format!("nazoauth-revocation-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let path = write_fresh_revocation_snapshot(&root);

    let optional = load_revocation_policy(&revocation_settings(
        Openid4vcRevocationPolicy::Optional,
        Some(path.clone()),
    ))
    .await
    .unwrap();
    assert!(optional.is_enabled());
    assert!(!optional.is_required());
    assert!(optional.snapshot().is_some());

    let required = load_revocation_policy(&revocation_settings(
        Openid4vcRevocationPolicy::Required,
        Some(path),
    ))
    .await
    .unwrap();
    assert!(required.is_enabled());
    assert!(required.is_required());
    assert!(required.snapshot().is_some());

    std::fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
async fn revocation_bootstrap_reports_snapshot_io_and_freshness_failures() {
    let missing = std::env::temp_dir().join(format!(
        "nazoauth-missing-revocation-{}.json",
        uuid::Uuid::now_v7()
    ));
    let error = match load_revocation_policy(&revocation_settings(
        Openid4vcRevocationPolicy::Required,
        Some(missing),
    ))
    .await
    {
        Ok(_) => panic!("missing revocation snapshot must fail bootstrap"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("failed to load OpenID4VC revocation snapshot")
    );

    let root = std::env::temp_dir().join(format!(
        "nazoauth-invalid-revocation-{}",
        uuid::Uuid::now_v7()
    ));
    std::fs::create_dir(&root).unwrap();
    let malformed = root.join("malformed.json");
    std::fs::write(&malformed, b"not-json").unwrap();
    let malformed_error = read_revocation_snapshot(&malformed)
        .await
        .expect_err("malformed revocation snapshot must be rejected");
    assert!(malformed_error.to_string().contains("invalid entry"));

    let expired = root.join("expired.json");
    let now = Utc::now();
    let snapshot = CertificateRevocationSnapshot {
        version: CertificateRevocationSnapshot::VERSION,
        this_update: now - ChronoDuration::minutes(10),
        next_update: now - ChronoDuration::minutes(1),
        entries: Vec::new(),
    };
    std::fs::write(&expired, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let expired_error = read_revocation_snapshot(&expired)
        .await
        .expect_err("expired revocation snapshot must be rejected");
    assert!(expired_error.to_string().contains("expired"));

    std::fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
async fn check_session_iframe_is_frameable_by_relying_parties() {
    let app = actix_test::init_service(App::new().wrap(from_fn(security_headers)).route(
        "/check_session",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/check_session")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    let headers = response.headers();

    assert!(headers.get(header::X_FRAME_OPTIONS).is_none());
    assert!(
        !headers
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
}

#[actix_web::test]
async fn fapi_resource_static_route_rejects_options_without_cors_and_keeps_security_headers() {
    let settings = Settings::from_config(&crate::config::ConfigSource::default()).unwrap();
    let app = actix_test::init_service(
        App::new()
            .wrap(from_fn(security_headers))
            .configure(|cfg| routes::configure(cfg, &settings, false)),
    )
    .await;

    for method in [
        actix_web::http::Method::OPTIONS,
        actix_web::http::Method::PUT,
        actix_web::http::Method::DELETE,
    ] {
        let response = actix_test::call_service(
            &app,
            actix_test::TestRequest::default()
                .method(method)
                .uri("/fapi/resource")
                .insert_header((header::ORIGIN, "https://browser.example"))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                .to_request(),
        )
        .await;
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::METHOD_NOT_ALLOWED
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
    }
}

#[actix_web::test]
async fn openid4vci_dataset_route_is_nested_inside_the_admin_scope() {
    let config = crate::config::ConfigSource::from_pairs_for_test([
        ("ENABLE_OPENID4VCI_ISSUER", "true"),
        (
            "OPENID4VC_DATA_ENCRYPTION_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE",
            "runtime/openid4vc-chain.pem",
        ),
        (
            "OPENID4VC_TRUST_ANCHORS_FILE",
            "runtime/openid4vc-roots.pem",
        ),
        (
            "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON",
            r#"{"pid":{"format":"dc+sd-jwt","scope":"pid","cryptographic_binding_methods_supported":["jwk"],"credential_signing_alg_values_supported":["ES256"],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}},"vct":"https://issuer.example/credentials/pid"}}"#,
        ),
        (
            "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN",
            "openid4vci-management-token-at-least-32-bytes",
        ),
    ]);
    let settings = Settings::from_config(&config).unwrap();
    let app = actix_test::init_service(
        App::new().configure(|cfg| routes::configure(cfg, &settings, false)),
    )
    .await;

    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/admin/openid4vci/credential-datasets/00000000-0000-0000-0000-000000000123/pid")
            .to_request(),
    )
    .await;

    assert_ne!(
        response.status(),
        actix_web::http::StatusCode::NOT_FOUND,
        "the generic /admin scope must not shadow the OpenID4VCI dataset route",
    );
}
