use super::*;
use actix_web::http::header;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, test as actix_test, web};
use chrono::{Duration as ChronoDuration, Utc};
use nazo_digital_credentials::CertificateRevocationSnapshot;

struct TestTlsMaterial {
    certificate_path: String,
    private_key_path: String,
    client_ca_path: String,
    client_ca_pem: String,
    client_identity_pem: String,
}

fn write_test_tls_material(root: &std::path::Path) -> TestTlsMaterial {
    write_test_tls_material_with_expired_server(root, false)
}

fn write_test_tls_material_with_expired_server(
    root: &std::path::Path,
    expired_server: bool,
) -> TestTlsMaterial {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::new(vec!["NazoAuth test CA".to_owned()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    server_params.is_ca = IsCa::NoCa;
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    if expired_server {
        server_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
        server_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    }
    let server_certificate = server_params.signed_by(&server_key, &ca).unwrap();

    let client_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut client_params = CertificateParams::new(vec!["client.example".to_owned()]).unwrap();
    client_params.is_ca = IsCa::NoCa;
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_certificate = client_params.signed_by(&client_key, &ca).unwrap();

    let certificate_path = root.join("server.pem");
    let private_key_path = root.join("server.key");
    let ca_path = root.join("ca.pem");
    let ca_pem = ca.pem();
    std::fs::write(
        &certificate_path,
        format!("{}{}", server_certificate.pem(), ca_pem),
    )
    .unwrap();
    std::fs::write(&ca_path, &ca_pem).unwrap();
    std::fs::write(&private_key_path, server_key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    TestTlsMaterial {
        certificate_path: certificate_path.display().to_string(),
        private_key_path: private_key_path.display().to_string(),
        client_ca_path: ca_path.display().to_string(),
        client_ca_pem: ca_pem.clone(),
        client_identity_pem: format!(
            "{}{}{}",
            client_certificate.pem(),
            ca_pem,
            client_key.serialize_pem()
        ),
    }
}

fn write_test_tls_identity(root: &std::path::Path) -> (String, String, String) {
    let material = write_test_tls_material(root);
    (
        material.certificate_path,
        material.private_key_path,
        material.client_ca_path,
    )
}

fn direct_tls_config(material: &TestTlsMaterial) -> ConfigSource {
    ConfigSource::from_owned_pairs_for_test([
        ("PUBLIC_BASE_URL".to_owned(), "https://localhost".to_owned()),
        (
            "CLIENT_SECRET_PEPPER".to_owned(),
            "test-client-secret-pepper-that-is-long-enough".to_owned(),
        ),
        ("TRANSPORT_MODE".to_owned(), "direct-tls".to_owned()),
        ("TLS_BIND".to_owned(), "127.0.0.1:0".to_owned()),
        (
            "TLS_CERTIFICATE_FILE".to_owned(),
            material.certificate_path.clone(),
        ),
        (
            "TLS_PRIVATE_KEY_FILE".to_owned(),
            material.private_key_path.clone(),
        ),
        (
            "TLS_CLIENT_CA_FILE".to_owned(),
            material.client_ca_path.clone(),
        ),
    ])
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
    let index_body = "<!doctype html><title>NazoAuth</title>";
    let asset_body = "console.log('nazoauth');";
    std::fs::write(root.join("index.html"), index_body).unwrap();
    std::fs::write(root.join("assets/app.js"), asset_body).unwrap();

    let app = actix_test::init_service(
        App::new()
            .wrap(from_fn(security_headers))
            .service(ui_static_files(root.clone())),
    )
    .await;

    for path in ["/ui/", "/ui/auth"] {
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
        assert_eq!(actix_test::read_body(response).await, index_body.as_bytes());
    }

    let asset = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/ui/assets/app.js")
            .to_request(),
    )
    .await;
    assert_eq!(asset.status(), actix_web::http::StatusCode::OK);
    assert!(
        !asset
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .is_empty()
    );
    let asset_etag = asset.headers().get(header::ETAG).unwrap().clone();
    assert_eq!(actix_test::read_body(asset).await, asset_body.as_bytes());

    let range = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/ui/assets/app.js")
            .insert_header((header::RANGE, "bytes=0-6"))
            .to_request(),
    )
    .await;
    assert_eq!(range.status(), actix_web::http::StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        range.headers().get(header::CONTENT_RANGE).unwrap(),
        format!("bytes 0-6/{}", asset_body.len()).as_str()
    );
    assert_eq!(
        actix_test::read_body(range).await,
        &asset_body.as_bytes()[..7]
    );

    let not_modified = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/ui/assets/app.js")
            .insert_header((header::IF_NONE_MATCH, asset_etag))
            .to_request(),
    )
    .await;
    assert_eq!(
        not_modified.status(),
        actix_web::http::StatusCode::NOT_MODIFIED
    );

    let head_builder = HttpServer::new({
        let root = root.clone();
        move || App::new().service(ui_static_files(root.clone()))
    })
    .bind(("127.0.0.1", 0))
    .unwrap();
    let head_address = head_builder.addrs()[0];
    let head_server = head_builder.run();
    let head_handle = head_server.handle();
    actix_web::rt::spawn(head_server);
    let head = reqwest::Client::new()
        .head(format!("http://{head_address}/ui/assets/app.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), reqwest::StatusCode::OK);
    assert_eq!(
        head.headers().get("content-length").unwrap(),
        asset_body.len().to_string().as_str()
    );
    assert!(head.bytes().await.unwrap().is_empty());
    head_handle.stop(true).await;

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

    std::fs::remove_file(root.join("index.html")).unwrap();
    let missing_index = actix_test::try_call_service(
        &app,
        actix_test::TestRequest::get().uri("/ui/auth").to_request(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        missing_index.as_error::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn direct_tls_listener_is_disabled_by_default_and_requires_complete_identity() {
    let disabled = ConfigSource::default();
    let disabled_settings = Settings::from_config(&disabled).unwrap();
    assert!(
        direct_tls_listeners(&disabled, &disabled_settings)
            .unwrap()
            .is_none()
    );

    let incomplete = ConfigSource::from_pairs_for_test([
        ("PUBLIC_BASE_URL", "https://localhost"),
        (
            "CLIENT_SECRET_PEPPER",
            "test-client-secret-pepper-that-is-long-enough",
        ),
        ("TRANSPORT_MODE", "direct-tls"),
    ]);
    let incomplete_settings = Settings::from_config(&incomplete).unwrap();
    let error = direct_tls_listeners(&incomplete, &incomplete_settings)
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "TLS_BIND is required for direct-tls transport"
    );

    let colliding = ConfigSource::from_pairs_for_test([
        ("BIND", "127.0.0.1:8443"),
        ("PUBLIC_BASE_URL", "https://localhost"),
        (
            "CLIENT_SECRET_PEPPER",
            "test-client-secret-pepper-that-is-long-enough",
        ),
        ("TRANSPORT_MODE", "direct-tls"),
        ("TLS_BIND", "127.0.0.1:8443"),
    ]);
    let colliding_settings = Settings::from_config(&colliding).unwrap();
    assert_eq!(
        direct_tls_listeners(&colliding, &colliding_settings)
            .err()
            .unwrap()
            .to_string(),
        "BIND and TLS_BIND must use different listener addresses"
    );
}

#[test]
fn direct_tls_listener_loads_a_complete_mutual_tls_identity() {
    let root = std::env::temp_dir().join(format!("nazoauth-tls-test-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let (certificate, private_key, client_ca) = write_test_tls_identity(&root);
    let config = ConfigSource::from_owned_pairs_for_test([
        ("PUBLIC_BASE_URL".to_owned(), "https://localhost".to_owned()),
        (
            "CLIENT_SECRET_PEPPER".to_owned(),
            "test-client-secret-pepper-that-is-long-enough".to_owned(),
        ),
        ("TRANSPORT_MODE".to_owned(), "direct-tls".to_owned()),
        ("TLS_BIND".to_owned(), "127.0.0.1:0".to_owned()),
        ("TLS_CERTIFICATE_FILE".to_owned(), certificate),
        ("TLS_PRIVATE_KEY_FILE".to_owned(), private_key),
        ("TLS_CLIENT_CA_FILE".to_owned(), client_ca),
    ]);
    let settings = Settings::from_config(&config).unwrap();
    let listeners = direct_tls_listeners(&config, &settings).unwrap().unwrap();
    assert_eq!(listeners.mtls_bind, "127.0.0.1:0".parse().unwrap());
    let debug = format!("{:?}", listeners.snapshots);
    assert!(debug.contains("DirectTlsSnapshotStore"));
    assert!(debug.contains("material_sha256"));
    assert!(
        listeners
            .snapshots
            .server_key_for(Some("localhost"))
            .is_some()
    );
    assert!(
        listeners
            .snapshots
            .server_key_for(Some("unknown.test"))
            .is_none()
    );
    assert!(listeners.snapshots.server_key_for(None).is_none());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn direct_tls_listener_rejects_malformed_or_unsafe_material_and_reload_intervals() {
    let malformed_key_root =
        std::env::temp_dir().join(format!("nazoauth-tls-invalid-key-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&malformed_key_root).unwrap();
    let malformed_key = write_test_tls_material(&malformed_key_root);
    std::fs::write(&malformed_key.private_key_path, "not a PEM private key").unwrap();
    let config = direct_tls_config(&malformed_key);
    let settings = Settings::from_config(&config).unwrap();
    assert!(
        direct_tls_listeners(&config, &settings)
            .err()
            .unwrap()
            .to_string()
            .contains("failed to parse TLS private key")
    );

    let malformed_ca_root =
        std::env::temp_dir().join(format!("nazoauth-tls-invalid-ca-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&malformed_ca_root).unwrap();
    let malformed_ca = write_test_tls_material(&malformed_ca_root);
    std::fs::write(
        &malformed_ca.client_ca_path,
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let config = direct_tls_config(&malformed_ca);
    let settings = Settings::from_config(&config).unwrap();
    assert!(
        direct_tls_listeners(&config, &settings)
            .err()
            .unwrap()
            .to_string()
            .contains("failed to parse TLS client CA bundle")
    );

    let empty_ca_root =
        std::env::temp_dir().join(format!("nazoauth-tls-empty-ca-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&empty_ca_root).unwrap();
    let empty_ca = write_test_tls_material(&empty_ca_root);
    std::fs::write(&empty_ca.client_ca_path, "").unwrap();
    let config = direct_tls_config(&empty_ca);
    let settings = Settings::from_config(&config).unwrap();
    assert!(
        direct_tls_listeners(&config, &settings)
            .err()
            .unwrap()
            .to_string()
            .contains("contains no certificates")
    );

    let oversized_ca_root =
        std::env::temp_dir().join(format!("nazoauth-tls-large-ca-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&oversized_ca_root).unwrap();
    let oversized_ca = write_test_tls_material(&oversized_ca_root);
    std::fs::File::create(&oversized_ca.client_ca_path)
        .unwrap()
        .set_len(4 * 1024 * 1024 + 1)
        .unwrap();
    let config = direct_tls_config(&oversized_ca);
    let settings = Settings::from_config(&config).unwrap();
    assert!(
        direct_tls_listeners(&config, &settings)
            .err()
            .unwrap()
            .to_string()
            .contains("exceeds 4194304 bytes")
    );

    let empty_chain_root =
        std::env::temp_dir().join(format!("nazoauth-tls-empty-chain-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&empty_chain_root).unwrap();
    let empty_chain = write_test_tls_material(&empty_chain_root);
    std::fs::write(&empty_chain.certificate_path, "").unwrap();
    let config = direct_tls_config(&empty_chain);
    let settings = Settings::from_config(&config).unwrap();
    assert!(
        direct_tls_listeners(&config, &settings)
            .err()
            .unwrap()
            .to_string()
            .contains("contains no certificates")
    );

    let malformed_der_root =
        std::env::temp_dir().join(format!("nazoauth-tls-invalid-der-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&malformed_der_root).unwrap();
    let malformed_der = write_test_tls_material(&malformed_der_root);
    std::fs::write(
        &malformed_der.certificate_path,
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let config = direct_tls_config(&malformed_der);
    let settings = Settings::from_config(&config).unwrap();
    assert!(
        direct_tls_listeners(&config, &settings)
            .err()
            .unwrap()
            .to_string()
            .contains("failed to parse TLS leaf certificate")
    );

    let directory_key_root = std::env::temp_dir().join(format!(
        "nazoauth-tls-directory-key-{}",
        uuid::Uuid::now_v7()
    ));
    std::fs::create_dir(&directory_key_root).unwrap();
    let directory_key = write_test_tls_material(&directory_key_root);
    std::fs::remove_file(&directory_key.private_key_path).unwrap();
    std::fs::create_dir(&directory_key.private_key_path).unwrap();
    let config = direct_tls_config(&directory_key);
    let settings = Settings::from_config(&config).unwrap();
    assert!(direct_tls_listeners(&config, &settings).is_err());

    let interval_root =
        std::env::temp_dir().join(format!("nazoauth-tls-interval-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&interval_root).unwrap();
    let interval_material = write_test_tls_material(&interval_root);
    let mut pairs = vec![
        ("PUBLIC_BASE_URL".to_owned(), "https://localhost".to_owned()),
        (
            "CLIENT_SECRET_PEPPER".to_owned(),
            "test-client-secret-pepper-that-is-long-enough".to_owned(),
        ),
        ("TRANSPORT_MODE".to_owned(), "direct-tls".to_owned()),
        ("TLS_BIND".to_owned(), "127.0.0.1:0".to_owned()),
        (
            "TLS_CERTIFICATE_FILE".to_owned(),
            interval_material.certificate_path.clone(),
        ),
        (
            "TLS_PRIVATE_KEY_FILE".to_owned(),
            interval_material.private_key_path.clone(),
        ),
        (
            "TLS_CLIENT_CA_FILE".to_owned(),
            interval_material.client_ca_path.clone(),
        ),
    ];
    pairs.push(("TLS_RELOAD_INTERVAL_SECONDS".to_owned(), "0".to_owned()));
    let config = ConfigSource::from_owned_pairs_for_test(pairs);
    let settings = Settings::from_config(&config).unwrap();
    assert!(
        direct_tls_listeners(&config, &settings)
            .err()
            .unwrap()
            .to_string()
            .contains("TLS_RELOAD_INTERVAL_SECONDS must be between 1 and 3600")
    );

    for root in [
        malformed_key_root,
        malformed_ca_root,
        empty_ca_root,
        oversized_ca_root,
        empty_chain_root,
        malformed_der_root,
        directory_key_root,
        interval_root,
    ] {
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[actix_web::test]
async fn direct_tls_reloader_ticks_and_stops_without_publishing_unchanged_material() {
    let root = std::env::temp_dir().join(format!("nazoauth-tls-reloader-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let (certificate, private_key, client_ca) = write_test_tls_identity(&root);
    let config = ConfigSource::from_owned_pairs_for_test([
        ("PUBLIC_BASE_URL".to_owned(), "https://localhost".to_owned()),
        (
            "CLIENT_SECRET_PEPPER".to_owned(),
            "test-client-secret-pepper-that-is-long-enough".to_owned(),
        ),
        ("TRANSPORT_MODE".to_owned(), "direct-tls".to_owned()),
        ("TLS_BIND".to_owned(), "127.0.0.1:0".to_owned()),
        ("TLS_CERTIFICATE_FILE".to_owned(), certificate),
        ("TLS_PRIVATE_KEY_FILE".to_owned(), private_key),
        ("TLS_CLIENT_CA_FILE".to_owned(), client_ca),
    ]);
    let settings = Settings::from_config(&config).unwrap();
    let listeners = direct_tls_listeners(&config, &settings).unwrap().unwrap();
    let reloader = spawn_direct_tls_reloader(
        Arc::clone(&listeners.snapshots),
        std::time::Duration::from_millis(5),
    );
    tokio::time::sleep(std::time::Duration::from_millis(18)).await;
    assert_eq!(listeners.snapshots.revision(), 1);
    reloader.abort();
    assert!(reloader.await.unwrap_err().is_cancelled());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn direct_tls_listener_rejects_an_expired_server_identity() {
    let root = std::env::temp_dir().join(format!("nazoauth-tls-test-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let material = write_test_tls_material_with_expired_server(&root, true);
    let config = ConfigSource::from_owned_pairs_for_test([
        ("PUBLIC_BASE_URL".to_owned(), "https://localhost".to_owned()),
        (
            "CLIENT_SECRET_PEPPER".to_owned(),
            "test-client-secret-pepper-that-is-long-enough".to_owned(),
        ),
        ("TRANSPORT_MODE".to_owned(), "direct-tls".to_owned()),
        ("TLS_BIND".to_owned(), "127.0.0.1:0".to_owned()),
        ("TLS_CERTIFICATE_FILE".to_owned(), material.certificate_path),
        ("TLS_PRIVATE_KEY_FILE".to_owned(), material.private_key_path),
        ("TLS_CLIENT_CA_FILE".to_owned(), material.client_ca_path),
    ]);
    let settings = Settings::from_config(&config).unwrap();
    let error = direct_tls_listeners(&config, &settings).err().unwrap();
    assert!(error.to_string().contains("is not currently valid"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn direct_tls_listener_rejects_a_server_identity_for_another_host() {
    let root = std::env::temp_dir().join(format!("nazoauth-tls-test-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let material = write_test_tls_material(&root);
    let config = ConfigSource::from_owned_pairs_for_test([
        (
            "PUBLIC_BASE_URL".to_owned(),
            "https://auth.example.test".to_owned(),
        ),
        (
            "CLIENT_SECRET_PEPPER".to_owned(),
            "test-client-secret-pepper-that-is-long-enough".to_owned(),
        ),
        ("TRANSPORT_MODE".to_owned(), "direct-tls".to_owned()),
        ("TLS_BIND".to_owned(), "127.0.0.1:0".to_owned()),
        ("TLS_CERTIFICATE_FILE".to_owned(), material.certificate_path),
        ("TLS_PRIVATE_KEY_FILE".to_owned(), material.private_key_path),
        ("TLS_CLIENT_CA_FILE".to_owned(), material.client_ca_path),
    ]);
    let settings = Settings::from_config(&config).unwrap();
    let error = direct_tls_listeners(&config, &settings).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("endpoint host auth.example.test")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn direct_tls_listener_rejects_a_mismatched_private_key() {
    let root = std::env::temp_dir().join(format!("nazoauth-tls-test-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let material = write_test_tls_material(&root);
    let unrelated_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    std::fs::write(&material.private_key_path, unrelated_key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(
            &material.private_key_path,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let config = ConfigSource::from_owned_pairs_for_test([
        ("PUBLIC_BASE_URL".to_owned(), "https://localhost".to_owned()),
        (
            "CLIENT_SECRET_PEPPER".to_owned(),
            "test-client-secret-pepper-that-is-long-enough".to_owned(),
        ),
        ("TRANSPORT_MODE".to_owned(), "direct-tls".to_owned()),
        ("TLS_BIND".to_owned(), "127.0.0.1:0".to_owned()),
        ("TLS_CERTIFICATE_FILE".to_owned(), material.certificate_path),
        ("TLS_PRIVATE_KEY_FILE".to_owned(), material.private_key_path),
        ("TLS_CLIENT_CA_FILE".to_owned(), material.client_ca_path),
    ]);
    let settings = Settings::from_config(&config).unwrap();
    let error = direct_tls_listeners(&config, &settings).err().unwrap();
    assert!(error.to_string().contains("does not match"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn direct_tls_listener_rejects_an_unrelated_issuer_chain() {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
        PKCS_ECDSA_P256_SHA256,
    };

    let root = std::env::temp_dir().join(format!(
        "nazoauth-tls-unrelated-chain-{}",
        uuid::Uuid::now_v7()
    ));
    std::fs::create_dir(&root).unwrap();
    let material = write_test_tls_material(&root);
    let original_chain = std::fs::read_to_string(&material.certificate_path).unwrap();
    let leaf = original_chain
        .split_inclusive("-----END CERTIFICATE-----")
        .next()
        .expect("test server chain should contain a leaf certificate");

    let unrelated_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut unrelated_params =
        CertificateParams::new(vec!["Unrelated NazoAuth test CA".to_owned()]).unwrap();
    unrelated_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    unrelated_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let unrelated_ca = CertifiedIssuer::self_signed(unrelated_params, unrelated_key).unwrap();
    std::fs::write(
        &material.certificate_path,
        format!("{leaf}\n{}", unrelated_ca.pem()),
    )
    .unwrap();

    let config = direct_tls_config(&material);
    let settings = Settings::from_config(&config).unwrap();
    let error = direct_tls_listeners(&config, &settings).err().unwrap();
    assert!(
        error.to_string().contains("TLS certificate chain")
            && error.to_string().contains("is invalid"),
        "an unrelated issuer must be rejected before the TLS identity is published: {error}"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn direct_tls_generation_rejects_partial_material_and_retains_last_known_good() {
    let root = std::env::temp_dir().join(format!("nazoauth-tls-reload-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let material = write_test_tls_material(&root);
    let config = ConfigSource::from_owned_pairs_for_test([
        ("BIND".to_owned(), "127.0.0.1:0".to_owned()),
        ("PUBLIC_BASE_URL".to_owned(), "https://localhost".to_owned()),
        (
            "CLIENT_SECRET_PEPPER".to_owned(),
            "test-client-secret-pepper-that-is-long-enough".to_owned(),
        ),
        ("TRANSPORT_MODE".to_owned(), "direct-tls".to_owned()),
        ("TLS_BIND".to_owned(), "127.0.0.1:1".to_owned()),
        (
            "TLS_CERTIFICATE_FILE".to_owned(),
            material.certificate_path.clone(),
        ),
        (
            "TLS_PRIVATE_KEY_FILE".to_owned(),
            material.private_key_path.clone(),
        ),
        (
            "TLS_CLIENT_CA_FILE".to_owned(),
            material.client_ca_path.clone(),
        ),
    ]);
    let settings = Settings::from_config(&config).unwrap();
    let listeners = direct_tls_listeners(&config, &settings).unwrap().unwrap();
    let initial_digest = listeners.snapshots.material_sha256();

    let unrelated_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    std::fs::write(&material.private_key_path, unrelated_key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(
            &material.private_key_path,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let error = listeners.snapshots.reload().unwrap_err();
    assert!(error.to_string().contains("does not match"));
    assert_eq!(listeners.snapshots.revision(), 1);
    assert_eq!(listeners.snapshots.material_sha256(), initial_digest);

    let replacement = write_test_tls_material(&root);
    assert_eq!(replacement.certificate_path, material.certificate_path);
    assert_eq!(
        listeners.snapshots.reload().unwrap(),
        DirectTlsReload::Published {
            previous: 1,
            current: 2
        }
    );
    assert_ne!(listeners.snapshots.material_sha256(), initial_digest);
    assert_eq!(
        listeners.snapshots.reload().unwrap(),
        DirectTlsReload::Unchanged { revision: 2 }
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
async fn direct_tls_new_handshakes_switch_server_identity_without_reloading_client_ca() {
    let active_root =
        std::env::temp_dir().join(format!("nazoauth-tls-active-{}", uuid::Uuid::now_v7()));
    let next_root =
        std::env::temp_dir().join(format!("nazoauth-tls-next-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&active_root).unwrap();
    std::fs::create_dir(&next_root).unwrap();
    let active = write_test_tls_material(&active_root);
    let next = write_test_tls_material(&next_root);
    let config = ConfigSource::from_owned_pairs_for_test([
        ("BIND".to_owned(), "127.0.0.1:0".to_owned()),
        ("PUBLIC_BASE_URL".to_owned(), "https://localhost".to_owned()),
        (
            "CLIENT_SECRET_PEPPER".to_owned(),
            "test-client-secret-pepper-that-is-long-enough".to_owned(),
        ),
        ("TRANSPORT_MODE".to_owned(), "direct-tls".to_owned()),
        ("TLS_BIND".to_owned(), "127.0.0.1:1".to_owned()),
        (
            "TLS_CERTIFICATE_FILE".to_owned(),
            active.certificate_path.clone(),
        ),
        (
            "TLS_PRIVATE_KEY_FILE".to_owned(),
            active.private_key_path.clone(),
        ),
        (
            "TLS_CLIENT_CA_FILE".to_owned(),
            active.client_ca_path.clone(),
        ),
    ]);
    let settings = Settings::from_config(&config).unwrap();
    let listeners = direct_tls_listeners(&config, &settings).unwrap().unwrap();
    let snapshots = listeners.snapshots.clone();

    let probe = || App::new().route("/probe", web::get().to(|| async { "ok" }));
    let public_builder = HttpServer::new(probe)
        .bind_rustls_0_23(("127.0.0.1", 0), listeners.public)
        .unwrap();
    let public_address = public_builder.addrs()[0];
    let public_server = public_builder.run();
    let public_handle = public_server.handle();
    actix_web::rt::spawn(public_server);
    let mtls_builder = HttpServer::new(probe)
        .bind_rustls_0_23(("127.0.0.1", 0), listeners.mtls)
        .unwrap();
    let mtls_address = mtls_builder.addrs()[0];
    let mtls_server = mtls_builder.run();
    let mtls_handle = mtls_server.handle();
    actix_web::rt::spawn(mtls_server);

    let active_root_certificate =
        reqwest::Certificate::from_pem(active.client_ca_pem.as_bytes()).unwrap();
    let next_root_certificate =
        reqwest::Certificate::from_pem(next.client_ca_pem.as_bytes()).unwrap();
    let active_client = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .https_only(true)
        .tls_backend_rustls()
        .tls_certs_only([
            active_root_certificate.clone(),
            next_root_certificate.clone(),
        ])
        .identity(reqwest::Identity::from_pem(active.client_identity_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let next_client = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .https_only(true)
        .tls_backend_rustls()
        .tls_certs_only([
            active_root_certificate.clone(),
            next_root_certificate.clone(),
        ])
        .identity(reqwest::Identity::from_pem(next.client_identity_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let active_public = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .https_only(true)
        .tls_backend_rustls()
        .tls_certs_only([active_root_certificate])
        .build()
        .unwrap();
    let next_public = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .https_only(true)
        .tls_backend_rustls()
        .tls_certs_only([next_root_certificate])
        .build()
        .unwrap();

    let public_url = format!("https://localhost:{}/probe", public_address.port());
    let mtls_url = format!("https://localhost:{}/probe", mtls_address.port());
    assert_eq!(
        active_public
            .get(&public_url)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    assert!(next_public.get(&public_url).send().await.is_err());
    assert!(active_client.get(&mtls_url).send().await.is_ok());
    assert!(next_client.get(&mtls_url).send().await.is_err());

    std::fs::copy(&next.certificate_path, &active.certificate_path).unwrap();
    std::fs::copy(&next.private_key_path, &active.private_key_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(
            &active.private_key_path,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    assert_eq!(
        snapshots.reload().unwrap(),
        DirectTlsReload::Published {
            previous: 1,
            current: 2
        }
    );

    assert!(active_public.get(&public_url).send().await.is_err());
    assert_eq!(
        next_public
            .get(&public_url)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    assert!(active_client.get(&mtls_url).send().await.is_ok());
    assert!(next_client.get(&mtls_url).send().await.is_err());

    public_handle.stop(true).await;
    mtls_handle.stop(true).await;
    std::fs::remove_dir_all(active_root).unwrap();
    std::fs::remove_dir_all(next_root).unwrap();
}

#[actix_web::test]
async fn direct_tls_serves_real_https_and_mtls_without_trusting_forged_headers() {
    let root = std::env::temp_dir().join(format!("nazoauth-tls-http-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let material = write_test_tls_material(&root);
    let config = ConfigSource::from_owned_pairs_for_test([
        ("BIND".to_owned(), "127.0.0.1:0".to_owned()),
        ("PUBLIC_BASE_URL".to_owned(), "https://localhost".to_owned()),
        (
            "CLIENT_SECRET_PEPPER".to_owned(),
            "test-client-secret-pepper-that-is-long-enough".to_owned(),
        ),
        ("TRANSPORT_MODE".to_owned(), "direct-tls".to_owned()),
        ("TLS_BIND".to_owned(), "127.0.0.1:0".to_owned()),
        ("TLS_CERTIFICATE_FILE".to_owned(), material.certificate_path),
        ("TLS_PRIVATE_KEY_FILE".to_owned(), material.private_key_path),
        ("TLS_CLIENT_CA_FILE".to_owned(), material.client_ca_path),
    ]);
    let settings = Settings::from_config(&config).unwrap();
    let listeners = direct_tls_listeners(&config, &settings).unwrap().unwrap();

    let probe = || {
        App::new()
            .app_data(web::Data::new(
                crate::http::mtls::MtlsCertificateSource::new(
                    crate::http::mtls::MtlsCertificateSourceMode::DirectTls,
                ),
            ))
            .route(
                "/probe",
                web::get().to(|request: HttpRequest| async move {
                    let certificate =
                        crate::http::mtls::request_mtls_client_certificate(&request, &[]);
                    HttpResponse::Ok().body(
                        certificate
                            .and_then(|certificate| certificate.thumbprint)
                            .unwrap_or_else(|| "none".to_owned()),
                    )
                }),
            )
    };
    let public_builder = HttpServer::new(probe)
        .on_connect(crate::http::mtls::capture_direct_tls_client_certificate)
        .bind_rustls_0_23(("127.0.0.1", 0), listeners.public)
        .unwrap();
    let public_address = public_builder.addrs()[0];
    let public_server = public_builder.run();
    let public_handle = public_server.handle();
    actix_web::rt::spawn(public_server);

    let mtls_builder = HttpServer::new(probe)
        .on_connect(crate::http::mtls::capture_direct_tls_client_certificate)
        .bind_rustls_0_23(("127.0.0.1", 0), listeners.mtls)
        .unwrap();
    let mtls_address = mtls_builder.addrs()[0];
    let mtls_server = mtls_builder.run();
    let mtls_handle = mtls_server.handle();
    actix_web::rt::spawn(mtls_server);

    let root_certificate = reqwest::Certificate::from_pem(material.client_ca_pem.as_bytes())
        .expect("test root certificate");
    let public_client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .http2_prior_knowledge()
        .tls_backend_rustls()
        .tls_certs_only([root_certificate.clone()])
        .build()
        .unwrap();
    let public_response = public_client
        .get(format!("https://localhost:{}/probe", public_address.port()))
        .header("x-ssl-client-verify", "SUCCESS")
        .header(
            "x-forwarded-tls-client-cert-sha256",
            "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8",
        )
        .header("forwarded", "for=203.0.113.7;proto=https")
        .header("x-forwarded-for", "203.0.113.7")
        .send()
        .await
        .unwrap();
    assert_eq!(public_response.version(), reqwest::Version::HTTP_2);
    assert_eq!(public_response.text().await.unwrap(), "none");

    let anonymous_mtls = public_client
        .get(format!("https://localhost:{}/probe", mtls_address.port()))
        .send()
        .await;
    assert!(
        anonymous_mtls.is_err(),
        "mTLS alias must reject anonymous TLS"
    );

    let identity = reqwest::Identity::from_pem(material.client_identity_pem.as_bytes())
        .expect("test client identity");
    let mtls_client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .tls_backend_rustls()
        .tls_certs_only([root_certificate])
        .identity(identity)
        .build()
        .unwrap();
    let thumbprint = mtls_client
        .get(format!("https://localhost:{}/probe", mtls_address.port()))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_ne!(thumbprint, "none");
    assert_eq!(thumbprint.len(), 43);

    drop(mtls_client);
    drop(public_client);
    public_handle.stop(true).await;
    mtls_handle.stop(true).await;
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
