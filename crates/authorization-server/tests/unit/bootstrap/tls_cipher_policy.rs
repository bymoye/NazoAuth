use super::*;
use rustls::{ClientConfig, RootCertStore, pki_types::pem::PemObject};
use std::sync::Arc;

#[actix_web::test]
async fn both_direct_listeners_enforce_fapi_tls12_policy_and_retain_tls13_suites() {
    use rustls::crypto::aws_lc_rs::cipher_suite::*;

    for (algorithm, rsa) in [
        (&rcgen::PKCS_RSA_SHA256, true),
        (&rcgen::PKCS_ECDSA_P256_SHA256, false),
    ] {
        let root = std::env::temp_dir().join(format!("nazoauth-ciphers-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let material = write_test_tls_material_with_server_algorithm(&root, false, algorithm);
        let config = direct_tls_config(&material);
        let settings = Settings::from_config(&config).unwrap();
        let listeners = direct_tls_listeners(&config, &settings).unwrap().unwrap();
        for (listener_name, listener) in [("public", listeners.public), ("mtls", listeners.mtls)] {
            let builder = HttpServer::new(|| {
                App::new().route(
                    "/probe",
                    web::get().to(|| async { HttpResponse::Ok().finish() }),
                )
            })
            .workers(1)
            .bind_rustls_0_23(("127.0.0.1", 0), listener)
            .unwrap();
            let url = format!("https://localhost:{}/probe", builder.addrs()[0].port());
            let server = builder.run();
            let handle = server.handle();
            actix_web::rt::spawn(server);

            for (suite, expected) in [
                (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, rsa),
                (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, rsa),
                (TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, false),
                (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, false),
                (TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, false),
                (TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, false),
                (TLS13_AES_128_GCM_SHA256, true),
                (TLS13_AES_256_GCM_SHA384, true),
                (TLS13_CHACHA20_POLY1305_SHA256, true),
            ] {
                let mut provider = rustls::crypto::aws_lc_rs::default_provider();
                provider.cipher_suites = vec![suite];
                let mut roots = RootCertStore::empty();
                for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(
                    material.client_ca_pem.as_bytes(),
                ) {
                    roots.add(certificate.unwrap()).unwrap();
                }
                let client_identity = material.client_identity_pem.as_bytes();
                let tls = ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_protocol_versions(&[suite.version()])
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_client_auth_cert(
                        rustls::pki_types::CertificateDer::pem_slice_iter(client_identity)
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap(),
                        rustls::pki_types::PrivateKeyDer::from_pem_slice(client_identity).unwrap(),
                    )
                    .unwrap();
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .pool_max_idle_per_host(0)
                    .timeout(std::time::Duration::from_secs(5))
                    .tls_backend_preconfigured(tls)
                    .build()
                    .unwrap();
                let response = client.get(&url).send().await;
                assert_eq!(
                    response.is_ok(),
                    expected,
                    "{listener_name}, RSA={rsa}, {:?}: {response:?}",
                    suite.suite()
                );
                if let Ok(response) = response {
                    assert!(response.status().is_success());
                }
            }
            handle.stop(true).await;
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
