use super::*;

use actix_web::{App, HttpRequest, HttpServer, web};
use rustls::{
    ClientConfig, RootCertStore,
    client::ResolvesClientCert,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    sign::CertifiedKey,
};
use std::sync::Arc;

#[derive(Debug)]
struct PresentedKey(Arc<CertifiedKey>);

impl ResolvesClientCert for PresentedKey {
    fn resolve(&self, _: &[&[u8]], _: &[rustls::SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[actix_web::test]
async fn mtls_admits_tenant_keys_but_rejects_a_forged_certificate_verify_signature() {
    let root = std::env::temp_dir().join(format!("nazoauth-client-proof-{}", uuid::Uuid::now_v7()));
    let other = root.join("other");
    std::fs::create_dir_all(&other).unwrap();
    let material = write_test_tls_material(&root);
    let unrelated = write_test_tls_material(&other);
    let config = direct_tls_config(&material);
    let settings = Settings::from_config(&config).unwrap();
    let listeners = direct_tls_listeners(&config, &settings).unwrap().unwrap();
    let verifier = listeners.client_verifier;
    let builder = HttpServer::new(|| {
        App::new().route(
            "/probe",
            web::get().to(|request: HttpRequest| async move {
                request
                    .conn_data::<crate::http::mtls::MtlsClientCertificate>()
                    .map(|certificate| certificate.deployment_trusted_chain.to_string())
                    .unwrap_or_else(|| "absent".to_owned())
            }),
        )
    })
    .workers(1)
    .on_connect(move |io, extensions| {
        crate::http::mtls::capture_direct_tls_client_certificate(
            io,
            extensions,
            Some(verifier.as_ref()),
        );
    })
    .bind_rustls_0_23(("127.0.0.1", 0), listeners.mtls)
    .unwrap();
    let url = format!("https://localhost:{}/probe", builder.addrs()[0].port());
    let server = builder.run();
    let handle = server.handle();
    actix_web::rt::spawn(server);

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(material.client_ca_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let certificate_chain =
        CertificateDer::pem_slice_iter(unrelated.client_identity_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    for (version, correct_key) in [
        (&rustls::version::TLS12, true),
        (&rustls::version::TLS12, false),
        (&rustls::version::TLS13, true),
        (&rustls::version::TLS13, false),
    ] {
        let key_pem = if correct_key {
            &unrelated.client_identity_pem
        } else {
            &material.client_identity_pem
        };
        let key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap())
            .unwrap();
        // Intentionally bypass the client builder's certificate/key consistency
        // check so the negative case reaches the server's CertificateVerify.
        let resolver = PresentedKey(Arc::new(CertifiedKey::new(certificate_chain.clone(), key)));
        let tls = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_client_cert_resolver(Arc::new(resolver));
        let client = reqwest::Client::builder()
            .no_proxy()
            .pool_max_idle_per_host(0)
            .timeout(std::time::Duration::from_secs(5))
            .tls_backend_preconfigured(tls)
            .build()
            .unwrap();
        let response = client.get(&url).send().await;
        if correct_key {
            assert_eq!(
                response.unwrap().text().await.unwrap(),
                "false",
                "the unrelated CA is not deployment trust; OAuth must select tenant trust"
            );
        } else {
            assert!(
                response.is_err(),
                "TLS must reject proof made with a different private key"
            );
        }
    }
    handle.stop(true).await;
    std::fs::remove_dir_all(root).unwrap();
}
