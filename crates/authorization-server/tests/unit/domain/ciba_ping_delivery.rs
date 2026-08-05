use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    sync::Arc,
    thread,
    time::Duration,
};

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

use super::ciba_ping_tls::{CIBA_PING_TLS_MAX, CIBA_PING_TLS_MIN, apply_ciba_ping_tls_policy};

fn test_identity() -> (
    rustls::pki_types::PrivateKeyDer<'static>,
    rustls::pki_types::CertificateDer<'static>,
) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate test P-256 key");
    let certificate = CertificateParams::new(vec!["localhost".to_owned()])
        .expect("certificate params")
        .self_signed(&key)
        .expect("self-signed certificate");
    let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
    (private_key.into(), certificate.der().clone())
}

fn single_version_tls_server(
    version: &'static rustls::SupportedProtocolVersion,
) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let (key, certificate) = test_identity();
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
        .expect("configure single-version TLS server")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("configure TLS test identity");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS test server");
    let address = listener.local_addr().expect("read TLS test address");
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept TLS test connection");
        let connection =
            rustls::ServerConnection::new(Arc::new(config)).expect("create TLS server connection");
        let mut stream = rustls::StreamOwned::new(connection, stream);
        if stream.conn.complete_io(&mut stream.sock).is_ok() {
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .expect("write TLS test response");
        }
    });
    (address, handle)
}

async fn post_to_server(
    address: std::net::SocketAddr,
    server: thread::JoinHandle<()>,
) -> reqwest::Result<reqwest::Response> {
    let client =
        apply_ciba_ping_tls_policy(reqwest::Client::builder().danger_accept_invalid_certs(true))
            .expect("apply CIBA Ping TLS policy")
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build CIBA Ping test client");

    let result = client
        .post(format!("https://{address}/ciba-notification-endpoint"))
        .send()
        .await;
    server.join().expect("join TLS test server");
    result
}

async fn post_to_single_version_server(
    version: &'static rustls::SupportedProtocolVersion,
) -> reqwest::Result<reqwest::Response> {
    let (address, server) = single_version_tls_server(version);
    post_to_server(address, server).await
}

#[test]
fn ciba_ping_transport_policy_is_bounded_to_tls12_and_tls13() {
    assert!(matches!(CIBA_PING_TLS_MIN, reqwest::tls::Version::TLS_1_2));
    assert!(matches!(CIBA_PING_TLS_MAX, reqwest::tls::Version::TLS_1_3));
}

#[tokio::test]
async fn ciba_ping_transport_supports_the_tls12_fapi_baseline() {
    let response = post_to_single_version_server(&rustls::version::TLS12)
        .await
        .expect("CIBA Ping must interoperate with a TLS 1.2-only FAPI endpoint");

    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn ciba_ping_transport_supports_tls13() {
    let (address, server) = single_version_tls_server(&rustls::version::TLS13);
    let response = post_to_server(address, server)
        .await
        .expect("CIBA Ping must offer TLS 1.3 when the endpoint supports it");

    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
}
