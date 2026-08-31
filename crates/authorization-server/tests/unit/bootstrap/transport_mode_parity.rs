use super::*;

use std::any::Any;

use actix_web::{App, HttpRequest, HttpResponse, HttpServer, web};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_http_actix::IpCidr;

struct ProbeEndpoint {
    client: reqwest::Client,
    url: String,
}

async fn mtls_probe(
    request: HttpRequest,
    trusted_proxy_cidrs: web::Data<Vec<IpCidr>>,
) -> HttpResponse {
    let thumbprint =
        crate::http::mtls::request_mtls_thumbprint(&request, trusted_proxy_cidrs.get_ref())
            .unwrap_or_else(|| "none".to_owned());
    HttpResponse::Ok().body(thumbprint)
}

fn capture_proxy_client_certificate(io: &dyn Any, extensions: &mut actix_web::dev::Extensions) {
    let Some(stream) = io
        .downcast_ref::<actix_tls::accept::rustls_0_23::TlsStream<actix_web::rt::net::TcpStream>>()
    else {
        return;
    };
    let Some(certificate) = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
    else {
        return;
    };
    extensions.insert(certificate.as_ref().to_vec());
}

async fn proxy_probe(
    request: HttpRequest,
    backend_url: web::Data<String>,
    client: web::Data<reqwest::Client>,
) -> HttpResponse {
    let Some(certificate) = request.conn_data::<Vec<u8>>() else {
        return HttpResponse::InternalServerError()
            .body("proxy did not capture client TLS identity");
    };
    let header_value = format!(":{}:", STANDARD.encode(certificate));
    let response = match client
        .get(backend_url.get_ref())
        .header("client-cert", header_value)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => return HttpResponse::BadGateway().body(error.to_string()),
    };
    let status = actix_web::http::StatusCode::from_u16(response.status().as_u16())
        .expect("reqwest status is a valid HTTP status");
    let body = match response.bytes().await {
        Ok(body) => body,
        Err(error) => return HttpResponse::BadGateway().body(error.to_string()),
    };
    HttpResponse::build(status).body(body)
}

async fn probe(endpoint: &ProbeEndpoint, forwarded_client_cert: Option<&str>) -> (u16, String) {
    let request = endpoint.client.get(&endpoint.url);
    let request = if let Some(value) = forwarded_client_cert {
        request.header("client-cert", value)
    } else {
        request
    };
    let response = request.send().await.expect("transport probe request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("transport probe body");
    (status, body)
}

#[actix_web::test]
async fn direct_tls_and_trusted_proxy_share_the_same_real_mtls_identity_contract() {
    let root = std::env::temp_dir().join(format!(
        "nazoauth-transport-parity-{}",
        uuid::Uuid::now_v7()
    ));
    std::fs::create_dir(&root).unwrap();
    let material = write_test_tls_material(&root);
    let config = direct_tls_config(&material);
    let settings = Settings::from_config(&config).unwrap();
    let direct_listeners = direct_tls_listeners(&config, &settings).unwrap().unwrap();
    let proxy_listeners = direct_tls_listeners(&config, &settings).unwrap().unwrap();

    let direct_app = || {
        App::new()
            .app_data(web::Data::new(
                crate::http::mtls::MtlsCertificateSource::new(
                    crate::http::mtls::MtlsCertificateSourceMode::DirectTls,
                ),
            ))
            .app_data(web::Data::new(Vec::<IpCidr>::new()))
            .route("/probe", web::get().to(mtls_probe))
    };
    let direct_public_builder = HttpServer::new(direct_app)
        .on_connect(crate::http::mtls::capture_direct_tls_client_certificate)
        .bind_rustls_0_23(("127.0.0.1", 0), direct_listeners.public)
        .unwrap();
    let direct_public_address = direct_public_builder.addrs()[0];
    let direct_public_server = direct_public_builder.run();
    let direct_public_handle = direct_public_server.handle();
    actix_web::rt::spawn(direct_public_server);

    let direct_mtls_builder = HttpServer::new(direct_app)
        .on_connect(crate::http::mtls::capture_direct_tls_client_certificate)
        .bind_rustls_0_23(("127.0.0.1", 0), direct_listeners.mtls)
        .unwrap();
    let direct_mtls_address = direct_mtls_builder.addrs()[0];
    let direct_mtls_server = direct_mtls_builder.run();
    let direct_mtls_handle = direct_mtls_server.handle();
    actix_web::rt::spawn(direct_mtls_server);

    let trusted_proxy_cidrs = vec![IpCidr::parse("127.0.0.0/8").unwrap()];
    let backend_app = {
        let trusted_proxy_cidrs = trusted_proxy_cidrs.clone();
        move || {
            App::new()
                .app_data(web::Data::new(
                    crate::http::mtls::MtlsCertificateSource::new(
                        crate::http::mtls::MtlsCertificateSourceMode::Rfc9440,
                    ),
                ))
                .app_data(web::Data::new(trusted_proxy_cidrs.clone()))
                .route("/probe", web::get().to(mtls_probe))
        }
    };
    let backend_builder = HttpServer::new(backend_app).bind(("127.0.0.1", 0)).unwrap();
    let backend_address = backend_builder.addrs()[0];
    let backend_server = backend_builder.run();
    let backend_handle = backend_server.handle();
    actix_web::rt::spawn(backend_server);

    let backend_url = format!("http://127.0.0.1:{}/probe", backend_address.port());
    let proxy_client = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let proxy_app = {
        let backend_url = backend_url.clone();
        let proxy_client = proxy_client.clone();
        move || {
            App::new()
                .app_data(web::Data::new(backend_url.clone()))
                .app_data(web::Data::new(proxy_client.clone()))
                .route("/probe", web::get().to(proxy_probe))
        }
    };
    let proxy_builder = HttpServer::new(proxy_app)
        .on_connect(capture_proxy_client_certificate)
        .bind_rustls_0_23(("127.0.0.1", 0), proxy_listeners.mtls)
        .unwrap();
    let proxy_address = proxy_builder.addrs()[0];
    let proxy_server = proxy_builder.run();
    let proxy_handle = proxy_server.handle();
    actix_web::rt::spawn(proxy_server);

    let root_certificate = reqwest::Certificate::from_pem(material.client_ca_pem.as_bytes())
        .expect("test root certificate");
    let anonymous_client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .tls_backend_rustls()
        .tls_certs_only([root_certificate.clone()])
        .build()
        .unwrap();
    let identity = reqwest::Identity::from_pem(material.client_identity_pem.as_bytes())
        .expect("test client identity");
    let client = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .https_only(true)
        .tls_backend_rustls()
        .tls_certs_only([root_certificate])
        .identity(identity)
        .build()
        .unwrap();
    let direct_mtls = ProbeEndpoint {
        client: client.clone(),
        url: format!("https://localhost:{}/probe", direct_mtls_address.port()),
    };
    let trusted_proxy = ProbeEndpoint {
        client: client.clone(),
        url: format!("https://localhost:{}/probe", proxy_address.port()),
    };
    let direct_public = ProbeEndpoint {
        client,
        url: format!("https://localhost:{}/probe", direct_public_address.port()),
    };

    assert!(
        anonymous_client
            .get(&trusted_proxy.url)
            .send()
            .await
            .is_err()
    );

    let direct_result = probe(&direct_mtls, None).await;
    let proxy_result = probe(&trusted_proxy, None).await;
    assert_eq!(direct_result, proxy_result);
    assert_ne!(direct_result.1, "none");

    let forged_header = ":AQ==:";
    assert_eq!(probe(&direct_public, Some(forged_header)).await.1, "none");
    assert_eq!(
        probe(&trusted_proxy, Some(forged_header)).await,
        proxy_result
    );

    direct_public_handle.stop(true).await;
    direct_mtls_handle.stop(true).await;
    proxy_handle.stop(true).await;
    backend_handle.stop(true).await;
    std::fs::remove_dir_all(root).unwrap();
}
