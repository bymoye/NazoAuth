use super::{ServiceAssembly, *};
use actix_web::body::MessageBody;
use actix_web::dev::Service;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::error::ErrorRequestTimeout;
use actix_web::middleware::Next;
use actix_web::middleware::from_fn;
use actix_web::{App, Error, HttpServer, web};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;
use tracing::Instrument;

/// Bounds the complete request future, including typed extractors and handlers
/// that drain `web::Payload` themselves. Actix's client request timeout only
/// covers request-head parsing, so this application-level guard is required to
/// close a connection whose body trickles after the head has been accepted.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Keep the head timeout explicit even though Actix has a default. This
/// protects the boundary if the framework default changes during an upgrade.
const HTTP_CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// `max_connections` is per worker in Actix. Four thousand is below the
/// framework default (25,000) while retaining headroom for normal API use.
const HTTP_MAX_CONNECTIONS_PER_WORKER: usize = 4_096;

async fn request_timeout<B>(
    request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody + 'static,
{
    request_timeout_with_duration(request, next, HTTP_REQUEST_TIMEOUT).await
}

async fn request_timeout_with_duration<B>(
    request: ServiceRequest,
    next: Next<B>,
    duration: Duration,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody + 'static,
{
    timeout(duration, next.call(request))
        .await
        .map_err(|_| ErrorRequestTimeout("request exceeded the configured time limit"))?
}

/// Owns the Actix worker factory, middleware, route registration, and
/// listener setup.  All application data is assembled before entering this
/// function so worker creation cannot repeat database/Valkey initialization.
pub(super) async fn run(assembly: ServiceAssembly) -> anyhow::Result<()> {
    let ServiceAssembly {
        startup,
        core,
        identity,
    } = assembly;
    let super::super::configuration::StartupConfiguration {
        config,
        perf_metrics_enabled,
        settings,
        control_discovery,
        mtls_certificate_source,
        readiness_dependencies,
        initial_admin_bootstrap,
        ..
    } = startup;

    let bind = config.string("BIND", "0.0.0.0:8000");
    let addr: SocketAddr = bind.parse()?;
    let direct_tls = crate::bootstrap::direct_tls_listener(&config, &settings)?;
    let ui_static_dir = crate::bootstrap::ui_release::resolve(&config).await?;
    tracing::info!("nazo-oauth-server(actix-web) listening on {addr}");

    let server = HttpServer::new(move || {
        let app = App::new()
            .wrap(from_fn(request_timeout))
            .wrap_fn(|req, service| {
                let method = req.method().clone();
                let path = req.path().to_owned();
                let started = std::time::Instant::now();
                let span = tracing::info_span!(
                    "http.request",
                    "otel.kind" = "server",
                    "http.request.method" = %method,
                    "url.path" = %path
                );
                let future = service.call(req);
                async move {
                    let result = future.await;
                    if let Ok(response) = &result {
                        let status = response.status().as_u16();
                        let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
                        tracing::info!(
                            monotonic_counter.http_server_requests = 1_u64,
                            histogram.http_server_request_duration_ms = elapsed_ms,
                            "http.request.method" = %method,
                            "http.response.status_code" = status as i64,
                            "url.path" = %path,
                            "HTTP request completed"
                        );
                    }
                    result
                }
                .instrument(span)
            })
            .wrap(from_fn(security_headers))
            .app_data(identity.runtime_module_admin_endpoint.clone())
            .app_data(identity.authorization_decision_endpoint.clone())
            .app_data(identity.authorization_endpoint.clone())
            .app_data(core.authorization_service.clone())
            .app_data(core.token_service.clone());
        #[cfg(not(test))]
        let app = app.app_data(core.token_management_endpoint.clone());
        let app = app.app_data(core.userinfo_endpoint.clone());
        let app = app
            .app_data(mtls_certificate_source.clone())
            .app_data(readiness_dependencies.clone())
            .app_data(control_discovery.clone())
            .app_data(initial_admin_bootstrap.clone())
            .app_data(core.token_endpoint_handles.clone())
            .app_data(core.ciba_service.clone())
            .app_data(core.ciba_users.clone())
            .app_data(core.ciba_config.clone())
            .app_data(core.conformance_leases.clone())
            .app_data(core.token_issuance_config.clone())
            .app_data(core.device_service.clone())
            .app_data(core.device_grants.clone())
            .app_data(identity.device_decision_handles.clone())
            .app_data(core.device_config.clone());
        let app = app
            .app_data(core.authorization_config.clone())
            .app_data(core.authorization_runtime.clone())
            .app_data(core.metadata_handles.clone())
            .app_data(identity.admin_sessions.clone())
            .app_data(identity.admin_federation.clone())
            .app_data(identity.session_profiles.clone())
            .app_data(identity.session_management_endpoint.clone())
            .app_data(identity.profile_logout_endpoint.clone())
            .app_data(identity.profile_account_endpoint.clone())
            .app_data(identity.oidc_logout.clone())
            .app_data(identity.csrf_http_config.clone())
            .app_data(identity.mfa_profiles.clone())
            .app_data(identity.account_profiles.clone())
            .app_data(identity.avatar_profiles.clone())
            .app_data(identity.profile_access_requests.clone())
            .app_data(identity.profile_federation.clone())
            .app_data(core.resource_server_http_data.clone())
            .app_data(identity.admin_users.clone())
            .app_data(identity.admin_user_registration.clone())
            .app_data(identity.admin_grants.clone())
            .app_data(identity.admin_access_requests.clone())
            .app_data(identity.mtls_trust_anchors.clone())
            .app_data(identity.admin_access_delivery.clone())
            .app_data(identity.admin_access_request_config.clone())
            .app_data(core.admin_client_service.clone())
            .app_data(core.admin_client_config.clone())
            .app_data(identity.client_ip_config.clone())
            .app_data(identity.auth_request_limiter.clone())
            .app_data(identity.token_management_limiter.clone())
            .app_data(identity.local_registration_endpoint.clone())
            .app_data(identity.password_login_endpoint.clone())
            .app_data(identity.passkey_login_endpoint.clone())
            .app_data(identity.passkey_profile_endpoint.clone())
            .app_data(identity.federation.clone())
            .app_data(identity.federation_http_config.clone())
            .app_data(core.dynamic_registration_handles.clone())
            .app_data(core.scim_endpoint.clone());
        let app = if let Some(endpoint) = core.credential_issuer_endpoint.clone() {
            app.app_data(endpoint)
        } else {
            app
        };
        let app = if let Some(service) = core.credential_dataset_admin.clone() {
            app.app_data(service)
        } else {
            app
        };
        let app = if let Some(endpoint) = core.presentation_endpoint.clone() {
            app.app_data(endpoint)
        } else {
            app
        };
        let app = if let Some(validator) = core.client_attestation_validator.clone() {
            app.app_data(web::Data::from(validator))
        } else {
            app
        };
        let app = if let Some(path) = ui_static_dir.clone() {
            app.service(crate::bootstrap::ui_static_files(path))
        } else {
            app
        };
        app.configure(|cfg| {
            crate::bootstrap::routes::configure(cfg, &settings, perf_metrics_enabled)
        })
    })
    .client_request_timeout(HTTP_CLIENT_REQUEST_TIMEOUT)
    .max_connections(HTTP_MAX_CONNECTIONS_PER_WORKER)
    .on_connect(|io, extensions| {
        let Some(stream) = io.downcast_ref::<
            actix_tls::accept::rustls_0_23::TlsStream<actix_web::rt::net::TcpStream>,
        >()
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
        if let Some(identity) = crate::http::mtls::certificate_der_identity(certificate.as_ref()) {
            extensions.insert(identity);
        }
    })
    .bind(addr)?;
    let server = if let Some((tls_addr, acceptor)) = direct_tls {
        tracing::info!("nazo-oauth-server direct mTLS listener on {tls_addr}");
        server.bind_rustls_0_23(tls_addr, acceptor)?
    } else {
        server
    };
    server.run().await?;
    Ok(())
}

#[cfg(test)]
#[path = "../../../../tests/unit/bootstrap/startup/services/factory.rs"]
mod tests;
