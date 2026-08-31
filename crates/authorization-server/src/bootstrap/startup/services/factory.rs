use super::super::tenant_runtime::{ProcessRuntime, TenantHostIndex, TenantRuntimeRegistry};
use super::*;
use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{Extensions, Service, ServiceRequest, ServiceResponse};
use actix_web::error::ErrorRequestTimeout;
use actix_web::middleware::{Next, from_fn};
use actix_web::{App, Error, HttpResponse, HttpServer, web};
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
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

#[derive(Default)]
struct WorkerTenantDataCache {
    index: Option<Arc<TenantHostIndex>>,
    by_host: HashMap<String, Rc<Extensions>>,
}

impl WorkerTenantDataCache {
    fn resolve(&mut self, index: Arc<TenantHostIndex>, host: &str) -> Option<Rc<Extensions>> {
        let changed = match &self.index {
            Some(current) => !Arc::ptr_eq(current, &index),
            None => true,
        };
        if changed {
            self.index = Some(Arc::clone(&index));
            self.by_host.clear();
        }

        let runtime = index.by_host.get(host)?;
        Some(
            self.by_host
                .entry(host.to_owned())
                .or_insert_with(|| runtime.assembly().app_data_container())
                .clone(),
        )
    }
}

async fn bind_tenant_app_data<B>(
    registry: TenantRuntimeRegistry,
    cache: Rc<RefCell<WorkerTenantDataCache>>,
    mut request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, Error>
where
    B: MessageBody + 'static,
{
    let Some(host) = crate::bootstrap::cors::canonical_request_host(request.head()) else {
        return Ok(request
            .into_response(HttpResponse::NotFound().finish())
            .map_into_right_body());
    };
    let container = cache.borrow_mut().resolve(registry.load(), &host);
    let Some(container) = container else {
        return Ok(request
            .into_response(HttpResponse::NotFound().finish())
            .map_into_right_body());
    };

    request.add_data_container(container);
    Ok(next.call(request).await?.map_into_left_body())
}

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
/// function so worker creation cannot repeat persistence/provider initialization.
pub(super) async fn run(
    process: Arc<ProcessRuntime>,
    registry: TenantRuntimeRegistry,
) -> anyhow::Result<()> {
    let config = process.config.clone();
    let route_settings = process.route_settings.clone();
    let perf_metrics_enabled = process.perf_metrics_enabled;
    let control_discovery = process.control_discovery.clone();
    let control_tenant_id = web::Data::new(crate::bootstrap::routes::ControlTenantId::new(
        process.control_tenant_id,
    ));
    let database_pool_metrics = process.database_pool_metrics.clone();
    let bind = config.string("BIND", "0.0.0.0:8000");
    let addr: SocketAddr = bind.parse()?;
    let direct_tls = crate::bootstrap::direct_tls_listeners(&config, &route_settings)?;
    let ui_static_dir = crate::bootstrap::ui_release::resolve(&config).await?;
    tracing::info!("nazo-oauth-server(actix-web) listening on {addr}");

    let server = HttpServer::new(move || {
        let cache = Rc::new(RefCell::new(WorkerTenantDataCache::default()));
        let tenant_registry = registry.clone();
        let mut tenant_scope = web::scope("");
        if let Some(path) = ui_static_dir.clone() {
            tenant_scope = tenant_scope.service(crate::bootstrap::ui_static_files(path));
        }
        let settings = Arc::clone(&route_settings);
        let cors_registry = registry.clone();
        tenant_scope = tenant_scope.configure(move |cfg| {
            crate::bootstrap::routes::configure_dynamic(
                cfg,
                &settings,
                perf_metrics_enabled,
                cors_registry.clone(),
            )
        });
        let tenant_scope = tenant_scope.wrap(from_fn(move |request, next| {
            bind_tenant_app_data(tenant_registry.clone(), Rc::clone(&cache), request, next)
        }));

        App::new()
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
            .app_data(database_pool_metrics.clone())
            .app_data(control_discovery.clone())
            .app_data(control_tenant_id.clone())
            .app_data(web::Data::new(registry.clone()))
            .service(tenant_scope)
    })
    .client_request_timeout(HTTP_CLIENT_REQUEST_TIMEOUT)
    .max_connections(HTTP_MAX_CONNECTIONS_PER_WORKER)
    .on_connect(crate::http::mtls::capture_direct_tls_client_certificate);
    let (server, tls_reloader) = if let Some(listeners) = direct_tls {
        tracing::info!("nazo-oauth-server direct HTTPS listener on {addr}");
        tracing::info!(
            "nazo-oauth-server direct mTLS listener on {}",
            listeners.mtls_bind
        );
        let snapshots = listeners.snapshots.clone();
        let reload_interval = listeners.reload_interval;
        let server = server
            .bind_rustls_0_23(addr, listeners.public)?
            .bind_rustls_0_23(listeners.mtls_bind, listeners.mtls)?;
        let reloader = crate::bootstrap::spawn_direct_tls_reloader(snapshots, reload_interval);
        (server, Some(reloader))
    } else {
        (server.bind(addr)?, None)
    };
    let result = server.run().await;
    if let Some(reloader) = tls_reloader {
        reloader.abort();
        let _ = reloader.await;
    }
    result?;
    Ok(())
}

#[cfg(test)]
#[path = "../../../../tests/unit/bootstrap/startup/services/factory.rs"]
mod tests;
