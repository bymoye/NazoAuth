//! 应用启动入口。
// 负责组装配置、外部连接、共享状态和 Actix HTTP server。

mod cors;
mod observability;
pub(crate) mod routes;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use actix_web::{
    App, Error, HttpServer,
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse},
    http::header::{self, HeaderMap, HeaderName, HeaderValue},
    middleware::{Next, from_fn},
    web,
};
use fred::{
    interfaces::ClientLike,
    prelude::{
        Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
    },
};

use crate::config::{ConfigSource, database_max_connections, database_url};
use crate::db::create_pool;
use crate::domain::{AppState, KeysetStore};
use crate::http::spawn_backchannel_logout_delivery_worker;
use crate::settings::Settings;
use crate::support::{
    configure_password_hash_limits, default_password_hash_max_concurrency,
    default_password_hash_queue_timeout_ms, initialize_dummy_password_hash, load_or_create_keyset,
};
use tracing::Instrument;

pub async fn run() -> anyhow::Result<()> {
    let config = ConfigSource::load()?;
    let _observability = observability::init(&config)?;
    let perf_metrics_enabled = config.bool("PERF_METRICS_ENABLED", false)?;
    let password_hash_max_concurrency = config.parse::<usize>(
        "PASSWORD_HASH_MAX_CONCURRENCY",
        default_password_hash_max_concurrency(),
    )?;
    let password_hash_queue_timeout_ms = config.parse::<u64>(
        "PASSWORD_HASH_QUEUE_TIMEOUT_MS",
        default_password_hash_queue_timeout_ms(),
    )?;
    configure_password_hash_limits(
        password_hash_max_concurrency,
        password_hash_queue_timeout_ms,
    )?;
    initialize_dummy_password_hash()?;

    // 配置只在启动阶段读取，运行期通过 AppState 共享不可变配置。
    let database_url = database_url(&config);
    let valkey_url = config.string("VALKEY_URL", "redis://127.0.0.1:6379/0");
    let valkey_command_timeout_ms = config.parse::<u64>("VALKEY_COMMAND_TIMEOUT_MS", 1_000)?;
    if valkey_command_timeout_ms == 0 {
        anyhow::bail!("VALKEY_COMMAND_TIMEOUT_MS must be greater than zero");
    }
    let valkey_command_timeout = Duration::from_millis(valkey_command_timeout_ms);

    // 数据库和 Valkey 客户端在 server factory 外创建，避免每个 worker 重复初始化。
    let diesel_db = create_pool(database_url.clone(), database_max_connections(&config)?)?;
    let mut valkey_builder = ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url)?);
    valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = valkey_command_timeout;
    });
    valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = valkey_command_timeout;
        connection.internal_command_timeout = valkey_command_timeout;
        connection.max_command_attempts = 1;
    });
    let valkey = valkey_builder.build()?;
    valkey.init().await?;

    let settings = Arc::new(Settings::from_config(&config)?);
    tokio::fs::create_dir_all(&settings.avatar_storage_dir)
        .await
        .ok();
    let keyset = KeysetStore::new(load_or_create_keyset(&settings).await?);
    spawn_keyset_lifecycle_task(settings.clone(), keyset.clone());

    let state = web::Data::new(AppState {
        diesel_db,
        valkey,
        settings,
        keyset,
    });
    spawn_backchannel_logout_delivery_worker(state.clone());

    let bind = config.string("BIND", "0.0.0.0:8000");
    let addr: SocketAddr = bind.parse()?;
    tracing::info!("nazo-oauth-server(actix-web) listening on {addr}");

    HttpServer::new(move || {
        App::new()
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
            .app_data(state.clone())
            .configure(|cfg| routes::configure(cfg, &state.settings, perf_metrics_enabled))
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

fn spawn_keyset_lifecycle_task(settings: Arc<Settings>, keyset: KeysetStore) {
    let interval = signing_key_refresh_interval(&settings);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            match load_or_create_keyset(&settings).await {
                Ok(next) => keyset.replace(next),
                Err(error) => terminate_after_keyset_refresh_failure(error),
            }
        }
    });
}

fn terminate_after_keyset_refresh_failure(error: anyhow::Error) -> ! {
    tracing::error!(
        error = %error,
        "signing key lifecycle refresh failed; terminating process"
    );
    #[cfg(test)]
    panic!("signing key lifecycle refresh failed: {error:#}");
    #[cfg(not(test))]
    std::process::abort();
}

fn signing_key_refresh_interval(settings: &Settings) -> Duration {
    let seconds = (settings.signing_key_prepublish_seconds / 2).clamp(1, 3_600);
    Duration::from_secs(seconds as u64)
}

async fn security_headers<B>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody,
{
    let is_check_session_iframe = req.path() == "/check_session";
    let mut response = next.call(req).await?;
    apply_security_headers(response.headers_mut(), is_check_session_iframe);
    Ok(response)
}

fn apply_security_headers(headers: &mut HeaderMap, is_check_session_iframe: bool) {
    if !is_check_session_iframe {
        insert_static_header(headers, header::X_FRAME_OPTIONS, "DENY");
        insert_static_header(
            headers,
            HeaderName::from_static("content-security-policy"),
            "frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
        );
    } else {
        insert_static_header(
            headers,
            HeaderName::from_static("content-security-policy"),
            "base-uri 'none'; object-src 'none'",
        );
    }
    insert_static_header(
        headers,
        HeaderName::from_static("referrer-policy"),
        "no-referrer",
    );
    insert_static_header(
        headers,
        HeaderName::from_static("permissions-policy"),
        "interest-cohort=()",
    );
    insert_static_header(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
}

fn insert_static_header(headers: &mut HeaderMap, name: HeaderName, value: &'static str) {
    if !headers.contains_key(&name) {
        headers.insert(name, HeaderValue::from_static(value));
    }
}

#[cfg(test)]
#[path = "../../tests/in_source/src/bootstrap/tests/bootstrap.rs"]
mod tests;
