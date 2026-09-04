use super::*;
use actix_web::body::EitherBody;
use actix_web::dev::Extensions;
use actix_web::{App, HttpResponse, test, web};
use arc_swap::ArcSwap;
use futures_util::{StreamExt as _, stream};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

#[test]
async fn direct_tls_sni_and_http_host_must_select_the_same_tenant() {
    assert!(direct_tls_host_matches(None, "tenant-a.example"));
    assert!(direct_tls_host_matches(
        Some("tenant-a.example"),
        "tenant-a.example"
    ));
    assert!(!direct_tls_host_matches(
        Some("tenant-a.example"),
        "tenant-b.example"
    ));
}

async fn test_request_timeout<B>(
    request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody + 'static,
{
    request_timeout_with_duration(request, next, Duration::from_millis(10)).await
}

fn delayed_payload() -> actix_web::dev::Payload {
    let stream = stream::once(async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok::<web::Bytes, actix_web::error::PayloadError>(web::Bytes::from_static(
            br#"{"value":"ok"}"#,
        ))
    });
    let stream: Pin<
        Box<dyn futures_util::Stream<Item = Result<web::Bytes, actix_web::error::PayloadError>>>,
    > = Box::pin(stream);
    actix_web::dev::Payload::from(stream)
}

#[actix_web::test]
async fn request_timeout_covers_typed_json_extractor() {
    let app = test::init_service(App::new().wrap(from_fn(test_request_timeout)).route(
        "/json",
        web::post().to(|_: web::Json<serde_json::Value>| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = test::TestRequest::post()
        .uri("/json")
        .insert_header(("content-type", "application/json"))
        .to_request();
    let (request, _) = request.replace_payload(delayed_payload());
    let error = test::try_call_service(&app, request)
        .await
        .expect_err("slow JSON body must time out");

    assert_eq!(
        error.as_response_error().status_code(),
        actix_web::http::StatusCode::REQUEST_TIMEOUT
    );
}

#[actix_web::test]
async fn request_timeout_covers_raw_payload_extractor() {
    let app = test::init_service(App::new().wrap(from_fn(test_request_timeout)).route(
        "/raw",
        web::post().to(|mut payload: web::Payload| async move {
            while payload.next().await.is_some() {}
            HttpResponse::Ok().finish()
        }),
    ))
    .await;

    let request = test::TestRequest::post().uri("/raw").to_request();
    let (request, _) = request.replace_payload(delayed_payload());
    let error = test::try_call_service(&app, request)
        .await
        .expect_err("slow raw payload must time out");

    assert_eq!(
        error.as_response_error().status_code(),
        actix_web::http::StatusCode::REQUEST_TIMEOUT
    );
}

async fn tenant_issuer(issuer: web::Data<&'static str>) -> HttpResponse {
    HttpResponse::Ok().body(*issuer.get_ref())
}

#[derive(Clone)]
struct TestTenantData {
    issuer: web::Data<&'static str>,
    context: web::Data<nazo_identity::TenantContext>,
}

impl TestTenantData {
    fn system(issuer: &'static str) -> Self {
        Self {
            issuer: web::Data::new(issuer),
            context: web::Data::new(nazo_identity::TenantContext::default_system()),
        }
    }

    fn tenant(issuer: &'static str, tenant_id: u128) -> Self {
        let mut context = nazo_identity::TenantContext::default_system();
        context.tenant_id = nazo_identity::TenantId::new(uuid::Uuid::from_u128(tenant_id))
            .expect("non-zero test tenant id");
        Self {
            issuer: web::Data::new(issuer),
            context: web::Data::new(context),
        }
    }
}

type TestTenantIndex = HashMap<String, TestTenantData>;

#[derive(Default)]
struct TestWorkerCache {
    index: Option<Arc<TestTenantIndex>>,
    by_host: HashMap<String, Rc<Extensions>>,
}

async fn bind_test_tenant<B>(
    registry: Arc<ArcSwap<TestTenantIndex>>,
    cache: Rc<RefCell<TestWorkerCache>>,
    builds: Rc<Cell<usize>>,
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
    let index = registry.load_full();
    let container = {
        let mut cache = cache.borrow_mut();
        let changed = match &cache.index {
            Some(current) => !Arc::ptr_eq(current, &index),
            None => true,
        };
        if changed {
            cache.index = Some(Arc::clone(&index));
            cache.by_host.clear();
        }
        if let Some(container) = cache.by_host.get(&host) {
            Some(Rc::clone(container))
        } else {
            index.get(&host).map(|tenant| {
                builds.set(builds.get() + 1);
                let mut extensions = Extensions::new();
                let _ = extensions.insert(tenant.issuer.clone());
                let _ = extensions.insert(tenant.context.clone());
                let container = Rc::new(extensions);
                cache.by_host.insert(host.clone(), Rc::clone(&container));
                container
            })
        }
    };
    let Some(container) = container else {
        return Ok(request
            .into_response(HttpResponse::NotFound().finish())
            .map_into_right_body());
    };
    request.add_data_container(container);
    Ok(next.call(request).await?.map_into_left_body())
}

#[actix_web::test]
async fn request_data_container_tracks_runtime_host_index_updates() {
    let registry = Arc::new(ArcSwap::from_pointee(HashMap::from([(
        "tenant-a.example".to_owned(),
        TestTenantData::tenant("https://tenant-a.example/v1", 2),
    )])));
    let cache = Rc::new(RefCell::new(TestWorkerCache::default()));
    let builds = Rc::new(Cell::new(0));
    let app = test::init_service(
        App::new().service(
            web::scope("")
                .app_data(web::Data::new("static-value-must-be-overridden"))
                .wrap(from_fn({
                    let registry = Arc::clone(&registry);
                    let cache = Rc::clone(&cache);
                    let builds = Rc::clone(&builds);
                    move |request, next| {
                        bind_test_tenant(
                            Arc::clone(&registry),
                            Rc::clone(&cache),
                            Rc::clone(&builds),
                            request,
                            next,
                        )
                    }
                }))
                .route("/issuer", web::get().to(tenant_issuer)),
        ),
    )
    .await;

    macro_rules! assert_issuer {
        ($host:expr, $expected:expr) => {{
            let request = test::TestRequest::get()
                .uri("/issuer")
                .insert_header(("host", $host))
                .to_request();
            let response = test::call_service(&app, request).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::OK);
            assert_eq!(test::read_body(response).await, $expected);
        }};
    }

    assert_issuer!("Tenant-A.Example.:443", "https://tenant-a.example/v1");
    assert_issuer!("tenant-a.example", "https://tenant-a.example/v1");
    assert_eq!(
        builds.get(),
        1,
        "same index must reuse the worker container"
    );

    let mut with_b = (*registry.load_full()).clone();
    with_b.insert(
        "tenant-b.example".to_owned(),
        TestTenantData::tenant("https://tenant-b.example", 3),
    );
    registry.store(Arc::new(with_b));
    assert_issuer!("tenant-b.example", "https://tenant-b.example");

    let mut replaced = (*registry.load_full()).clone();
    replaced.insert(
        "tenant-a.example".to_owned(),
        TestTenantData::tenant("https://tenant-a.example/v2", 2),
    );
    registry.store(Arc::new(replaced));
    assert_issuer!("tenant-a.example", "https://tenant-a.example/v2");

    let mut without_b = (*registry.load_full()).clone();
    without_b.remove("tenant-b.example");
    registry.store(Arc::new(without_b));
    let disabled = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/issuer")
            .insert_header(("host", "tenant-b.example"))
            .to_request(),
    )
    .await;
    assert_eq!(disabled.status(), actix_web::http::StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn deployment_routes_are_gated_but_runtime_modules_are_tenant_scoped() {
    let registry = Arc::new(ArcSwap::from_pointee(HashMap::from([
        (
            "system.example".to_owned(),
            TestTenantData::system("https://system.example"),
        ),
        (
            "tenant.example".to_owned(),
            TestTenantData::tenant("https://tenant.example", 2),
        ),
    ])));
    let cache = Rc::new(RefCell::new(TestWorkerCache::default()));
    let builds = Rc::new(Cell::new(0));
    let mut settings =
        crate::settings::Settings::from_config(&crate::config::ConfigSource::default())
            .expect("test settings");
    settings.endpoint.cors_allowed_origins = vec!["https://admin.example".to_owned()];

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(
                crate::bootstrap::routes::ControlTenantId::new(
                    nazo_identity::TenantContext::default_system().tenant_id,
                ),
            ))
            .service(
                web::scope("")
                    .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false))
                    .wrap(from_fn({
                        let registry = Arc::clone(&registry);
                        let cache = Rc::clone(&cache);
                        let builds = Rc::clone(&builds);
                        move |request, next| {
                            bind_test_tenant(
                                Arc::clone(&registry),
                                Rc::clone(&cache),
                                Rc::clone(&builds),
                                request,
                                next,
                            )
                        }
                    })),
            ),
    )
    .await;

    let preflight = |host: &'static str, path: &'static str| {
        test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri(path)
            .insert_header((actix_web::http::header::HOST, host))
            .insert_header((actix_web::http::header::ORIGIN, "https://admin.example"))
            .insert_header((
                actix_web::http::header::ACCESS_CONTROL_REQUEST_METHOD,
                "GET",
            ))
            .to_request()
    };

    let tenant_runtime_modules =
        test::call_service(&app, preflight("tenant.example", "/admin/runtime-modules")).await;
    assert_eq!(
        tenant_runtime_modules.status(),
        actix_web::http::StatusCode::OK
    );

    let system_route =
        test::call_service(&app, preflight("system.example", "/admin/runtime-modules")).await;
    assert_eq!(system_route.status(), actix_web::http::StatusCode::OK);

    let tenant_admin_route =
        test::call_service(&app, preflight("tenant.example", "/admin/users")).await;
    assert_eq!(tenant_admin_route.status(), actix_web::http::StatusCode::OK);
}

#[actix_web::test]
async fn legacy_custom_control_tenant_remains_authorized() {
    let control_tenant_id =
        nazo_identity::TenantId::new(uuid::Uuid::from_u128(42)).expect("non-zero test tenant id");
    let mut context = nazo_identity::TenantContext::default_system();
    context.tenant_id = control_tenant_id;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(context))
            .app_data(web::Data::new(
                crate::bootstrap::routes::ControlTenantId::new(control_tenant_id),
            ))
            .service(
                web::resource("/control")
                    .wrap(from_fn(crate::bootstrap::routes::control_tenant_only))
                    .route(web::get().to(HttpResponse::NoContent)),
            ),
    )
    .await;

    let response =
        test::call_service(&app, test::TestRequest::get().uri("/control").to_request()).await;
    assert_eq!(response.status(), actix_web::http::StatusCode::NO_CONTENT);
}
