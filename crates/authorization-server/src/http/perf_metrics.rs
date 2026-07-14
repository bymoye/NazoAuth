use actix_web::HttpResponse;
use nazo_postgres::db_pool_metrics;
use serde_json::json;

pub(crate) async fn perf_metrics() -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "db_pool": db_pool_metrics()
    }))
}
