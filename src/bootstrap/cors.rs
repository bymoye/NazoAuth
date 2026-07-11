//! CORS per-policy constructors.
// 为路由组提供独立的 CORS 策略，避免统一宽泛的跨域配置。

use actix_cors::Cors;
use actix_web::http::header;

use crate::settings::Settings;

fn apply_allowed_origins(mut cors: Cors, settings: &Settings) -> Cors {
    for origin in &settings.cors_allowed_origins {
        cors = cors.allowed_origin(origin);
    }
    cors
}

pub(crate) fn cors_well_known(settings: &Settings) -> Cors {
    let cors = Cors::default()
        .allowed_methods(vec!["GET", "HEAD"])
        .allowed_headers(vec![header::ACCEPT])
        .expose_headers(vec![header::RETRY_AFTER])
        .max_age(3600);
    apply_allowed_origins(cors, settings)
}

pub(crate) fn cors_browser_oauth(settings: &Settings) -> Cors {
    let cors = Cors::default()
        .allowed_methods(vec!["GET", "POST"])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("dpop"),
            header::HeaderName::from_static("x-csrf-token"),
        ])
        .expose_headers(vec![
            header::WWW_AUTHENTICATE,
            header::HeaderName::from_static("dpop-nonce"),
            header::RETRY_AFTER,
        ])
        .max_age(0);
    apply_allowed_origins(cors, settings)
}

pub(crate) fn cors_auth_api(settings: &Settings) -> Cors {
    let cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE"])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-csrf-token"),
        ])
        .supports_credentials()
        .max_age(3600);
    apply_allowed_origins(cors, settings)
}

pub(crate) fn cors_admin(settings: &Settings) -> Cors {
    let cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE"])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-csrf-token"),
        ])
        .supports_credentials()
        .max_age(3600);
    apply_allowed_origins(cors, settings)
}

pub(crate) fn cors_scim(settings: &Settings) -> Cors {
    let cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE"])
        .allowed_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(3600);
    apply_allowed_origins(cors, settings)
}

#[cfg(test)]
#[path = "../../tests/in_source/src/bootstrap/tests/cors.rs"]
mod tests;
