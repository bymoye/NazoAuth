//! CORS per-policy constructors.
// 为路由组提供独立的 CORS 策略，避免统一宽泛的跨域配置。

use actix_cors::Cors;
#[cfg(test)]
use actix_web::http::header;

use crate::settings::Settings;

pub(crate) fn cors_well_known(settings: &Settings) -> Cors {
    nazo_http_actix::cors_well_known(&settings.endpoint.cors_allowed_origins)
}

pub(crate) fn cors_browser_token_management(settings: &Settings) -> Cors {
    nazo_http_actix::cors_browser_token_management(&settings.endpoint.cors_allowed_origins)
}

pub(crate) fn cors_browser_userinfo(settings: &Settings) -> Cors {
    nazo_http_actix::cors_browser_userinfo(&settings.endpoint.cors_allowed_origins)
}

pub(crate) fn cors_auth_api(settings: &Settings) -> Cors {
    nazo_http_actix::cors_auth_api(&settings.endpoint.cors_allowed_origins)
}

pub(crate) fn cors_admin(settings: &Settings) -> Cors {
    nazo_http_actix::cors_admin(&settings.endpoint.cors_allowed_origins)
}

pub(crate) fn cors_scim(settings: &Settings) -> Cors {
    nazo_http_actix::cors_scim(&settings.endpoint.cors_allowed_origins)
}

#[cfg(test)]
#[path = "../../tests/in_source/src/bootstrap/tests/cors.rs"]
mod tests;
