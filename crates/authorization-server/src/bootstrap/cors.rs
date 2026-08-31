//! CORS per-policy constructors.
// 为路由组提供独立的 CORS 策略，避免统一宽泛的跨域配置。

use actix_cors::Cors;
use actix_web::{
    dev::RequestHead,
    http::{
        Version,
        header::{HOST, HeaderValue},
        uri::Authority,
    },
};

use crate::{
    bootstrap::startup::tenant_runtime::TenantRuntimeRegistry,
    settings::{Settings, canonical_tenant_host},
};

pub(super) enum CorsPolicy<'a> {
    Static(&'a [String]),
    Dynamic(TenantRuntimeRegistry),
}

impl<'a> CorsPolicy<'a> {
    pub(super) fn from_settings(settings: &'a Settings) -> Self {
        Self::Static(&settings.endpoint.cors_allowed_origins)
    }

    pub(super) fn dynamic(registry: TenantRuntimeRegistry) -> Self {
        Self::Dynamic(registry)
    }

    pub(super) fn well_known(&self) -> Cors {
        match self {
            Self::Static(origins) => nazo_http_actix::cors_well_known(origins),
            Self::Dynamic(registry) => nazo_http_actix::cors_well_known_with_origin_predicate(
                origin_predicate(registry.clone()),
            ),
        }
    }

    pub(super) fn browser_token_management(&self) -> Cors {
        match self {
            Self::Static(origins) => nazo_http_actix::cors_browser_token_management(origins),
            Self::Dynamic(registry) => {
                nazo_http_actix::cors_browser_token_management_with_origin_predicate(
                    origin_predicate(registry.clone()),
                )
            }
        }
    }

    pub(super) fn browser_userinfo(&self) -> Cors {
        match self {
            Self::Static(origins) => nazo_http_actix::cors_browser_userinfo(origins),
            Self::Dynamic(registry) => {
                nazo_http_actix::cors_browser_userinfo_with_origin_predicate(origin_predicate(
                    registry.clone(),
                ))
            }
        }
    }

    pub(super) fn auth_api(&self) -> Cors {
        match self {
            Self::Static(origins) => nazo_http_actix::cors_auth_api(origins),
            Self::Dynamic(registry) => nazo_http_actix::cors_auth_api_with_origin_predicate(
                origin_predicate(registry.clone()),
            ),
        }
    }

    pub(super) fn admin(&self) -> Cors {
        match self {
            Self::Static(origins) => nazo_http_actix::cors_admin(origins),
            Self::Dynamic(registry) => nazo_http_actix::cors_admin_with_origin_predicate(
                origin_predicate(registry.clone()),
            ),
        }
    }

    pub(super) fn scim(&self) -> Cors {
        match self {
            Self::Static(origins) => nazo_http_actix::cors_scim(origins),
            Self::Dynamic(registry) => {
                nazo_http_actix::cors_scim_with_origin_predicate(origin_predicate(registry.clone()))
            }
        }
    }
}

pub(crate) fn canonical_request_host(request: &RequestHead) -> Option<String> {
    let authority = request
        .headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|_| request.version < Version::HTTP_2)
        .or_else(|| request.uri.authority().map(|authority| authority.as_str()))?
        .parse::<Authority>()
        .ok()?;
    if authority.as_str().contains('@') {
        return None;
    }
    canonical_tenant_host(authority.host()).ok()
}

fn origin_predicate(
    registry: TenantRuntimeRegistry,
) -> impl Fn(&HeaderValue, &RequestHead) -> bool + 'static {
    move |origin, request| {
        let Some(host) = canonical_request_host(request) else {
            return false;
        };
        let Some(runtime) = registry.resolve(&host) else {
            return false;
        };
        runtime
            .cors_allowed_origins()
            .iter()
            .any(|allowed| origin.as_bytes() == allowed.as_bytes())
    }
}

pub(crate) fn cors_well_known(settings: &Settings) -> Cors {
    CorsPolicy::from_settings(settings).well_known()
}

pub(crate) fn cors_browser_token_management(settings: &Settings) -> Cors {
    CorsPolicy::from_settings(settings).browser_token_management()
}

pub(crate) fn cors_browser_userinfo(settings: &Settings) -> Cors {
    CorsPolicy::from_settings(settings).browser_userinfo()
}

pub(crate) fn cors_auth_api(settings: &Settings) -> Cors {
    CorsPolicy::from_settings(settings).auth_api()
}

pub(crate) fn cors_admin(settings: &Settings) -> Cors {
    CorsPolicy::from_settings(settings).admin()
}

pub(crate) fn cors_scim(settings: &Settings) -> Cors {
    CorsPolicy::from_settings(settings).scim()
}

#[cfg(test)]
#[path = "../../tests/unit/bootstrap/cors.rs"]
mod tests;
