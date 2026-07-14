//! HTTP 路由表。
// 本文件只声明 URL 到 handler 的映射，不承载业务逻辑。

use actix_web::web;
#[cfg(not(test))]
use nazo_http_actix::authorize_decision;
use nazo_http_actix::{
    admin_patch_runtime_module, admin_runtime_module_events, admin_runtime_modules,
    check_session_iframe, check_session_status, configure_mfa_challenge_route,
    configure_mfa_profile_routes, configure_passkey_login_routes, configure_passkey_profile_routes,
    discovery, fapi_resource, introspect, jwks, login, oauth_authorization_server_metadata,
    oauth_protected_resource_metadata, oidc_logout, profile_applications, profile_logout,
    profile_me, profile_update, register, revoke, send_code,
};
#[cfg(not(test))]
use nazo_http_actix::{
    client_configuration_delete, client_configuration_get, client_configuration_put,
    dynamic_client_registration, userinfo,
};

use crate::http::admin::{
    access_requests::{
        admin_access_requests, admin_approve_access_request, admin_reject_access_request,
    },
    clients::{
        create::admin_create_client, detail::admin_get_client, list::admin_clients,
        update::admin_patch_client,
    },
    federation::admin_federation_providers,
    grants::{admin_grants, admin_revoke_grant},
    users::{admin_patch_user, admin_users},
};
use crate::http::auth::{
    csrf::csrf,
    federation::{
        federation_provider_callback, federation_provider_list, federation_provider_start,
        federation_saml_acs,
    },
};
#[cfg(test)]
use crate::http::authorization::decision::authorize_decision;
use crate::http::authorization::{
    consent::authorize_consent,
    par::par,
    request::{authorize_get, authorize_post},
};
#[cfg(test)]
use crate::http::dynamic_client_registration::{
    client_configuration_delete, client_configuration_get, client_configuration_put,
    dynamic_client_registration,
};
use crate::http::perf_metrics::perf_metrics;
use crate::http::profile::{
    access_requests::{create_access_request, my_access_requests},
    avatar::{delete_avatar, get_avatar, upload_avatar},
    delivery::access_delivery,
    federation_links::{my_federation_links, unlink_my_federation_link},
};
#[cfg(test)]
use crate::http::scim::{
    scim_create_user, scim_delete_user, scim_get_user, scim_list_users, scim_patch_user,
    scim_replace_user, scim_resource_types, scim_schemas, scim_service_provider_config,
};
#[cfg(test)]
use crate::http::token::userinfo::userinfo;
use crate::http::token::{
    ciba::{
        backchannel_authentication, ciba_automated_decision, ciba_decision, ciba_verification,
        ciba_verification_page,
    },
    device::{
        device_authorization, device_decision, device_verification, device_verification_page,
    },
    dispatch::token,
};
use crate::http::well_known::{captcha_config, health};
use crate::settings::Settings;
#[cfg(not(test))]
use nazo_http_actix::{
    scim_create_user, scim_delete_user, scim_get_user, scim_list_users, scim_patch_user,
    scim_replace_user, scim_resource_types, scim_schemas, scim_service_provider_config,
};

use super::cors;

pub(crate) fn configure(
    cfg: &mut web::ServiceConfig,
    settings: &Settings,
    perf_metrics_enabled: bool,
) {
    cfg.service(
        web::resource("/health")
            .wrap(cors::cors_well_known(settings))
            .route(web::get().to(health)),
    );
    // NO CORS: /authorize
    cfg.route("/authorize", web::get().to(authorize_get))
        .route("/authorize", web::post().to(authorize_post))
        .route("/authorize/consent", web::get().to(authorize_consent))
        .route("/authorize/decision", web::post().to(authorize_decision))
        // NO CORS: /par
        .route("/par", web::post().to(par))
        .route("/bc-authorize", web::post().to(backchannel_authentication))
        .route("/ciba/{auth_req_id}", web::get().to(ciba_verification_page))
        // NO CORS: /device_authorization and device verification backchannel
        .route(
            "/device_authorization",
            web::post().to(device_authorization),
        )
        .route("/device", web::get().to(device_verification_page))
        .route("/device/verification", web::get().to(device_verification))
        .route("/device/decision", web::post().to(device_decision))
        // CORS: non-credentialed browser token management — /token
        .service(
            web::resource("/token")
                .wrap(cors::cors_browser_token_management(settings))
                .route(web::post().to(token)),
        )
        // NO CORS: /logout (backchannel)
        .service(
            web::resource("/logout")
                .route(web::get().to(oidc_logout))
                .route(web::post().to(oidc_logout)),
        )
        .route("/check_session", web::get().to(check_session_iframe))
        .route("/check_session/status", web::get().to(check_session_status))
        // CORS: non-credentialed browser token management — /revoke
        .service(
            web::resource("/revoke")
                .wrap(cors::cors_browser_token_management(settings))
                .route(web::post().to(revoke)),
        )
        // NO CORS: /introspect (backchannel)
        .route("/introspect", web::post().to(introspect))
        // NO CORS: /fapi/resource
        .service(
            web::resource("/fapi/resource")
                .route(web::get().to(fapi_resource))
                .route(web::post().to(fapi_resource)),
        )
        // CORS: cors_well_known — /.well-known/*
        .service(
            web::scope("/.well-known")
                .wrap(cors::cors_well_known(settings))
                .route("/openid-configuration", web::get().to(discovery))
                .route(
                    "/oauth-authorization-server",
                    web::get().to(oauth_authorization_server_metadata),
                )
                .route(
                    "/oauth-protected-resource",
                    web::get().to(oauth_protected_resource_metadata),
                )
                .route(
                    "/oauth-protected-resource/{tail:.*}",
                    web::get().to(oauth_protected_resource_metadata),
                ),
        )
        // CORS: cors_well_known — /jwks.json
        .service(
            web::resource("/jwks.json")
                .wrap(cors::cors_well_known(settings))
                .route(web::get().to(jwks)),
        )
        // CORS: non-credentialed browser bearer/DPoP access — /userinfo
        .service(
            web::resource("/userinfo")
                .wrap(cors::cors_browser_userinfo(settings))
                .route(web::get().to(userinfo))
                .route(web::post().to(userinfo)),
        )
        // CORS: cors_scim — /scim/v2/*
        .service(
            web::scope("/scim/v2")
                .wrap(cors::cors_scim(settings))
                .route(
                    "/ServiceProviderConfig",
                    web::get().to(scim_service_provider_config),
                )
                .route("/Schemas", web::get().to(scim_schemas))
                .route("/ResourceTypes", web::get().to(scim_resource_types))
                .service(
                    web::resource("/Users")
                        .route(web::get().to(scim_list_users))
                        .route(web::post().to(scim_create_user)),
                )
                .service(
                    web::resource("/Users/{user_id}")
                        .route(web::get().to(scim_get_user))
                        .route(web::put().to(scim_replace_user))
                        .route(web::patch().to(scim_patch_user))
                        .route(web::delete().to(scim_delete_user)),
                ),
        )
        // /auth scope — NO CORS for UI routes, cors_auth_api for /auth/me
        .service(
            web::scope("/auth")
                .route("/captcha-config", web::get().to(captcha_config))
                .route("/send-code", web::post().to(send_code))
                .route("/register", web::post().to(register))
                .route("/login", web::post().to(login))
                .route(
                    "/federation/providers",
                    web::get().to(federation_provider_list),
                )
                .route("/federation/saml/acs", web::post().to(federation_saml_acs))
                .route(
                    "/federation/{provider_id}/start",
                    web::get().to(federation_provider_start),
                )
                .route(
                    "/federation/{provider_id}/callback",
                    web::get().to(federation_provider_callback),
                )
                .configure(configure_passkey_login_routes)
                .service(web::scope("/mfa").configure(configure_mfa_challenge_route))
                .route("/csrf", web::get().to(csrf))
                // CORS: cors_auth_api — /auth/me/*
                .service(
                    web::scope("/me")
                        .wrap(cors::cors_auth_api(settings))
                        .route("", web::get().to(profile_me))
                        .route("", web::patch().to(profile_update))
                        .configure(configure_passkey_profile_routes)
                        .service(web::scope("/mfa").configure(configure_mfa_profile_routes))
                        .route("/avatar", web::post().to(upload_avatar))
                        .route("/avatar", web::get().to(get_avatar))
                        .route("/avatar", web::delete().to(delete_avatar))
                        .route("/applications", web::get().to(profile_applications))
                        .route("/federation/links", web::get().to(my_federation_links))
                        .route(
                            "/federation/links/{link_id}",
                            web::delete().to(unlink_my_federation_link),
                        )
                        .route("/access-requests", web::get().to(my_access_requests))
                        .route("/access-requests", web::post().to(create_access_request))
                        .route("/access-delivery", web::get().to(access_delivery)),
                )
                .route(
                    "/ciba-automated-decision",
                    web::get().to(ciba_automated_decision),
                )
                .route(
                    "/ciba-automated-decision",
                    web::post().to(ciba_automated_decision),
                )
                .route("/ciba/automated", web::get().to(ciba_automated_decision))
                .route("/ciba/automated", web::post().to(ciba_automated_decision))
                .route("/ciba/{auth_req_id}", web::get().to(ciba_verification))
                .route("/ciba/{auth_req_id}", web::post().to(ciba_decision))
                .route("/logout", web::post().to(profile_logout)),
        )
        // CORS: cors_admin — /admin/*
        .service(
            web::scope("/admin")
                .wrap(cors::cors_admin(settings))
                .route("/users", web::get().to(admin_users))
                .route("/users/{user_id}", web::patch().to(admin_patch_user))
                .route("/runtime-modules", web::get().to(admin_runtime_modules))
                .route(
                    "/runtime-modules/events",
                    web::get().to(admin_runtime_module_events),
                )
                .route(
                    "/runtime-modules/{module_id}",
                    web::patch().to(admin_patch_runtime_module),
                )
                .route("/clients", web::get().to(admin_clients))
                .route("/clients", web::post().to(admin_create_client))
                .route("/clients/{client_id}", web::get().to(admin_get_client))
                .route("/clients/{client_id}", web::patch().to(admin_patch_client))
                .route(
                    "/federation/providers",
                    web::get().to(admin_federation_providers),
                )
                .route("/grants", web::get().to(admin_grants))
                .route("/grants/revoke", web::post().to(admin_revoke_grant))
                .route("/access-requests", web::get().to(admin_access_requests))
                .route(
                    "/access-requests/{request_id}/approve",
                    web::post().to(admin_approve_access_request),
                )
                .route(
                    "/access-requests/{request_id}/reject",
                    web::post().to(admin_reject_access_request),
                ),
        );
    cfg.route("/register", web::post().to(dynamic_client_registration))
        .service(
            web::resource("/register/{client_id}")
                .route(web::get().to(client_configuration_get))
                .route(web::put().to(client_configuration_put))
                .route(web::delete().to(client_configuration_delete)),
        );
    if perf_metrics_enabled {
        cfg.route("/__perf/metrics", web::get().to(perf_metrics));
    }
}
