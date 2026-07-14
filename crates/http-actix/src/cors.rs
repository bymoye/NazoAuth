use actix_cors::Cors;
use actix_web::http::header;

fn apply_allowed_origins(mut cors: Cors, allowed_origins: &[String]) -> Cors {
    for origin in allowed_origins {
        cors = cors.allowed_origin(origin);
    }
    cors
}

pub fn cors_well_known(allowed_origins: &[String]) -> Cors {
    apply_allowed_origins(
        Cors::default()
            .allowed_methods(vec!["GET", "HEAD"])
            .allowed_headers(vec![header::ACCEPT])
            .expose_headers(vec![header::RETRY_AFTER])
            .max_age(3600),
        allowed_origins,
    )
}

fn public_oauth_cors(allowed_origins: &[String], methods: Vec<&str>) -> Cors {
    apply_allowed_origins(
        Cors::default()
            .allowed_methods(methods)
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::HeaderName::from_static("dpop"),
            ])
            .expose_headers(vec![
                header::WWW_AUTHENTICATE,
                header::HeaderName::from_static("dpop-nonce"),
                header::RETRY_AFTER,
            ])
            .max_age(0),
        allowed_origins,
    )
}

pub fn cors_browser_token_management(allowed_origins: &[String]) -> Cors {
    public_oauth_cors(allowed_origins, vec!["POST"])
}

pub fn cors_browser_userinfo(allowed_origins: &[String]) -> Cors {
    public_oauth_cors(allowed_origins, vec!["GET", "POST"])
}

fn credentialed_api_cors(allowed_origins: &[String]) -> Cors {
    apply_allowed_origins(
        Cors::default()
            .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE"])
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::HeaderName::from_static("x-csrf-token"),
            ])
            .supports_credentials()
            .max_age(3600),
        allowed_origins,
    )
}

pub fn cors_auth_api(allowed_origins: &[String]) -> Cors {
    credentialed_api_cors(allowed_origins)
}

pub fn cors_admin(allowed_origins: &[String]) -> Cors {
    credentialed_api_cors(allowed_origins)
}

pub fn cors_scim(allowed_origins: &[String]) -> Cors {
    apply_allowed_origins(
        Cors::default()
            .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE"])
            .allowed_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
            .max_age(3600),
        allowed_origins,
    )
}
