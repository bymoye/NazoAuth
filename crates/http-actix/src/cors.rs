use actix_cors::Cors;
use actix_web::{
    dev::RequestHead,
    http::header::{self, HeaderValue},
};

fn apply_allowed_origins(mut cors: Cors, allowed_origins: &[String]) -> Cors {
    for origin in allowed_origins {
        cors = cors.allowed_origin(origin);
    }
    cors
}

fn well_known_cors() -> Cors {
    Cors::default()
        .allowed_methods(vec!["GET", "HEAD"])
        .allowed_headers(vec![header::ACCEPT])
        .expose_headers(vec![header::RETRY_AFTER])
        .max_age(3600)
}

pub fn cors_well_known(allowed_origins: &[String]) -> Cors {
    apply_allowed_origins(well_known_cors(), allowed_origins)
}

pub fn cors_well_known_with_origin_predicate<F>(predicate: F) -> Cors
where
    F: Fn(&HeaderValue, &RequestHead) -> bool + 'static,
{
    well_known_cors().allowed_origin_fn(predicate)
}

fn public_oauth_cors(methods: Vec<&str>) -> Cors {
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
        .max_age(0)
}

pub fn cors_browser_token_management(allowed_origins: &[String]) -> Cors {
    apply_allowed_origins(public_oauth_cors(vec!["POST"]), allowed_origins)
}

pub fn cors_browser_token_management_with_origin_predicate<F>(predicate: F) -> Cors
where
    F: Fn(&HeaderValue, &RequestHead) -> bool + 'static,
{
    public_oauth_cors(vec!["POST"]).allowed_origin_fn(predicate)
}

pub fn cors_browser_userinfo(allowed_origins: &[String]) -> Cors {
    apply_allowed_origins(public_oauth_cors(vec!["GET", "POST"]), allowed_origins)
}

pub fn cors_browser_userinfo_with_origin_predicate<F>(predicate: F) -> Cors
where
    F: Fn(&HeaderValue, &RequestHead) -> bool + 'static,
{
    public_oauth_cors(vec!["GET", "POST"]).allowed_origin_fn(predicate)
}

fn credentialed_api_cors() -> Cors {
    Cors::default()
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE"])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-csrf-token"),
        ])
        .supports_credentials()
        .max_age(3600)
}

pub fn cors_auth_api(allowed_origins: &[String]) -> Cors {
    apply_allowed_origins(credentialed_api_cors(), allowed_origins)
}

pub fn cors_auth_api_with_origin_predicate<F>(predicate: F) -> Cors
where
    F: Fn(&HeaderValue, &RequestHead) -> bool + 'static,
{
    credentialed_api_cors().allowed_origin_fn(predicate)
}

pub fn cors_admin(allowed_origins: &[String]) -> Cors {
    apply_allowed_origins(credentialed_api_cors(), allowed_origins)
}

pub fn cors_admin_with_origin_predicate<F>(predicate: F) -> Cors
where
    F: Fn(&HeaderValue, &RequestHead) -> bool + 'static,
{
    credentialed_api_cors().allowed_origin_fn(predicate)
}

fn scim_cors() -> Cors {
    Cors::default()
        .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE"])
        .allowed_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(3600)
}

pub fn cors_scim(allowed_origins: &[String]) -> Cors {
    apply_allowed_origins(scim_cors(), allowed_origins)
}

pub fn cors_scim_with_origin_predicate<F>(predicate: F) -> Cors
where
    F: Fn(&HeaderValue, &RequestHead) -> bool + 'static,
{
    scim_cors().allowed_origin_fn(predicate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, http::StatusCode, test, web};

    #[actix_web::test]
    async fn dynamic_origin_predicate_keeps_the_token_endpoint_policy() {
        let app = test::init_service(
            App::new()
                .wrap(cors_browser_token_management_with_origin_predicate(
                    |origin, request| {
                        origin == "https://app.tenant-a.example"
                            && request
                                .headers
                                .get(header::HOST)
                                .is_some_and(|host| host == "tenant-a.example")
                    },
                ))
                .route("/token", web::post().to(HttpResponse::NoContent)),
        )
        .await;

        let allowed = test::call_service(
            &app,
            test::TestRequest::default()
                .method(actix_web::http::Method::OPTIONS)
                .uri("/token")
                .insert_header((header::HOST, "tenant-a.example"))
                .insert_header((header::ORIGIN, "https://app.tenant-a.example"))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .to_request(),
        )
        .await;
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(
            allowed.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static("https://app.tenant-a.example"))
        );

        let wrong_tenant = test::call_service(
            &app,
            test::TestRequest::default()
                .method(actix_web::http::Method::OPTIONS)
                .uri("/token")
                .insert_header((header::HOST, "tenant-b.example"))
                .insert_header((header::ORIGIN, "https://app.tenant-a.example"))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .to_request(),
        )
        .await;
        assert_eq!(wrong_tenant.status(), StatusCode::BAD_REQUEST);

        let wrong_method = test::call_service(
            &app,
            test::TestRequest::default()
                .method(actix_web::http::Method::OPTIONS)
                .uri("/token")
                .insert_header((header::HOST, "tenant-a.example"))
                .insert_header((header::ORIGIN, "https://app.tenant-a.example"))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                .to_request(),
        )
        .await;
        assert_eq!(wrong_method.status(), StatusCode::BAD_REQUEST);
    }
}
