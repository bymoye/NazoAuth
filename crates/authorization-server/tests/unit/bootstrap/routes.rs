use actix_web::{App, http::StatusCode, test};

use super::*;

#[actix_web::test]
async fn controller_slot_list_has_one_public_route_and_no_admin_get_alias() {
    let settings = Settings::from_config(&crate::config::ConfigSource::default()).unwrap();
    let app =
        test::init_service(App::new().configure(|cfg| configure(cfg, &settings, false))).await;

    let public = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/controller-registry/slots?deployment_id=deployment-a")
            .to_request(),
    )
    .await;
    assert_ne!(public.status(), StatusCode::NOT_FOUND);
    assert_ne!(public.status(), StatusCode::METHOD_NOT_ALLOWED);

    let old_admin_get = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/admin/controller-registry/slots?deployment_id=deployment-a")
            .to_request(),
    )
    .await;
    assert_eq!(
        old_admin_get.status(),
        StatusCode::NOT_FOUND,
        "the old GET path must not remain as a compatibility alias"
    );
}
