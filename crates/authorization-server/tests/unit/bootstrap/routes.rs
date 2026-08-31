use actix_web::{App, http::StatusCode, test, web};

use super::*;

#[actix_web::test]
async fn controller_slot_list_has_one_control_tenant_route_and_no_admin_get_alias() {
    let settings = Settings::from_config(&crate::config::ConfigSource::default()).unwrap();
    let context = nazo_identity::TenantContext::default_system();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(context))
            .app_data(web::Data::new(ControlTenantId::new(context.tenant_id)))
            .configure(|cfg| configure(cfg, &settings, false)),
    )
    .await;

    let control = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/controller-registry/slots?deployment_id=deployment-a")
            .to_request(),
    )
    .await;
    assert_ne!(control.status(), StatusCode::NOT_FOUND);
    assert_ne!(control.status(), StatusCode::METHOD_NOT_ALLOWED);

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
