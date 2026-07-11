use super::*;
use std::path::PathBuf;

use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings, PasskeySettings,
    RateLimitSettings, RequestObjectJtiPolicy, SubjectType,
};
use crate::support::{ClientIpHeaderMode, IpCidr};

fn settings() -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://issuer.example".to_owned(),
        frontend_base_url: "https://app.example".to_owned(),
        cors_allowed_origins: vec!["https://app.example".to_owned()],
        default_audience: "resource://default".to_owned(),
        protected_resource_identifier: "https://issuer.example/fapi/resource".to_owned(),
        authorization_server_profile: AuthorizationServerProfile::Oauth2Baseline,
        ciba_security_profile:
            crate::settings::CibaSecurityProfile::FapiCibaId1PlainPrivateKeyJwtPoll,
        dpop_nonce_policy: DpopNoncePolicy::Required,
        request_object_jti_policy: RequestObjectJtiPolicy::Optional,
        session_cookie_name: "sid".to_owned(),
        csrf_cookie_name: "csrf".to_owned(),
        cookie_secure: true,
        session_ttl_seconds: 3600,
        auth_code_ttl_seconds: 60,
        access_token_ttl_seconds: 300,
        id_token_ttl_seconds: 600,
        refresh_token_ttl_seconds: 2_592_000,
        avatar_max_bytes: 2_097_152,
        client_delivery_ttl_seconds: 86_400,
        client_secret_pepper: "client-secret-pepper-for-tests-000000000001".to_owned(),
        rate_limit: RateLimitSettings {
            window_seconds: 60,
            auth_max_requests: 30,
            token_max_requests: 60,
            token_management_max_requests: 120,
            login_failure_window_seconds: 900,
            login_failure_email_max_attempts: 50,
            login_failure_ip_email_max_attempts: 5,
        },
        email: EmailSettings {
            delivery: EmailDelivery::Disabled,
            code_ttl_seconds: 900,
            send_cooldown_seconds: 60,
            send_peer_cooldown_seconds: 5,
        },
        email_code_dev_response_enabled: false,
        avatar_storage_dir: PathBuf::from("runtime/avatars"),
        jwk_keys_dir: PathBuf::from("runtime/keys"),
        signing_external_command: Vec::new(),
        signing_external_timeout_ms: 2_000,
        signing_key_rotation_interval_seconds: 7_776_000,
        signing_key_prepublish_seconds: 86_400,
        trusted_proxy_cidrs: Vec::<IpCidr>::new(),
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: false,
        scim_bearer_token: None,
        passkey: PasskeySettings {
            rp_id: "issuer.example".to_owned(),
            rp_name: "Nazo OAuth".to_owned(),
            origin: "https://issuer.example".to_owned(),
            require_user_verification: true,
            require_user_handle: true,
            strict_base64: true,
        },
        federation: crate::settings::FederationSettings {
            providers: crate::settings::FederationProviderRegistry::default(),
            saml_gateway: None,
        },
        enable_request_object: false,
        enable_request_uri_parameter: false,
        enable_par_request_object: false,
        enable_authorization_details: false,
        enable_legacy_audience_param: false,
        enable_device_authorization_grant: false,
        enable_dynamic_client_registration: false,
        enable_frontchannel_logout: false,
        enable_session_management: false,
        enable_ciba: false,
        enable_native_sso: false,
        dynamic_client_registration_initial_access_token: None,
        device_authorization_ttl_seconds: 600,
        device_authorization_poll_interval_seconds: 5,
        ciba_auth_req_id_ttl_seconds: 600,
        ciba_poll_interval_seconds: 5,
        ciba_automated_decision_token: None,
    }
}

#[actix_web::test]
async fn logout_response_clears_session_and_csrf_cookies_without_cacheable_state() {
    let response = logout_response(&settings());

    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    assert_eq!(set_cookie.len(), 2);
    assert!(
        set_cookie
            .iter()
            .any(|cookie| cookie.contains("sid=") && cookie.contains("Max-Age=0"))
    );
    assert!(
        set_cookie
            .iter()
            .any(|cookie| cookie.contains("csrf=") && cookie.contains("Max-Age=0"))
    );
    assert!(
        set_cookie
            .iter()
            .all(|cookie| cookie.contains("SameSite=Lax") && cookie.contains("Secure"))
    );

    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("logout response body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body, json!({"success": true}));
}
