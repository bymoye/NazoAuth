use super::*;
use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings, RateLimitSettings,
    RequestObjectJtiPolicy, SubjectType,
};
use crate::support::ClientIpHeaderMode;

fn user() -> UserRow {
    let now = Utc::now();
    UserRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        username: "alice".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: Some("Alice Example".to_owned()),
        avatar_url: Some("https://cdn.example/alice.png".to_owned()),
        given_name: Some("Alice".to_owned()),
        family_name: Some("Example".to_owned()),
        middle_name: Some("Quinn".to_owned()),
        nickname: Some("ally".to_owned()),
        profile_url: Some("https://profiles.example/alice".to_owned()),
        website_url: Some("https://alice.example".to_owned()),
        gender: Some("female".to_owned()),
        birthdate: Some("1990-01-02".to_owned()),
        zoneinfo: Some("Asia/Shanghai".to_owned()),
        locale: Some("zh-CN".to_owned()),
        role: "user".to_owned(),
        admin_level: 0,
        address_formatted: Some(
            "100 Universal City Plaza\nUniversal City, CA 91608\nUS".to_owned(),
        ),
        address_street_address: Some("100 Universal City Plaza".to_owned()),
        address_locality: Some("Universal City".to_owned()),
        address_region: Some("CA".to_owned()),
        address_postal_code: Some("91608".to_owned()),
        address_country: Some("US".to_owned()),
        phone_number: Some("+15555550000".to_owned()),
        phone_number_verified: true,
        email_verified: true,
        mfa_enabled: false,
        password_hash: "hash".to_owned(),
        is_active: true,
        created_at: now,
        updated_at: now,
    }
}

fn settings() -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://issuer.example".to_owned(),
        frontend_base_url: "https://frontend.example".to_owned(),
        cors_allowed_origins: vec!["https://frontend.example".to_owned()],
        default_audience: "resource://default".to_owned(),
        protected_resource_identifier: "https://issuer.example/fapi/resource".to_owned(),
        authorization_server_profile: AuthorizationServerProfile::Oauth2Baseline,
        ciba_security_profile:
            crate::settings::CibaSecurityProfile::FapiCibaId1PlainPrivateKeyJwtPoll,
        dpop_nonce_policy: DpopNoncePolicy::Required,
        request_object_jti_policy: RequestObjectJtiPolicy::Optional,
        session_cookie_name: "session".to_owned(),
        csrf_cookie_name: "csrf".to_owned(),
        cookie_secure: true,
        session_ttl_seconds: 28_800,
        auth_code_ttl_seconds: 300,
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
        avatar_storage_dir: std::env::temp_dir().join("unused-avatars"),
        jwk_keys_dir: std::env::temp_dir().join("unused-keys"),
        signing_external_command: Vec::new(),
        signing_external_timeout_ms: 2_000,
        signing_key_rotation_interval_seconds: 7_776_000,
        signing_key_prepublish_seconds: 86_400,
        trusted_proxy_cidrs: Vec::new(),
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: false,
        scim_bearer_token: None,
        passkey: crate::settings::PasskeySettings {
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

#[test]
fn userinfo_claims_follow_authorized_scopes() {
    let user = user();
    let claims = oidc_user_claims(
        &user,
        &[
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
            "address".to_owned(),
            "phone".to_owned(),
        ],
        "subject-1",
        &[],
        &[],
        None,
    );

    assert_eq!(claims["sub"], "subject-1");
    assert_eq!(claims["preferred_username"], "alice");
    assert_eq!(claims["name"], "Alice Example");
    assert_eq!(claims["given_name"], "Alice");
    assert_eq!(claims["family_name"], "Example");
    assert_eq!(claims["middle_name"], "Quinn");
    assert_eq!(claims["nickname"], "ally");
    assert_eq!(claims["profile"], "https://profiles.example/alice");
    assert_eq!(claims["picture"], "https://cdn.example/alice.png");
    assert_eq!(claims["website"], "https://alice.example");
    assert_eq!(claims["gender"], "female");
    assert_eq!(claims["birthdate"], "1990-01-02");
    assert_eq!(claims["zoneinfo"], "Asia/Shanghai");
    assert_eq!(claims["locale"], "zh-CN");
    assert_eq!(claims["email"], "alice@example.com");
    assert_eq!(claims["email_verified"], true);
    assert_eq!(
        claims["address"]["formatted"],
        "100 Universal City Plaza\nUniversal City, CA 91608\nUS"
    );
    assert_eq!(
        claims["address"]["street_address"],
        "100 Universal City Plaza"
    );
    assert_eq!(claims["address"]["locality"], "Universal City");
    assert_eq!(claims["address"]["region"], "CA");
    assert_eq!(claims["address"]["postal_code"], "91608");
    assert_eq!(claims["address"]["country"], "US");
    assert_eq!(claims["phone_number"], "+15555550000");
    assert_eq!(claims["phone_number_verified"], true);
}

#[test]
fn userinfo_claims_omit_unrequested_profile_and_email() {
    let user = user();
    let claims = oidc_user_claims(&user, &["openid".to_owned()], "subject-1", &[], &[], None);

    assert!(claims.get("name").is_none());
    assert!(claims.get("given_name").is_none());
    assert!(claims.get("family_name").is_none());
    assert!(claims.get("middle_name").is_none());
    assert!(claims.get("nickname").is_none());
    assert!(claims.get("profile").is_none());
    assert!(claims.get("preferred_username").is_none());
    assert!(claims.get("picture").is_none());
    assert!(claims.get("website").is_none());
    assert!(claims.get("gender").is_none());
    assert!(claims.get("birthdate").is_none());
    assert!(claims.get("zoneinfo").is_none());
    assert!(claims.get("locale").is_none());
    assert!(claims.get("email").is_none());
    assert!(claims.get("email_verified").is_none());
    assert!(claims.get("address").is_none());
    assert!(claims.get("phone_number").is_none());
    assert!(claims.get("phone_number_verified").is_none());
}

#[test]
fn id_token_user_claims_do_not_expose_email_scope_claims() {
    let user = user();
    let claims = oidc_id_token_user_claims(
        &user,
        &[
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
        ],
        "subject-1",
        &[],
        &[],
        None,
    );

    assert_eq!(claims["sub"], "subject-1");
    assert_eq!(claims["preferred_username"], "alice");
    assert!(claims.get("email").is_none());
    assert!(claims.get("email_verified").is_none());
    assert!(claims.get("address").is_none());
    assert!(claims.get("phone_number").is_none());
    assert!(claims.get("phone_number_verified").is_none());
}

#[test]
fn requested_userinfo_claims_allow_explicit_profile_claims_without_profile_scope() {
    let mut user = user();
    user.display_name = None;
    let claims = oidc_user_claims(
        &user,
        &["openid".to_owned()],
        "subject-1",
        &["name".to_owned()],
        &[],
        None,
    );

    assert_eq!(claims["sub"], "subject-1");
    assert_eq!(claims["name"], "alice");
    assert!(claims.get("preferred_username").is_none());
}

#[test]
fn requested_contact_claims_allow_explicit_contact_claims_without_contact_scopes() {
    let user = user();
    let claims = oidc_user_claims(
        &user,
        &["openid".to_owned()],
        "subject-1",
        &[
            "address".to_owned(),
            "phone_number".to_owned(),
            "phone_number_verified".to_owned(),
        ],
        &[],
        None,
    );

    assert_eq!(claims["sub"], "subject-1");
    assert_eq!(
        claims["address"]["formatted"],
        "100 Universal City Plaza\nUniversal City, CA 91608\nUS"
    );
    assert_eq!(claims["phone_number"], "+15555550000");
    assert_eq!(claims["phone_number_verified"], true);
}

#[test]
fn requested_userinfo_claim_values_filter_output_even_without_matching_scope() {
    let user = user();
    let claims = oidc_user_claims(
        &user,
        &["openid".to_owned()],
        "subject-1",
        &[
            "email".to_owned(),
            "email_verified".to_owned(),
            "phone_number".to_owned(),
        ],
        &[
            OidcClaimRequest {
                name: "email".to_owned(),
                essential: true,
                value: Some(json!("other@example.com")),
                values: Vec::new(),
            },
            OidcClaimRequest {
                name: "email_verified".to_owned(),
                essential: false,
                value: Some(json!(true)),
                values: Vec::new(),
            },
            OidcClaimRequest {
                name: "phone_number".to_owned(),
                essential: false,
                value: None,
                values: vec![json!("+15555550000"), json!("+15555550001")],
            },
        ],
        None,
    );

    assert!(claims.get("email").is_none());
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["phone_number"], "+15555550000");
}

#[test]
fn id_token_claim_values_filter_output_and_allow_matching_contact_claims() {
    let user = user();
    let claims = oidc_id_token_user_claims(
        &user,
        &["openid".to_owned(), "email".to_owned(), "phone".to_owned()],
        "subject-1",
        &[
            "email".to_owned(),
            "email_verified".to_owned(),
            "phone_number".to_owned(),
        ],
        &[
            OidcClaimRequest {
                name: "email".to_owned(),
                essential: false,
                value: Some(json!("alice@example.com")),
                values: Vec::new(),
            },
            OidcClaimRequest {
                name: "email_verified".to_owned(),
                essential: false,
                value: None,
                values: vec![json!(false)],
            },
            OidcClaimRequest {
                name: "phone_number".to_owned(),
                essential: false,
                value: None,
                values: vec![json!("+15555550000")],
            },
        ],
        None,
    );

    assert_eq!(claims["email"], "alice@example.com");
    assert!(claims.get("email_verified").is_none());
    assert_eq!(claims["phone_number"], "+15555550000");
}

#[test]
fn pairwise_subject_is_stable_within_sector_and_distinct_across_sectors() {
    let user_id = Uuid::now_v7();
    let settings = settings();
    let secret = b"this-is-a-long-enough-secret-key-for-hmac-sha256!!";

    let first = oidc_subject(secret, &settings.issuer, "client.example", user_id);
    let second = oidc_subject(secret, &settings.issuer, "client.example", user_id);
    let third = oidc_subject(secret, &settings.issuer, "other.example", user_id);

    assert_eq!(first, second);
    assert_ne!(first, third);
    assert_ne!(first, user_id.to_string());
}

#[test]
fn compute_subject_for_client_public_returns_uuid() {
    let user_id = Uuid::now_v7();
    let mut settings = settings();
    settings.pairwise_subject_secret =
        Some("this-is-a-long-enough-secret-key-for-hmac-sha256!!".to_owned());
    let subject = compute_subject_for_client(
        &settings,
        user_id,
        "public",
        Some("example.com"),
        "https://example.com/callback",
    )
    .expect("public client subject should compute");
    assert_eq!(subject, user_id.to_string());
}

#[test]
fn compute_subject_for_client_pairwise_uses_sector_host() {
    let user_id = Uuid::now_v7();
    let mut settings = settings();
    settings.pairwise_subject_secret =
        Some("this-is-a-long-enough-secret-key-for-hmac-sha256!!".to_owned());
    let subject = compute_subject_for_client(
        &settings,
        user_id,
        "pairwise",
        Some("pairwise.example"),
        "https://client.example/callback",
    )
    .expect("pairwise client subject should compute");
    assert_ne!(subject, user_id.to_string());
    assert_eq!(
        subject,
        oidc_subject(
            settings
                .pairwise_subject_secret
                .as_ref()
                .unwrap()
                .as_bytes(),
            &settings.issuer,
            "pairwise.example",
            user_id
        )
    );
}

#[test]
fn compute_subject_for_client_pairwise_falls_back_to_redirect_uri_host() {
    let user_id = Uuid::now_v7();
    let mut settings = settings();
    settings.pairwise_subject_secret =
        Some("this-is-a-long-enough-secret-key-for-hmac-sha256!!".to_owned());
    let subject = compute_subject_for_client(
        &settings,
        user_id,
        "pairwise",
        None,
        "https://fallback.example/callback",
    )
    .expect("pairwise client subject should compute");
    assert_ne!(subject, user_id.to_string());
    let same_subject = compute_subject_for_client(
        &settings,
        user_id,
        "pairwise",
        None,
        "https://fallback.example/other",
    )
    .expect("pairwise subject should be stable for the same redirect host");
    assert_eq!(subject, same_subject);
}

#[test]
fn compute_subject_for_client_rejects_pairwise_without_server_secret() {
    let err = compute_subject_for_client(
        &settings(),
        Uuid::now_v7(),
        "pairwise",
        Some("pairwise.example"),
        "https://client.example/callback",
    )
    .expect_err("pairwise clients must fail closed when the server secret is missing");

    assert!(
        err.to_string().contains("PAIRWISE_SUBJECT_SECRET"),
        "error should identify the missing pairwise secret: {err}"
    );
}

#[test]
fn compute_subject_for_client_rejects_unsupported_subject_type() {
    let err = compute_subject_for_client(
        &settings(),
        Uuid::now_v7(),
        "transient",
        Some("client.example"),
        "https://client.example/callback",
    )
    .expect_err("unsupported client subject_type must fail closed");

    assert!(
        err.to_string().contains("unsupported client subject_type"),
        "error should identify the invalid client subject_type: {err}"
    );
}
