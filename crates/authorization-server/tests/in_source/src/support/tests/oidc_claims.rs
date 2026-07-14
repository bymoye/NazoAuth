use super::*;
use crate::settings::DpopNoncePolicy;

fn user() -> nazo_identity::SubjectClaims {
    nazo_identity::SubjectClaims {
        subject: nazo_identity::UserId::new(Uuid::now_v7()).unwrap(),
        preferred_username: "alice".to_owned(),
        email: "alice@example.com".to_owned(),
        name: Some("Alice Example".to_owned()),
        picture: Some("https://cdn.example/alice.png".to_owned()),
        given_name: Some("Alice".to_owned()),
        family_name: Some("Example".to_owned()),
        middle_name: Some("Quinn".to_owned()),
        nickname: Some("ally".to_owned()),
        profile: Some("https://profiles.example/alice".to_owned()),
        website: Some("https://alice.example".to_owned()),
        gender: Some("female".to_owned()),
        birthdate: Some("1990-01-02".to_owned()),
        zoneinfo: Some("Asia/Shanghai".to_owned()),
        locale: Some("zh-CN".to_owned()),
        address: Some(nazo_identity::PostalAddress {
            formatted: Some("100 Universal City Plaza\nUniversal City, CA 91608\nUS".to_owned()),
            street_address: Some("100 Universal City Plaza".to_owned()),
            locality: Some("Universal City".to_owned()),
            region: Some("CA".to_owned()),
            postal_code: Some("91608".to_owned()),
            country: Some("US".to_owned()),
        }),
        phone_number: Some("+15555550000".to_owned()),
        phone_number_verified: true,
        email_verified: true,
        updated_at: Utc::now().timestamp(),
    }
}

fn settings() -> Settings {
    let mut settings =
        Settings::from_config(&crate::config::ConfigSource::default()).expect("settings");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.endpoint.mtls_endpoint_base_url = "https://issuer.example".to_owned();
    settings.endpoint.frontend_base_url = "https://frontend.example".to_owned();
    settings.endpoint.cors_allowed_origins = vec!["https://frontend.example".to_owned()];
    settings.protocol.protected_resource_identifier =
        "https://issuer.example/fapi/resource".to_owned();
    settings.protocol.dpop_nonce_policy = DpopNoncePolicy::Required;
    settings.storage.avatar_storage_dir = std::env::temp_dir().join("unused-avatars");
    settings.keys.jwk_keys_dir = std::env::temp_dir().join("unused-keys");
    settings
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
    user.name = None;
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

    let first = oidc_subject(secret, &settings.endpoint.issuer, "client.example", user_id);
    let second = oidc_subject(secret, &settings.endpoint.issuer, "client.example", user_id);
    let third = oidc_subject(secret, &settings.endpoint.issuer, "other.example", user_id);

    assert_eq!(first, second);
    assert_ne!(first, third);
    assert_ne!(first, user_id.to_string());
}

#[test]
fn compute_subject_for_client_public_returns_uuid() {
    let user_id = Uuid::now_v7();
    let mut settings = settings();
    settings.protocol.pairwise_subject_secret =
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
    settings.protocol.pairwise_subject_secret =
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
                .protocol
                .pairwise_subject_secret
                .as_ref()
                .unwrap()
                .as_bytes(),
            &settings.endpoint.issuer,
            "pairwise.example",
            user_id
        )
    );
}

#[test]
fn compute_subject_for_client_pairwise_falls_back_to_redirect_uri_host() {
    let user_id = Uuid::now_v7();
    let mut settings = settings();
    settings.protocol.pairwise_subject_secret =
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
