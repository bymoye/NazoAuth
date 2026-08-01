use super::*;
use chrono::Utc;
use uuid::Uuid;

#[test]
fn prompt_none_claims_require_their_authorizing_scope() {
    let openid_only = vec!["openid".to_owned()];
    assert!(user_claims_are_covered_by_scopes(&openid_only, &[]));
    assert!(!user_claims_are_covered_by_scopes(
        &openid_only,
        &["email".to_owned()]
    ));
    assert!(!user_claims_are_covered_by_scopes(
        &openid_only,
        &["unknown_claim".to_owned()]
    ));

    let authorized = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
        "address".to_owned(),
        "phone".to_owned(),
    ];
    assert!(user_claims_are_covered_by_scopes(
        &authorized,
        &[
            "birthdate".to_owned(),
            "email_verified".to_owned(),
            "address".to_owned(),
            "phone_number".to_owned(),
        ]
    ));
}
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
