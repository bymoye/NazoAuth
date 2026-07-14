use nazo_identity::{
    AuthMethod, AuthenticationContext, IdentityModelError, OrganizationId, PostalAddress,
    Principal, RealmId, SubjectClaims, TenantContext, TenantId, UserId, UserRole,
};
use uuid::Uuid;

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

#[test]
fn identity_ids_reject_nil_uuid_values() {
    assert_eq!(UserId::new(Uuid::nil()), Err(IdentityModelError::EmptyId));
    assert_eq!(TenantId::new(Uuid::nil()), Err(IdentityModelError::EmptyId));
    assert_eq!(RealmId::new(Uuid::nil()), Err(IdentityModelError::EmptyId));
    assert_eq!(
        OrganizationId::new(Uuid::nil()),
        Err(IdentityModelError::EmptyId)
    );
}

#[test]
fn identity_ids_reject_nil_uuid_during_deserialization() {
    let encoded = format!("\"{}\"", Uuid::nil());

    assert!(serde_json::from_str::<UserId>(&encoded).is_err());
    assert!(serde_json::from_str::<TenantId>(&encoded).is_err());
    assert!(serde_json::from_str::<RealmId>(&encoded).is_err());
    assert!(serde_json::from_str::<OrganizationId>(&encoded).is_err());
}

#[test]
fn principal_and_tenant_context_do_not_require_database_rows() {
    let principal = Principal {
        user_id: UserId::new(id(4)).unwrap(),
        tenant: TenantContext::default_system(),
        role: UserRole::Admin { level: 2 },
        active: true,
    };

    assert_eq!(principal.admin_level(), Some(2));
    assert!(principal.tenant.matches_raw(id(1), id(2), id(3)));
    assert!(!principal.tenant.matches_raw(id(9), id(2), id(3)));
}

#[test]
fn authentication_context_has_ordered_deduplicated_amr_and_mfa() {
    let context = AuthenticationContext::new(
        1_700_000_000,
        [
            AuthMethod::Password,
            AuthMethod::Totp,
            AuthMethod::Password,
            AuthMethod::Federated("oidc".to_owned()),
        ],
    )
    .unwrap();

    assert!(context.has_mfa());
    assert_eq!(context.amr(), ["password", "otp", "oidc", "federated"]);
    assert!(!context.oidc_sid.trim().is_empty());
}

#[test]
fn authentication_context_validates_persisted_metadata() {
    assert!(AuthenticationContext::from_amr(1_000, ["password"], "sid-1", 1_001).is_ok());
    assert!(AuthenticationContext::from_amr(0, ["password"], "sid-1", 1_001).is_err());
    assert!(AuthenticationContext::from_amr(1_032, ["password"], "sid-1", 1_001).is_err());
    assert!(
        AuthenticationContext::from_amr(1_000, std::iter::empty::<&str>(), "sid-1", 1_001).is_err()
    );
    assert!(AuthenticationContext::from_amr(1_000, ["password"], " ", 1_001).is_err());
}

#[test]
fn subject_claims_are_framework_and_storage_independent() {
    let claims = SubjectClaims {
        subject: UserId::new(id(4)).unwrap(),
        preferred_username: "alice".to_owned(),
        name: Some("Alice Example".to_owned()),
        given_name: Some("Alice".to_owned()),
        family_name: Some("Example".to_owned()),
        middle_name: None,
        nickname: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: Some("zh-CN".to_owned()),
        email: "alice@example.com".to_owned(),
        email_verified: true,
        address: Some(PostalAddress {
            formatted: None,
            street_address: None,
            locality: Some("Shanghai".to_owned()),
            region: None,
            postal_code: None,
            country: Some("CN".to_owned()),
        }),
        phone_number: None,
        phone_number_verified: false,
        updated_at: 1_700_000_000,
    };

    assert_eq!(claims.subject.as_uuid(), id(4));
    assert_eq!(claims.address.unwrap().country.as_deref(), Some("CN"));
}
