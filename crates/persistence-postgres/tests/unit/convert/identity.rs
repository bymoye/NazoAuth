use super::*;
use chrono::Utc;
use uuid::Uuid;

fn user_row() -> UserRow {
    UserRow {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        realm_id: Uuid::now_v7(),
        organization_id: Uuid::now_v7(),
        username: "user".into(),
        email: "user@example.test".into(),
        password_hash: "hash".into(),
        is_active: true,
        mfa_enabled: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        email_verified: true,
        display_name: None,
        avatar_url: None,
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        profile_url: None,
        website_url: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        role: "user".into(),
        admin_level: 0,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        phone_number: None,
        phone_number_verified: false,
    }
}

fn authentication_row(row: UserRow) -> AuthenticationIdentityRow {
    AuthenticationIdentityRow {
        id: row.id,
        tenant_id: row.tenant_id,
        realm_id: row.realm_id,
        organization_id: row.organization_id,
        username: row.username,
        email: row.email,
        password_hash: row.password_hash,
        is_active: row.is_active,
        mfa_enabled: row.mfa_enabled,
        email_verified: row.email_verified,
        role: row.role,
        admin_level: row.admin_level,
    }
}

fn subject_claims_row(row: UserRow) -> SubjectClaimsRow {
    SubjectClaimsRow {
        id: row.id,
        tenant_id: row.tenant_id,
        realm_id: row.realm_id,
        organization_id: row.organization_id,
        username: row.username,
        email: row.email,
        is_active: row.is_active,
        updated_at: row.updated_at,
        email_verified: row.email_verified,
        display_name: row.display_name,
        avatar_url: row.avatar_url,
        given_name: row.given_name,
        family_name: row.family_name,
        middle_name: row.middle_name,
        nickname: row.nickname,
        profile_url: row.profile_url,
        website_url: row.website_url,
        gender: row.gender,
        birthdate: row.birthdate,
        zoneinfo: row.zoneinfo,
        locale: row.locale,
        role: row.role,
        admin_level: row.admin_level,
        address_formatted: row.address_formatted,
        address_street_address: row.address_street_address,
        address_locality: row.address_locality,
        address_region: row.address_region,
        address_postal_code: row.address_postal_code,
        address_country: row.address_country,
        phone_number: row.phone_number,
        phone_number_verified: row.phone_number_verified,
    }
}

#[test]
fn subject_claims_uses_full_persisted_user_invariant() {
    let mut invalid_role = user_row();
    invalid_role.role = "admin".into();
    assert!(active_subject_claims(subject_claims_row(invalid_role)).is_err());

    let mut nil_user = user_row();
    nil_user.id = Uuid::nil();
    assert!(active_subject_claims(subject_claims_row(nil_user)).is_err());

    let mut nil_tenant = user_row();
    nil_tenant.tenant_id = Uuid::nil();
    assert!(active_subject_claims(subject_claims_row(nil_tenant)).is_err());
}

#[test]
fn persisted_blank_password_hash_is_rejected() {
    let mut row = user_row();
    row.password_hash = "   ".to_owned();

    let error = authentication_identity(authentication_row(row)).unwrap_err();

    assert_eq!(error.0, "password hash must not be blank");
}
