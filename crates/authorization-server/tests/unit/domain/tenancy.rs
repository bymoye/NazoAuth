use crate::domain::ClientRow;
use crate::test_support::DatabaseUserFixture;

use chrono::Utc;

use nazo_identity::{PublicAccount, TenantContext};

use serde_json::json;
use uuid::Uuid;

fn includes_user(context: TenantContext, user: &PublicAccount) -> bool {
    context.matches_raw(user.tenant_id(), user.realm_id(), user.organization_id())
}

fn includes_client(context: TenantContext, client: &ClientRow) -> bool {
    context.matches_raw(client.tenant_id, client.realm_id, client.organization_id)
}

use super::*;

fn user_in_context(context: TenantContext) -> PublicAccount {
    DatabaseUserFixture {
        id: Uuid::now_v7(),
        tenant_id: context.tenant_id.as_uuid(),
        realm_id: context.realm_id.as_uuid(),
        organization_id: context.organization_id.as_uuid(),
        username: "user".to_owned(),
        email: "user@example.com".to_owned(),
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
        role: "user".to_owned(),
        admin_level: 0,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        phone_number: None,
        phone_number_verified: false,
        email_verified: true,
        mfa_enabled: false,
        password_hash: "hash".to_owned(),
        is_active: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
    .identity()
}

fn client_in_context(context: TenantContext) -> ClientRow {
    client_row! {
        id: Uuid::now_v7(),
        tenant_id: context.tenant_id.as_uuid(),
        realm_id: context.realm_id.as_uuid(),
        organization_id: context.organization_id.as_uuid(),
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "public".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "none".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        is_active: true,
        jwks: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: true,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}

#[test]
fn tenant_context_rejects_cross_tenant_entities() {
    let context = TenantContext::default_system();
    let other = TenantContext {
        tenant_id: nazo_identity::TenantId::new(Uuid::now_v7()).unwrap(),
        ..context
    };

    assert!(includes_user(context, &user_in_context(context)));
    assert!(!includes_user(context, &user_in_context(other)));
    assert!(includes_client(context, &client_in_context(context)));
    assert!(!includes_client(context, &client_in_context(other)));
    assert!(context.same_tenant(nazo_identity::TenantId::new(DEFAULT_TENANT_ID).unwrap()));
    assert!(!context.same_tenant(other.tenant_id));
}
