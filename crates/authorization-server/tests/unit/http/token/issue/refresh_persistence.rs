use super::*;
use crate::domain::tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};

#[test]
fn rotated_refresh_token_preserves_the_original_scope_authorization() {
    let access_token_scopes = vec!["openid".to_owned()];
    let original_refresh_token_scopes = vec!["openid".to_owned(), "offline_access".to_owned()];

    assert_eq!(
        refresh_token_persistence_scopes(
            &access_token_scopes,
            Some(&original_refresh_token_scopes),
        ),
        original_refresh_token_scopes
    );
}

fn openid_issue() -> TokenIssue {
    TokenIssue {
        user_id: Some(Uuid::now_v7()),
        subject: "subject-1".to_owned(),
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        audiences: vec!["resource://default".to_owned()],
        nonce: Some("original-nonce".to_owned()),
        auth_time: Some(1_700_000_000),
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("original-sid".to_owned()),
        acr: Some("1".to_owned()),
        userinfo_claims: vec!["email".to_owned()],
        userinfo_claim_requests: Vec::new(),
        id_token_claims: vec!["email".to_owned()],
        id_token_claim_requests: Vec::new(),
        refresh_id_token_sid: None,
        include_refresh: true,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: None,
        refresh_token_dpop_jkt: None,
        mtls_x5t_s256: None,
        refresh_token_mtls_x5t_s256: None,
        refresh_token_client_attestation_jkt: None,
        refresh_token_scopes: None,
        authorization_code_hash: None,
        actor: None,
        issued_token_type: None,
        native_sso: None,
    }
}

#[test]
fn refresh_authentication_context_preserves_original_claim_contract_on_scope_narrowing() {
    let mut issue = openid_issue();
    issue.refresh_token_scopes = Some(vec!["openid".to_owned(), "offline_access".to_owned()]);
    issue.scopes = vec!["openid".to_owned()];

    let context = refresh_authentication_context(
        &issue,
        "https://issuer.example",
        "client-1",
        Some("original-sid"),
    )
    .expect("openid refresh token should carry authentication context");
    assert_eq!(context.issuer, "https://issuer.example");
    assert_eq!(context.audience, "client-1");
    assert_eq!(context.id_token_sid.as_deref(), Some("original-sid"));
    assert_eq!(context.auth_time, 1_700_000_000);
    assert_eq!(context.amr, vec!["pwd"]);
    assert_eq!(context.oidc_sid.as_deref(), Some("original-sid"));
    assert_eq!(context.acr.as_deref(), Some("1"));
    assert_eq!(context.nonce.as_deref(), Some("original-nonce"));
    assert_eq!(context.id_token_claims, vec!["email"]);
}

fn client_with_grants(grant_types: &[&str]) -> ClientRow {
    client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "public".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "offline_access"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(grant_types),
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
fn should_issue_refresh_token_true_with_refresh_grant_and_offline_access() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(should_issue_refresh_token(&client, &scopes, false));
}

#[test]
fn should_issue_refresh_token_false_without_offline_access_scope() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let scopes = vec!["openid".to_owned(), "profile".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));
}

#[test]
fn should_issue_refresh_token_for_openid4vci_credential_authorization() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let scopes = vec!["org.iso.18013.5.1.mDL".to_owned()];
    assert!(should_issue_refresh_token(&client, &scopes, true));
}

#[test]
fn openid4vci_credential_authorization_still_requires_refresh_grant() {
    let client = client_with_grants(&["authorization_code"]);
    let scopes = vec!["org.iso.18013.5.1.mDL".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, true));
}

#[test]
fn should_issue_refresh_token_false_without_refresh_grant() {
    let client = client_with_grants(&["authorization_code"]);
    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));
}

#[test]
fn should_issue_refresh_token_exact_grant_match_required() {
    let client = client_with_grants(&["authorization_code", "refresh_token:legacy"]);
    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));
}

#[test]
fn should_issue_refresh_token_scope_case_sensitive() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let scopes = vec!["openid".to_owned(), "OFFLINE_ACCESS".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));

    let scopes = vec!["openid".to_owned(), "offline_access ".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));

    let scopes = vec!["openid".to_owned(), "offline".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));
}
