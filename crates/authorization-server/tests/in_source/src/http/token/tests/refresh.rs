use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use nazo_postgres::{create_pool, get_conn};

use crate::test_support::client_signing_fixture;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{Bool, Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;

#[derive(QueryableByName)]
struct RefreshFamilyTokenRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    refresh_token_blake3: String,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    rotated_from_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    reuse_detected_at: Option<DateTime<Utc>>,
}

fn test_state() -> TestAppState {
    TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_refresh_test_invalid:nazo_refresh_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn live_refresh_state(profile: AuthorizationServerProfile) -> Option<TestAppState> {
    live_refresh_state_from_database_url(profile, std::env::var("DATABASE_URL").ok()?)
}

fn live_refresh_state_from_database_url(
    profile: AuthorizationServerProfile,
    database_url: String,
) -> Option<TestAppState> {
    let key_material = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    let active_kid = "refresh-test-kid".to_owned();
    let _public_jwk = key_material.public_jwk(&active_kid);
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.protocol.authorization_server_profile = profile;

    Some(TestAppState {
        diesel_db: create_pool(database_url, 4).expect("database pool should build"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    })
}

fn database_url_with_search_path(schema: &str) -> Option<String> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let separator = if base.contains('?') { "&" } else { "?" };
    Some(format!(
        "{base}{separator}options=-csearch_path%3D{schema}%2Cpublic"
    ))
}

async fn exec_sql(state: &TestAppState, sql: &str) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(sql)
        .execute(&mut conn)
        .await
        .expect("schema mutation should succeed");
}

async fn create_isolated_schema(state: &TestAppState, schema: &str, tables: &[&str]) {
    exec_sql(
        state,
        &format!(r#"CREATE SCHEMA IF NOT EXISTS "{}""#, schema),
    )
    .await;
    for table in tables {
        exec_sql(
            state,
            &format!(
                r#"CREATE TABLE "{}"."{}" (LIKE public."{}" INCLUDING ALL)"#,
                schema, table, table
            ),
        )
        .await;
    }
}

async fn rename_column(state: &TestAppState, schema: &str, table: &str, from: &str, to: &str) {
    exec_sql(
        state,
        &format!(
            r#"ALTER TABLE "{}"."{}" RENAME COLUMN "{}" TO "{}""#,
            schema, table, from, to
        ),
    )
    .await;
}

async fn drop_schema(state: &TestAppState, schema: &str) {
    exec_sql(
        state,
        &format!(r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#, schema),
    )
    .await;
}

fn live_trusted_proxy_refresh_state(profile: AuthorizationServerProfile) -> Option<TestAppState> {
    let mut state = live_refresh_state(profile)?;
    let mut settings = (*state.settings).clone();
    settings.endpoint.trusted_proxy_cidrs = vec![
        crate::http::client_ip::IpCidr::parse("127.0.0.1/32")
            .expect("trusted proxy CIDR should parse"),
    ];
    state.settings = Arc::new(settings);
    Some(state)
}

async fn insert_refresh_token_row(
    state: &TestAppState,
    raw_refresh_token: &str,
    token: &TokenRow,
    rotated_from_id: Option<Uuid>,
    reuse_detected_at: Option<DateTime<Utc>>,
) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query("DELETE FROM oauth_tokens WHERE tenant_id = $1 AND refresh_token_blake3 = $2")
        .bind::<SqlUuid, _>(token.tenant_id)
        .bind::<Text, _>(blake3_hex(raw_refresh_token))
        .execute(&mut conn)
        .await
        .expect("refresh token cleanup should succeed");
    sql_query(
        r#"
        INSERT INTO oauth_tokens (
            id, tenant_id, refresh_token_blake3, token_family_id, rotated_from_id,
            client_id, user_id, scopes, authorization_details, issued_at, expires_at,
            revoked_at, reuse_detected_at, subject, dpop_jkt, mtls_x5t_s256
        )
        VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, $10, $11,
            $12, $13, $14, $15, $16
        )
        "#,
    )
    .bind::<SqlUuid, _>(token.id)
    .bind::<SqlUuid, _>(token.tenant_id)
    .bind::<Text, _>(blake3_hex(raw_refresh_token))
    .bind::<SqlUuid, _>(token.token_family_id)
    .bind::<Nullable<SqlUuid>, _>(rotated_from_id)
    .bind::<SqlUuid, _>(token.client_id)
    .bind::<Nullable<SqlUuid>, _>(token.user_id)
    .bind::<Jsonb, _>(token.scopes.clone())
    .bind::<Jsonb, _>(token.authorization_details.clone())
    .bind::<Timestamptz, _>(token.issued_at)
    .bind::<Timestamptz, _>(token.expires_at)
    .bind::<Nullable<Timestamptz>, _>(token.revoked_at)
    .bind::<Nullable<Timestamptz>, _>(reuse_detected_at)
    .bind::<Text, _>(token.subject.as_str())
    .bind::<Nullable<Text>, _>(token.dpop_jkt.as_deref())
    .bind::<Nullable<Text>, _>(token.mtls_x5t_s256.as_deref())
    .execute(&mut conn)
    .await
    .expect("refresh token insert should succeed");
}

async fn insert_refresh_client(state: &TestAppState, client: &ClientRow) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        DELETE FROM oauth_tokens
        USING oauth_clients
        WHERE oauth_tokens.client_id = oauth_clients.id
          AND oauth_clients.tenant_id = $1
          AND oauth_clients.client_id = $2
        "#,
    )
    .bind::<SqlUuid, _>(client.tenant_id)
    .bind::<Text, _>(client.client_id.as_str())
    .execute(&mut conn)
    .await
    .expect("refresh token cleanup for existing client should succeed");
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
        .bind::<SqlUuid, _>(client.tenant_id)
        .bind::<Text, _>(client.client_id.as_str())
        .execute(&mut conn)
        .await
        .expect("refresh test client cleanup should succeed");
    sql_query(
        r#"
        INSERT INTO oauth_clients (
            id, tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            client_secret_hash, redirect_uris, scopes, allowed_audiences,
            grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
            require_mtls_bound_tokens, tls_client_auth_san_dns, tls_client_auth_san_uri,
            tls_client_auth_san_ip, tls_client_auth_san_email,
            allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience, require_par_request_object,
            allow_authorization_code_without_pkce, is_active,
            post_logout_redirect_uris, backchannel_logout_session_required
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11,
            $12, $13, $14,
            $15, $16, $17,
            $18, $19,
            $20, $21, $22,
            $23, $24,
            $25, $26
        )
        "#,
    )
    .bind::<SqlUuid, _>(client.id)
    .bind::<SqlUuid, _>(client.tenant_id)
    .bind::<SqlUuid, _>(client.realm_id)
    .bind::<SqlUuid, _>(client.organization_id)
    .bind::<Text, _>(client.client_id.as_str())
    .bind::<Text, _>(client.client_name.as_str())
    .bind::<Text, _>(client.client_type.as_str())
    .bind::<Nullable<Text>, _>(Option::<&str>::None)
    .bind::<Jsonb, _>(json!(&client.redirect_uris))
    .bind::<Jsonb, _>(json!(&client.scopes))
    .bind::<Jsonb, _>(json!(&client.allowed_audiences))
    .bind::<Jsonb, _>(json!(&client.grant_types))
    .bind::<Text, _>(client.token_endpoint_auth_method.as_str())
    .bind::<Bool, _>(client.require_dpop_bound_tokens)
    .bind::<Bool, _>(client.require_mtls_bound_tokens)
    .bind::<Jsonb, _>(json!(&client.tls_client_auth_san_dns))
    .bind::<Jsonb, _>(json!(&client.tls_client_auth_san_uri))
    .bind::<Jsonb, _>(json!(&client.tls_client_auth_san_ip))
    .bind::<Jsonb, _>(json!(&client.tls_client_auth_san_email))
    .bind::<Bool, _>(client.allow_client_assertion_audience_array)
    .bind::<Bool, _>(client.allow_client_assertion_endpoint_audience)
    .bind::<Bool, _>(client.require_par_request_object)
    .bind::<Bool, _>(client.allow_authorization_code_without_pkce)
    .bind::<Bool, _>(client.is_active)
    .bind::<Jsonb, _>(json!(&client.post_logout_redirect_uris))
    .bind::<Bool, _>(client.backchannel_logout_session_required)
    .execute(&mut conn)
    .await
    .expect("refresh test client should insert");
}

async fn insert_refresh_user(state: &TestAppState, user_id: Uuid, active: bool) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(user_id)
        .execute(&mut conn)
        .await
        .expect("refresh test user cleanup should succeed");
    sql_query(
        r#"
        INSERT INTO users (
            id, tenant_id, realm_id, organization_id, username, email, password_hash,
            is_active, mfa_enabled, email_verified, role, admin_level
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE, TRUE, 'user', 0)
        "#,
    )
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
    .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(format!("refresh-user-{user_id}"))
    .bind::<Text, _>(format!("refresh-user-{user_id}@example.test"))
    .bind::<Text, _>("argon2-test-hash")
    .bind::<Bool, _>(active)
    .execute(&mut conn)
    .await
    .expect("refresh test user should insert");
}

async fn load_family_rows(state: &TestAppState, family_id: Uuid) -> Vec<RefreshFamilyTokenRow> {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        SELECT id, refresh_token_blake3, rotated_from_id, revoked_at, reuse_detected_at
        FROM oauth_tokens
        WHERE tenant_id = $1 AND token_family_id = $2
        "#,
    )
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(family_id)
    .load::<RefreshFamilyTokenRow>(&mut conn)
    .await
    .expect("refresh token family should load")
}

fn refresh_form_without_token() -> TokenForm {
    TokenForm {
        grant_type: "refresh_token".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        audiences: Vec::new(),
        has_audience_param: false,
    }
}

fn mtls_refresh_request(thumbprint: &str) -> HttpRequest {
    actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-verify"),
            "SUCCESS",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            thumbprint,
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-subject-dn"),
            "CN=refresh-lost-response",
        ))
        .to_http_request()
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(header::PRAGMA)
            .and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json)
}

fn client_row() -> ClientRow {
    crate::client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: format!("client-{}", Uuid::now_v7()),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "offline_access"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code", "refresh_token"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
        require_dpop_bound_tokens: true,
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
        allow_authorization_code_without_pkce: false,
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

fn token_row() -> TokenRow {
    TokenRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        token_family_id: Uuid::now_v7(),
        client_id: Uuid::now_v7(),
        user_id: Some(Uuid::now_v7()),
        scopes: json!(["openid", "offline_access"]),
        audience: json!(["resource://default"]),
        authorization_details: json!([]),
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(30),
        revoked_at: None,
        subject: "subject-1".to_owned(),
        dpop_jkt: Some("dpop-jkt".to_owned()),
        mtls_x5t_s256: None,
    }
}

#[test]
fn fapi_profiles_preserve_refresh_tokens_for_sender_constrained_confidential_clients() {
    let mut token = token_row();
    token.dpop_jkt = None;
    token.mtls_x5t_s256 = None;
    let client = client_row();

    for profile in [
        AuthorizationServerProfile::Fapi2Security,
        AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest,
    ] {
        assert_eq!(
            refresh_token_policy_for_authorization_server_profile(profile, &client, &token),
            RefreshTokenPolicy::PreserveExisting,
            "FAPI prohibits routine refresh-token rotation even when the confidential client's sender constraint is enforced by client policy rather than stored on the refresh-token row"
        );
    }
}

#[test]
fn baseline_profile_preserves_confidential_sender_constrained_refresh_tokens() {
    let token = token_row();
    let client = client_row();

    assert_eq!(
        refresh_token_policy_for_authorization_server_profile(
            AuthorizationServerProfile::Oauth2Baseline,
            &client,
            &token,
        ),
        RefreshTokenPolicy::PreserveExisting,
        "client policy identifies sender-constrained confidential clients even when the server hosts multiple profiles"
    );
}

#[test]
fn baseline_profile_rotates_public_sender_constrained_refresh_tokens() {
    let token = token_row();
    let mut client = client_row();
    client.client_type = "public".to_owned();
    client.token_endpoint_auth_method = "none".to_owned();

    assert_eq!(
        refresh_token_policy_for_authorization_server_profile(
            AuthorizationServerProfile::Oauth2Baseline,
            &client,
            &token,
        ),
        RefreshTokenPolicy::Rotate {
            family_id: token.token_family_id,
            rotated_from_id: token.id,
        },
        "public-client refresh tokens must rotate even when sender-constrained"
    );
}

#[test]
fn baseline_profile_preserves_confidential_secret_authenticated_sender_constrained_refresh_tokens()
{
    let token = token_row();
    let mut client = client_row();
    client.token_endpoint_auth_method = "client_secret_basic".to_owned();

    assert_eq!(
        refresh_token_policy_for_authorization_server_profile(
            AuthorizationServerProfile::Oauth2Baseline,
            &client,
            &token,
        ),
        RefreshTokenPolicy::PreserveExisting,
        "confidential client authentication plus the enforced access-token sender constraint makes routine refresh-token rotation unnecessary"
    );
}

#[test]
fn baseline_profile_rotates_unbound_refresh_tokens() {
    let mut token = token_row();
    token.dpop_jkt = None;
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = false;

    assert_eq!(
        refresh_token_policy_for_authorization_server_profile(
            AuthorizationServerProfile::Oauth2Baseline,
            &client,
            &token,
        ),
        RefreshTokenPolicy::Rotate {
            family_id: token.token_family_id,
            rotated_from_id: token.id,
        }
    );
}

#[test]
fn refresh_token_policy_uses_configured_authorization_server_profile() {
    let mut settings = Settings::from_config(&ConfigSource::default()).unwrap();
    settings.protocol.authorization_server_profile = AuthorizationServerProfile::Fapi2Security;
    let token = token_row();
    let client = client_row();

    assert_eq!(
        refresh_token_policy_for_profile(&settings, &client, &token),
        RefreshTokenPolicy::PreserveExisting,
        "FAPI profiles preserve refresh tokens for valid sender-constrained confidential clients"
    );

    let mut unbound_token = token_row();
    unbound_token.dpop_jkt = None;
    unbound_token.mtls_x5t_s256 = None;
    assert_eq!(
        refresh_token_policy_for_profile(&settings, &client, &unbound_token),
        RefreshTokenPolicy::PreserveExisting,
        "the client policy, not nullable refresh-token row bindings, determines whether a FAPI client is sender constrained"
    );

    let mut mtls_bound_token = token_row();
    mtls_bound_token.dpop_jkt = None;
    mtls_bound_token.mtls_x5t_s256 = Some("mtls-thumbprint".to_owned());
    assert_eq!(
        refresh_token_policy_for_profile(&settings, &client, &mtls_bound_token),
        RefreshTokenPolicy::PreserveExisting,
        "stored mTLS binding remains compatible with the non-rotating FAPI policy"
    );

    settings.protocol.authorization_server_profile = AuthorizationServerProfile::Oauth2Baseline;
    assert_eq!(
        refresh_token_policy_for_profile(&settings, &client, &token),
        RefreshTokenPolicy::PreserveExisting,
        "client-level sender constraints remain authoritative in a multi-profile baseline server"
    );
}

#[actix_web::test]
async fn concurrent_baseline_refreshes_preserve_an_unbound_row_for_an_mtls_constrained_client() {
    let Some(state) = live_trusted_proxy_refresh_state(AuthorizationServerProfile::Oauth2Baseline)
    else {
        return;
    };
    let thumbprint = "REREREREREREREREREREREREREREREREREREREREREQ";
    let req = mtls_refresh_request(thumbprint);
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;
    insert_refresh_client(&state, &client).await;

    let family_id = Uuid::now_v7();
    let raw = format!("refresh-fapi-unbound-{}", Uuid::now_v7());
    let mut token = token_row();
    token.client_id = client.id;
    token.token_family_id = family_id;
    token.scopes = json!(["accounts", "offline_access"]);
    token.subject = client.client_id.clone();
    token.user_id = None;
    token.dpop_jkt = None;
    token.mtls_x5t_s256 = None;
    insert_refresh_token_row(&state, &raw, &token, None, None).await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(raw);
    let (first, second) = tokio::join!(
        token_refresh(&state, &req, &client, &form, None),
        token_refresh(&state, &req, &client, &form, None)
    );
    let (first, second) = tokio::join!(response_json(first), response_json(second));

    for (status, body) in [first, second] {
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body["access_token"].is_string());
        assert!(
            body.get("refresh_token").is_none(),
            "FAPI must not rotate the refresh token during routine refresh: {body}"
        );
    }
    let family = load_family_rows(&state, family_id).await;
    assert_eq!(family.len(), 1, "no rotated family member may be inserted");
    assert!(family[0].revoked_at.is_none());
    assert!(family[0].reuse_detected_at.is_none());
}

#[test]
fn refresh_token_scope_request_defaults_to_original_authorization() {
    let original = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "offline_access".to_owned(),
    ];

    assert_eq!(refresh_token_scopes(&original, None).unwrap(), original);
    assert_eq!(refresh_token_scopes(&original, Some("")).unwrap(), original);
    assert_eq!(
        refresh_token_scopes(&original, Some("   ")).unwrap(),
        original
    );
}

#[test]
fn refresh_token_scope_request_may_only_narrow_original_authorization_with_offline_access() {
    let original = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "offline_access".to_owned(),
    ];

    assert_eq!(
        refresh_token_scopes(&original, Some("openid offline_access")).unwrap(),
        vec!["openid".to_owned(), "offline_access".to_owned()]
    );
    assert!(
        refresh_token_scopes(&original, Some("openid openid")).is_err(),
        "scope requests without offline_access must be rejected so refresh-token rotation cannot be bypassed"
    );
}

#[test]
fn refresh_token_scope_request_rejects_privilege_expansion() {
    let original = vec!["openid".to_owned(), "offline_access".to_owned()];

    for requested in ["email", "openid", "openid email", "offline_access admin"] {
        assert!(
            refresh_token_scopes(&original, Some(requested)).is_err(),
            "refresh_token grant must reject scope requests that cannot rotate refresh tokens safely: {requested}"
        );
    }
}

#[test]
fn refresh_token_audience_request_defaults_to_refresh_token_audience() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();
    let mut token = token_row();
    token.audience = json!(["https://api.example/one", "https://api.example/two"]);
    let form = refresh_form_without_token();

    assert_eq!(
        refresh_token_audiences(&settings, &token, &form).unwrap(),
        vec![
            "https://api.example/one".to_owned(),
            "https://api.example/two".to_owned(),
        ]
    );
}

#[test]
fn refresh_token_audience_request_may_only_narrow_original_audience() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();
    let mut token = token_row();
    token.audience = json!(["https://api.example/one", "https://api.example/two"]);
    let mut form = refresh_form_without_token();
    form.audiences = vec!["https://api.example/two".to_owned()];

    assert_eq!(
        refresh_token_audiences(&settings, &token, &form).unwrap(),
        vec!["https://api.example/two".to_owned()]
    );
}

#[test]
fn refresh_token_audience_request_rejects_expansion() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();
    let mut token = token_row();
    token.audience = json!(["https://api.example/one"]);
    let mut form = refresh_form_without_token();
    form.audiences = vec!["https://api.example/two".to_owned()];

    assert!(refresh_token_audiences(&settings, &token, &form).is_err());
}

#[actix_web::test]
async fn refresh_grant_requires_refresh_token_before_database_lookup_or_token_issue() {
    let state = test_state();
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let client = client_row();
    let form = refresh_form_without_token();

    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("id_token").is_none());
    assert!(body.get("token_type").is_none());
}

#[actix_web::test]
async fn refresh_grant_reports_lookup_failure_without_issuing_tokens() {
    let state = test_state();
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let client = client_row();
    let mut form = refresh_form_without_token();
    form.refresh_token = Some("refresh-token-value".to_owned());

    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("id_token").is_none());
    assert!(body.get("token_type").is_none());
}

#[actix_web::test]
async fn refresh_grant_reports_lookup_query_failure_without_issuing_tokens() {
    let schema = format!("refresh_lookup_failure_{}", Uuid::now_v7().simple());
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_refresh_state_from_database_url(
        AuthorizationServerProfile::Oauth2Baseline,
        database_url,
    ) else {
        return;
    };
    create_isolated_schema(&state, &schema, &["oauth_tokens"]).await;
    rename_column(
        &state,
        &schema,
        "oauth_tokens",
        "refresh_token_blake3",
        "refresh_token_blake3_broken",
    )
    .await;
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let client = client_row();
    let mut form = refresh_form_without_token();
    form.refresh_token = Some("refresh-token-value".to_owned());

    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("id_token").is_none());
    assert!(body.get("token_type").is_none());
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn refresh_grant_rejects_unknown_expired_and_wrong_client_tokens() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;

    let mut missing_form = refresh_form_without_token();
    missing_form.refresh_token = Some("missing-refresh-token".to_owned());
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &missing_form, None).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());

    let mut wrong_client = token_row();
    let mut other_client = client_row();
    other_client.id = Uuid::now_v7();
    other_client.client_id = format!("client-other-{}", Uuid::now_v7());
    insert_refresh_client(&state, &other_client).await;
    wrong_client.client_id = other_client.id;
    wrong_client.user_id = None;
    wrong_client.dpop_jkt = None;
    let wrong_client_raw = "refresh-token-wrong-client";
    insert_refresh_token_row(&state, wrong_client_raw, &wrong_client, None, None).await;
    let mut wrong_client_form = refresh_form_without_token();
    wrong_client_form.refresh_token = Some(wrong_client_raw.to_owned());
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &wrong_client_form, None).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());

    let mut expired = token_row();
    expired.client_id = client.id;
    expired.scopes = json!(["accounts", "offline_access"]);
    expired.subject = client.client_id.clone();
    expired.user_id = None;
    expired.expires_at = Utc::now() - Duration::seconds(5);
    expired.dpop_jkt = None;
    let expired_raw = "refresh-token-expired";
    insert_refresh_token_row(&state, expired_raw, &expired, None, None).await;
    let mut expired_form = refresh_form_without_token();
    expired_form.refresh_token = Some(expired_raw.to_owned());
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &expired_form, None).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());
}

#[actix_web::test]
async fn refresh_grant_marks_family_reuse_and_revokes_active_family_tokens() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;
    let family_id = Uuid::now_v7();
    let suffix = Uuid::now_v7().simple();

    let mut reused = token_row();
    reused.client_id = client.id;
    reused.token_family_id = family_id;
    reused.scopes = json!(["accounts", "offline_access"]);
    reused.subject = client.client_id.clone();
    reused.user_id = None;
    reused.dpop_jkt = None;
    reused.revoked_at = Some(Utc::now() - Duration::seconds(65));
    let reused_raw = format!("refresh-token-reused-{suffix}");
    insert_refresh_token_row(&state, &reused_raw, &reused, None, None).await;

    let mut active_sibling = token_row();
    active_sibling.client_id = client.id;
    active_sibling.token_family_id = family_id;
    active_sibling.scopes = json!(["accounts", "offline_access"]);
    active_sibling.subject = client.client_id.clone();
    active_sibling.user_id = None;
    active_sibling.dpop_jkt = None;
    let active_raw = format!("refresh-token-active-sibling-{suffix}");
    insert_refresh_token_row(&state, &active_raw, &active_sibling, Some(reused.id), None).await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(reused_raw);
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    let family_rows = load_family_rows(&state, family_id).await;
    assert!(
        family_rows
            .iter()
            .all(|row| row.reuse_detected_at.is_some()),
        "refresh token reuse must be marked on the whole family"
    );
    assert!(
        family_rows
            .iter()
            .filter(|row| row.id == active_sibling.id)
            .all(|row| row.revoked_at.is_some()),
        "active family members must be revoked after reuse detection"
    );
}

#[actix_web::test]
async fn refresh_grant_rolls_back_reuse_marker_when_family_revoke_fails() {
    let schema = format!("refresh_reuse_marker_failure_{}", Uuid::now_v7().simple());
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_refresh_state_from_database_url(
        AuthorizationServerProfile::Oauth2Baseline,
        database_url,
    ) else {
        return;
    };
    create_isolated_schema(&state, &schema, &["oauth_tokens"]).await;

    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    let family_id = Uuid::now_v7();

    let mut reused = token_row();
    reused.client_id = client.id;
    reused.token_family_id = family_id;
    reused.scopes = json!(["accounts", "offline_access"]);
    reused.subject = client.client_id.clone();
    reused.user_id = None;
    reused.dpop_jkt = None;
    reused.revoked_at = Some(Utc::now() - Duration::seconds(65));
    let reused_raw = "refresh-token-reuse-marker-failure";
    insert_refresh_token_row(&state, reused_raw, &reused, None, None).await;
    let mut active_sibling = token_row();
    active_sibling.client_id = client.id;
    active_sibling.token_family_id = family_id;
    active_sibling.scopes = json!(["accounts", "offline_access"]);
    active_sibling.subject = client.client_id.clone();
    active_sibling.user_id = None;
    active_sibling.dpop_jkt = None;
    insert_refresh_token_row(
        &state,
        "refresh-token-active-marker-failure-sibling",
        &active_sibling,
        Some(reused.id),
        None,
    )
    .await;

    exec_sql(
        &state,
        &format!(
            r#"
            CREATE OR REPLACE FUNCTION "{}".reject_refresh_family_revoke()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'reject refresh family revoke in coverage test';
            END;
            $$;
            "#,
            schema
        ),
    )
    .await;
    exec_sql(
        &state,
        &format!(
            r#"
            CREATE TRIGGER reject_refresh_family_revoke
            BEFORE UPDATE OF revoked_at ON "{}".oauth_tokens
            FOR EACH ROW
            WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
            EXECUTE FUNCTION "{}".reject_refresh_family_revoke();
            "#,
            schema, schema
        ),
    )
    .await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(reused_raw.to_owned());
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("id_token").is_none());
    let family = load_family_rows(&state, family_id).await;
    assert!(
        family.iter().all(|row| row.reuse_detected_at.is_none()),
        "the first family UPDATE must roll back when the second UPDATE fails"
    );
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn refresh_grant_rejects_unbound_active_successor_inside_lost_response_window() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Fapi2Security) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;
    let family_id = Uuid::now_v7();
    let suffix = Uuid::now_v7();

    let mut revoked = token_row();
    revoked.client_id = client.id;
    revoked.token_family_id = family_id;
    revoked.scopes = json!(["accounts", "offline_access"]);
    revoked.subject = client.client_id.clone();
    revoked.user_id = None;
    revoked.dpop_jkt = None;
    revoked.revoked_at = Some(Utc::now() - Duration::seconds(35));
    let revoked_raw = format!("refresh-token-retry-original-{suffix}");
    insert_refresh_token_row(&state, &revoked_raw, &revoked, None, None).await;

    let mut successor = token_row();
    successor.client_id = client.id;
    successor.token_family_id = family_id;
    successor.scopes = json!(["accounts", "offline_access"]);
    successor.subject = client.client_id.clone();
    successor.user_id = None;
    successor.dpop_jkt = None;
    let successor_raw = format!("refresh-token-retry-successor-{suffix}");
    insert_refresh_token_row(&state, &successor_raw, &successor, Some(revoked.id), None).await;
    assert!(
        nazo_postgres::TokenRepository::new(state.diesel_db.clone())
            .inspect_lost_response_successor(&revoked, client.id, Utc::now())
            .await
            .expect("lost-response successor inspection should succeed")
            .is_none(),
        "an unbound bearer refresh token must never be eligible for lost-response recovery"
    );

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(revoked_raw.clone());
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unexpected response: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());

    let family = load_family_rows(&state, family_id).await;
    assert_eq!(family.len(), 2);
    assert!(family.iter().all(|row| row.reuse_detected_at.is_some()));
    assert!(family.iter().all(|row| row.revoked_at.is_some()));
    assert!(family.iter().any(|row| row.id == successor.id));
}

#[actix_web::test]
async fn refresh_grant_rotates_from_mtls_bound_successor_inside_lost_response_window() {
    let Some(state) = live_trusted_proxy_refresh_state(AuthorizationServerProfile::Fapi2Security)
    else {
        return;
    };
    let thumbprint = "REREREREREREREREREREREREREREREREREREREREREQ";
    let req = mtls_refresh_request(thumbprint);
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;
    let family_id = Uuid::now_v7();
    let suffix = Uuid::now_v7();

    let mut revoked = token_row();
    revoked.client_id = client.id;
    revoked.token_family_id = family_id;
    revoked.scopes = json!(["accounts", "offline_access"]);
    revoked.subject = client.client_id.clone();
    revoked.user_id = None;
    revoked.dpop_jkt = None;
    revoked.mtls_x5t_s256 = Some(thumbprint.to_owned());
    revoked.revoked_at = Some(Utc::now() - Duration::seconds(35));
    let revoked_raw = format!("refresh-token-mtls-retry-original-{suffix}");
    insert_refresh_token_row(&state, &revoked_raw, &revoked, None, None).await;

    let mut successor = token_row();
    successor.client_id = client.id;
    successor.token_family_id = family_id;
    successor.scopes = revoked.scopes.clone();
    successor.subject = revoked.subject.clone();
    successor.user_id = None;
    successor.dpop_jkt = None;
    successor.mtls_x5t_s256 = revoked.mtls_x5t_s256.clone();
    let successor_raw = format!("refresh-token-mtls-retry-successor-{suffix}");
    insert_refresh_token_row(&state, &successor_raw, &successor, Some(revoked.id), None).await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(revoked_raw.clone());
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    let returned_refresh = body["refresh_token"]
        .as_str()
        .expect("bound lost-response retry must return a newly issued refresh token");
    assert_ne!(returned_refresh, revoked_raw);
    assert_ne!(returned_refresh, successor_raw);
    let family = load_family_rows(&state, family_id).await;
    assert_eq!(family.len(), 3);
    assert!(family.iter().all(|row| row.reuse_detected_at.is_none()));
    assert_eq!(
        family.iter().filter(|row| row.revoked_at.is_none()).count(),
        1,
        "exactly the newly issued bound successor must remain active"
    );
    let active = family
        .iter()
        .find(|row| row.revoked_at.is_none())
        .expect("the newly issued family member should remain active");
    assert_eq!(active.rotated_from_id, Some(successor.id));
    assert_eq!(active.refresh_token_blake3, blake3_hex(returned_refresh));
}

#[actix_web::test]
async fn sequential_unbound_replay_after_first_commit_fails_closed() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;

    let family_id = Uuid::now_v7();
    let raw = format!("refresh-sequential-unbound-{}", Uuid::now_v7());
    let mut token = token_row();
    token.client_id = client.id;
    token.token_family_id = family_id;
    token.scopes = json!(["accounts", "offline_access"]);
    token.subject = client.client_id.clone();
    token.user_id = None;
    token.dpop_jkt = None;
    insert_refresh_token_row(&state, &raw, &token, None, None).await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(raw);
    let (first_status, first_body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;
    assert_eq!(
        first_status,
        StatusCode::OK,
        "unexpected response: {first_body}"
    );

    let (second_status, second_body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;
    assert_eq!(
        second_status,
        StatusCode::BAD_REQUEST,
        "a request started after the first response committed must not recover an unbound bearer successor: {second_body}"
    );
    assert_eq!(second_body["error"], "invalid_grant");
    let family = load_family_rows(&state, family_id).await;
    assert!(family.iter().all(|row| row.reuse_detected_at.is_some()));
    assert!(family.iter().all(|row| row.revoked_at.is_some()));
}

#[actix_web::test]
async fn lost_response_successor_enforces_fixed_window_boundaries_in_real_postgres() {
    let schema = format!("refresh_lost_window_{}", Uuid::now_v7().simple());
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_refresh_state_from_database_url(
        AuthorizationServerProfile::Oauth2Baseline,
        database_url,
    ) else {
        return;
    };
    create_isolated_schema(&state, &schema, &["oauth_tokens"]).await;

    let now = DateTime::parse_from_rfc3339("2026-07-13T12:00:00Z")
        .expect("fixed test timestamp should parse")
        .with_timezone(&Utc);
    let client_id = Uuid::now_v7();
    let family_id = Uuid::now_v7();
    let mut revoked = token_row();
    revoked.client_id = client_id;
    revoked.token_family_id = family_id;
    revoked.user_id = None;
    revoked.dpop_jkt = Some("fixed-window-dpop-jkt".to_owned());
    revoked.issued_at = now - Duration::hours(1);
    revoked.expires_at = now + Duration::hours(1);
    revoked.revoked_at = Some(now);
    insert_refresh_token_row(
        &state,
        &format!("refresh-lost-window-original-{}", Uuid::now_v7()),
        &revoked,
        None,
        None,
    )
    .await;

    let mut successor = token_row();
    successor.client_id = client_id;
    successor.token_family_id = family_id;
    successor.user_id = None;
    successor.dpop_jkt = revoked.dpop_jkt.clone();
    successor.issued_at = now;
    successor.expires_at = now + Duration::hours(1);
    insert_refresh_token_row(
        &state,
        &format!("refresh-lost-window-successor-{}", Uuid::now_v7()),
        &successor,
        Some(revoked.id),
        None,
    )
    .await;

    let repository = nazo_postgres::TokenRepository::new(state.diesel_db.clone());
    revoked.revoked_at = Some(now);
    let at_zero = repository
        .inspect_lost_response_successor(&revoked, client_id, now)
        .await;
    revoked.revoked_at = Some(now - Duration::seconds(60));
    let at_sixty_seconds = repository
        .inspect_lost_response_successor(&revoked, client_id, now)
        .await;
    revoked.revoked_at = Some(now - Duration::seconds(60) - Duration::milliseconds(1));
    let after_sixty_seconds = repository
        .inspect_lost_response_successor(&revoked, client_id, now)
        .await;
    revoked.revoked_at = Some(now + Duration::milliseconds(1));
    let future = repository
        .inspect_lost_response_successor(&revoked, client_id, now)
        .await;
    drop_schema(&state, &schema).await;

    let (at_zero, at_sixty_seconds, after_sixty_seconds, future) = (
        at_zero.expect("zero boundary should load"),
        at_sixty_seconds.expect("sixty-second boundary should load"),
        after_sixty_seconds.expect("after-window lookup should load"),
        future.expect("future lookup should load"),
    );
    assert_eq!(at_zero.map(|row| row.id), Some(successor.id));
    assert_eq!(
        at_sixty_seconds.map(|row| row.id),
        Some(successor.id),
        "the exact 60-second boundary must remain inclusive"
    );
    assert!(
        after_sixty_seconds.is_none(),
        "60 seconds plus 1 millisecond must be outside the retry window"
    );
    assert!(
        future.is_none(),
        "a future revocation must not become retryable"
    );
}

#[actix_web::test]
async fn refresh_grant_rejects_lost_response_retry_without_exactly_one_active_successor() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;

    for shape in ["none", "multiple", "expired", "revoked"] {
        let successor_count = usize::from(shape != "none") + usize::from(shape == "multiple");
        let family_id = Uuid::now_v7();
        let mut revoked = token_row();
        revoked.client_id = client.id;
        revoked.token_family_id = family_id;
        revoked.scopes = json!(["accounts", "offline_access"]);
        revoked.subject = client.client_id.clone();
        revoked.user_id = None;
        revoked.dpop_jkt = Some(format!("lost-shape-{shape}-dpop-jkt"));
        revoked.revoked_at = Some(Utc::now() - Duration::seconds(10));
        let revoked_raw = format!("refresh-lost-shape-{shape}-{}", Uuid::now_v7());
        insert_refresh_token_row(&state, &revoked_raw, &revoked, None, None).await;

        for _ in 0..successor_count {
            let mut successor = token_row();
            successor.client_id = client.id;
            successor.token_family_id = family_id;
            successor.scopes = revoked.scopes.clone();
            successor.subject = revoked.subject.clone();
            successor.user_id = None;
            successor.dpop_jkt = revoked.dpop_jkt.clone();
            if shape == "expired" {
                successor.expires_at = Utc::now() - Duration::seconds(1);
            }
            if shape == "revoked" {
                successor.revoked_at = Some(Utc::now() - Duration::seconds(1));
            }
            insert_refresh_token_row(
                &state,
                &format!("refresh-lost-shape-successor-{}", Uuid::now_v7()),
                &successor,
                Some(revoked.id),
                None,
            )
            .await;
        }

        let mut form = refresh_form_without_token();
        form.refresh_token = Some(revoked_raw);
        let (status, body) =
            response_json(token_refresh(&state, &req, &client, &form, None).await).await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "unexpected response: {body}"
        );
        assert_eq!(body["error"], "invalid_grant");
        let family = load_family_rows(&state, family_id).await;
        assert!(family.iter().all(|row| row.reuse_detected_at.is_some()));
        assert!(family.iter().all(|row| row.revoked_at.is_some()));
    }
}

#[actix_web::test]
async fn refresh_grant_rejects_wrong_client_family_or_sender_constrained_successors() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;
    let mut other_client = client_row();
    other_client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &other_client).await;

    let family_id = Uuid::now_v7();
    let mut revoked = token_row();
    revoked.client_id = client.id;
    revoked.token_family_id = family_id;
    revoked.scopes = json!(["accounts", "offline_access"]);
    revoked.subject = client.client_id.clone();
    revoked.user_id = None;
    revoked.dpop_jkt = Some("expected-jkt".to_owned());
    revoked.mtls_x5t_s256 = Some("expected-x5t".to_owned());
    revoked.revoked_at = Some(Utc::now() - Duration::seconds(10));
    let revoked_raw = format!("refresh-lost-wrong-constraints-{}", Uuid::now_v7());
    insert_refresh_token_row(&state, &revoked_raw, &revoked, None, None).await;

    let mut wrong_client = token_row();
    wrong_client.client_id = other_client.id;
    wrong_client.token_family_id = family_id;
    wrong_client.user_id = None;
    wrong_client.subject = revoked.subject.clone();
    wrong_client.scopes = revoked.scopes.clone();
    wrong_client.dpop_jkt = revoked.dpop_jkt.clone();
    wrong_client.mtls_x5t_s256 = revoked.mtls_x5t_s256.clone();
    insert_refresh_token_row(
        &state,
        &format!("refresh-lost-wrong-client-{}", Uuid::now_v7()),
        &wrong_client,
        Some(revoked.id),
        None,
    )
    .await;

    let mut wrong_family = token_row();
    wrong_family.client_id = client.id;
    wrong_family.user_id = None;
    wrong_family.subject = revoked.subject.clone();
    wrong_family.scopes = revoked.scopes.clone();
    wrong_family.dpop_jkt = revoked.dpop_jkt.clone();
    wrong_family.mtls_x5t_s256 = revoked.mtls_x5t_s256.clone();
    let wrong_family_id = wrong_family.token_family_id;
    insert_refresh_token_row(
        &state,
        &format!("refresh-lost-wrong-family-{}", Uuid::now_v7()),
        &wrong_family,
        Some(revoked.id),
        None,
    )
    .await;

    let mut wrong_sender = token_row();
    wrong_sender.client_id = client.id;
    wrong_sender.token_family_id = family_id;
    wrong_sender.user_id = None;
    wrong_sender.subject = revoked.subject.clone();
    wrong_sender.scopes = revoked.scopes.clone();
    wrong_sender.dpop_jkt = Some("wrong-jkt".to_owned());
    wrong_sender.mtls_x5t_s256 = revoked.mtls_x5t_s256.clone();
    insert_refresh_token_row(
        &state,
        &format!("refresh-lost-wrong-sender-{}", Uuid::now_v7()),
        &wrong_sender,
        Some(revoked.id),
        None,
    )
    .await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(revoked_raw);
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unexpected response: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
    let family = load_family_rows(&state, family_id).await;
    assert!(family.iter().all(|row| row.reuse_detected_at.is_some()));
    assert!(family.iter().all(|row| row.revoked_at.is_some()));
    let unrelated_family = load_family_rows(&state, wrong_family_id).await;
    assert!(
        unrelated_family
            .iter()
            .all(|row| row.reuse_detected_at.is_none() && row.revoked_at.is_none()),
        "family compromise must remain isolated to the presented token family"
    );
}

#[actix_web::test]
async fn lost_response_successor_requires_same_tenant_in_real_postgres() {
    let schema = format!("refresh_lost_tenant_{}", Uuid::now_v7().simple());
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_refresh_state_from_database_url(
        AuthorizationServerProfile::Oauth2Baseline,
        database_url,
    ) else {
        return;
    };
    create_isolated_schema(&state, &schema, &["oauth_tokens"]).await;

    let client_id = Uuid::now_v7();
    let family_id = Uuid::now_v7();
    let mut revoked = token_row();
    revoked.client_id = client_id;
    revoked.token_family_id = family_id;
    revoked.user_id = None;
    revoked.dpop_jkt = Some("same-tenant-dpop-jkt".to_owned());
    revoked.revoked_at = Some(Utc::now() - Duration::seconds(10));
    insert_refresh_token_row(&state, "refresh-lost-tenant-original", &revoked, None, None).await;

    let mut wrong_tenant = token_row();
    wrong_tenant.tenant_id = Uuid::now_v7();
    wrong_tenant.client_id = client_id;
    wrong_tenant.token_family_id = family_id;
    wrong_tenant.user_id = None;
    wrong_tenant.dpop_jkt = revoked.dpop_jkt.clone();
    insert_refresh_token_row(
        &state,
        "refresh-lost-wrong-tenant-successor",
        &wrong_tenant,
        Some(revoked.id),
        None,
    )
    .await;

    assert!(
        nazo_postgres::TokenRepository::new(state.diesel_db.clone())
            .inspect_lost_response_successor(&revoked, client_id, Utc::now())
            .await
            .expect("successor lookup should succeed")
            .is_none(),
        "a cross-tenant child must not satisfy lost-response recovery"
    );
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn lost_response_rotation_rolls_back_successor_revoke_when_insert_fails() {
    let schema = format!("refresh_lost_insert_failure_{}", Uuid::now_v7().simple());
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(mut state) = live_refresh_state_from_database_url(
        AuthorizationServerProfile::Oauth2Baseline,
        database_url,
    ) else {
        return;
    };
    let mut settings = (*state.settings).clone();
    settings.endpoint.trusted_proxy_cidrs = vec![
        crate::http::client_ip::IpCidr::parse("127.0.0.1/32")
            .expect("trusted proxy CIDR should parse"),
    ];
    state.settings = Arc::new(settings);
    create_isolated_schema(&state, &schema, &["oauth_tokens"]).await;

    let thumbprint = "REREREREREREREREREREREREREREREREREREREREREQ";
    let req = mtls_refresh_request(thumbprint);
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    let family_id = Uuid::now_v7();
    let mut revoked = token_row();
    revoked.client_id = client.id;
    revoked.token_family_id = family_id;
    revoked.scopes = json!(["accounts", "offline_access"]);
    revoked.subject = client.client_id.clone();
    revoked.user_id = None;
    revoked.dpop_jkt = None;
    revoked.mtls_x5t_s256 = Some(thumbprint.to_owned());
    revoked.revoked_at = Some(Utc::now() - Duration::seconds(10));
    insert_refresh_token_row(
        &state,
        "refresh-lost-insert-failure-original",
        &revoked,
        None,
        None,
    )
    .await;
    let mut successor = token_row();
    successor.client_id = client.id;
    successor.token_family_id = family_id;
    successor.scopes = revoked.scopes.clone();
    successor.subject = revoked.subject.clone();
    successor.user_id = None;
    successor.dpop_jkt = None;
    successor.mtls_x5t_s256 = revoked.mtls_x5t_s256.clone();
    insert_refresh_token_row(
        &state,
        "refresh-lost-insert-failure-successor",
        &successor,
        Some(revoked.id),
        None,
    )
    .await;

    exec_sql(
        &state,
        &format!(
            r#"
            CREATE OR REPLACE FUNCTION "{}".reject_lost_response_insert()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'reject lost-response refresh insert in coverage test';
            END;
            $$;
            "#,
            schema
        ),
    )
    .await;
    exec_sql(
        &state,
        &format!(
            r#"
            CREATE TRIGGER reject_lost_response_insert
            BEFORE INSERT ON "{}".oauth_tokens
            FOR EACH ROW
            EXECUTE FUNCTION "{}".reject_lost_response_insert();
            "#,
            schema, schema
        ),
    )
    .await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some("refresh-lost-insert-failure-original".to_owned());
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    let family = load_family_rows(&state, family_id).await;
    assert!(family.iter().all(|row| row.reuse_detected_at.is_none()));
    assert!(
        family
            .iter()
            .any(|row| row.id == successor.id && row.revoked_at.is_none()),
        "successor revocation must roll back with the failed child insert"
    );
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn refresh_grant_rejects_future_revocation_or_reuse_marked_lost_response_family() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;

    for (label, revoked_at, reuse_detected_at) in [
        ("future", Utc::now() + Duration::seconds(10), None),
        (
            "reused",
            Utc::now() - Duration::seconds(10),
            Some(Utc::now() - Duration::seconds(1)),
        ),
    ] {
        let family_id = Uuid::now_v7();
        let mut revoked = token_row();
        revoked.client_id = client.id;
        revoked.token_family_id = family_id;
        revoked.scopes = json!(["accounts", "offline_access"]);
        revoked.subject = client.client_id.clone();
        revoked.user_id = None;
        revoked.dpop_jkt = Some(format!("lost-{label}-dpop-jkt"));
        revoked.revoked_at = Some(revoked_at);
        let revoked_raw = format!("refresh-lost-{label}-{}", Uuid::now_v7());
        insert_refresh_token_row(&state, &revoked_raw, &revoked, None, reuse_detected_at).await;

        let mut successor = token_row();
        successor.client_id = client.id;
        successor.token_family_id = family_id;
        successor.scopes = revoked.scopes.clone();
        successor.subject = revoked.subject.clone();
        successor.user_id = None;
        successor.dpop_jkt = revoked.dpop_jkt.clone();
        insert_refresh_token_row(
            &state,
            &format!("refresh-lost-{label}-successor-{}", Uuid::now_v7()),
            &successor,
            Some(revoked.id),
            None,
        )
        .await;

        let mut form = refresh_form_without_token();
        form.refresh_token = Some(revoked_raw);
        let (status, body) =
            response_json(token_refresh(&state, &req, &client, &form, None).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {body}");
        assert_eq!(body["error"], "invalid_grant");
        let family = load_family_rows(&state, family_id).await;
        assert!(family.iter().all(|row| row.reuse_detected_at.is_some()));
        assert!(family.iter().all(|row| row.revoked_at.is_some()));
    }
}

#[actix_web::test]
async fn concurrent_mtls_bound_lost_response_retries_yield_one_success_then_compromise_family() {
    let Some(state) = live_trusted_proxy_refresh_state(AuthorizationServerProfile::Oauth2Baseline)
    else {
        return;
    };
    let thumbprint = "REREREREREREREREREREREREREREREREREREREREREQ";
    let req = mtls_refresh_request(thumbprint);
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;

    let family_id = Uuid::now_v7();
    let mut revoked = token_row();
    revoked.client_id = client.id;
    revoked.token_family_id = family_id;
    revoked.scopes = json!(["accounts", "offline_access"]);
    revoked.subject = client.client_id.clone();
    revoked.user_id = None;
    revoked.dpop_jkt = None;
    revoked.mtls_x5t_s256 = Some(thumbprint.to_owned());
    revoked.revoked_at = Some(Utc::now() - Duration::seconds(10));
    let revoked_raw = format!("refresh-concurrent-lost-original-{}", Uuid::now_v7());
    insert_refresh_token_row(&state, &revoked_raw, &revoked, None, None).await;

    let mut successor = token_row();
    successor.client_id = client.id;
    successor.token_family_id = family_id;
    successor.scopes = revoked.scopes.clone();
    successor.subject = revoked.subject.clone();
    successor.user_id = None;
    successor.dpop_jkt = None;
    successor.mtls_x5t_s256 = revoked.mtls_x5t_s256.clone();
    insert_refresh_token_row(
        &state,
        &format!("refresh-concurrent-lost-successor-{}", Uuid::now_v7()),
        &successor,
        Some(revoked.id),
        None,
    )
    .await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(revoked_raw);
    let (first, second) = tokio::join!(
        token_refresh(&state, &req, &client, &form, None),
        token_refresh(&state, &req, &client, &form, None)
    );
    let (first, second) = tokio::join!(response_json(first), response_json(second));
    let mut outcomes = [first, second];
    outcomes.sort_by_key(|outcome| outcome.0.as_u16());
    assert_eq!(outcomes[0].0, StatusCode::OK);
    assert_eq!(outcomes[1].0, StatusCode::BAD_REQUEST);
    assert_eq!(outcomes[1].1["error"], "invalid_grant");
    let family = load_family_rows(&state, family_id).await;
    assert!(family.iter().all(|row| row.reuse_detected_at.is_some()));
    assert!(family.iter().all(|row| row.revoked_at.is_some()));
}

#[actix_web::test]
async fn concurrent_refresh_replay_yields_one_success_and_one_invalid_grant() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;

    let family_id = Uuid::now_v7();
    let raw = format!("refresh-concurrent-replay-{}", Uuid::now_v7());
    let mut token = token_row();
    token.client_id = client.id;
    token.token_family_id = family_id;
    token.scopes = json!(["accounts", "offline_access"]);
    token.subject = client.client_id.clone();
    token.user_id = None;
    token.dpop_jkt = None;
    insert_refresh_token_row(&state, &raw, &token, None, None).await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(raw);
    let (first, second) = tokio::join!(
        token_refresh(&state, &req, &client, &form, None),
        token_refresh(&state, &req, &client, &form, None)
    );
    let (first, second) = tokio::join!(response_json(first), response_json(second));
    let mut outcomes = [first, second];
    outcomes.sort_by_key(|outcome| outcome.0.as_u16());

    assert_eq!(outcomes[0].0, StatusCode::OK);
    assert_eq!(outcomes[1].0, StatusCode::BAD_REQUEST);
    assert_eq!(outcomes[1].1["error"], "invalid_grant");
    assert!(
        outcomes[0].1["refresh_token"].as_str().is_some(),
        "the HTTP winner still returns its already-issued response"
    );
    let family = load_family_rows(&state, family_id).await;
    assert!(
        family.iter().all(|row| row.reuse_detected_at.is_some()),
        "replay compromises every family member"
    );
    assert!(
        family.iter().all(|row| row.revoked_at.is_some()),
        "HTTP 200 does not guarantee its refresh token remains active after family compromise"
    );
}

#[actix_web::test]
async fn refresh_grant_rejects_tokens_for_inactive_users_without_openid_scope() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    client.scopes = vec!["offline_access".to_owned(), "api".to_owned()];
    insert_refresh_client(&state, &client).await;

    let user_id = Uuid::now_v7();
    insert_refresh_user(&state, user_id, false).await;
    let raw_refresh_token = format!("refresh-inactive-user-{}", Uuid::now_v7());
    let mut token = token_row();
    token.client_id = client.id;
    token.user_id = Some(user_id);
    token.scopes = json!(["offline_access", "api"]);
    token.subject = user_id.to_string();
    token.dpop_jkt = None;
    insert_refresh_token_row(&state, &raw_refresh_token, &token, None, None).await;
    let mut form = refresh_form_without_token();
    form.refresh_token = Some(raw_refresh_token);

    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("id_token").is_none());
}

#[actix_web::test]
async fn refresh_grant_accepts_tokens_for_active_users_without_openid_scope() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    client.scopes = vec!["offline_access".to_owned(), "api".to_owned()];
    insert_refresh_client(&state, &client).await;

    let user_id = Uuid::now_v7();
    insert_refresh_user(&state, user_id, true).await;
    let raw_refresh_token = format!("refresh-active-user-{}", Uuid::now_v7());
    let mut token = token_row();
    token.client_id = client.id;
    token.user_id = Some(user_id);
    token.scopes = json!(["offline_access", "api"]);
    token.subject = user_id.to_string();
    token.dpop_jkt = None;
    insert_refresh_token_row(&state, &raw_refresh_token, &token, None, None).await;
    let mut form = refresh_form_without_token();
    form.refresh_token = Some(raw_refresh_token);

    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "unexpected refresh response: {body}"
    );
    assert_eq!(body["token_type"], "Bearer");
    assert!(
        body["access_token"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
}

#[actix_web::test]
async fn refresh_grant_rejects_unbound_refresh_tokens_for_dpop_required_clients() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = true;
    insert_refresh_client(&state, &client).await;

    let raw_refresh_token = format!("refresh-unbound-dpop-{}", Uuid::now_v7());
    let mut token = token_row();
    token.client_id = client.id;
    token.user_id = None;
    token.subject = client.client_id.clone();
    token.scopes = json!(["offline_access", "api"]);
    token.dpop_jkt = None;
    insert_refresh_token_row(&state, &raw_refresh_token, &token, None, None).await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(raw_refresh_token);
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        body["error_description"],
        "refresh_token requires proof of possession."
    );
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn refresh_grant_rejects_public_dpop_required_clients_with_unbound_refresh_tokens() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.client_type = "public".to_owned();
    client.token_endpoint_auth_method = "none".to_owned();
    client.require_dpop_bound_tokens = true;
    insert_refresh_client(&state, &client).await;

    let raw_refresh_token = format!("refresh-public-unbound-dpop-{}", Uuid::now_v7());
    let mut token = token_row();
    token.client_id = client.id;
    token.user_id = None;
    token.subject = client.client_id.clone();
    token.scopes = json!(["offline_access", "api"]);
    token.dpop_jkt = None;
    insert_refresh_token_row(&state, &raw_refresh_token, &token, None, None).await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(raw_refresh_token);
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        body["error_description"],
        "refresh_token is not DPoP-bound."
    );
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn refresh_grant_rejects_dpop_bound_refresh_token_without_proof() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;

    let raw_refresh_token = format!("refresh-token-bound-no-proof-{}", Uuid::now_v7());
    let mut token = token_row();
    token.client_id = client.id;
    token.user_id = None;
    token.subject = client.client_id.clone();
    token.scopes = json!(["offline_access", "api"]);
    token.dpop_jkt = Some("stored-dpop-jkt".to_owned());
    insert_refresh_token_row(&state, &raw_refresh_token, &token, None, None).await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(raw_refresh_token);
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        body["error_description"],
        "refresh_token requires proof of possession."
    );
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn refresh_grant_rejects_missing_offline_access_scope_expansion_and_invalid_audience() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();

    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;
    let mut no_offline = token_row();
    no_offline.client_id = client.id;
    no_offline.subject = client.client_id.clone();
    no_offline.user_id = None;
    no_offline.scopes = json!(["accounts"]);
    no_offline.dpop_jkt = None;
    let no_offline_raw = "refresh-token-no-offline-access";
    insert_refresh_token_row(&state, no_offline_raw, &no_offline, None, None).await;
    let mut form = refresh_form_without_token();
    form.refresh_token = Some(no_offline_raw.to_owned());
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());

    let mut scope_token = token_row();
    scope_token.client_id = client.id;
    scope_token.subject = client.client_id.clone();
    scope_token.user_id = None;
    scope_token.scopes = json!(["accounts", "offline_access"]);
    scope_token.dpop_jkt = None;
    let scope_raw = "refresh-token-invalid-scope";
    insert_refresh_token_row(&state, scope_raw, &scope_token, None, None).await;
    let mut scope_form = refresh_form_without_token();
    scope_form.refresh_token = Some(scope_raw.to_owned());
    scope_form.scope = Some("accounts offline_access admin".to_owned());
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &scope_form, None).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_scope");
    assert!(body.get("access_token").is_none());

    let audience_raw = "refresh-token-invalid-audience";
    let mut audience_token = token_row();
    audience_token.client_id = client.id;
    audience_token.subject = client.client_id.clone();
    audience_token.user_id = None;
    audience_token.scopes = json!(["accounts", "offline_access"]);
    audience_token.dpop_jkt = None;
    insert_refresh_token_row(&state, audience_raw, &audience_token, None, None).await;
    let mut audience_form = refresh_form_without_token();
    audience_form.refresh_token = Some(audience_raw.to_owned());
    audience_form.audiences = vec!["resource://other".to_owned()];
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &audience_form, None).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_target");
    assert!(body.get("access_token").is_none());
}

#[actix_web::test]
async fn refresh_grant_rejects_mtls_bound_tokens_without_matching_verified_certificate() {
    let Some(state) = live_trusted_proxy_refresh_state(AuthorizationServerProfile::Oauth2Baseline)
    else {
        return;
    };
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;

    let mut token = token_row();
    token.client_id = client.id;
    token.subject = client.client_id.clone();
    token.user_id = None;
    token.scopes = json!(["accounts", "offline_access"]);
    token.dpop_jkt = None;
    token.mtls_x5t_s256 = Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned());

    let missing_cert_raw = format!("refresh-mtls-missing-{}", Uuid::now_v7());
    insert_refresh_token_row(&state, &missing_cert_raw, &token, None, None).await;
    let mut missing_cert_form = refresh_form_without_token();
    missing_cert_form.refresh_token = Some(missing_cert_raw);
    let missing_cert_req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let (status, body) = response_json(
        token_refresh(&state, &missing_cert_req, &client, &missing_cert_form, None).await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());

    let mismatch_raw = format!("refresh-mtls-mismatch-{}", Uuid::now_v7());
    token.id = Uuid::now_v7();
    insert_refresh_token_row(&state, &mismatch_raw, &token, None, None).await;
    let mut mismatch_form = refresh_form_without_token();
    mismatch_form.refresh_token = Some(mismatch_raw);
    let mismatch_req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-verify"),
            "SUCCESS",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-subject-dn"),
            "CN=refresh-actual",
        ))
        .to_http_request();
    let (status, body) =
        response_json(token_refresh(&state, &mismatch_req, &client, &mismatch_form, None).await)
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());
}

#[actix_web::test]
async fn refresh_grant_requires_verified_certificate_when_client_policy_demands_mtls() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;
    insert_refresh_client(&state, &client).await;

    let raw_refresh_token = format!("refresh-policy-mtls-{}", Uuid::now_v7());
    let mut token = token_row();
    token.client_id = client.id;
    token.subject = client.client_id.clone();
    token.user_id = None;
    token.scopes = json!(["accounts", "offline_access"]);
    token.dpop_jkt = None;
    token.mtls_x5t_s256 = None;
    insert_refresh_token_row(&state, &raw_refresh_token, &token, None, None).await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(raw_refresh_token);
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .to_http_request();
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());
}

#[actix_web::test]
async fn refresh_grant_accepts_existing_mtls_bound_token_with_matching_certificate() {
    let Some(state) = live_trusted_proxy_refresh_state(AuthorizationServerProfile::Oauth2Baseline)
    else {
        return;
    };
    let thumbprint = "REREREREREREREREREREREREREREREREREREREREREQ";
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;

    let raw_refresh_token = format!("refresh-token-mtls-bound-{}", Uuid::now_v7());
    let mut token = token_row();
    token.client_id = client.id;
    token.subject = client.client_id.clone();
    token.user_id = None;
    token.scopes = json!(["accounts", "offline_access"]);
    token.dpop_jkt = None;
    token.mtls_x5t_s256 = Some(thumbprint.to_owned());
    insert_refresh_token_row(&state, &raw_refresh_token, &token, None, None).await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(raw_refresh_token);
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-verify"),
            "SUCCESS",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            thumbprint,
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-subject-dn"),
            "CN=refresh-existing-binding",
        ))
        .to_http_request();

    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "unexpected refresh response: {body}"
    );
    let access_token = body["access_token"]
        .as_str()
        .expect("successful refresh response should return an access token");
    let claims =
        decode_access_claims_with(&state.keyset, &state.settings.endpoint.issuer, access_token)
            .expect("newly issued access token should be verifiable");
    assert_eq!(
        claims.cnf.as_ref().and_then(|cnf| cnf.x5t_s256.as_deref()),
        Some(thumbprint)
    );
}

#[actix_web::test]
async fn refresh_grant_binds_access_tokens_to_verified_mtls_certificate_when_required() {
    let Some(state) = live_trusted_proxy_refresh_state(AuthorizationServerProfile::Oauth2Baseline)
    else {
        return;
    };
    let thumbprint = "REREREREREREREREREREREREREREREREREREREREREQ";
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;
    client.token_endpoint_auth_method = "tls_client_auth".to_owned();
    client.tls_client_auth_cert_sha256 = Some(thumbprint.to_owned());
    insert_refresh_client(&state, &client).await;

    let raw_refresh_token = format!("refresh-policy-mtls-success-{}", Uuid::now_v7());
    let mut token = token_row();
    token.client_id = client.id;
    token.subject = client.client_id.clone();
    token.user_id = None;
    token.scopes = json!(["accounts", "offline_access"]);
    token.dpop_jkt = None;
    token.mtls_x5t_s256 = None;
    insert_refresh_token_row(&state, &raw_refresh_token, &token, None, None).await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(raw_refresh_token);
    let req = actix_web::test::TestRequest::post()
        .uri("/oauth/token")
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-verify"),
            "SUCCESS",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            thumbprint,
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-subject-dn"),
            "CN=refresh-actual",
        ))
        .to_http_request();
    let request_thumbprint = crate::http::mtls::request_mtls_thumbprint(&req, &state.settings)
        .expect("trusted proxy request should expose verified client certificate thumbprint");
    assert_eq!(request_thumbprint, thumbprint);
    let (status, body) =
        response_json(token_refresh(&state, &req, &client, &form, None).await).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "unexpected refresh response: {body}"
    );
    let access_token = body["access_token"]
        .as_str()
        .expect("successful refresh response should return an access token");
    let claims =
        decode_access_claims_with(&state.keyset, &state.settings.endpoint.issuer, access_token)
            .expect("newly issued access token should be verifiable");
    let cnf = claims
        .cnf
        .expect("mTLS-bound refresh grants must issue sender-constrained access tokens");
    assert_eq!(cnf.x5t_s256.as_deref(), Some(thumbprint));
    assert_eq!(body["token_type"], "Bearer");
    assert!(
        body.get("refresh_token").is_none(),
        "sender-constrained confidential clients preserve their existing refresh token"
    );
}
