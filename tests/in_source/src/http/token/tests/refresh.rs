use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::{create_pool, get_conn};
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore, VerificationKey};
use crate::support::{generate_key_material, public_jwk_from_private_der};
use diesel::sql_query;
use diesel::sql_types::{Bool, Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;

#[derive(QueryableByName)]
struct RefreshFamilyTokenRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    reuse_detected_at: Option<DateTime<Utc>>,
}

fn test_state() -> AppState {
    AppState {
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
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

fn live_refresh_state(profile: AuthorizationServerProfile) -> Option<AppState> {
    live_refresh_state_from_database_url(profile, std::env::var("DATABASE_URL").ok()?)
}

fn live_refresh_state_from_database_url(
    profile: AuthorizationServerProfile,
    database_url: String,
) -> Option<AppState> {
    let key_material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("test key should generate");
    let active_kid = "refresh-test-kid".to_owned();
    let active_alg = jsonwebtoken::Algorithm::EdDSA;
    let public_jwk =
        public_jwk_from_private_der(&active_kid, active_alg, &key_material.private_pkcs8_der)
            .expect("test public JWK should derive from signing key");
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.authorization_server_profile = profile;

    Some(AppState {
        diesel_db: create_pool(database_url, 1).expect("database pool should build"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: active_kid.clone(),
            active_alg,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(key_material.private_pkcs8_der),
            verification_keys: vec![VerificationKey {
                kid: active_kid,
                public_jwk,
                local_signing_key: None,
            }],
        }),
    })
}

fn database_url_with_search_path(schema: &str) -> Option<String> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let separator = if base.contains('?') { "&" } else { "?" };
    Some(format!(
        "{base}{separator}options=-csearch_path%3D{schema}%2Cpublic"
    ))
}

async fn exec_sql(state: &AppState, sql: &str) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(sql)
        .execute(&mut conn)
        .await
        .expect("schema mutation should succeed");
}

async fn create_isolated_schema(state: &AppState, schema: &str, tables: &[&str]) {
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

async fn rename_column(state: &AppState, schema: &str, table: &str, from: &str, to: &str) {
    exec_sql(
        state,
        &format!(
            r#"ALTER TABLE "{}"."{}" RENAME COLUMN "{}" TO "{}""#,
            schema, table, from, to
        ),
    )
    .await;
}

async fn drop_schema(state: &AppState, schema: &str) {
    exec_sql(
        state,
        &format!(r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#, schema),
    )
    .await;
}

fn live_trusted_proxy_refresh_state(profile: AuthorizationServerProfile) -> Option<AppState> {
    let mut state = live_refresh_state(profile)?;
    let mut settings = (*state.settings).clone();
    settings.trusted_proxy_cidrs = vec![
        crate::support::IpCidr::parse("127.0.0.1/32").expect("trusted proxy CIDR should parse"),
    ];
    state.settings = Arc::new(settings);
    Some(state)
}

async fn insert_refresh_token_row(
    state: &AppState,
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

async fn insert_refresh_client(state: &AppState, client: &ClientRow) {
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
    .bind::<Nullable<Text>, _>(client.client_secret_hash.as_deref())
    .bind::<Jsonb, _>(client.redirect_uris.clone())
    .bind::<Jsonb, _>(client.scopes.clone())
    .bind::<Jsonb, _>(client.allowed_audiences.clone())
    .bind::<Jsonb, _>(client.grant_types.clone())
    .bind::<Text, _>(client.token_endpoint_auth_method.as_str())
    .bind::<Bool, _>(client.require_dpop_bound_tokens)
    .bind::<Bool, _>(client.require_mtls_bound_tokens)
    .bind::<Jsonb, _>(client.tls_client_auth_san_dns.clone())
    .bind::<Jsonb, _>(client.tls_client_auth_san_uri.clone())
    .bind::<Jsonb, _>(client.tls_client_auth_san_ip.clone())
    .bind::<Jsonb, _>(client.tls_client_auth_san_email.clone())
    .bind::<Bool, _>(client.allow_client_assertion_audience_array)
    .bind::<Bool, _>(client.allow_client_assertion_endpoint_audience)
    .bind::<Bool, _>(client.require_par_request_object)
    .bind::<Bool, _>(client.allow_authorization_code_without_pkce)
    .bind::<Bool, _>(client.is_active)
    .bind::<Jsonb, _>(client.post_logout_redirect_uris.clone())
    .bind::<Bool, _>(client.backchannel_logout_session_required)
    .execute(&mut conn)
    .await
    .expect("refresh test client should insert");
}

async fn insert_refresh_user(state: &AppState, user_id: Uuid, active: bool) {
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

async fn load_family_rows(state: &AppState, family_id: Uuid) -> Vec<RefreshFamilyTokenRow> {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        SELECT id, revoked_at, reuse_detected_at
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
    ClientRow {
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
fn fapi_profiles_preserve_sender_constrained_refresh_tokens() {
    let token = token_row();
    let client = client_row();

    for profile in [
        AuthorizationServerProfile::Fapi2Security,
        AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest,
    ] {
        assert_eq!(
            refresh_token_policy_for_authorization_server_profile(profile, &client, &token),
            RefreshTokenPolicy::PreserveExisting
        );
    }
}

#[test]
fn baseline_profile_rotates_confidential_sender_constrained_refresh_tokens() {
    let token = token_row();
    let client = client_row();

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
        "baseline refresh-token grants keep replay detection by rotating"
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
fn baseline_profile_rotates_confidential_secret_authenticated_sender_constrained_refresh_tokens() {
    let token = token_row();
    let mut client = client_row();
    client.token_endpoint_auth_method = "client_secret_basic".to_owned();

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
        "only confidential clients using holder-of-key client auth may preserve sender-constrained refresh tokens"
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
    settings.authorization_server_profile = AuthorizationServerProfile::Fapi2Security;
    let token = token_row();
    let mut client = client_row();
    client.client_type = "public".to_owned();
    client.token_endpoint_auth_method = "none".to_owned();
    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = false;

    assert_eq!(
        refresh_token_policy_for_profile(&settings, &client, &token),
        RefreshTokenPolicy::PreserveExisting,
        "FAPI profiles may preserve refresh-token families when the token stores a sender constraint"
    );

    let mut unbound_token = token_row();
    unbound_token.dpop_jkt = None;
    unbound_token.mtls_x5t_s256 = None;
    assert_eq!(
        refresh_token_policy_for_profile(&settings, &client, &unbound_token),
        RefreshTokenPolicy::Rotate {
            family_id: unbound_token.token_family_id,
            rotated_from_id: unbound_token.id,
        },
        "FAPI refresh-token grants rotate when the stored token has no stable sender constraint"
    );

    let mut mtls_bound_token = token_row();
    mtls_bound_token.dpop_jkt = None;
    mtls_bound_token.mtls_x5t_s256 = Some("mtls-thumbprint".to_owned());
    assert_eq!(
        refresh_token_policy_for_profile(&settings, &client, &mtls_bound_token),
        RefreshTokenPolicy::PreserveExisting,
        "mTLS-bound refresh-token families are also stable sender-constrained tokens"
    );

    settings.authorization_server_profile = AuthorizationServerProfile::Oauth2Baseline;
    assert_eq!(
        refresh_token_policy_for_profile(&settings, &client, &token),
        RefreshTokenPolicy::Rotate {
            family_id: token.token_family_id,
            rotated_from_id: token.id,
        }
    );
}

#[test]
fn lost_refresh_retry_allows_only_short_post_rotation_window() {
    let now = Utc::now();

    assert!(within_lost_refresh_token_retry_window(
        now - Duration::seconds(1),
        now
    ));
    assert!(within_lost_refresh_token_retry_window(
        now - Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS),
        now
    ));
    assert!(!within_lost_refresh_token_retry_window(
        now - Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS + 1),
        now
    ));
}

#[test]
fn lost_refresh_retry_rejects_future_revocation_times() {
    let now = Utc::now();

    assert!(!within_lost_refresh_token_retry_window(
        now + Duration::seconds(1),
        now
    ));
}

#[actix_web::test]
async fn lost_refresh_token_successor_returns_none_for_non_retriable_states() {
    let Some(state) = live_refresh_state(AuthorizationServerProfile::Oauth2Baseline) else {
        return;
    };
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    insert_refresh_client(&state, &client).await;

    let mut active = token_row();
    active.client_id = client.id;
    active.user_id = None;
    active.subject = client.client_id.clone();
    active.scopes = json!(["accounts", "offline_access"]);
    active.dpop_jkt = None;
    assert!(
        lost_refresh_token_successor(&state, &active, client.id)
            .await
            .expect("active token should inspect")
            .is_none()
    );

    let mut old_revoked = token_row();
    old_revoked.client_id = client.id;
    old_revoked.user_id = None;
    old_revoked.subject = client.client_id.clone();
    old_revoked.scopes = json!(["accounts", "offline_access"]);
    old_revoked.dpop_jkt = None;
    old_revoked.revoked_at = Some(Utc::now() - Duration::seconds(61));
    assert!(
        lost_refresh_token_successor(&state, &old_revoked, client.id)
            .await
            .expect("old revoked token should inspect")
            .is_none()
    );

    let mut reused = token_row();
    reused.client_id = client.id;
    reused.user_id = None;
    reused.subject = client.client_id.clone();
    reused.scopes = json!(["accounts", "offline_access"]);
    reused.dpop_jkt = None;
    reused.token_family_id = Uuid::now_v7();
    reused.revoked_at = Some(Utc::now() - Duration::seconds(10));
    let reused_raw = format!("refresh-token-reused-{}", Uuid::now_v7());
    insert_refresh_token_row(
        &state,
        &reused_raw,
        &reused,
        None,
        Some(Utc::now() - Duration::seconds(5)),
    )
    .await;
    assert!(
        lost_refresh_token_successor(&state, &reused, client.id)
            .await
            .expect("reuse-marked family should inspect")
            .is_none()
    );

    let mut revoked_without_successor = token_row();
    revoked_without_successor.client_id = client.id;
    revoked_without_successor.user_id = None;
    revoked_without_successor.subject = client.client_id.clone();
    revoked_without_successor.scopes = json!(["accounts", "offline_access"]);
    revoked_without_successor.dpop_jkt = None;
    revoked_without_successor.token_family_id = Uuid::now_v7();
    revoked_without_successor.revoked_at = Some(Utc::now() - Duration::seconds(10));
    let revoked_raw = format!("refresh-token-no-successor-{}", Uuid::now_v7());
    insert_refresh_token_row(&state, &revoked_raw, &revoked_without_successor, None, None).await;
    assert!(
        lost_refresh_token_successor(&state, &revoked_without_successor, client.id)
            .await
            .expect("revoked token without successor should inspect")
            .is_none()
    );
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

#[test]
fn lost_refresh_retry_allows_exact_rotation_timestamp_only_until_window_expires() {
    let now = Utc::now();

    assert!(within_lost_refresh_token_retry_window(now, now));
    assert!(!within_lost_refresh_token_retry_window(
        now - Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS + 1),
        now
    ));
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

    let mut reused = token_row();
    reused.client_id = client.id;
    reused.token_family_id = family_id;
    reused.scopes = json!(["accounts", "offline_access"]);
    reused.subject = client.client_id.clone();
    reused.user_id = None;
    reused.dpop_jkt = None;
    reused.revoked_at = Some(Utc::now() - Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS + 5));
    let reused_raw = "refresh-token-reused";
    insert_refresh_token_row(&state, reused_raw, &reused, None, None).await;

    let mut active_sibling = token_row();
    active_sibling.client_id = client.id;
    active_sibling.token_family_id = family_id;
    active_sibling.scopes = json!(["accounts", "offline_access"]);
    active_sibling.subject = client.client_id.clone();
    active_sibling.user_id = None;
    active_sibling.dpop_jkt = None;
    let active_raw = "refresh-token-active-sibling";
    insert_refresh_token_row(&state, active_raw, &active_sibling, Some(reused.id), None).await;

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(reused_raw.to_owned());
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
async fn refresh_grant_fails_closed_when_reuse_marker_cannot_be_persisted() {
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
    reused.revoked_at = Some(Utc::now() - Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS + 5));
    let reused_raw = "refresh-token-reuse-marker-failure";
    insert_refresh_token_row(&state, reused_raw, &reused, None, None).await;

    exec_sql(
        &state,
        &format!(
            r#"
            CREATE OR REPLACE FUNCTION "{}".reject_refresh_reuse_marker()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'reject refresh reuse marker in coverage test';
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
            CREATE TRIGGER reject_refresh_reuse_marker
            BEFORE UPDATE OF reuse_detected_at ON "{}".oauth_tokens
            FOR EACH ROW
            WHEN (NEW.reuse_detected_at IS NOT NULL)
            EXECUTE FUNCTION "{}".reject_refresh_reuse_marker();
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
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn refresh_grant_rotates_unbound_successor_for_lost_response_retries() {
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

    let mut form = refresh_form_without_token();
    form.refresh_token = Some(revoked_raw);
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
    assert!(
        body["refresh_token"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "unbound refresh-token families must continue rotating during lost-response retries"
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
    client.scopes = json!(["offline_access", "api"]);
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
    client.scopes = json!(["offline_access", "api"]);
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
    let claims = decode_access_claims(&state, access_token)
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
    let request_thumbprint = crate::support::request_mtls_thumbprint(&req, &state.settings)
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
    let claims = decode_access_claims(&state, access_token)
        .expect("newly issued access token should be verifiable");
    let cnf = claims
        .cnf
        .expect("mTLS-bound refresh grants must issue sender-constrained access tokens");
    assert_eq!(cnf.x5t_s256.as_deref(), Some(thumbprint));
    assert_eq!(body["token_type"], "Bearer");
    assert!(
        body["refresh_token"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "baseline refresh-token grants rotate even when the new token is mTLS-bound"
    );
}
