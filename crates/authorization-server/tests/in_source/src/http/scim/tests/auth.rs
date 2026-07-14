use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::http::client_ip::ClientIpConfig;
use crate::http::scim::{ScimConfig, ScimEndpoint};
use crate::settings::Settings;
use nazo_postgres::{create_pool, get_conn};

use crate::domain::tenancy::DEFAULT_TENANT_ID;
use chrono::Utc;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;

type ScimHandles = ScimEndpoint;

struct ScimAuthFixture {
    state: ScimHandles,
    pool: nazo_postgres::DbPool,
}

#[derive(QueryableByName)]
struct ScimTokenUseRow {
    #[diesel(sql_type = Nullable<Timestamptz>)]
    last_used_at: Option<chrono::DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    audit_count: i64,
}

fn test_scim_config(settings: &Settings) -> ScimConfig {
    let endpoint = &settings.endpoint;
    ScimConfig::new(
        settings.storage.scim_bearer_token.as_deref(),
        &settings.protocol.client_secret_pepper,
        ClientIpConfig::new(
            &endpoint.trusted_proxy_cidrs,
            endpoint.client_ip_header_mode,
        ),
    )
    .expect("test SCIM settings should be valid")
}

fn test_scim_service(pool: &nazo_postgres::DbPool) -> nazo_identity::scim::ScimService {
    nazo_identity::scim::ScimService::new(
        Arc::new(nazo_postgres::ScimRepository::new(pool.clone())),
        Arc::new(nazo_postgres::AuditRepository::new(pool.clone())),
    )
}

fn test_state(scim_bearer_token: Option<&str>) -> ScimHandles {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.storage.scim_bearer_token = scim_bearer_token.map(ToOwned::to_owned);
    let pool = create_pool(
        "postgres://nazo_scim_test_invalid:nazo_scim_test_invalid@127.0.0.1:1/nazo".to_owned(),
        1,
    )
    .expect("pool construction should not connect");
    ScimHandles::for_test(test_scim_service(&pool), test_scim_config(&settings))
}

async fn live_state(scim_bearer_token: Option<&str>) -> Option<ScimAuthFixture> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.storage.scim_bearer_token = scim_bearer_token.map(ToOwned::to_owned);
    let pool = create_pool(database_url, 4).expect("database pool should build");
    let state = ScimHandles::for_test(test_scim_service(&pool), test_scim_config(&settings));
    Some(ScimAuthFixture { state, pool })
}

async fn insert_scim_token(
    pool: &nazo_postgres::DbPool,
    raw_token: &str,
    scopes: Value,
    expires_at: Option<chrono::DateTime<Utc>>,
    revoked_at: Option<chrono::DateTime<Utc>>,
) -> Uuid {
    let token_id = Uuid::now_v7();
    let mut conn = get_conn(pool)
        .await
        .expect("database connection should be available");
    sql_query(
        "DELETE FROM scim_audit_events WHERE scim_token_id IN \
         (SELECT id FROM scim_tokens WHERE token_hash = $1)",
    )
    .bind::<Text, _>(blake3_hex(raw_token))
    .execute(&mut conn)
    .await
    .expect("SCIM audit cleanup should succeed");
    sql_query("DELETE FROM scim_tokens WHERE token_hash = $1")
        .bind::<Text, _>(blake3_hex(raw_token))
        .execute(&mut conn)
        .await
        .expect("SCIM token cleanup should succeed");
    sql_query(
        "INSERT INTO scim_tokens \
         (id, tenant_id, token_hash, label, scopes, expires_at, revoked_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind::<SqlUuid, _>(token_id)
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<Text, _>(blake3_hex(raw_token))
    .bind::<Text, _>(format!("test-token-{token_id}"))
    .bind::<Jsonb, _>(scopes)
    .bind::<Nullable<Timestamptz>, _>(expires_at)
    .bind::<Nullable<Timestamptz>, _>(revoked_at)
    .execute(&mut conn)
    .await
    .expect("SCIM token insert should succeed");
    token_id
}

fn bearer_request(token: &str) -> HttpRequest {
    actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .to_http_request()
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json)
}

async fn assert_scim_error_response(
    response: HttpResponse,
    expected_status: StatusCode,
    expected_scim_type: &str,
    expected_detail: &str,
) {
    let (status, body) = response_json(response).await;
    assert_eq!(status, expected_status);
    assert_eq!(body["status"], expected_status.as_u16().to_string());
    assert_eq!(body["scimType"], expected_scim_type);
    assert_eq!(body["detail"], expected_detail);
}

// bearer_token

#[test]
fn bearer_token_extracts_valid_bearer_token() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer scim-secret-token"))
        .to_http_request();
    assert_eq!(bearer_token(&req), Some("scim-secret-token"));
}

#[test]
fn bearer_token_rejects_basic_scheme() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Basic dXNlcjpwYXNz"))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);
}

#[test]
fn bearer_token_rejects_digest_scheme() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Digest token"))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);
}

#[test]
fn bearer_token_is_case_insensitive_for_scheme() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "bearer token123"))
        .to_http_request();
    assert_eq!(bearer_token(&req), Some("token123"));
}

#[test]
fn bearer_token_rejects_empty_token() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer   "))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);
}

#[test]
fn bearer_token_rejects_token_with_inner_whitespace() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer token with spaces"))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);
}

#[test]
fn bearer_token_returns_none_when_authorization_header_missing() {
    let req = actix_web::test::TestRequest::default().to_http_request();
    assert_eq!(bearer_token(&req), None);
}

#[test]
fn bearer_token_trims_whitespace_around_scheme() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "  Bearer token123  "))
        .to_http_request();
    assert_eq!(bearer_token(&req), Some("token123"));
}

#[test]
fn bearer_token_handles_token_with_hyphens_and_underscores() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer scim_token-v2_secret"))
        .to_http_request();
    assert_eq!(bearer_token(&req), Some("scim_token-v2_secret"));
}

#[test]
fn legacy_scim_credential_requires_exact_configured_token() {
    let state = test_state(Some("legacy-scim-secret"));
    let credential = legacy_scim_credential(&state, "legacy-scim-secret")
        .expect("configured legacy token should be accepted");
    assert_eq!(credential.token_id, None);
    assert_eq!(credential.tenant_id, default_tenant_context().tenant_id);
    assert_eq!(
        credential.scopes,
        vec![SCIM_SCOPE_READ.to_owned(), SCIM_SCOPE_WRITE.to_owned()]
    );
    assert_eq!(credential.source, "legacy-env");
    assert!(legacy_scim_credential(&state, "legacy-scim-secret ").is_none());
    assert!(legacy_scim_credential(&state, "different-secret").is_none());
    assert!(legacy_scim_credential(&test_state(None), "legacy-scim-secret").is_none());
}

#[actix_web::test]
async fn require_scim_bearer_accepts_legacy_token_when_database_lookup_fails() {
    let state = test_state(Some("legacy-scim-secret"));
    let req = bearer_request("legacy-scim-secret");

    let credential = require_scim_bearer(&state, &req, ScimRequiredScope::Write)
        .await
        .expect("legacy token should authorize when database lookup is unavailable");

    assert_eq!(credential.token_id, None);
    assert_eq!(credential.tenant_id, default_tenant_context().tenant_id);
    assert_eq!(
        credential.scopes,
        vec![SCIM_SCOPE_READ.to_owned(), SCIM_SCOPE_WRITE.to_owned()]
    );
    assert_eq!(credential.source, "legacy-env");
}

#[actix_web::test]
async fn require_scim_bearer_surfaces_backend_unavailable_for_unknown_token_during_lookup_error() {
    let state = test_state(Some("legacy-scim-secret"));
    let req = bearer_request("not-the-legacy-token");

    let response = match require_scim_bearer(&state, &req, ScimRequiredScope::Read).await {
        Ok(_) => panic!("unknown token should not bypass lookup failure"),
        Err(response) => response,
    };

    assert_scim_error_response(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn authorize_scim_credential_rejects_insufficient_scope() {
    let state = test_state(None);
    let req = bearer_request("ignored");
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned()],
        source: "test",
    };

    let response =
        match authorize_scim_credential(&state, &req, ScimRequiredScope::Write, credential).await {
            Ok(_) => panic!("read-only credential must not authorize write access"),
            Err(response) => response,
        };

    assert_scim_error_response(
        response,
        StatusCode::FORBIDDEN,
        "forbidden",
        "SCIM token lacks the required scope",
    )
    .await;
}

#[actix_web::test]
async fn authorize_scim_credential_rejects_wrong_tenant_before_recording_use() {
    let state = test_state(None);
    let req = bearer_request("ignored");
    let credential = ScimCredential {
        token_id: Some(Uuid::now_v7()),
        tenant_id: Uuid::from_u128(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa),
        scopes: vec![SCIM_SCOPE_READ.to_owned(), SCIM_SCOPE_WRITE.to_owned()],
        source: "test",
    };

    let response =
        match authorize_scim_credential(&state, &req, ScimRequiredScope::Write, credential).await {
            Ok(_) => panic!("non-default tenant SCIM credential must not authorize this endpoint"),
            Err(response) => response,
        };

    assert_scim_error_response(
        response,
        StatusCode::FORBIDDEN,
        "forbidden",
        "SCIM token is not valid for this tenant",
    )
    .await;
}

#[actix_web::test]
async fn require_scim_bearer_accepts_database_token_and_records_use() {
    let Some(ScimAuthFixture { state, pool }) = live_state(None).await else {
        return;
    };
    let raw_token = format!("database-scim-token-{}", Uuid::now_v7());
    let token_id = insert_scim_token(
        &pool,
        &raw_token,
        json!([SCIM_SCOPE_READ, SCIM_SCOPE_WRITE]),
        Some(Utc::now() + chrono::Duration::minutes(5)),
        None,
    )
    .await;
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, format!("Bearer {raw_token}")))
        .insert_header((header::USER_AGENT, "SCIM-Provisioner/1.0"))
        .to_http_request();

    let credential = require_scim_bearer(&state, &req, ScimRequiredScope::Write)
        .await
        .expect("active database token with write scope should authorize");

    assert_eq!(credential.token_id, Some(token_id));
    assert_eq!(credential.tenant_id, DEFAULT_TENANT_ID);
    assert_eq!(credential.source, "database");
    assert_eq!(
        credential.scopes,
        vec![SCIM_SCOPE_READ.to_owned(), SCIM_SCOPE_WRITE.to_owned()]
    );

    let mut conn = get_conn(&pool)
        .await
        .expect("database connection should be available");
    let row = sql_query(
        "SELECT \
             token.last_used_at, \
             (SELECT COUNT(*) FROM scim_audit_events event \
              WHERE event.scim_token_id = token.id \
                AND event.event_type = 'scim_token_used' \
                AND event.scopes = '[\"scim:write\"]'::jsonb \
                AND event.user_agent_hash IS NOT NULL) AS audit_count \
         FROM scim_tokens token \
         WHERE token.id = $1",
    )
    .bind::<SqlUuid, _>(token_id)
    .get_result::<ScimTokenUseRow>(&mut conn)
    .await
    .expect("SCIM token usage row should be readable");
    assert!(
        row.last_used_at.is_some(),
        "database token use must update last_used_at"
    );
    assert_eq!(row.audit_count, 1);
}

#[actix_web::test]
async fn require_scim_bearer_rejects_database_token_without_required_scope() {
    let Some(ScimAuthFixture { state, pool }) = live_state(None).await else {
        return;
    };
    let raw_token = format!("database-scim-read-only-{}", Uuid::now_v7());
    let token_id = insert_scim_token(
        &pool,
        &raw_token,
        json!([SCIM_SCOPE_READ]),
        Some(Utc::now() + chrono::Duration::minutes(5)),
        None,
    )
    .await;
    let req = bearer_request(&raw_token);

    let response = match require_scim_bearer(&state, &req, ScimRequiredScope::Write).await {
        Ok(_) => panic!("read-only database token must not authorize write access"),
        Err(response) => response,
    };

    assert_scim_error_response(
        response,
        StatusCode::FORBIDDEN,
        "forbidden",
        "SCIM token lacks the required scope",
    )
    .await;
    let mut conn = get_conn(&pool)
        .await
        .expect("database connection should be available");
    let row = sql_query(
        "SELECT \
             token.last_used_at, \
             (SELECT COUNT(*) FROM scim_audit_events event \
              WHERE event.scim_token_id = token.id \
                AND event.event_type = 'scim_token_used') AS audit_count \
         FROM scim_tokens token \
         WHERE token.id = $1",
    )
    .bind::<SqlUuid, _>(token_id)
    .get_result::<ScimTokenUseRow>(&mut conn)
    .await
    .expect("SCIM token row should be readable");
    assert!(
        row.last_used_at.is_none(),
        "insufficient-scope token must not be recorded as used"
    );
    assert_eq!(row.audit_count, 0);
}

#[actix_web::test]
async fn require_scim_bearer_rejects_revoked_and_expired_database_tokens() {
    let Some(ScimAuthFixture { state, pool }) = live_state(Some("legacy-scim-secret")).await else {
        return;
    };
    let revoked = format!("database-scim-revoked-{}", Uuid::now_v7());
    let expired = format!("database-scim-expired-{}", Uuid::now_v7());
    insert_scim_token(
        &pool,
        &revoked,
        json!([SCIM_SCOPE_READ, SCIM_SCOPE_WRITE]),
        Some(Utc::now() + chrono::Duration::minutes(5)),
        Some(Utc::now()),
    )
    .await;
    insert_scim_token(
        &pool,
        &expired,
        json!([SCIM_SCOPE_READ, SCIM_SCOPE_WRITE]),
        Some(Utc::now() - chrono::Duration::minutes(5)),
        None,
    )
    .await;

    for raw_token in [revoked, expired] {
        let response =
            match require_scim_bearer(&state, &bearer_request(&raw_token), ScimRequiredScope::Read)
                .await
            {
                Ok(_) => panic!("inactive database token must not authorize"),
                Err(response) => response,
            };
        assert_scim_error_response(
            response,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid bearer token",
        )
        .await;
    }
}

// scim_credential_allows

#[test]
fn credential_targets_only_served_default_tenant() {
    let default_tenant_credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned()],
        source: "test",
    };
    let other_tenant_credential = ScimCredential {
        tenant_id: Uuid::from_u128(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb),
        ..default_tenant_credential.clone()
    };

    assert!(scim_credential_targets_served_tenant(
        &default_tenant_credential
    ));
    assert!(!scim_credential_targets_served_tenant(
        &other_tenant_credential
    ));
}

#[test]
fn credential_allows_read_with_read_scope() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned()],
        source: "test",
    };
    assert!(scim_credential_allows(&credential, ScimRequiredScope::Read));
}

#[test]
fn credential_denies_write_with_read_only_scope() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned()],
        source: "test",
    };
    assert!(!scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

#[test]
fn credential_allows_write_with_write_scope() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_WRITE.to_owned()],
        source: "test",
    };
    assert!(scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

#[test]
fn credential_denies_read_with_write_only_scope() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_WRITE.to_owned()],
        source: "test",
    };
    assert!(!scim_credential_allows(
        &credential,
        ScimRequiredScope::Read
    ));
}

#[test]
fn credential_allows_any_scope_with_wildcard() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_ALL.to_owned()],
        source: "test",
    };
    assert!(scim_credential_allows(&credential, ScimRequiredScope::Read));
    assert!(scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

#[test]
fn credential_allows_with_both_read_and_write_scopes() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned(), SCIM_SCOPE_WRITE.to_owned()],
        source: "test",
    };
    assert!(scim_credential_allows(&credential, ScimRequiredScope::Read));
    assert!(scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

#[test]
fn credential_denies_when_scope_list_empty() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![],
        source: "test",
    };
    assert!(!scim_credential_allows(
        &credential,
        ScimRequiredScope::Read
    ));
    assert!(!scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

#[test]
fn credential_denies_when_scope_does_not_match() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec!["other:scope".to_owned()],
        source: "test",
    };
    assert!(!scim_credential_allows(
        &credential,
        ScimRequiredScope::Read
    ));
    assert!(!scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

#[test]
fn credential_allows_wildcard_among_other_scopes() {
    let credential = ScimCredential {
        token_id: None,
        tenant_id: default_tenant_context().tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned(), SCIM_SCOPE_ALL.to_owned()],
        source: "test",
    };
    assert!(scim_credential_allows(&credential, ScimRequiredScope::Read));
    assert!(scim_credential_allows(
        &credential,
        ScimRequiredScope::Write
    ));
}

// ScimRequiredScope::as_str

#[test]
fn required_scope_read_returns_scim_read() {
    assert_eq!(ScimRequiredScope::Read.as_str(), SCIM_SCOPE_READ);
}

#[test]
fn required_scope_write_returns_scim_write() {
    assert_eq!(ScimRequiredScope::Write.as_str(), SCIM_SCOPE_WRITE);
}

#[test]
fn scope_constants_have_correct_values() {
    assert_eq!(SCIM_SCOPE_READ, "scim:read");
    assert_eq!(SCIM_SCOPE_WRITE, "scim:write");
    assert_eq!(SCIM_SCOPE_ALL, "scim:*");
}

// scim_scope_values

#[test]
fn scope_values_extracts_strings_from_json_array() {
    let scopes = scim_scope_values(&json!(["scim:read", "scim:write"]));
    assert_eq!(
        scopes,
        vec!["scim:read".to_owned(), "scim:write".to_owned()]
    );
}

#[test]
fn scope_values_skips_non_string_elements() {
    let scopes = scim_scope_values(&json!(["scim:read", 7, true, "scim:write"]));
    assert_eq!(
        scopes,
        vec!["scim:read".to_owned(), "scim:write".to_owned()]
    );
}

#[test]
fn scope_values_skips_empty_strings() {
    let scopes = scim_scope_values(&json!(["scim:read", "", "scim:write"]));
    assert_eq!(
        scopes,
        vec!["scim:read".to_owned(), "scim:write".to_owned()]
    );
}

#[test]
fn scope_values_trims_whitespace() {
    let scopes = scim_scope_values(&json!(["  scim:read  ", "scim:write"]));
    assert_eq!(
        scopes,
        vec!["scim:read".to_owned(), "scim:write".to_owned()]
    );
}

#[test]
fn scope_values_returns_empty_for_non_array() {
    let scopes = scim_scope_values(&json!("not-an-array"));
    assert!(scopes.is_empty());
}

#[test]
fn scope_values_returns_empty_for_null() {
    let scopes = scim_scope_values(&json!(null));
    assert!(scopes.is_empty());
}

#[test]
fn scope_values_returns_empty_for_object() {
    let scopes = scim_scope_values(&json!({"key": "value"}));
    assert!(scopes.is_empty());
}

#[test]
fn scope_values_returns_empty_for_empty_array() {
    let scopes = scim_scope_values(&json!([]));
    assert!(scopes.is_empty());
}

#[test]
fn scope_values_skips_whitespace_only_strings() {
    let scopes = scim_scope_values(&json!(["scim:read", "   ", "scim:write"]));
    assert_eq!(
        scopes,
        vec!["scim:read".to_owned(), "scim:write".to_owned()]
    );
}
