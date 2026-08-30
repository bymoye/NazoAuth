use std::{sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use diesel::{
    sql_query,
    sql_types::{Bool, Jsonb, Text, Uuid as SqlUuid},
};
use diesel_async::RunQueryDsl;
use ed25519_dalek::{Signer, SigningKey};
use nazo_http_actix::{FapiHttpMessageSignatures, FapiSignatureVerificationError};
use nazo_http_signatures::{
    RequestInput, RequestPolicy, VerificationPolicy, parse_request_for_verification,
    prepare_request,
};
use nazo_postgres::{DbPool, create_pool, get_conn};
use serde_json::{Value, json};
use uuid::Uuid;

use super::production::{
    FapiHttpSignatureReplayConsumption, FapiHttpSignatureReplayStore,
    FapiHttpSignatureReplayStoreError, ServerFapiHttpMessageSignatures, same_key_generation,
};
use crate::{config::ConfigSource, settings::Settings};

struct TestFapiHttpSignatureReplayStore(nazo_valkey::ReplayStore);

impl FapiHttpSignatureReplayStore for TestFapiHttpSignatureReplayStore {
    fn consume<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        fingerprint: &'a [u8],
        ttl_seconds: i64,
    ) -> nazo_http_actix::FapiFuture<
        'a,
        Result<FapiHttpSignatureReplayConsumption, FapiHttpSignatureReplayStoreError>,
    > {
        Box::pin(async move {
            let fingerprint = <&[u8; 32]>::try_from(fingerprint)
                .map_err(|_| FapiHttpSignatureReplayStoreError)?;
            self.0
                .consume_fapi_http_signature(tenant_id, fingerprint, ttl_seconds)
                .await
                .map(|accepted| {
                    if accepted {
                        FapiHttpSignatureReplayConsumption::Accepted
                    } else {
                        FapiHttpSignatureReplayConsumption::Replay
                    }
                })
                .map_err(|_| FapiHttpSignatureReplayStoreError)
        })
    }
}

fn database_url_with_search_path(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { "&" } else { "?" };
    format!("{base}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

async fn exec_sql(pool: &DbPool, sql: &str) {
    let mut connection = get_conn(pool)
        .await
        .expect("test database connection should open");
    sql_query(sql)
        .execute(&mut connection)
        .await
        .expect("test schema mutation should succeed");
}

async fn insert_signature_client(pool: &DbPool, tenant_id: Uuid, client_id: &str, jwks: Value) {
    let mut connection = get_conn(pool)
        .await
        .expect("test database connection should open");
    sql_query(
        r#"
        INSERT INTO oauth_clients (
            tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            client_secret_hash, redirect_uris, scopes, allowed_audiences,
            grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
            require_mtls_bound_tokens, tls_client_auth_subject_dn, tls_client_auth_cert_sha256,
            tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip,
            tls_client_auth_san_email, allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience, require_par_request_object,
            is_active, security_policy, post_logout_redirect_uris, backchannel_logout_session_required, jwks
        )
        VALUES (
            $1, '00000000-0000-0000-0000-000000000002',
            '00000000-0000-0000-0000-000000000003', $2,
            'FAPI Signature Test Client', 'confidential', NULL,
            '["https://client.example/callback"]'::jsonb, '["openid"]'::jsonb,
            '["resource://default"]'::jsonb, '["authorization_code"]'::jsonb,
            'private_key_jwt', false, false, NULL, NULL,
            '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
            false, false, false, $3,
            '{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}'::jsonb,
            '[]'::jsonb, true, $4
        )
        "#,
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<Text, _>(client_id)
    .bind::<Bool, _>(true)
    .bind::<Jsonb, _>(jwks)
    .execute(&mut connection)
    .await
    .expect("signature test client should insert");
}

#[test]
fn verifier_cache_hits_only_the_same_live_snapshot_generation() {
    let original_manager = crate::test_support::test_key_manager();
    let original = original_manager.snapshot();
    let same_generation = original_manager.snapshot();
    assert!(same_key_generation(&original, &same_generation));

    // Test managers intentionally reuse the same public kid. Distinct
    // key material must still be treated as a rotation and miss.
    let rotated = crate::test_support::test_key_manager().snapshot();
    assert_eq!(original.active_kid, rotated.active_kid);
    assert!(!Arc::ptr_eq(&original, &rotated));
    assert_ne!(original.jwks(), rotated.jwks());
    assert!(!same_key_generation(&original, &rotated));
}

#[tokio::test]
async fn production_signature_verifier_binds_replay_to_the_scoped_client_tenant() {
    let (Ok(database_url), Ok(valkey_url)) =
        (std::env::var("DATABASE_URL"), std::env::var("VALKEY_URL"))
    else {
        return;
    };
    let schema = format!("fapi_replay_{}", Uuid::now_v7().simple());
    let scoped_url = database_url_with_search_path(&database_url, &schema);
    let pool = create_pool(scoped_url, 4).expect("test database pool should build");
    exec_sql(&pool, &format!(r#"CREATE SCHEMA "{schema}""#)).await;
    exec_sql(
        &pool,
        &format!(
            r#"CREATE TABLE "{schema}".oauth_clients (LIKE public.oauth_clients INCLUDING ALL)"#
        ),
    )
    .await;

    let signing_key = SigningKey::from_bytes(&[17; 32]);
    let public_jwk = json!({
        "kid": "client-key",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
        "key_ops": ["verify"],
        "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()),
    });
    let jwks = json!({"keys": [public_jwk]});
    let first_tenant = Uuid::now_v7();
    let second_tenant = Uuid::now_v7();
    let client_id = format!("fapi-signature-{}", Uuid::now_v7().simple());
    insert_signature_client(&pool, first_tenant, &client_id, jwks.clone()).await;
    insert_signature_client(&pool, second_tenant, &client_id, jwks).await;

    let replay_connection =
        nazo_valkey::test_support::scoped_connect(&valkey_url, Duration::from_secs(1))
            .await
            .expect("configured Valkey should connect");
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("test settings should load");
    let runtime_modules = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        pool.clone(),
        &settings,
    )
    .expect("test runtime module registry should build");
    let verifier = ServerFapiHttpMessageSignatures::from_port(
        Arc::new(nazo_postgres::OAuthClientRepository::new(pool.clone())),
        Arc::new(TestFapiHttpSignatureReplayStore(
            nazo_valkey::ReplayStore::new(&replay_connection),
        )),
        crate::test_support::test_key_manager(),
        runtime_modules,
        60,
    );

    let created = Utc::now().timestamp();
    let headers = [("authorization", "Bearer access-token")];
    let prepared = prepare_request(
        RequestInput {
            method: "GET",
            target_uri: "https://auth.example/fapi/resource",
            headers: &headers,
            body: b"",
        },
        RequestPolicy {
            created,
            keyid: "client-key",
            algorithm: "ed25519",
            covered_headers: &[],
        },
    )
    .expect("signature input should prepare");
    let signature = signing_key.sign(prepared.signature_base()).to_bytes();
    let fields = prepared.finish(&signature);
    let input = parse_request_for_verification(
        RequestInput {
            method: "GET",
            target_uri: "https://auth.example/fapi/resource",
            headers: &headers,
            body: b"",
        },
        fields,
        VerificationPolicy {
            now: created,
            max_age_seconds: 60,
            future_skew_seconds: 5,
        },
    )
    .expect("signature input should verify structurally");

    verifier
        .verify_and_consume(&first_tenant.to_string(), &client_id, &input)
        .await
        .expect("first tenant should reserve its replay marker");
    verifier
        .verify_and_consume(&second_tenant.to_string(), &client_id, &input)
        .await
        .expect("second tenant should reserve an independent marker");
    assert!(matches!(
        verifier
            .verify_and_consume(&first_tenant.to_string(), &client_id, &input)
            .await,
        Err(FapiSignatureVerificationError::Replay)
    ));

    exec_sql(&pool, &format!(r#"DROP SCHEMA "{schema}" CASCADE"#)).await;
}
