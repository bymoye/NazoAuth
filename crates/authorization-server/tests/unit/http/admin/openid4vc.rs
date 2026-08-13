use super::*;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
    time::Duration as StdDuration,
};

use actix_web::{
    HttpRequest,
    cookie::Cookie,
    web::{Data, Json, Path},
};
use chrono::Utc;
use diesel::sql_query;
use diesel::sql_types::{Int4, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use nazo_digital_credentials::{
    CertificateRevocationPolicy, CredentialFormat, VcIssuerTrustPolicy,
};
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_key_management::KeyManager;
use nazo_openid4vci::CredentialConfiguration;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use serde_json::{Value, json};

use crate::{
    config::ConfigSource,
    domain::tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID},
    domain::{
        CredentialDatasetAdminService, Openid4vcCredentialCrypto, Openid4vcProofValidator,
        PutCredentialDatasetRequest, ServerCredentialIssuerOperations,
    },
    http::{
        authorization::ServerAuthorizationService,
        sessions::{AdminSessionHandles, SessionHttpConfig, SessionPayload},
        token::ServerTokenService,
    },
    runtime_modules::test_support::runtime_module_registry_for_test,
    settings::Settings,
    test_support::{
        DatabaseUserFixture, TestInfrastructure, initialize_audit_dependencies,
        valkey::valkey_set_ex,
    },
};

use nazo_postgres::{create_pool, get_conn};

#[actix_web::test]
async fn dataset_error_preserves_protocol_status_and_no_store_boundary() {
    let response = dataset_error(CredentialHttpError {
        status: 409,
        error: "invalid_request",
        description: "dataset conflict",
        dpop_nonce: None,
    });

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("credential error body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body).expect("credential error body should be JSON");
    assert_eq!(
        body.get("error"),
        Some(&serde_json::json!("invalid_request"))
    );
    assert_eq!(
        body.get("error_description"),
        Some(&serde_json::json!("dataset conflict"))
    );
}

#[test]
fn dataset_error_fails_closed_for_invalid_http_status_values() {
    let response = dataset_error(CredentialHttpError {
        status: 0,
        error: "server_error",
        description: "unavailable",
        dpop_nonce: None,
    });

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

struct LiveOpenid4vcAdminFixture {
    state: Data<TestInfrastructure>,
    endpoint: Data<CredentialDatasetAdminService>,
    crypto: Openid4vcCredentialCrypto,
    key_dir: PathBuf,
}

impl Drop for LiveOpenid4vcAdminFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.key_dir);
    }
}

impl LiveOpenid4vcAdminFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;

        let mut settings =
            Settings::from_config(&ConfigSource::default()).expect("unit settings should load");
        settings.endpoint.issuer = "https://issuer.example".to_owned();
        settings.modules.enable_openid4vci_issuer = true;
        settings.openid4vc.data_encryption_key = Some([0x51; 32]);
        settings.openid4vc.credential_configurations = BTreeMap::from([(
            "unit-config".to_owned(),
            CredentialConfiguration {
                format: CredentialFormat::SdJwtVc,
                scope: Some("unit-credential".to_owned()),
                cryptographic_binding_methods_supported: Vec::new(),
                credential_signing_alg_values_supported: vec!["ES256".to_owned()],
                proof_types_supported: Default::default(),
                vct: Some("https://issuer.example/unit".to_owned()),
                doctype: None,
                credential_metadata: None,
            },
        )]);

        let mut valkey_builder = ValkeyBuilder::from_config(
            ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
        );
        valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = StdDuration::from_secs(2);
        });
        valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = StdDuration::from_secs(2);
            connection.internal_command_timeout = StdDuration::from_secs(2);
            connection.max_command_attempts = 1;
        });
        let valkey = valkey_builder.build().expect("valkey client should build");
        valkey.init().await.expect("valkey should connect");
        let diesel_db = create_pool(database_url, 4).expect("database pool should build");
        initialize_audit_dependencies(&diesel_db);

        let key_dir =
            std::env::temp_dir().join(format!("nazo-openid4vc-admin-{}", Uuid::now_v7().simple()));
        std::fs::create_dir_all(&key_dir).expect("credential key directory should be created");
        let (keyset, chain_pem, anchors_pem) = credential_key_material(&key_dir);
        let key_manager = KeyManager::load_or_create(keyset)
            .await
            .expect("credential test keyset should load");
        let crypto = Openid4vcCredentialCrypto::new_with_policies(
            key_manager.clone(),
            chain_pem.as_bytes(),
            anchors_pem.as_bytes(),
            VcIssuerTrustPolicy::san_bound(),
            CertificateRevocationPolicy::disabled(),
        )
        .expect("credential crypto should validate the generated chain");

        let state = Data::new(TestInfrastructure {
            diesel_db: diesel_db.clone(),
            valkey,
            settings: Arc::new(settings.clone()),
            keyset: key_manager.clone(),
        });
        let token_service = Arc::new(ServerTokenService::new(
            crate::test_support::token_issuance_repository(diesel_db.clone()),
            nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
            key_manager.clone(),
        ));
        let authorization = Arc::new(ServerAuthorizationService::new(
            nazo_postgres::AuthorizationFlowRepository::new(diesel_db.clone(), DEFAULT_TENANT_ID),
            nazo_valkey::AuthorizationStateAdapter::new(&state.valkey_connection()),
            key_manager.clone(),
        ));
        let runtime = runtime_module_registry_for_test(diesel_db.clone(), &settings)
            .expect("runtime module fixture should build");
        let proof_validator = Openid4vcProofValidator::new(json!({"keys": []}))
            .expect("proof validator fixture should build");
        let operations = Arc::new(
            ServerCredentialIssuerOperations::new(
                diesel_db,
                DEFAULT_TENANT_ID,
                [0x51; 32],
                token_service,
                authorization,
                runtime,
                crypto.clone(),
                proof_validator,
                None,
                settings.endpoint.issuer.clone(),
                settings.openid4vc.credential_configurations.clone(),
                BTreeSet::new(),
                nazo_auth::DpopNoncePolicy::Optional,
            )
            .expect("credential issuer fixture should build"),
        );

        Some(Self {
            state,
            endpoint: Data::new(CredentialDatasetAdminService::new(operations)),
            crypto,
            key_dir,
        })
    }

    async fn create_user(
        &self,
        suffix: &str,
        role: &str,
        admin_level: i32,
        mfa_enabled: bool,
    ) -> DatabaseUserFixture {
        let email = format!("openid4vc-{suffix}@example.com");
        let username = format!("openid4vc-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-openid4vc-hash', true, $6, true, $7, $8)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<diesel::sql_types::Bool, _>(mfa_enabled)
        .bind::<Text, _>(role.to_owned())
        .bind::<Int4, _>(admin_level)
        .get_result::<DatabaseUserFixture>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn store_session(&self, user: &DatabaseUserFixture, sid: &str, mfa: bool) {
        let mut amr = vec!["pwd".to_owned()];
        if mfa {
            amr.extend(["otp".to_owned(), "mfa".to_owned()]);
        }
        let payload = SessionPayload {
            user_id: user.id,
            auth_time: Utc::now().timestamp(),
            amr,
            pending_mfa: false,
            oidc_sid: Some(format!("oidc-{sid}")),
        };
        valkey_set_ex(
            &self.state.valkey,
            format!("oauth:session:{sid}"),
            serde_json::to_string(&payload).expect("session should serialize"),
            self.state.settings.session.session_ttl_seconds,
        )
        .await
        .expect("test session should store");
    }

    fn sessions(&self) -> Data<AdminSessionHandles> {
        let session = &self.state.settings.session;
        Data::new(AdminSessionHandles::new(
            nazo_valkey::SessionStore::new(&self.state.valkey_connection()),
            nazo_postgres::UserRepository::new(self.state.diesel_db.clone()),
            SessionHttpConfig::new(
                &session.session_cookie_name,
                &session.csrf_cookie_name,
                session.cookie_secure,
            ),
        ))
    }

    fn get_request(&self, sid: &str, uri: &str) -> HttpRequest {
        actix_web::test::TestRequest::get()
            .uri(uri)
            .cookie(Cookie::new(
                self.state.settings.session.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .to_http_request()
    }

    fn post_request(&self, sid: &str, csrf: Option<&str>, uri: &str) -> HttpRequest {
        let mut request = actix_web::test::TestRequest::post().uri(uri);
        request = request.cookie(Cookie::new(
            self.state.settings.session.session_cookie_name.clone(),
            sid.to_owned(),
        ));
        if let Some(csrf) = csrf {
            request = request
                .cookie(Cookie::new(
                    self.state.settings.session.csrf_cookie_name.clone(),
                    csrf.to_owned(),
                ))
                .insert_header(("x-csrf-token", csrf));
        }
        request.to_http_request()
    }

    async fn endpoint_with_admission(&self, enabled: bool) -> Data<CredentialDatasetAdminService> {
        let mut settings = (*self.state.settings).clone();
        settings.modules.enable_openid4vci_issuer = enabled;
        let token_service = Arc::new(ServerTokenService::new(
            crate::test_support::token_issuance_repository(self.state.diesel_db.clone()),
            nazo_valkey::TokenIssuanceStateAdapter::new(&self.state.valkey_connection()),
            self.state.keyset.clone(),
        ));
        let authorization = Arc::new(ServerAuthorizationService::new(
            nazo_postgres::AuthorizationFlowRepository::new(
                self.state.diesel_db.clone(),
                DEFAULT_TENANT_ID,
            ),
            nazo_valkey::AuthorizationStateAdapter::new(&self.state.valkey_connection()),
            self.state.keyset.clone(),
        ));
        let runtime = runtime_module_registry_for_test(self.state.diesel_db.clone(), &settings)
            .expect("runtime module fixture should build");
        let proof_validator = Openid4vcProofValidator::new(json!({"keys": []}))
            .expect("proof validator fixture should build");
        let operations = ServerCredentialIssuerOperations::new(
            self.state.diesel_db.clone(),
            DEFAULT_TENANT_ID,
            [0x51; 32],
            token_service,
            authorization,
            runtime,
            self.crypto.clone(),
            proof_validator,
            None,
            settings.endpoint.issuer,
            settings.openid4vc.credential_configurations,
            BTreeSet::new(),
            nazo_auth::DpopNoncePolicy::Optional,
        )
        .expect("credential issuer fixture should build");
        Data::new(CredentialDatasetAdminService::new(Arc::new(operations)))
    }
}

fn credential_key_material(
    key_dir: &std::path::Path,
) -> (nazo_key_management::KeySettings, String, String) {
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let leaf_pem = leaf_key.serialize_pem();
    std::fs::write(key_dir.join("credential-test.pem"), leaf_pem)
        .expect("credential private key should be written");
    std::fs::write(
        key_dir.join("keyset.json"),
        serde_json::to_vec_pretty(&json!({
            "active_kid": "credential-test",
            "keys": [{
                "kid": "credential-test",
                "alg": "ES256",
                "file": "credential-test.pem",
                "created_at": Utc::now().to_rfc3339(),
                "retire_at": Value::Null,
                "purposes": ["credential", "presentation_request"]
            }]
        }))
        .expect("credential keyset should serialize"),
    )
    .expect("credential keyset should be written");

    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
    let mut root_params = CertificateParams::default();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root = CertifiedIssuer::self_signed(root_params, root_key).expect("root certificate");
    let leaf_params =
        CertificateParams::new(vec!["issuer.example".to_owned()]).expect("leaf certificate params");
    let leaf = leaf_params
        .signed_by(&leaf_key, &root)
        .expect("leaf certificate");
    let chain_pem = format!("{}{}", leaf.pem(), root.pem());
    let anchors_pem = root.pem();
    (
        nazo_key_management::KeySettings {
            keys_dir: key_dir.to_owned(),
            external_command: Vec::new(),
            external_timeout: StdDuration::from_secs(1),
            rotation_interval: chrono::Duration::days(1),
            prepublish_window: chrono::Duration::hours(1),
            verification_grace: chrono::Duration::hours(1),
        },
        chain_pem,
        anchors_pem,
    )
}

#[actix_web::test]
async fn admin_dataset_mutations_fail_closed_on_csrf_and_recent_mfa() {
    let Some(fixture) = LiveOpenid4vcAdminFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10, true)
        .await;
    let subject = fixture
        .create_user(&format!("{suffix}-subject"), "user", 0, false)
        .await;
    let admin_sid = format!("openid4vc-admin-sid-{suffix}");
    fixture.store_session(&admin, &admin_sid, true).await;

    let missing_csrf = admin_put_credential_dataset(
        fixture.sessions(),
        fixture.endpoint.clone(),
        fixture.post_request(&admin_sid, None, "/admin/openid4vci/credential-datasets"),
        Path::from((subject.id, "unit-config".to_owned())),
        Json(PutCredentialDatasetRequest {
            claims: json!({"given_name": "Ada"}),
            valid_from: None,
            valid_until: None,
        }),
    )
    .await;
    assert_eq!(missing_csrf.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        missing_csrf
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_request")
    );

    let no_mfa_user = fixture
        .create_user(&format!("{suffix}-no-mfa"), "admin", 10, false)
        .await;
    let no_mfa_sid = format!("openid4vc-no-mfa-sid-{suffix}");
    fixture
        .store_session(&no_mfa_user, &no_mfa_sid, false)
        .await;
    let no_mfa = admin_delete_credential_dataset(
        fixture.sessions(),
        fixture.endpoint.clone(),
        fixture.post_request(
            &no_mfa_sid,
            Some(&format!("openid4vc-csrf-{suffix}")),
            "/admin/openid4vci/credential-datasets",
        ),
        Path::from((subject.id, "unit-config".to_owned())),
    )
    .await;
    assert_eq!(no_mfa.status(), StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(
        no_mfa
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("mfa_step_up_required")
    );

    let non_admin = fixture
        .create_user(&format!("{suffix}-non-admin"), "user", 0, true)
        .await;
    let non_admin_sid = format!("openid4vc-non-admin-sid-{suffix}");
    fixture
        .store_session(&non_admin, &non_admin_sid, true)
        .await;
    let access_denied = admin_delete_credential_dataset(
        fixture.sessions(),
        fixture.endpoint.clone(),
        fixture.post_request(
            &non_admin_sid,
            Some(&format!("openid4vc-non-admin-csrf-{suffix}")),
            "/admin/openid4vci/credential-datasets",
        ),
        Path::from((subject.id, "unit-config".to_owned())),
    )
    .await;
    assert_eq!(access_denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        access_denied
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("access_denied")
    );

    let unauthenticated_get = admin_get_credential_dataset(
        fixture.sessions(),
        fixture.endpoint.clone(),
        fixture.get_request("missing-session", "/admin/openid4vci/credential-datasets"),
        Path::from((subject.id, "unit-config".to_owned())),
    )
    .await;
    assert_eq!(unauthenticated_get.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn admin_dataset_handlers_round_trip_and_map_domain_errors() {
    let Some(fixture) = LiveOpenid4vcAdminFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10, true)
        .await;
    let subject = fixture
        .create_user(&format!("{suffix}-subject"), "user", 0, false)
        .await;
    let sid = format!("openid4vc-roundtrip-sid-{suffix}");
    let csrf = format!("openid4vc-roundtrip-csrf-{suffix}");
    fixture.store_session(&admin, &sid, true).await;

    let put = admin_put_credential_dataset(
        fixture.sessions(),
        fixture.endpoint.clone(),
        fixture.post_request(&sid, Some(&csrf), "/admin/openid4vci/credential-datasets"),
        Path::from((subject.id, "unit-config".to_owned())),
        Json(PutCredentialDatasetRequest {
            claims: json!({"given_name": "Ada", "age_over_18": true}),
            valid_from: None,
            valid_until: None,
        }),
    )
    .await;
    assert_eq!(put.status(), StatusCode::OK);
    let put_body = actix_web::body::to_bytes(put.into_body())
        .await
        .expect("dataset response body should be readable");
    let put_body: Value =
        serde_json::from_slice(&put_body).expect("dataset response should be JSON");
    assert_eq!(put_body["subject_id"], json!(subject.id));
    assert_eq!(put_body["credential_configuration_id"], "unit-config");
    assert_eq!(put_body["claims"]["given_name"], "Ada");

    let get = admin_get_credential_dataset(
        fixture.sessions(),
        fixture.endpoint.clone(),
        fixture.get_request(&sid, "/admin/openid4vci/credential-datasets"),
        Path::from((subject.id, "unit-config".to_owned())),
    )
    .await;
    assert_eq!(get.status(), StatusCode::OK);
    let get_body = actix_web::body::to_bytes(get.into_body())
        .await
        .expect("dataset read body should be readable");
    let get_body: Value = serde_json::from_slice(&get_body).expect("dataset read should be JSON");
    assert_eq!(get_body["claims"]["age_over_18"], true);

    let unknown_configuration = admin_get_credential_dataset(
        fixture.sessions(),
        fixture.endpoint.clone(),
        fixture.get_request(&sid, "/admin/openid4vci/credential-datasets"),
        Path::from((subject.id, "unknown-config".to_owned())),
    )
    .await;
    assert_eq!(unknown_configuration.status(), StatusCode::NOT_FOUND);

    let delete = admin_delete_credential_dataset(
        fixture.sessions(),
        fixture.endpoint.clone(),
        fixture.post_request(&sid, Some(&csrf), "/admin/openid4vci/credential-datasets"),
        Path::from((subject.id, "unit-config".to_owned())),
    )
    .await;
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);
    assert_eq!(delete.headers().get("cache-control").unwrap(), "no-store");

    let missing = admin_get_credential_dataset(
        fixture.sessions(),
        fixture.endpoint.clone(),
        fixture.get_request(&sid, "/admin/openid4vci/credential-datasets"),
        Path::from((subject.id, "unit-config".to_owned())),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let invalid_claims = fixture
        .endpoint
        .put_dataset(
            DEFAULT_TENANT_ID,
            admin.id,
            subject.id,
            "unit-config".to_owned(),
            PutCredentialDatasetRequest {
                claims: json!({}),
                valid_from: None,
                valid_until: None,
            },
        )
        .await
        .expect_err("empty claims must be rejected before persistence");
    assert_eq!(invalid_claims.status, 400);
    assert_eq!(invalid_claims.error, "invalid_request");

    let unknown_put = fixture
        .endpoint
        .put_dataset(
            DEFAULT_TENANT_ID,
            admin.id,
            subject.id,
            "unknown-config".to_owned(),
            PutCredentialDatasetRequest {
                claims: json!({"given_name": "Ada"}),
                valid_from: None,
                valid_until: None,
            },
        )
        .await
        .expect_err("unknown credential configuration must be rejected");
    assert_eq!(unknown_put.status, 400);

    let wrong_tenant = fixture
        .endpoint
        .get_dataset(Uuid::now_v7(), subject.id, "unit-config".to_owned())
        .await
        .expect_err("a dataset from another tenant must not be disclosed");
    assert_eq!(wrong_tenant.status, 404);

    let missing_delete = fixture
        .endpoint
        .delete_dataset(
            DEFAULT_TENANT_ID,
            admin.id,
            subject.id,
            "unit-config".to_owned(),
        )
        .await
        .expect_err("deleting a missing dataset must map to not found");
    assert_eq!(missing_delete.status, 404);

    let disabled = fixture.endpoint_with_admission(false).await;
    let disabled_error = disabled
        .put_dataset(
            DEFAULT_TENANT_ID,
            admin.id,
            subject.id,
            "unit-config".to_owned(),
            PutCredentialDatasetRequest {
                claims: json!({"given_name": "Ada"}),
                valid_from: None,
                valid_until: None,
            },
        )
        .await
        .expect_err("disabled issuer must fail closed before persistence");
    assert_eq!(disabled_error.status, 503);
}
