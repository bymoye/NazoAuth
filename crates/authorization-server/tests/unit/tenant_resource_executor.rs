use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::RunQueryDsl as _;
use futures_util::future::BoxFuture;
use nazo_operator_protocol::{
    Actor, ActorKind, TenantResourceIdentity, TenantResourceKind, TenantResourceOperation,
    TenantResourceOutcome, TenantResourceReceipt, TenantResourceTask, TenantResourceTaskPayload,
    canonical_tenant_resource_manifest_sha256,
};
use serde_json::json;
use uuid::Uuid;

use super::*;
use crate::tenant_resource_provider::{
    IssuedTenantResourceReceipt, MtlsTrustAnchorResourcePayload, OauthClientResourcePayload,
    Openid4vcDatasetResourcePayload, Openid4vcTrustPolicyResourcePayload,
    TenantResourceProviderError, TenantResourceStateSource, UserResourcePayload,
};

struct TestPreparation;

impl TenantResourcePreparation for TestPreparation {
    fn hash_user_password<'a>(
        &'a self,
        _password: String,
    ) -> BoxFuture<'a, Result<String, TenantResourcePreparationError>> {
        Box::pin(async { Ok("test-only-password-hash".to_owned()) })
    }

    fn prepare_oauth_client<'a>(
        &'a self,
        request: nazo_auth::CreateClientRequest,
        supplied_secret: Option<String>,
        tenant: nazo_identity::TenantContext,
    ) -> BoxFuture<'a, Result<PreparedOAuthClient, TenantResourcePreparationError>> {
        Box::pin(async move { Ok(prepared_test_client(request, supplied_secret, tenant)) })
    }
}

fn prepared_test_client(
    request: nazo_auth::CreateClientRequest,
    supplied_secret: Option<String>,
    tenant: nazo_identity::TenantContext,
) -> PreparedOAuthClient {
    PreparedOAuthClient {
        client: nazo_auth::OAuthClient {
            id: Uuid::now_v7(),
            tenant_id: tenant.tenant_id.as_uuid(),
            realm_id: tenant.realm_id.as_uuid(),
            organization_id: tenant.organization_id.as_uuid(),
            registration: nazo_auth::ValidatedClientRegistration {
                client_id: format!("managed-client-{}", Uuid::now_v7()),
                client_name: request.client_name,
                client_type: request.client_type,
                redirect_uris: request.redirect_uris,
                post_logout_redirect_uris: request.post_logout_redirect_uris,
                scopes: request.scopes,
                allowed_audiences: request.allowed_audiences,
                grant_types: request.grant_types,
                token_endpoint_auth_method: request.token_endpoint_auth_method,
                subject_type: request.subject_type.unwrap_or_else(|| "public".to_owned()),
                sector_identifier_uri: request.sector_identifier_uri,
                sector_identifier_host: None,
                require_dpop_bound_tokens: request.require_dpop_bound_tokens,
                allow_client_assertion_audience_array: request
                    .allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience: request
                    .allow_client_assertion_endpoint_audience,
                require_par_request_object: request.require_par_request_object,
                backchannel_token_delivery_mode: request.backchannel_token_delivery_mode,
                backchannel_client_notification_endpoint: request
                    .backchannel_client_notification_endpoint,
                backchannel_authentication_request_signing_alg: request
                    .backchannel_authentication_request_signing_alg,
                backchannel_user_code_parameter: request.backchannel_user_code_parameter,
                backchannel_logout_uri: request.backchannel_logout_uri,
                backchannel_logout_session_required: request.backchannel_logout_session_required,
                frontchannel_logout_uri: request.frontchannel_logout_uri,
                frontchannel_logout_session_required: request.frontchannel_logout_session_required,
                tls_client_auth_subject_dn: request.tls_client_auth_subject_dn,
                tls_client_auth_cert_sha256: request.tls_client_auth_cert_sha256,
                tls_client_auth_san_dns: request.tls_client_auth_san_dns,
                tls_client_auth_san_uri: request.tls_client_auth_san_uri,
                tls_client_auth_san_ip: request.tls_client_auth_san_ip,
                tls_client_auth_san_email: request.tls_client_auth_san_email,
                jwks_uri: request.jwks_uri,
                jwks: request.jwks,
                request_uris: request.request_uris,
                initiate_login_uri: request.initiate_login_uri,
                presentation: request.presentation,
                id_token_signed_response_alg: request.id_token_signed_response_alg,
                id_token_encrypted_response_alg: request.id_token_encrypted_response_alg,
                id_token_encrypted_response_enc: request.id_token_encrypted_response_enc,
                request_object_signing_alg: request.request_object_signing_alg,
                request_object_encryption_alg: request.request_object_encryption_alg,
                request_object_encryption_enc: request.request_object_encryption_enc,
                token_endpoint_auth_signing_alg: request.token_endpoint_auth_signing_alg,
                introspection_signed_response_alg: request.introspection_signed_response_alg,
                introspection_encrypted_response_alg: request.introspection_encrypted_response_alg,
                introspection_encrypted_response_enc: request.introspection_encrypted_response_enc,
                userinfo_signed_response_alg: request.userinfo_signed_response_alg,
                userinfo_encrypted_response_alg: request.userinfo_encrypted_response_alg,
                userinfo_encrypted_response_enc: request.userinfo_encrypted_response_enc,
                authorization_signed_response_alg: request.authorization_signed_response_alg,
                authorization_encrypted_response_alg: request.authorization_encrypted_response_alg,
                authorization_encrypted_response_enc: request.authorization_encrypted_response_enc,
                security_policy: Some(request.security_policy),
            },
            require_mtls_bound_tokens: request.require_mtls_bound_tokens,
            is_active: true,
        },
        client_secret_hash: supplied_secret.map(|_| "test-only-client-secret-hash".to_owned()),
    }
}

fn test_ca_certificate_pem() -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["client.example".to_owned()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    params.self_signed(&key).unwrap().pem()
}

fn test_openid4vc_trust_policy() -> nazo_operator_protocol::Openid4vcTrustPolicy {
    let coordinate = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    serde_json::from_value(json!({
        "schema": 1,
        "client_attestation_issuer": "https://issuer.example/attestation",
        "client_attestation_jwks": {"keys": [{
            "kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate, "kid": "client"
        }]},
        "key_attestation_jwks": {"keys": [{
            "kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate, "kid": "holder"
        }]},
        "credential_trust_anchor_pem": "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n",
        "wallet_authorization_origins": ["https://wallet.example"]
    }))
    .unwrap()
}

struct TestReceiptIssuer {
    task: TenantResourceTask,
    request_sha256: String,
    calls: Arc<AtomicUsize>,
}

impl TenantResourceReceiptIssuer for TestReceiptIssuer {
    fn issue(
        &self,
        result: TenantResourceExecutionResult,
    ) -> Result<IssuedTenantResourceReceipt, TenantResourceProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(IssuedTenantResourceReceipt {
            receipt: TenantResourceReceipt {
                ver: nazo_operator_protocol::PROTOCOL_VERSION,
                iss: format!("runtime:{}", self.task.deployment_id),
                aud: format!("controller:{}", self.task.deployment_id),
                jti: self.task.jti.clone(),
                request_sha256: self.request_sha256.clone(),
                deployment_id: self.task.deployment_id.clone(),
                tenant_id: self.task.tenant_id.clone(),
                capability_jti: self.task.capability_jti.clone(),
                capability_sha256: self.task.capability_sha256.clone(),
                actor: self.task.actor.clone(),
                change_set_id: self.task.change_set_id.clone(),
                change_set_sha256: self.task.change_set_sha256.clone(),
                operation: self.task.operation,
                expected_revision: self.task.expected_revision,
                revision: result.revision,
                outcome: TenantResourceOutcome::Succeeded,
                resources: result.resources,
                resource_mappings: result.resource_mappings,
                baseline_manifest_sha256: self.task.baseline_manifest_sha256.clone(),
                resource_manifest_sha256: self.task.resource_manifest_sha256.clone(),
                started_at: 1_800_000_000,
                completed_at: 1_800_000_001,
                exp: 1_800_000_060,
                audit_sequence: result.audit_sequence,
                audit_previous_sha256: result.audit_previous_sha256,
            },
            compact: format!("receipt-{}", self.task.jti),
        })
    }
}

fn resource_task(
    tenant_id: Uuid,
    jti: &str,
    change_set_id: &str,
    operation: TenantResourceOperation,
    payload: TenantResourceTaskPayload,
    expected_revision: u64,
    manifests: (String, String),
) -> TenantResourceTask {
    TenantResourceTask {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: "controller:test-deployment".to_owned(),
        aud: "runtime:test-deployment".to_owned(),
        jti: jti.to_owned(),
        iat: 1_800_000_000,
        nbf: 1_800_000_000,
        exp: 1_800_000_060,
        deployment_id: "test-deployment".to_owned(),
        tenant_id: tenant_id.to_string(),
        capability_jti: "capability-test".to_owned(),
        capability_sha256: "a".repeat(64),
        actor: Actor {
            kind: ActorKind::Automation,
            id: "test-controller".to_owned(),
        },
        expected_revision,
        change_set_id: change_set_id.to_owned(),
        change_set_sha256: "b".repeat(64),
        operation,
        payload,
        baseline_manifest_sha256: manifests.0,
        resource_manifest_sha256: manifests.1,
    }
}

#[test]
fn locators_are_kind_fenced_and_round_trip() {
    let user = Uuid::now_v7();
    let client = Uuid::now_v7();
    let anchor = Uuid::now_v7();
    let dataset = Uuid::now_v7();
    let trust_policy = Uuid::now_v7();

    assert!(matches!(
        parse_locator(&user_locator(user), TenantResourceKind::User),
        Ok(ResourceLocator::User(value)) if value == user
    ));
    assert!(matches!(
        parse_locator(&oauth_client_locator(client), TenantResourceKind::OauthClient),
        Ok(ResourceLocator::OauthClient(value)) if value == client
    ));
    assert!(matches!(
        parse_locator(&mtls_locator(anchor), TenantResourceKind::MtlsTrustAnchor),
        Ok(ResourceLocator::Mtls(value)) if value == anchor
    ));
    assert!(matches!(
        parse_locator(
            &trust_policy_locator(trust_policy),
            TenantResourceKind::Openid4vcTrustPolicy
        ),
        Ok(ResourceLocator::TrustPolicy(value)) if value == trust_policy
    ));
    let dataset_locator = dataset_locator(dataset, "openid4vc-example");
    assert!(matches!(
        parse_locator(&dataset_locator, TenantResourceKind::Openid4vcDataset),
        Ok(ResourceLocator::Dataset { subject_id, configuration_id })
            if subject_id == dataset && configuration_id == "openid4vc-example"
    ));
    assert!(parse_locator(&user_locator(user), TenantResourceKind::OauthClient).is_err());
    assert!(parse_locator("user/not-a-uuid", TenantResourceKind::User).is_err());
}

#[test]
fn dataset_locator_rejects_empty_configuration_and_extra_user_segments() {
    let id = Uuid::now_v7();
    assert!(
        parse_locator(
            &format!("openid4vc-dataset/{id}/"),
            TenantResourceKind::Openid4vcDataset
        )
        .is_err()
    );
    assert!(parse_locator(&format!("user/{id}/extra"), TenantResourceKind::User).is_err());
}

#[test]
fn identity_sorting_is_kind_then_logical_id() {
    let mut identities = vec![
        TenantResourceIdentity {
            kind: TenantResourceKind::OauthClient,
            resource_id: "b".to_owned(),
            digest: "b".repeat(64),
        },
        TenantResourceIdentity {
            kind: TenantResourceKind::User,
            resource_id: "z".to_owned(),
            digest: "z".repeat(64),
        },
        TenantResourceIdentity {
            kind: TenantResourceKind::User,
            resource_id: "a".to_owned(),
            digest: "a".repeat(64),
        },
    ];
    identities = sort_identities(identities);
    assert_eq!(identities[0].kind, TenantResourceKind::User);
    assert_eq!(identities[0].resource_id, "a");
    assert_eq!(identities[1].resource_id, "z");
    assert_eq!(identities[2].kind, TenantResourceKind::OauthClient);
}

#[test]
fn delta_dependencies_accept_existing_mtls_and_dataset_parent_resources() {
    let mtls_identity = TenantResourceIdentity {
        kind: TenantResourceKind::MtlsTrustAnchor,
        resource_id: "anchor".to_owned(),
        digest: "a".repeat(64),
    };
    let dataset_identity = TenantResourceIdentity {
        kind: TenantResourceKind::Openid4vcDataset,
        resource_id: "dataset".to_owned(),
        digest: "b".repeat(64),
    };
    let payloads = vec![
        PreparedApplyPayload::Mtls(Box::new(PreparedMtls {
            identity: mtls_identity.clone(),
            client_resource_id: "client".to_owned(),
            certificate_pem: "certificate".to_owned(),
            certificate_sha256: "c".repeat(64),
            subject_dn: "CN=test".to_owned(),
            not_before: chrono::Utc::now(),
            not_after: chrono::Utc::now(),
        })),
        PreparedApplyPayload::Dataset(Box::new(PreparedDataset {
            identity: dataset_identity.clone(),
            user_resource_id: "user".to_owned(),
            configuration_id: "configuration".to_owned(),
            claims: json!({}),
        })),
    ];
    let delta = [
        ResourceKey::from_identity(&mtls_identity),
        ResourceKey::from_identity(&dataset_identity),
    ]
    .into_iter()
    .collect();

    assert!(matches!(
        validate_desired_dependencies(&payloads, &delta),
        Err(ExecutorTransactionError::Executor(
            TenantResourceExecutorError::Rejected
        ))
    ));

    let available = delta
        .into_iter()
        .chain([
            ResourceKey::new(TenantResourceKind::OauthClient, "client"),
            ResourceKey::new(TenantResourceKind::User, "user"),
        ])
        .collect();
    assert!(validate_desired_dependencies(&payloads, &available).is_ok());
}

#[tokio::test]
async fn apply_preparation_types_and_sorts_every_ordinary_resource_without_persisting() {
    let tenant = nazo_identity::TenantContext {
        tenant_id: nazo_identity::TenantId::try_from(Uuid::now_v7()).unwrap(),
        realm_id: nazo_identity::RealmId::try_from(Uuid::now_v7()).unwrap(),
        organization_id: nazo_identity::OrganizationId::try_from(Uuid::now_v7()).unwrap(),
    };
    let pool =
        nazo_postgres::create_pool("postgres://postgres:unused@127.0.0.1:1/unused", 1).unwrap();
    let executor = PostgresTenantResourceExecutor::new(
        TenantResourceRepository::new(pool),
        tenant,
        Some(rand::random::<[u8; 32]>()),
        Arc::new(TestPreparation),
    );
    let identity = |kind, resource_id: &str, digest: u8| TenantResourceIdentity {
        kind,
        resource_id: resource_id.to_owned(),
        digest: format!("{digest:x}").repeat(64),
    };
    let certificate = test_ca_certificate_pem();
    let trust_policy = test_openid4vc_trust_policy();
    let oauth_request: nazo_auth::CreateClientRequest = serde_json::from_value(json!({
        "client_name": "prepared-client",
        "client_type": "confidential",
        "redirect_uris": ["https://client.example/callback"],
        "scopes": ["openid"],
        "allowed_audiences": ["resource://default"],
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "jwks": null
    }))
    .unwrap();
    let resources = vec![
        PreparedTenantResource {
            identity: identity(TenantResourceKind::Openid4vcTrustPolicy, "policy", 6),
            payload: Some(TenantResourcePayload::Openid4vcTrustPolicy(Box::new(
                Openid4vcTrustPolicyResourcePayload {
                    public_material: trust_policy,
                },
            ))),
        },
        PreparedTenantResource {
            identity: identity(TenantResourceKind::Openid4vcDataset, "dataset", 5),
            payload: Some(TenantResourcePayload::Openid4vcDataset(
                Openid4vcDatasetResourcePayload {
                    user_resource_id: "user".to_owned(),
                    configuration_id: "pid-sd-jwt".to_owned(),
                    claims: json!({"given_name": "Nazo"}),
                },
            )),
        },
        PreparedTenantResource {
            identity: identity(TenantResourceKind::MtlsTrustAnchor, "mtls", 3),
            payload: Some(TenantResourcePayload::MtlsTrustAnchor(
                MtlsTrustAnchorResourcePayload {
                    client_resource_id: "client".to_owned(),
                    certificate_pem: certificate,
                },
            )),
        },
        PreparedTenantResource {
            identity: identity(TenantResourceKind::OauthClient, "client", 2),
            payload: Some(TenantResourcePayload::OauthClient(Box::new(
                OauthClientResourcePayload {
                    request: oauth_request,
                    supplied_secret: Some("0123456789abcdef0123456789abcdef".to_owned()),
                    trust_policy_resource_id: Some("policy".to_owned()),
                },
            ))),
        },
        PreparedTenantResource {
            identity: identity(TenantResourceKind::User, "user", 1),
            payload: Some(TenantResourcePayload::User(UserResourcePayload {
                username: "prepared-user".to_owned(),
                email: "prepared-user@example.test".to_owned(),
                password: "test-password".to_owned(),
                email_verified: true,
                profile: Some(json!({"display_name": "Prepared User"})),
            })),
        },
    ];
    for resource in &resources {
        executor
            .prepare_apply_payloads(std::slice::from_ref(resource))
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "{:?} ordinary resource should prepare: {error:?}",
                    resource.identity.kind
                )
            });
    }
    let prepared = executor
        .prepare_apply_payloads(&resources)
        .await
        .expect("every ordinary resource should prepare");
    assert_eq!(prepared.len(), 5);
    assert!(matches!(prepared[0], PreparedApplyPayload::User(_)));
    assert!(matches!(prepared[1], PreparedApplyPayload::OauthClient(_)));
    assert!(matches!(prepared[2], PreparedApplyPayload::Mtls(_)));
    assert!(matches!(prepared[3], PreparedApplyPayload::Dataset(_)));
    assert!(matches!(prepared[4], PreparedApplyPayload::TrustPolicy(_)));

    let mut missing = resources;
    missing[0].payload = None;
    assert!(matches!(
        executor.prepare_apply_payloads(&missing).await,
        Err(TenantResourceExecutorError::Rejected)
    ));
}

#[test]
fn profile_mapping_is_bounded_and_does_not_accept_structural_values() {
    let profile = json!({
        "display_name": "Alice",
        "given_name": "A",
        "phone_number_verified": true,
    });
    let fields = profile_fields(Some(&profile)).expect("profile fields");
    assert_eq!(fields.display_name.as_deref(), Some("Alice"));
    assert_eq!(fields.given_name.as_deref(), Some("A"));
    assert!(fields.phone_number_verified);
    assert!(
        profile_fields(Some(&json!({
            "unknown_secret": "must not be copied"
        })))
        .is_err()
    );
    assert!(profile_fields(Some(&json!({"given_name": 7}))).is_err());
    assert!(
        profile_fields(Some(&json!({
            "display_name": "x".repeat(513)
        })))
        .is_err()
    );
}

#[test]
fn prepared_client_debug_redacts_secret_hash() {
    let request = nazo_auth::CreateClientRequest {
        client_name: "client".to_owned(),
        client_type: "public".to_owned(),
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        scopes: Vec::new(),
        allowed_audiences: Vec::new(),
        grant_types: Vec::new(),
        token_endpoint_auth_method: "none".to_owned(),
        subject_type: None,
        sector_identifier_uri: None,
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        backchannel_token_delivery_mode: "poll".to_owned(),
        backchannel_client_notification_endpoint: None,
        backchannel_authentication_request_signing_alg: None,
        backchannel_user_code_parameter: false,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: Vec::new(),
        tls_client_auth_san_uri: Vec::new(),
        tls_client_auth_san_ip: Vec::new(),
        tls_client_auth_san_email: Vec::new(),
        jwks_uri: None,
        jwks: None,
        request_uris: Vec::new(),
        initiate_login_uri: None,
        presentation: Default::default(),
        id_token_signed_response_alg: None,
        id_token_encrypted_response_alg: None,
        id_token_encrypted_response_enc: None,
        request_object_signing_alg: None,
        request_object_encryption_alg: None,
        request_object_encryption_enc: None,
        token_endpoint_auth_signing_alg: None,
        introspection_signed_response_alg: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        security_policy: Default::default(),
    };
    let client = nazo_auth::OAuthClient {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        realm_id: Uuid::now_v7(),
        organization_id: Uuid::now_v7(),
        registration: nazo_auth::ValidatedClientRegistration {
            client_id: "client-id".to_owned(),
            client_name: request.client_name.clone(),
            client_type: request.client_type.clone(),
            redirect_uris: request.redirect_uris.clone(),
            post_logout_redirect_uris: request.post_logout_redirect_uris.clone(),
            scopes: request.scopes.clone(),
            allowed_audiences: request.allowed_audiences.clone(),
            grant_types: request.grant_types.clone(),
            token_endpoint_auth_method: request.token_endpoint_auth_method.clone(),
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            backchannel_token_delivery_mode: "poll".to_owned(),
            backchannel_client_notification_endpoint: None,
            backchannel_authentication_request_signing_alg: None,
            backchannel_user_code_parameter: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: Vec::new(),
            tls_client_auth_san_uri: Vec::new(),
            tls_client_auth_san_ip: Vec::new(),
            tls_client_auth_san_email: Vec::new(),
            jwks_uri: None,
            jwks: None,
            request_uris: Vec::new(),
            initiate_login_uri: None,
            presentation: Default::default(),
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_signing_alg: None,
            introspection_signed_response_alg: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            security_policy: Some(Default::default()),
        },
        require_mtls_bound_tokens: false,
        is_active: true,
    };
    let prepared = PreparedOAuthClient {
        client,
        client_secret_hash: Some("super-secret-hash".to_owned()),
    };
    let debug = format!("{prepared:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("super-secret-hash"));
}

#[derive(QueryableByName)]
struct ActiveRow {
    #[diesel(sql_type = sql_types::Bool)]
    is_active: bool,
}

#[derive(QueryableByName)]
struct IdRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = sql_types::BigInt)]
    count: i64,
}

#[tokio::test]
async fn postgres_executor_applies_replays_and_revokes_one_owned_user_atomically() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("tenant-resource executor test requires NAZO_TEST_DATABASE_URL or DATABASE_URL");
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("pending migrations");
    let pool = nazo_postgres::create_pool(&database_url, 4).expect("test pool");
    let tenant_id = Uuid::now_v7();
    let realm_id = Uuid::now_v7();
    let organization_id = Uuid::now_v7();
    let tenant = nazo_identity::TenantContext {
        tenant_id: nazo_identity::TenantId::try_from(tenant_id).expect("tenant id"),
        realm_id: nazo_identity::RealmId::try_from(realm_id).expect("realm id"),
        organization_id: nazo_identity::OrganizationId::try_from(organization_id)
            .expect("organization id"),
    };
    let mut connection = nazo_postgres::get_conn(&pool).await.expect("connection");
    sql_query(
        "INSERT INTO tenants (id, slug, display_name, status)
         VALUES ($1, $2, 'tenant resource executor', 'active')",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(format!("tenant-resource-{tenant_id}"))
    .execute(&mut connection)
    .await
    .expect("tenant");
    sql_query(
        "INSERT INTO realms (id, tenant_id, slug, display_name, status)
         VALUES ($1, $2, 'default', 'tenant resource executor', 'active')",
    )
    .bind::<sql_types::Uuid, _>(realm_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .execute(&mut connection)
    .await
    .expect("realm");
    sql_query(
        "INSERT INTO organizations (id, tenant_id, slug, display_name, status)
         VALUES ($1, $2, 'default', 'tenant resource executor', 'active')",
    )
    .bind::<sql_types::Uuid, _>(organization_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .execute(&mut connection)
    .await
    .expect("organization");
    drop(connection);

    let executor = PostgresTenantResourceExecutor::new(
        TenantResourceRepository::new(pool.clone()),
        tenant,
        None,
        Arc::new(TestPreparation),
    );
    let empty_manifest = PostgresTenantResourceExecutor::empty_manifest_sha256();
    let identity = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: format!("managed-user-{tenant_id}"),
        digest: "d".repeat(64),
    };
    let desired_manifest =
        canonical_tenant_resource_manifest_sha256(std::slice::from_ref(&identity))
            .expect("desired manifest");
    let apply_task = resource_task(
        tenant_id,
        "apply-user",
        "apply-user-change",
        TenantResourceOperation::Apply,
        TenantResourceTaskPayload::Apply {
            resources: vec![identity.clone()],
        },
        0,
        (empty_manifest.clone(), desired_manifest.clone()),
    );
    let apply_request_sha256 = "c".repeat(64);
    let apply = PreparedTenantResourceTask {
        task: apply_task.clone(),
        request_sha256: apply_request_sha256.clone(),
        resources: vec![PreparedTenantResource {
            identity: identity.clone(),
            payload: Some(TenantResourcePayload::User(UserResourcePayload {
                username: format!("user-{tenant_id}"),
                email: format!("user-{tenant_id}@example.test"),
                password: "test-password".to_owned(),
                email_verified: true,
                profile: None,
            })),
        }],
    };
    let apply_calls = Arc::new(AtomicUsize::new(0));
    let apply_issuer = TestReceiptIssuer {
        task: apply_task,
        request_sha256: apply_request_sha256,
        calls: apply_calls.clone(),
    };
    let first_receipt = TenantResourceExecutor::execute(&executor, apply.clone(), &apply_issuer)
        .await
        .expect("first apply");
    let replayed_receipt = TenantResourceExecutor::execute(&executor, apply.clone(), &apply_issuer)
        .await
        .expect("idempotent replay");
    assert_eq!(first_receipt, replayed_receipt);
    assert_eq!(apply_calls.as_ref().load(Ordering::SeqCst), 1);
    let mut drift = apply;
    drift.request_sha256 = "e".repeat(64);
    assert!(matches!(
        TenantResourceExecutor::execute(&executor, drift, &apply_issuer).await,
        Err(TenantResourceExecutorError::Conflict)
    ));

    let mut connection = nazo_postgres::get_conn(&pool).await.expect("connection");
    let managed_user = sql_query(
        "SELECT id FROM users
         WHERE tenant_id = $1 AND username = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(format!("user-{tenant_id}"))
    .get_result::<IdRow>(&mut connection)
    .await
    .expect("managed user id");
    let drift = sql_query(
        "UPDATE users SET email = $3, updated_at = CURRENT_TIMESTAMP
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(managed_user.id)
    .bind::<sql_types::Varchar, _>(format!("drift-{tenant_id}@example.test"))
    .execute(&mut connection)
    .await;
    assert!(
        drift.is_err(),
        "active machine-owned user drift must fail closed"
    );

    // Apply is an atomic delta: an omitted active resource remains managed
    // while the new resource is created and bound in the same transaction.
    let identity_two = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: format!("managed-user-two-{tenant_id}"),
        digest: "e".repeat(64),
    };
    let full_manifest =
        canonical_tenant_resource_manifest_sha256(&[identity.clone(), identity_two.clone()])
            .expect("full delta manifest");
    let delta_task = resource_task(
        tenant_id,
        "apply-user-two",
        "apply-user-two-change",
        TenantResourceOperation::Apply,
        TenantResourceTaskPayload::Apply {
            resources: vec![identity_two.clone()],
        },
        1,
        (desired_manifest.clone(), full_manifest.clone()),
    );
    let delta_request_sha256 = "6".repeat(64);
    let delta = PreparedTenantResourceTask {
        task: delta_task.clone(),
        request_sha256: delta_request_sha256.clone(),
        resources: vec![PreparedTenantResource {
            identity: identity_two.clone(),
            payload: Some(TenantResourcePayload::User(UserResourcePayload {
                username: format!("user-two-{tenant_id}"),
                email: format!("user-two-{tenant_id}@example.test"),
                password: "test-password-two".to_owned(),
                email_verified: true,
                profile: None,
            })),
        }],
    };
    let delta_calls = Arc::new(AtomicUsize::new(0));
    let delta_issuer = TestReceiptIssuer {
        task: delta_task,
        request_sha256: delta_request_sha256,
        calls: delta_calls.clone(),
    };
    let stale_delta = {
        let mut stale = delta.clone();
        stale.task.baseline_manifest_sha256 = "f".repeat(64);
        stale.request_sha256 = "7".repeat(64);
        stale.task.change_set_id = "apply-user-two-stale".to_owned();
        stale
    };
    assert!(matches!(
        TenantResourceExecutor::execute(&executor, stale_delta, &delta_issuer).await,
        Err(TenantResourceExecutorError::Conflict)
    ));
    let delta_receipt = TenantResourceExecutor::execute(&executor, delta.clone(), &delta_issuer)
        .await
        .expect("delta apply");
    assert_eq!(
        delta_receipt,
        TenantResourceExecutor::execute(&executor, delta.clone(), &delta_issuer)
            .await
            .expect("delta replay")
    );
    assert_eq!(delta_calls.as_ref().load(Ordering::SeqCst), 1);
    let mut changed_digest = delta.clone();
    changed_digest.task.jti = "apply-user-two-digest-conflict".to_owned();
    changed_digest.task.change_set_id = "apply-user-two-digest-conflict-change".to_owned();
    changed_digest.request_sha256 = "8".repeat(64);
    changed_digest.resources[0].identity.digest = "f".repeat(64);
    if let TenantResourceTaskPayload::Apply { resources } = &mut changed_digest.task.payload {
        resources[0].digest = "f".repeat(64);
    }
    let changed_full_manifest = canonical_tenant_resource_manifest_sha256(&[
        identity.clone(),
        changed_digest.resources[0].identity.clone(),
    ])
    .expect("changed digest manifest");
    changed_digest.task.resource_manifest_sha256 = changed_full_manifest;
    assert!(matches!(
        TenantResourceExecutor::execute(&executor, changed_digest, &delta_issuer).await,
        Err(TenantResourceExecutorError::Conflict)
    ));
    let state = TenantResourceStateSource::current(&executor)
        .await
        .expect("delta state");
    assert_eq!(state.revision, 2);
    assert_eq!(state.resource_manifest_sha256, full_manifest);
    let active_after_delta =
        TenantResourceRepository::active_bindings_on_connection(&mut connection, tenant_id)
            .await
            .expect("active delta bindings");
    assert_eq!(active_after_delta.len(), 2);

    let public_client_id = format!("revocation-client-{tenant_id}");
    let client_id = sql_query(
        "INSERT INTO oauth_clients (
             tenant_id, realm_id, organization_id, client_id, client_name, client_type,
             redirect_uris, scopes, grant_types, token_endpoint_auth_method
         ) VALUES (
             $1, $2, $3, $4, 'Tenant Resource Revocation', 'confidential',
             '[\"https://client.example/callback\"]'::jsonb, '[\"openid\"]'::jsonb,
             '[\"authorization_code\"]'::jsonb, 'client_secret_basic'
         ) RETURNING id",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(realm_id)
    .bind::<sql_types::Uuid, _>(organization_id)
    .bind::<sql_types::Varchar, _>(&public_client_id)
    .get_result::<IdRow>(&mut connection)
    .await
    .expect("revocation client")
    .id;
    let access_token_jti = format!("managed-user-access-token-{tenant_id}");
    sql_query(
        "INSERT INTO oauth_token_issuances (
             issuance_id, tenant_id, client_id, user_id, grant_key_blake3, request_digest,
             phase, access_token_jti, access_token_expires_at, response_ciphertext,
             response_digest, response_envelope_version, response_key_id, expires_at
         ) VALUES (
             $1, $2, $3, $4, $5, $6, 'delivered', $7, CURRENT_TIMESTAMP + INTERVAL '5 minutes',
             decode('00', 'hex'), $8, 'v1', 'test-key', CURRENT_TIMESTAMP + INTERVAL '5 minutes'
         )",
    )
    .bind::<sql_types::Uuid, _>(Uuid::now_v7())
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(client_id)
    .bind::<sql_types::Uuid, _>(managed_user.id)
    .bind::<sql_types::Varchar, _>("1".repeat(64))
    .bind::<sql_types::Varchar, _>("2".repeat(64))
    .bind::<sql_types::Varchar, _>(&access_token_jti)
    .bind::<sql_types::Varchar, _>("3".repeat(64))
    .execute(&mut connection)
    .await
    .expect("user-owned access token issuance");
    let openid4vci_token_id = Uuid::now_v7();
    let openid4vci_token_hash = blake3::hash(format!("vci-token-{tenant_id}").as_bytes())
        .to_hex()
        .to_string();
    sql_query(
        "INSERT INTO openid4vci_access_grants (
             token_id, token_hash, tenant_id, subject_id, client_id,
             credential_configuration_ids, credential_identifiers, expires_at
         ) VALUES (
             $1, $2, $3, $4, $5, '[\"test-credential\"]'::jsonb, '[]'::jsonb,
             CURRENT_TIMESTAMP + INTERVAL '5 minutes'
         )",
    )
    .bind::<sql_types::Uuid, _>(openid4vci_token_id)
    .bind::<sql_types::Varchar, _>(&openid4vci_token_hash)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(managed_user.id)
    .bind::<sql_types::Varchar, _>(&public_client_id)
    .execute(&mut connection)
    .await
    .expect("openid4vci access grant");
    let openid4vci_offer_id = Uuid::now_v7();
    let pre_authorized_code_hash = blake3::hash(format!("vci-offer-{tenant_id}").as_bytes())
        .to_hex()
        .to_string();
    sql_query(
        "INSERT INTO openid4vci_offers (
             id, tenant_id, subject_id, credential_configuration_ids, grants_ciphertext,
             pre_authorized_code_hash, expires_at
         ) VALUES (
             $1, $2, $3, '[\"test-credential\"]'::jsonb, decode('00', 'hex'), $4,
             CURRENT_TIMESTAMP + INTERVAL '5 minutes'
         )",
    )
    .bind::<sql_types::Uuid, _>(openid4vci_offer_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(managed_user.id)
    .bind::<sql_types::Varchar, _>(&pre_authorized_code_hash)
    .execute(&mut connection)
    .await
    .expect("openid4vci pre-authorized offer");
    drop(connection);

    let remaining_manifest =
        canonical_tenant_resource_manifest_sha256(std::slice::from_ref(&identity_two))
            .expect("remaining manifest");
    let revoke_task = resource_task(
        tenant_id,
        "revoke-user",
        "revoke-user-change",
        TenantResourceOperation::Revoke,
        TenantResourceTaskPayload::Revoke {
            resources: vec![identity.clone()],
        },
        2,
        (full_manifest.clone(), remaining_manifest.clone()),
    );
    let revoke_request_sha256 = "f".repeat(64);
    let revoke = PreparedTenantResourceTask {
        task: revoke_task.clone(),
        request_sha256: revoke_request_sha256.clone(),
        resources: vec![PreparedTenantResource {
            identity,
            payload: None,
        }],
    };
    let revoke_calls = Arc::new(AtomicUsize::new(0));
    let revoke_issuer = TestReceiptIssuer {
        task: revoke_task,
        request_sha256: revoke_request_sha256,
        calls: revoke_calls.clone(),
    };
    TenantResourceExecutor::execute(&executor, revoke.clone(), &revoke_issuer)
        .await
        .expect("revoke");
    TenantResourceExecutor::execute(&executor, revoke, &revoke_issuer)
        .await
        .expect("revoke replay");
    assert_eq!(revoke_calls.as_ref().load(Ordering::SeqCst), 1);

    let state = TenantResourceStateSource::current(&executor)
        .await
        .expect("state");
    assert_eq!(state.revision, 3);
    assert_eq!(state.resource_manifest_sha256, remaining_manifest);
    let mut connection = nazo_postgres::get_conn(&pool).await.expect("connection");
    let user = sql_query(
        "SELECT is_active FROM users
         WHERE tenant_id = $1 AND username = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(format!("user-{tenant_id}"))
    .get_result::<ActiveRow>(&mut connection)
    .await
    .expect("managed user");
    assert!(!user.is_active);
    let revoked = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM access_token_revocations
         WHERE tenant_id = $1 AND access_token_jti_blake3 = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(
        blake3::hash(access_token_jti.as_bytes())
            .to_hex()
            .to_string(),
    )
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("access-token revocation count");
    assert_eq!(revoked.count, 1);
    let openid4vci_revoked = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM access_token_revocations
         WHERE tenant_id = $1 AND access_token_jti_blake3 = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(
        blake3::hash(openid4vci_token_id.to_string().as_bytes())
            .to_hex()
            .to_string(),
    )
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("openid4vci revocation count");
    assert_eq!(openid4vci_revoked.count, 1);
    let openid4vci_grant_revoked = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM openid4vci_access_grants
         WHERE tenant_id = $1 AND token_id = $2 AND revoked_at IS NOT NULL",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(openid4vci_token_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("openid4vci grant revocation count");
    assert_eq!(openid4vci_grant_revoked.count, 1);
    let openid4vci_offer_consumed = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM openid4vci_offers
         WHERE tenant_id = $1 AND id = $2 AND consumed_at IS NOT NULL",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(openid4vci_offer_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("openid4vci offer invalidation count");
    assert_eq!(openid4vci_offer_consumed.count, 1);
    let active =
        TenantResourceRepository::active_bindings_on_connection(&mut connection, tenant_id)
            .await
            .expect("active bindings");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].resource_id, identity_two.resource_id);

    let final_revoke_task = resource_task(
        tenant_id,
        "revoke-user-two",
        "revoke-user-two-change",
        TenantResourceOperation::Revoke,
        TenantResourceTaskPayload::Revoke {
            resources: vec![identity_two.clone()],
        },
        3,
        (remaining_manifest, empty_manifest.clone()),
    );
    let final_revoke_request_sha256 = "9".repeat(64);
    let final_revoke = PreparedTenantResourceTask {
        task: final_revoke_task.clone(),
        request_sha256: final_revoke_request_sha256.clone(),
        resources: vec![PreparedTenantResource {
            identity: identity_two,
            payload: None,
        }],
    };
    let final_revoke_calls = Arc::new(AtomicUsize::new(0));
    let final_revoke_issuer = TestReceiptIssuer {
        task: final_revoke_task,
        request_sha256: final_revoke_request_sha256,
        calls: final_revoke_calls.clone(),
    };
    TenantResourceExecutor::execute(&executor, final_revoke.clone(), &final_revoke_issuer)
        .await
        .expect("final revoke");
    TenantResourceExecutor::execute(&executor, final_revoke, &final_revoke_issuer)
        .await
        .expect("final revoke replay");
    assert_eq!(final_revoke_calls.as_ref().load(Ordering::SeqCst), 1);
    let state = TenantResourceStateSource::current(&executor)
        .await
        .expect("final state");
    assert_eq!(state.revision, 4);
    assert_eq!(state.resource_manifest_sha256, empty_manifest);
    let active =
        TenantResourceRepository::active_bindings_on_connection(&mut connection, tenant_id)
            .await
            .expect("final active bindings");
    assert!(active.is_empty());
}

#[tokio::test]
async fn postgres_executor_applies_and_revokes_the_complete_ordinary_resource_graph() {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("tenant-resource executor test requires NAZO_TEST_DATABASE_URL or DATABASE_URL");
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("pending migrations");
    let pool = nazo_postgres::create_pool(&database_url, 4).expect("test pool");
    let tenant_id = Uuid::now_v7();
    let realm_id = Uuid::now_v7();
    let organization_id = Uuid::now_v7();
    let tenant = nazo_identity::TenantContext {
        tenant_id: nazo_identity::TenantId::try_from(tenant_id).expect("tenant id"),
        realm_id: nazo_identity::RealmId::try_from(realm_id).expect("realm id"),
        organization_id: nazo_identity::OrganizationId::try_from(organization_id)
            .expect("organization id"),
    };
    let mut connection = nazo_postgres::get_conn(&pool).await.expect("connection");
    sql_query(
        "INSERT INTO tenants (id, slug, display_name, status)
         VALUES ($1, $2, 'ordinary graph executor', 'active')",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(format!("ordinary-graph-{tenant_id}"))
    .execute(&mut connection)
    .await
    .expect("tenant");
    sql_query(
        "INSERT INTO realms (id, tenant_id, slug, display_name, status)
         VALUES ($1, $2, 'default', 'ordinary graph executor', 'active')",
    )
    .bind::<sql_types::Uuid, _>(realm_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .execute(&mut connection)
    .await
    .expect("realm");
    sql_query(
        "INSERT INTO organizations (id, tenant_id, slug, display_name, status)
         VALUES ($1, $2, 'default', 'ordinary graph executor', 'active')",
    )
    .bind::<sql_types::Uuid, _>(organization_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .execute(&mut connection)
    .await
    .expect("organization");
    drop(connection);

    let data_key = rand::random::<[u8; 32]>();
    let executor = PostgresTenantResourceExecutor::new(
        TenantResourceRepository::new(pool.clone()),
        tenant,
        Some(data_key),
        Arc::new(TestPreparation),
    );
    let identity = |kind, resource_id: &str, digest: u8| TenantResourceIdentity {
        kind,
        resource_id: format!("{resource_id}-{tenant_id}"),
        digest: format!("{digest:x}").repeat(64),
    };
    let user = identity(TenantResourceKind::User, "ordinary-user", 1);
    let policy = identity(
        TenantResourceKind::Openid4vcTrustPolicy,
        "ordinary-policy",
        2,
    );
    let client = identity(TenantResourceKind::OauthClient, "ordinary-client", 3);
    let mtls = identity(TenantResourceKind::MtlsTrustAnchor, "ordinary-mtls", 4);
    let dataset = identity(TenantResourceKind::Openid4vcDataset, "ordinary-dataset", 5);
    let resources = vec![
        PreparedTenantResource {
            identity: policy.clone(),
            payload: Some(TenantResourcePayload::Openid4vcTrustPolicy(Box::new(
                Openid4vcTrustPolicyResourcePayload {
                    public_material: test_openid4vc_trust_policy(),
                },
            ))),
        },
        PreparedTenantResource {
            identity: dataset.clone(),
            payload: Some(TenantResourcePayload::Openid4vcDataset(
                Openid4vcDatasetResourcePayload {
                    user_resource_id: user.resource_id.clone(),
                    configuration_id: "pid-sd-jwt".to_owned(),
                    claims: json!({"given_name": "Ordinary", "family_name": "Graph"}),
                },
            )),
        },
        PreparedTenantResource {
            identity: mtls.clone(),
            payload: Some(TenantResourcePayload::MtlsTrustAnchor(
                MtlsTrustAnchorResourcePayload {
                    client_resource_id: client.resource_id.clone(),
                    certificate_pem: test_ca_certificate_pem(),
                },
            )),
        },
        PreparedTenantResource {
            identity: client.clone(),
            payload: Some(TenantResourcePayload::OauthClient(Box::new(
                OauthClientResourcePayload {
                    request: serde_json::from_value(json!({
                        "client_name": "ordinary graph client",
                        "client_type": "confidential",
                        "redirect_uris": ["https://client.example/callback"],
                        "scopes": ["openid"],
                        "allowed_audiences": ["resource://default"],
                        "grant_types": [
                            "authorization_code",
                            "urn:openid:params:grant-type:ciba"
                        ],
                        "token_endpoint_auth_method": "client_secret_basic",
                        "require_mtls_bound_tokens": true,
                        "jwks": null
                    }))
                    .expect("OAuth request"),
                    supplied_secret: Some("abcdef0123456789abcdef0123456789".to_owned()),
                    trust_policy_resource_id: Some(policy.resource_id.clone()),
                },
            ))),
        },
        PreparedTenantResource {
            identity: user.clone(),
            payload: Some(TenantResourcePayload::User(UserResourcePayload {
                username: format!("ordinary-user-{tenant_id}"),
                email: format!("ordinary-user-{tenant_id}@example.test"),
                password: "ordinary-password".to_owned(),
                email_verified: true,
                profile: Some(json!({
                    "display_name": "Ordinary Graph",
                    "given_name": "Ordinary",
                    "family_name": "Graph"
                })),
            })),
        },
    ];
    let payloads = executor
        .prepare_apply_payloads(&resources)
        .await
        .expect("prepare complete graph");
    let desired = resources
        .iter()
        .map(|resource| resource.identity.clone())
        .collect::<Vec<_>>();
    let desired_manifest =
        canonical_tenant_resource_manifest_sha256(&desired).expect("complete graph manifest");
    let empty_manifest = PostgresTenantResourceExecutor::empty_manifest_sha256();
    let apply_task = resource_task(
        tenant_id,
        "ordinary-graph-apply",
        "ordinary-graph-change",
        TenantResourceOperation::Apply,
        TenantResourceTaskPayload::Apply {
            resources: desired.clone(),
        },
        0,
        (empty_manifest.clone(), desired_manifest.clone()),
    );
    let mut connection = nazo_postgres::get_conn(&pool).await.expect("connection");
    let (applied, mappings) = apply_resources(
        &mut connection,
        tenant_id,
        tenant,
        &apply_task,
        &resources,
        &payloads,
        &Some(data_key),
    )
    .await
    .expect("apply complete graph");
    assert_eq!(applied.len(), 5);
    assert_eq!(mappings.len(), 2);
    assert!(mappings.iter().any(|mapping| {
        mapping.kind == TenantResourceKind::User && mapping.resource_id == user.resource_id
    }));
    assert!(mappings.iter().any(|mapping| {
        mapping.kind == TenantResourceKind::OauthClient && mapping.resource_id == client.resource_id
    }));

    let (replayed, replayed_mappings) = apply_resources(
        &mut connection,
        tenant_id,
        tenant,
        &apply_task,
        &resources,
        &payloads,
        &Some(data_key),
    )
    .await
    .expect("replay complete graph");
    assert_eq!(replayed, applied);
    assert_eq!(replayed_mappings, mappings);

    let parent_only = [ResourceKey::from_identity(&user)].into_iter().collect();
    let active = active_binding_map(&mut connection, tenant_id)
        .await
        .expect("active graph");
    assert!(matches!(
        validate_revoke_dependency_closure(&mut connection, tenant_id, &active, &parent_only).await,
        Err(ExecutorTransactionError::Executor(
            TenantResourceExecutorError::Rejected
        ))
    ));

    let revoke_task = resource_task(
        tenant_id,
        "ordinary-graph-revoke",
        "ordinary-graph-revoke-change",
        TenantResourceOperation::Revoke,
        TenantResourceTaskPayload::Revoke {
            resources: desired.clone(),
        },
        1,
        (desired_manifest, empty_manifest),
    );
    let revoked = revoke_resources(
        &mut connection,
        tenant_id,
        tenant,
        &revoke_task,
        &resources
            .iter()
            .map(|resource| PreparedTenantResource {
                identity: resource.identity.clone(),
                payload: None,
            })
            .collect::<Vec<_>>(),
    )
    .await
    .expect("revoke complete graph");
    assert_eq!(revoked.len(), 5);
    assert!(
        TenantResourceRepository::active_bindings_on_connection(&mut connection, tenant_id)
            .await
            .expect("remaining bindings")
            .is_empty()
    );
}
