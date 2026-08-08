use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use chrono::{Duration, TimeZone, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::{
    AuthorizationCodeState, ConsentPayload, OAuthClient, PushedAuthorizationRequest,
    RequestObjectClaims, RequestObjectJtiPolicy, RequestObjectPolicy, ValidatedClientRegistration,
};

use super::{
    AuthorizationApprovalCommitError, AuthorizationApprovalError, AuthorizationApprovalInput,
    AuthorizationDecisionAdmissionError, AuthorizationFuture, AuthorizationPortError,
    AuthorizationRateDimension, AuthorizationRepositoryPort, AuthorizationResponseSignInput,
    AuthorizationResponseSignerPort, AuthorizationService, AuthorizationStateStorePort, GrantWrite,
    StoredAuthorizationGrant, stored_grant_covers_requested_authorization,
};

#[derive(Default)]
struct RepositoryState {
    client: Mutex<Option<OAuthClient>>,
    grant_error: Mutex<Option<AuthorizationPortError>>,
    grant_writes: AtomicUsize,
}

#[derive(Clone, Default)]
struct FakeRepository(Arc<RepositoryState>);

impl AuthorizationRepositoryPort for FakeRepository {
    fn client_by_id<'a>(
        &'a self,
        _client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>> {
        let client = self.0.client.lock().unwrap().clone();
        Box::pin(async move { Ok(client) })
    }

    fn active_mtls_candidates(&self, _limit: usize) -> AuthorizationFuture<'_, Vec<OAuthClient>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn grant<'a>(
        &'a self,
        _user_id: Uuid,
        _client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<StoredAuthorizationGrant>> {
        Box::pin(async { Ok(None) })
    }

    fn upsert_grant<'a>(&'a self, _write: GrantWrite<'a>) -> AuthorizationFuture<'a, ()> {
        self.0.grant_writes.fetch_add(1, Ordering::Relaxed);
        let error = self.0.grant_error.lock().unwrap().take();
        Box::pin(async move { error.map_or(Ok(()), Err) })
    }

    fn client_secret_salt<'a>(
        &'a self,
        _client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<String>> {
        Box::pin(async { Ok(None) })
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        _client_id: Uuid,
        _candidate_digest: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }
}

#[derive(Default)]
struct StoreState {
    consent: Mutex<Option<ConsentPayload>>,
    replace_consent_after_load: Mutex<Option<ConsentPayload>>,
    pushed: Mutex<Option<PushedAuthorizationRequest>>,
    replace_pushed_after_load: Mutex<Option<PushedAuthorizationRequest>>,
    stored_code: Mutex<Option<AuthorizationCodeState>>,
    code_error: Mutex<Option<AuthorizationPortError>>,
    jar_error: Mutex<Option<AuthorizationPortError>>,
    delete_error: Mutex<Option<AuthorizationPortError>>,
    consent_takes: AtomicUsize,
    pushed_takes: AtomicUsize,
    code_deletes: AtomicUsize,
}

#[derive(Clone, Default)]
struct FakeStore(Arc<StoreState>);

impl AuthorizationStateStorePort for FakeStore {
    fn load_par<'a>(
        &'a self,
        _request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>> {
        let pushed = self.0.pushed.lock().unwrap().clone();
        if let Some(replacement) = self.0.replace_pushed_after_load.lock().unwrap().take() {
            *self.0.pushed.lock().unwrap() = Some(replacement);
        }
        Box::pin(async move { Ok(pushed) })
    }

    fn take_par<'a>(
        &'a self,
        _request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>> {
        self.0.pushed_takes.fetch_add(1, Ordering::Relaxed);
        let pushed = self.0.pushed.lock().unwrap().take();
        Box::pin(async move { Ok(pushed) })
    }

    fn compare_and_delete_par<'a>(
        &'a self,
        _request_uri: &'a str,
        expected: &'a PushedAuthorizationRequest,
    ) -> AuthorizationFuture<'a, bool> {
        self.0.pushed_takes.fetch_add(1, Ordering::Relaxed);
        let mut current = self.0.pushed.lock().unwrap();
        let matches = current.as_ref().is_some_and(|current| {
            serde_json::to_vec(current).unwrap() == serde_json::to_vec(expected).unwrap()
        });
        if matches {
            current.take();
        }
        Box::pin(async move { Ok(matches) })
    }

    fn store_par<'a>(
        &'a self,
        _request_uri: &'a str,
        _payload: &'a PushedAuthorizationRequest,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn load_consent<'a>(
        &'a self,
        _request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        let consent = self.0.consent.lock().unwrap().clone();
        if let Some(replacement) = self.0.replace_consent_after_load.lock().unwrap().take() {
            *self.0.consent.lock().unwrap() = Some(replacement);
        }
        Box::pin(async move { Ok(consent) })
    }

    fn take_consent<'a>(
        &'a self,
        _request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        self.0.consent_takes.fetch_add(1, Ordering::Relaxed);
        let consent = self.0.consent.lock().unwrap().take();
        Box::pin(async move { Ok(consent) })
    }

    fn compare_and_delete_consent<'a>(
        &'a self,
        _request_id: &'a str,
        expected: &'a ConsentPayload,
    ) -> AuthorizationFuture<'a, bool> {
        self.0.consent_takes.fetch_add(1, Ordering::Relaxed);
        let mut current = self.0.consent.lock().unwrap();
        let matches = current.as_ref().is_some_and(|current| {
            serde_json::to_vec(current).unwrap() == serde_json::to_vec(expected).unwrap()
        });
        if matches {
            current.take();
        }
        Box::pin(async move { Ok(matches) })
    }

    fn store_consent<'a>(
        &'a self,
        _request_id: &'a str,
        _payload: &'a ConsentPayload,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn store_authorization_code<'a>(
        &'a self,
        _code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        let error = self.0.code_error.lock().unwrap().take();
        if error.is_none() {
            *self.0.stored_code.lock().unwrap() = Some(state.clone());
        }
        Box::pin(async move { error.map_or(Ok(()), Err) })
    }

    fn delete_authorization_code<'a>(&'a self, _code_hash: &'a str) -> AuthorizationFuture<'a, ()> {
        self.0.code_deletes.fetch_add(1, Ordering::Relaxed);
        let error = self.0.delete_error.lock().unwrap().take();
        if error.is_none() {
            *self.0.stored_code.lock().unwrap() = None;
        }
        Box::pin(async move { error.map_or(Ok(()), Err) })
    }

    fn take_reauth_nonce<'a>(&'a self, _nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>> {
        Box::pin(async { Ok(None) })
    }

    fn store_reauth_nonce<'a>(
        &'a self,
        _nonce: &'a str,
        _started_at: i64,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn consume_jar<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        let error = self.0.jar_error.lock().unwrap().take();
        Box::pin(async move { error.map_or(Ok(true), Err) })
    }

    fn consume_private_key_jwt<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn consume_jwt_bearer<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn consume_ciba_request_object<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn consume_dpop<'a>(
        &'a self,
        _thumbprint: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn issue_dpop_nonce<'a>(
        &'a self,
        _nonce: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn validate_dpop_nonce<'a>(&'a self, _nonce: &'a str) -> AuthorizationFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn increment_rate<'a>(
        &'a self,
        _dimension: AuthorizationRateDimension,
        _subject: &'a str,
        _window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64> {
        Box::pin(async { Ok(1) })
    }
}

#[derive(Clone, Copy)]
struct FakeSigner;

impl AuthorizationResponseSignerPort for FakeSigner {
    fn sign_authorization_response<'a>(
        &'a self,
        _input: AuthorizationResponseSignInput<'a>,
    ) -> AuthorizationFuture<'a, String> {
        Box::pin(async { Err(AuthorizationPortError::Unexpected) })
    }
}

fn registration(client_id: &str) -> ValidatedClientRegistration {
    ValidatedClientRegistration {
        client_id: client_id.to_owned(),
        client_name: "Test client".to_owned(),
        client_type: "confidential".to_owned(),
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_owned()],
        allowed_audiences: Vec::new(),
        grant_types: vec!["authorization_code".to_owned()],
        token_endpoint_auth_method: "client_secret_post".to_owned(),
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
        require_dpop_bound_tokens: false,
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        backchannel_token_delivery_mode: "poll".to_owned(),
        backchannel_client_notification_endpoint: None,
        backchannel_authentication_request_signing_alg: None,
        backchannel_user_code_parameter: false,
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
        presentation: crate::ClientPresentationMetadata::default(),
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
        security_policy: None,
    }
}

fn client(tenant_id: Uuid) -> OAuthClient {
    OAuthClient {
        id: Uuid::from_u128(20),
        tenant_id,
        realm_id: Uuid::from_u128(2),
        organization_id: Uuid::from_u128(3),
        registration: registration("client-1"),
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}

fn consent(user_id: Uuid, request_uri: Option<&str>) -> ConsentPayload {
    let issued_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    ConsentPayload {
        request_id: "request-1".to_owned(),
        user_id,
        client_id: "client-1".to_owned(),
        client_name: "Test client".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        resource_indicators: vec!["https://api.example".to_owned()],
        authorization_details: json!([]),
        state: Some("state-1".to_owned()),
        response_mode: None,
        nonce: Some("nonce-1".to_owned()),
        auth_time: 1_699_999_990,
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("sid-1".to_owned()),
        acr: Some("1".to_owned()),
        userinfo_claims: vec!["name".to_owned()],
        userinfo_claim_requests: Vec::new(),
        id_token_claims: vec!["email".to_owned()],
        id_token_claim_requests: Vec::new(),
        code_challenge: Some("challenge".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: Some("jkt".to_owned()),
        mtls_x5t_s256: None,
        pushed_request_uri: request_uri.map(str::to_owned),
        pushed_request_digest: None,
        signed_authorization_response_required: None,
        session_management_allowed: None,
        authorization_code_ttl_seconds: None,
        issued_at,
        expires_at: issued_at + Duration::minutes(10),
    }
}

fn pushed() -> PushedAuthorizationRequest {
    let issued_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    PushedAuthorizationRequest {
        client_id: "client-1".to_owned(),
        params: std::collections::HashMap::new(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at,
        expires_at: issued_at + Duration::minutes(10),
    }
}

fn service(
    repository: FakeRepository,
    store: FakeStore,
) -> AuthorizationService<FakeRepository, FakeStore, FakeSigner> {
    AuthorizationService::new(repository, store, FakeSigner)
}

#[test]
fn ciba_request_object_replay_is_delegated_to_the_state_store() {
    let accepted = futures_executor::block_on(
        service(FakeRepository::default(), FakeStore::default()).consume_ciba_request_object(
            "client-1",
            "request-object-jti",
            30,
        ),
    )
    .unwrap();
    assert!(accepted);
}

#[test]
fn owned_request_object_admission_keeps_outer_parameters_on_replay_dependency_failure() {
    let store = FakeStore::default();
    *store.0.jar_error.lock().unwrap() = Some(AuthorizationPortError::Unavailable);
    let service = service(FakeRepository::default(), store);
    let now = 1_700_000_000;
    let claims = RequestObjectClaims {
        client_id: "client".to_owned(),
        iss: Some("client".to_owned()),
        sub: Some("client".to_owned()),
        aud: Some(json!("https://issuer.example")),
        exp: Some(now + 120),
        nbf: Some(now),
        iat: Some(now),
        jti: Some("replay-jti".to_owned()),
        parameters: std::collections::HashMap::from([(
            "redirect_uri".to_owned(),
            json!("https://client.example/cb"),
        )]),
    };
    let policy = RequestObjectPolicy {
        issuer: "https://issuer.example",
        client_id: "client",
        jti_policy: RequestObjectJtiPolicy::RequiredForSignedJar,
        require_integrity_protected_parameters: true,
        now,
    };
    let mut outer = std::collections::HashMap::from([
        ("client_id".to_owned(), "client".to_owned()),
        ("request".to_owned(), "signed.jwt".to_owned()),
        ("state".to_owned(), "outer-state".to_owned()),
    ]);
    let original = outer.clone();

    assert_eq!(
        futures_executor::block_on(
            service.admit_request_object_owned(&mut outer, &claims, policy,)
        ),
        Err(crate::AuthorizationRequestError::Dependency(
            AuthorizationPortError::Unavailable,
        ))
    );
    assert_eq!(outer, original);
}

#[test]
fn stored_grant_must_cover_every_scope_and_resource() {
    let stored = StoredAuthorizationGrant {
        scopes: json!(["openid", "profile"]),
        resource_indicators: json!(["https://api.example"]),
        authorization_details: json!([]),
    };

    assert!(stored_grant_covers_requested_authorization(
        &stored,
        &["openid".to_owned()],
        &["https://api.example".to_owned()],
        &json!([]),
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &stored,
        &["email".to_owned()],
        &["https://api.example".to_owned()],
        &json!([]),
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &stored,
        &["openid".to_owned()],
        &["https://other.example".to_owned()],
        &json!([]),
    ));
}

#[test]
fn pushed_request_digest_is_independent_of_hash_map_iteration_order() {
    let mut first = pushed();
    first.params.insert("scope".to_owned(), "openid".to_owned());
    first.params.insert(
        "redirect_uri".to_owned(),
        "https://client.example/cb".to_owned(),
    );
    let mut second = pushed();
    second.params.insert(
        "redirect_uri".to_owned(),
        "https://client.example/cb".to_owned(),
    );
    second
        .params
        .insert("scope".to_owned(), "openid".to_owned());

    assert_eq!(
        super::pushed_authorization_request_digest(&first).unwrap(),
        super::pushed_authorization_request_digest(&second).unwrap()
    );
}

#[test]
fn foreign_user_cannot_consume_an_observed_consent() {
    futures_executor::block_on(foreign_user_cannot_consume_an_observed_consent_async());
}

async fn foreign_user_cannot_consume_an_observed_consent_async() {
    let owner = Uuid::from_u128(10);
    let store = FakeStore::default();
    *store.0.consent.lock().unwrap() = Some(consent(owner, None));
    let service = service(FakeRepository::default(), store.clone());

    assert!(matches!(
        service
            .admit_user_decision("request-1", Uuid::from_u128(11))
            .await,
        Err(AuthorizationDecisionAdmissionError::UserMismatch)
    ));
    assert_eq!(store.0.consent_takes.load(Ordering::Relaxed), 0);
    assert!(store.0.consent.lock().unwrap().is_some());
}

#[test]
fn concurrent_consent_admission_has_exactly_one_winner() {
    futures_executor::block_on(concurrent_consent_admission_has_exactly_one_winner_async());
}

async fn concurrent_consent_admission_has_exactly_one_winner_async() {
    let owner = Uuid::from_u128(10);
    let store = FakeStore::default();
    *store.0.consent.lock().unwrap() = Some(consent(owner, None));
    let service = service(FakeRepository::default(), store.clone());

    let (first, second) = futures_util::join!(
        service.admit_user_decision("request-1", owner),
        service.admit_user_decision("request-1", owner),
    );
    let results = [first, second];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(AuthorizationDecisionAdmissionError::ConsentMissing)
                )
            })
            .count(),
        1
    );
    assert_eq!(store.0.consent_takes.load(Ordering::Relaxed), 1);
}

#[test]
fn consent_replacement_between_load_and_claim_is_preserved() {
    futures_executor::block_on(consent_replacement_between_load_and_claim_is_preserved_async());
}

async fn consent_replacement_between_load_and_claim_is_preserved_async() {
    let owner = Uuid::from_u128(10);
    let replacement_owner = Uuid::from_u128(11);
    let store = FakeStore::default();
    *store.0.consent.lock().unwrap() = Some(consent(owner, None));
    *store.0.replace_consent_after_load.lock().unwrap() = Some(consent(replacement_owner, None));
    let service = service(FakeRepository::default(), store.clone());

    assert!(matches!(
        service.admit_user_decision("request-1", owner).await,
        Err(AuthorizationDecisionAdmissionError::ConsentMissing)
    ));
    let retained = store.0.consent.lock().unwrap().clone().unwrap();
    assert_eq!(retained.user_id, replacement_owner);
    assert_eq!(store.0.consent_takes.load(Ordering::Relaxed), 1);
}

#[test]
fn admitted_consent_consumes_its_par_handle_once() {
    futures_executor::block_on(admitted_consent_consumes_its_par_handle_once_async());
}

async fn admitted_consent_consumes_its_par_handle_once_async() {
    let owner = Uuid::from_u128(10);
    let store = FakeStore::default();
    *store.0.consent.lock().unwrap() = Some(consent(owner, Some("request-uri-1")));
    *store.0.pushed.lock().unwrap() = Some(pushed());
    let service = service(FakeRepository::default(), store.clone());

    let admitted = service
        .admit_user_decision("request-1", owner)
        .await
        .unwrap();
    assert_eq!(
        admitted.pushed_request_uri.as_deref(),
        Some("request-uri-1")
    );
    assert_eq!(store.0.pushed_takes.load(Ordering::Relaxed), 1);
    assert!(store.0.pushed.lock().unwrap().is_none());
}

#[test]
fn missing_par_error_retains_consumed_consent_for_protocol_redirect() {
    futures_executor::block_on(
        missing_par_error_retains_consumed_consent_for_protocol_redirect_async(),
    );
}

async fn missing_par_error_retains_consumed_consent_for_protocol_redirect_async() {
    let owner = Uuid::from_u128(10);
    let store = FakeStore::default();
    *store.0.consent.lock().unwrap() = Some(consent(owner, Some("missing-request-uri")));
    let service = service(FakeRepository::default(), store.clone());

    let error = service
        .admit_user_decision("request-1", owner)
        .await
        .unwrap_err();
    let AuthorizationDecisionAdmissionError::PushedRequestMissing(consent) = error else {
        panic!("missing PAR must retain the consumed consent payload")
    };
    assert_eq!(consent.redirect_uri, "https://client.example/callback");
    assert_eq!(consent.state.as_deref(), Some("state-1"));
    assert_eq!(store.0.consent_takes.load(Ordering::Relaxed), 1);
    assert_eq!(store.0.pushed_takes.load(Ordering::Relaxed), 0);
}

#[test]
fn par_replacement_between_load_and_claim_is_preserved() {
    futures_executor::block_on(par_replacement_between_load_and_claim_is_preserved_async());
}

async fn par_replacement_between_load_and_claim_is_preserved_async() {
    let owner = Uuid::from_u128(10);
    let original = pushed();
    let mut bound_consent = consent(owner, Some("request-uri-1"));
    bound_consent.pushed_request_digest =
        Some(super::pushed_authorization_request_digest(&original).unwrap());
    let mut replacement = pushed();
    replacement.client_id = "replacement-client".to_owned();
    let store = FakeStore::default();
    *store.0.consent.lock().unwrap() = Some(bound_consent);
    *store.0.pushed.lock().unwrap() = Some(original);
    *store.0.replace_pushed_after_load.lock().unwrap() = Some(replacement.clone());
    let service = service(FakeRepository::default(), store.clone());

    let error = service
        .admit_user_decision("request-1", owner)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        AuthorizationDecisionAdmissionError::PushedRequestMissing(_)
    ));
    assert_eq!(
        store.0.pushed.lock().unwrap().as_ref().unwrap().client_id,
        replacement.client_id
    );
    assert_eq!(store.0.pushed_takes.load(Ordering::Relaxed), 1);
}

#[test]
fn inactive_client_is_rejected_before_authorization_code_publication() {
    futures_executor::block_on(
        inactive_client_is_rejected_before_authorization_code_publication_async(),
    );
}

async fn inactive_client_is_rejected_before_authorization_code_publication_async() {
    let tenant_id = Uuid::from_u128(1);
    let repository = FakeRepository::default();
    let mut inactive = client(tenant_id);
    inactive.is_active = false;
    *repository.0.client.lock().unwrap() = Some(inactive);
    let store = FakeStore::default();
    let service = service(repository.clone(), store.clone());
    let consent = consent(Uuid::from_u128(10), None);

    assert_eq!(
        service
            .approve_consent(AuthorizationApprovalInput {
                consent: &consent,
                code_hash: "hash",
                code_id: "code-id",
                issued_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
                code_ttl_seconds: 60,
                tenant_id,
            })
            .await,
        Err(AuthorizationApprovalError::ClientUnavailable)
    );
    assert!(store.0.stored_code.lock().unwrap().is_none());
    assert_eq!(repository.0.grant_writes.load(Ordering::Relaxed), 0);
}

#[test]
fn grant_failure_deletes_the_undisclosed_authorization_code() {
    futures_executor::block_on(grant_failure_deletes_the_undisclosed_authorization_code_async());
}

async fn grant_failure_deletes_the_undisclosed_authorization_code_async() {
    let tenant_id = Uuid::from_u128(1);
    let repository = FakeRepository::default();
    *repository.0.client.lock().unwrap() = Some(client(tenant_id));
    *repository.0.grant_error.lock().unwrap() = Some(AuthorizationPortError::Unavailable);
    let store = FakeStore::default();
    let service = service(repository, store.clone());
    let consent = consent(Uuid::from_u128(10), None);

    assert_eq!(
        service
            .approve_consent(AuthorizationApprovalInput {
                consent: &consent,
                code_hash: "hash",
                code_id: "code-id",
                issued_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
                code_ttl_seconds: 60,
                tenant_id,
            })
            .await,
        Err(AuthorizationApprovalError::Commit(
            AuthorizationApprovalCommitError::GrantWrite {
                source: AuthorizationPortError::Unavailable,
                cleanup: None,
            }
        ))
    );
    assert!(store.0.stored_code.lock().unwrap().is_none());
    assert_eq!(store.0.code_deletes.load(Ordering::Relaxed), 1);
}

#[test]
fn compensation_failure_is_not_silently_discarded() {
    futures_executor::block_on(compensation_failure_is_not_silently_discarded_async());
}

async fn compensation_failure_is_not_silently_discarded_async() {
    let tenant_id = Uuid::from_u128(1);
    let repository = FakeRepository::default();
    *repository.0.client.lock().unwrap() = Some(client(tenant_id));
    *repository.0.grant_error.lock().unwrap() = Some(AuthorizationPortError::Unavailable);
    let store = FakeStore::default();
    *store.0.delete_error.lock().unwrap() = Some(AuthorizationPortError::Unavailable);
    let service = service(repository, store.clone());
    let consent = consent(Uuid::from_u128(10), None);

    assert_eq!(
        service
            .approve_consent(AuthorizationApprovalInput {
                consent: &consent,
                code_hash: "hash",
                code_id: "code-id",
                issued_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
                code_ttl_seconds: 60,
                tenant_id,
            })
            .await,
        Err(AuthorizationApprovalError::Commit(
            AuthorizationApprovalCommitError::GrantWrite {
                source: AuthorizationPortError::Unavailable,
                cleanup: Some(AuthorizationPortError::Unavailable),
            }
        ))
    );
    assert!(store.0.stored_code.lock().unwrap().is_some());
}

#[test]
fn successful_approval_preserves_nonce_and_sender_constraints() {
    futures_executor::block_on(successful_approval_preserves_nonce_and_sender_constraints_async());
}

async fn successful_approval_preserves_nonce_and_sender_constraints_async() {
    let tenant_id = Uuid::from_u128(1);
    let repository = FakeRepository::default();
    *repository.0.client.lock().unwrap() = Some(client(tenant_id));
    let store = FakeStore::default();
    let service = service(repository.clone(), store.clone());
    let consent = consent(Uuid::from_u128(10), None);
    let issued_at = Utc.timestamp_opt(1_700_000_100, 0).unwrap();

    service
        .approve_consent(AuthorizationApprovalInput {
            consent: &consent,
            code_hash: "hash",
            code_id: "code-id",
            issued_at,
            code_ttl_seconds: 60,
            tenant_id,
        })
        .await
        .unwrap();

    let stored = store.0.stored_code.lock().unwrap().clone().unwrap();
    let AuthorizationCodeState::Pending { payload } = stored else {
        panic!("approval must publish a pending authorization code")
    };
    assert_eq!(payload.code_id, "code-id");
    assert_eq!(payload.nonce.as_deref(), Some("nonce-1"));
    assert_eq!(payload.dpop_jkt.as_deref(), Some("jkt"));
    assert_eq!(payload.code_challenge.as_deref(), Some("challenge"));
    assert_eq!(payload.issued_at, issued_at);
    assert_eq!(payload.expires_at, issued_at + Duration::seconds(60));
    assert_eq!(repository.0.grant_writes.load(Ordering::Relaxed), 1);
}
