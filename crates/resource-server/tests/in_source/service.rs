use std::{
    collections::HashSet,
    future::Future,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use serde_json::json;

use super::*;
use crate::DpopProofVerifierConfig;
use crate::tests::fixtures::{dpop_fixture, dpop_proof, fixture, token};

fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[derive(Clone)]
struct TestRevocations {
    result: Arc<Mutex<Result<bool, ProtectedResourceDependencyError>>>,
}

impl TestRevocations {
    fn returning(result: Result<bool, ProtectedResourceDependencyError>) -> Self {
        Self {
            result: Arc::new(Mutex::new(result)),
        }
    }
}

impl AccessTokenRevocationLookup for TestRevocations {
    fn is_revoked<'a>(
        &'a self,
        _key: RevocationLookupKey<'a>,
    ) -> ResourceServerPortFuture<'a, Result<bool, ProtectedResourceDependencyError>> {
        let result = *self.result.lock().expect("revocation result lock");
        Box::pin(async move { result })
    }
}

#[derive(Clone, Default)]
struct AtomicReplayStore {
    keys: Arc<Mutex<HashSet<String>>>,
    nonces: Arc<Mutex<HashSet<String>>>,
    replay_failure: bool,
    nonce_failure: bool,
}

impl AtomicReplayStore {
    fn replay_unavailable() -> Self {
        Self {
            keys: Arc::default(),
            nonces: Arc::default(),
            replay_failure: true,
            nonce_failure: false,
        }
    }

    fn nonce_unavailable() -> Self {
        Self {
            keys: Arc::default(),
            nonces: Arc::default(),
            replay_failure: false,
            nonce_failure: true,
        }
    }
}

impl DpopReplayConsumption for AtomicReplayStore {
    fn consume<'a>(
        &'a self,
        key: DpopReplayKey<'a>,
    ) -> ResourceServerPortFuture<
        'a,
        Result<DpopReplayConsumptionResult, ProtectedResourceDependencyError>,
    > {
        Box::pin(async move {
            if self.replay_failure {
                return Err(ProtectedResourceDependencyError::DpopReplayStoreUnavailable);
            }
            let key = format!("{}:{}", key.jkt, key.jti);
            let mut keys = self.keys.lock().expect("replay store lock");
            Ok(if keys.insert(key) {
                DpopReplayConsumptionResult::Accepted
            } else {
                DpopReplayConsumptionResult::Replay
            })
        })
    }
}

impl DpopNonceStorage for AtomicReplayStore {
    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a str,
        _expires_at: i64,
    ) -> ResourceServerPortFuture<'a, Result<(), ProtectedResourceDependencyError>> {
        Box::pin(async move {
            if self.nonce_failure {
                return Err(ProtectedResourceDependencyError::DpopNonceStoreUnavailable);
            }
            self.nonces
                .lock()
                .expect("nonce store lock")
                .insert(nonce.to_owned());
            Ok(())
        })
    }

    fn consume_nonce<'a>(
        &'a self,
        nonce: &'a str,
    ) -> ResourceServerPortFuture<
        'a,
        Result<DpopNonceConsumptionResult, ProtectedResourceDependencyError>,
    > {
        Box::pin(async move {
            if self.nonce_failure {
                return Err(ProtectedResourceDependencyError::DpopNonceStoreUnavailable);
            }
            Ok(
                if self.nonces.lock().expect("nonce store lock").remove(nonce) {
                    DpopNonceConsumptionResult::Accepted
                } else {
                    DpopNonceConsumptionResult::Unknown
                },
            )
        })
    }
}

fn context<'a>(mtls_x5t_s256: Option<&'a str>) -> ProtectedResourceAuthorizationContext<'a> {
    const TARGET_URIS: &[&str] = &["https://api.example/orders"];
    ProtectedResourceAuthorizationContext {
        method: "GET",
        target_uris: TARGET_URIS,
        mtls_x5t_s256,
    }
}

fn request<'a>(
    access_token: &'a str,
    scheme: AccessTokenScheme,
    dpop_proof: Option<&'a str>,
) -> ProtectedResourceAuthorizationRequest<'a> {
    ProtectedResourceAuthorizationRequest {
        access_token,
        scheme,
        dpop_proof,
    }
}

#[test]
fn bearer_authorization_returns_typed_verified_result() {
    block_on(bearer_authorization_returns_typed_verified_result_async());
}

async fn bearer_authorization_returns_typed_verified_result_async() {
    let fixture = fixture();
    let access_token = token(&fixture, json!({}), None);
    let service = ProtectedResourceAuthorizationService::new(
        fixture.verifier,
        DpopProofVerifier::new(DpopProofVerifierConfig::default()),
        TestRevocations::returning(Ok(false)),
        AtomicReplayStore::default(),
    );

    let result = service
        .authorize(
            request(&access_token, AccessTokenScheme::Bearer, None),
            context(None),
        )
        .await
        .expect("valid bearer token");

    assert_eq!(result.token.subject, "subject-1");
    assert_eq!(result.token.client_id, "client-1");
    assert_eq!(
        result.token.tenant_id.as_deref(),
        Some("00000000-0000-0000-0000-000000000001")
    );
    assert_eq!(
        result.sender_constraint,
        VerifiedSenderConstraintProof::default()
    );
}

#[test]
fn token_issuer_audience_and_use_are_enforced_before_dependencies() {
    block_on(token_issuer_audience_and_use_are_enforced_before_dependencies_async());
}

async fn token_issuer_audience_and_use_are_enforced_before_dependencies_async() {
    let cases = [
        (
            json!({"iss": "https://attacker.example"}),
            ResourceServerVerifierError::IssuerMismatch,
        ),
        (
            json!({"aud": "resource://other"}),
            ResourceServerVerifierError::AudienceMismatch,
        ),
        (
            json!({"token_use": "id"}),
            ResourceServerVerifierError::WrongTokenType,
        ),
    ];

    for (overrides, expected) in cases {
        let fixture = fixture();
        let access_token = token(&fixture, overrides, None);
        let service = ProtectedResourceAuthorizationService::new(
            fixture.verifier,
            DpopProofVerifier::new(DpopProofVerifierConfig::default()),
            TestRevocations::returning(Err(
                ProtectedResourceDependencyError::RevocationLookupUnavailable,
            )),
            AtomicReplayStore::default(),
        );

        let error = service
            .authorize(
                request(&access_token, AccessTokenScheme::Bearer, None),
                context(None),
            )
            .await
            .expect_err("invalid token claims must fail locally");
        assert_eq!(
            error,
            ProtectedResourceAuthorizationError::InvalidToken(expected)
        );
    }
}

#[test]
fn revocation_and_revocation_dependency_failure_are_fail_closed() {
    block_on(revocation_and_revocation_dependency_failure_are_fail_closed_async());
}

async fn revocation_and_revocation_dependency_failure_are_fail_closed_async() {
    for (revocation_result, expected) in [
        (Ok(true), ProtectedResourceAuthorizationError::Revoked),
        (
            Err(ProtectedResourceDependencyError::RevocationLookupUnavailable),
            ProtectedResourceAuthorizationError::DependencyUnavailable(
                ProtectedResourceDependencyError::RevocationLookupUnavailable,
            ),
        ),
    ] {
        let fixture = fixture();
        let access_token = token(&fixture, json!({}), None);
        let service = ProtectedResourceAuthorizationService::new(
            fixture.verifier,
            DpopProofVerifier::new(DpopProofVerifierConfig::default()),
            TestRevocations::returning(revocation_result),
            AtomicReplayStore::default(),
        );

        let error = service
            .authorize(
                request(&access_token, AccessTokenScheme::Bearer, None),
                context(None),
            )
            .await
            .expect_err("revoked or unknown state must not authorize");
        assert_eq!(error, expected);
    }
}

#[test]
fn mtls_bound_bearer_requires_the_verified_certificate_thumbprint() {
    block_on(mtls_bound_bearer_requires_the_verified_certificate_thumbprint_async());
}

async fn mtls_bound_bearer_requires_the_verified_certificate_thumbprint_async() {
    let fixture = fixture();
    let access_token = token(
        &fixture,
        json!({"cnf": {"x5t#S256": "certificate-thumbprint"}}),
        None,
    );
    let service = ProtectedResourceAuthorizationService::new(
        fixture.verifier,
        DpopProofVerifier::new(DpopProofVerifierConfig::default()),
        TestRevocations::returning(Ok(false)),
        AtomicReplayStore::default(),
    );

    let missing = service
        .authorize(
            request(&access_token, AccessTokenScheme::Bearer, None),
            context(None),
        )
        .await
        .expect_err("missing certificate must fail");
    assert_eq!(
        missing,
        ProtectedResourceAuthorizationError::MissingSenderConstraint
    );

    let mismatch = service
        .authorize(
            request(&access_token, AccessTokenScheme::Bearer, None),
            context(Some("different-thumbprint")),
        )
        .await
        .expect_err("wrong certificate must fail");
    assert_eq!(
        mismatch,
        ProtectedResourceAuthorizationError::MtlsBindingMismatch
    );

    let authorized = service
        .authorize(
            request(&access_token, AccessTokenScheme::Bearer, None),
            context(Some("certificate-thumbprint")),
        )
        .await
        .expect("matching certificate must authorize");
    assert_eq!(
        authorized.sender_constraint.mtls_x5t_s256.as_deref(),
        Some("certificate-thumbprint")
    );
}

#[test]
fn dpop_authorization_consumes_replay_marker_atomically() {
    block_on(dpop_authorization_consumes_replay_marker_atomically_async());
}

async fn dpop_authorization_consumes_replay_marker_atomically_async() {
    let fixture = fixture();
    let dpop = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop.jkt}}), None);
    let proof = dpop_proof(
        &dpop,
        &access_token,
        "GET",
        "https://api.example/orders",
        "service-replay",
        None,
        None,
    );
    let service = ProtectedResourceAuthorizationService::new(
        fixture.verifier,
        DpopProofVerifier::new(DpopProofVerifierConfig::default()),
        TestRevocations::returning(Ok(false)),
        AtomicReplayStore::default(),
    );

    service
        .authorize(
            request(&access_token, AccessTokenScheme::Dpop, Some(&proof)),
            context(None),
        )
        .await
        .expect("first proof use must authorize");
    let replay = service
        .authorize(
            request(&access_token, AccessTokenScheme::Dpop, Some(&proof)),
            context(None),
        )
        .await
        .expect_err("second proof use must be rejected");
    assert_eq!(replay, ProtectedResourceAuthorizationError::ReplayDetected);
}

#[test]
fn dpop_accepts_any_explicit_transport_target_without_retrying_authorization() {
    block_on(dpop_accepts_any_explicit_transport_target_without_retrying_authorization_async());
}

async fn dpop_accepts_any_explicit_transport_target_without_retrying_authorization_async() {
    let fixture = fixture();
    let dpop = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop.jkt}}), None);
    let alternate_target = "https://mtls.api.example/orders";
    let proof = dpop_proof(
        &dpop,
        &access_token,
        "GET",
        alternate_target,
        "alternate-target",
        None,
        None,
    );
    let replay = AtomicReplayStore::default();
    let service = ProtectedResourceAuthorizationService::new(
        fixture.verifier,
        DpopProofVerifier::new(DpopProofVerifierConfig::default()),
        TestRevocations::returning(Ok(false)),
        replay.clone(),
    );
    let targets = ["https://api.example/orders", alternate_target];

    service
        .authorize(
            request(&access_token, AccessTokenScheme::Dpop, Some(&proof)),
            ProtectedResourceAuthorizationContext {
                method: "GET",
                target_uris: &targets,
                mtls_x5t_s256: None,
            },
        )
        .await
        .expect("the alternate externally visible target must be accepted");

    assert_eq!(replay.keys.lock().unwrap().len(), 1);
}

#[test]
fn replay_marker_is_consumed_before_required_nonce_validation() {
    block_on(replay_marker_is_consumed_before_required_nonce_validation_async());
}

async fn replay_marker_is_consumed_before_required_nonce_validation_async() {
    let fixture = fixture();
    let dpop = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop.jkt}}), None);
    let replay = AtomicReplayStore::default();
    let service = ProtectedResourceAuthorizationService::new(
        fixture.verifier,
        DpopProofVerifier::new(DpopProofVerifierConfig::default()),
        TestRevocations::returning(Ok(false)),
        replay.clone(),
    )
    .with_dpop_nonce_policy(DpopNoncePolicy::Required);
    let initial = dpop_proof(
        &dpop,
        &access_token,
        "GET",
        "https://api.example/orders",
        "nonce-before-replay",
        None,
        None,
    );

    let nonce = match service
        .authorize(
            request(&access_token, AccessTokenScheme::Dpop, Some(&initial)),
            context(None),
        )
        .await
        .expect_err("a missing required nonce must return a challenge")
    {
        ProtectedResourceAuthorizationError::UseDpopNonce(nonce) => nonce,
        error => panic!("unexpected nonce challenge error: {error:?}"),
    };
    assert_eq!(replay.keys.lock().unwrap().len(), 1);

    let replayed_with_nonce = dpop_proof(
        &dpop,
        &access_token,
        "GET",
        "https://api.example/orders",
        "nonce-before-replay",
        Some(&nonce),
        None,
    );
    let replay_error = service
        .authorize(
            request(
                &access_token,
                AccessTokenScheme::Dpop,
                Some(&replayed_with_nonce),
            ),
            context(None),
        )
        .await
        .expect_err("the same jti must be rejected even after a nonce challenge");
    assert_eq!(
        replay_error,
        ProtectedResourceAuthorizationError::ReplayDetected
    );

    let fresh_with_nonce = dpop_proof(
        &dpop,
        &access_token,
        "GET",
        "https://api.example/orders",
        "fresh-jti-after-nonce",
        Some(&nonce),
        None,
    );
    service
        .authorize(
            request(
                &access_token,
                AccessTokenScheme::Dpop,
                Some(&fresh_with_nonce),
            ),
            context(None),
        )
        .await
        .expect("a fresh jti with the issued nonce must authorize");
    assert_eq!(replay.keys.lock().unwrap().len(), 2);
}

#[test]
fn concurrent_nonce_consumers_have_exactly_one_winner() {
    let fixture = fixture();
    let dpop = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop.jkt}}), None);
    let replay = AtomicReplayStore::default();
    let service = ProtectedResourceAuthorizationService::new(
        fixture.verifier,
        DpopProofVerifier::new(DpopProofVerifierConfig::default()),
        TestRevocations::returning(Ok(false)),
        replay,
    )
    .with_dpop_nonce_policy(DpopNoncePolicy::Required);
    let challenge = dpop_proof(
        &dpop,
        &access_token,
        "GET",
        "https://api.example/orders",
        "nonce-challenge",
        None,
        None,
    );
    let nonce = match block_on(service.authorize(
        request(&access_token, AccessTokenScheme::Dpop, Some(&challenge)),
        context(None),
    ))
    .unwrap_err()
    {
        ProtectedResourceAuthorizationError::UseDpopNonce(nonce) => nonce,
        error => panic!("unexpected nonce challenge error: {error:?}"),
    };
    let proofs = [
        dpop_proof(
            &dpop,
            &access_token,
            "GET",
            "https://api.example/orders",
            "nonce-race-left",
            Some(&nonce),
            None,
        ),
        dpop_proof(
            &dpop,
            &access_token,
            "GET",
            "https://api.example/orders",
            "nonce-race-right",
            Some(&nonce),
            None,
        ),
    ];

    let (left, right) = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            block_on(service.authorize(
                request(&access_token, AccessTokenScheme::Dpop, Some(&proofs[0])),
                context(None),
            ))
        });
        let right = scope.spawn(|| {
            block_on(service.authorize(
                request(&access_token, AccessTokenScheme::Dpop, Some(&proofs[1])),
                context(None),
            ))
        });
        (left.join().unwrap(), right.join().unwrap())
    });
    let results = [left, right];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(ProtectedResourceAuthorizationError::UseDpopNonce(_))
            ))
            .count(),
        1
    );
}

#[test]
fn nonce_store_failure_is_fail_closed() {
    block_on(nonce_store_failure_is_fail_closed_async());
}

async fn nonce_store_failure_is_fail_closed_async() {
    let fixture = fixture();
    let dpop = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop.jkt}}), None);
    let proof = dpop_proof(
        &dpop,
        &access_token,
        "GET",
        "https://api.example/orders",
        "nonce-store-unavailable",
        None,
        None,
    );
    let service = ProtectedResourceAuthorizationService::new(
        fixture.verifier,
        DpopProofVerifier::new(DpopProofVerifierConfig::default()),
        TestRevocations::returning(Ok(false)),
        AtomicReplayStore::nonce_unavailable(),
    )
    .with_dpop_nonce_policy(DpopNoncePolicy::Required);

    assert_eq!(
        service
            .authorize(
                request(&access_token, AccessTokenScheme::Dpop, Some(&proof)),
                context(None),
            )
            .await
            .unwrap_err(),
        ProtectedResourceAuthorizationError::DependencyUnavailable(
            ProtectedResourceDependencyError::DpopNonceStoreUnavailable
        )
    );
}

#[test]
fn concurrent_dpop_replay_has_exactly_one_winner() {
    let fixture = fixture();
    let dpop = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop.jkt}}), None);
    let proof = dpop_proof(
        &dpop,
        &access_token,
        "GET",
        "https://api.example/orders",
        "concurrent-service-replay",
        None,
        None,
    );
    let service = ProtectedResourceAuthorizationService::new(
        fixture.verifier,
        DpopProofVerifier::new(DpopProofVerifierConfig::default()),
        TestRevocations::returning(Ok(false)),
        AtomicReplayStore::default(),
    );
    let (left, right) = std::thread::scope(|scope| {
        let authorize = || {
            block_on(service.authorize(
                request(&access_token, AccessTokenScheme::Dpop, Some(&proof)),
                context(None),
            ))
        };
        let left = scope.spawn(authorize);
        let right = scope.spawn(authorize);
        (
            left.join().expect("left authorization thread"),
            right.join().expect("right authorization thread"),
        )
    });
    let results = [left, right];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(ProtectedResourceAuthorizationError::ReplayDetected)
                )
            })
            .count(),
        1
    );
}

#[test]
fn dpop_replay_dependency_failure_is_fail_closed() {
    block_on(dpop_replay_dependency_failure_is_fail_closed_async());
}

async fn dpop_replay_dependency_failure_is_fail_closed_async() {
    let fixture = fixture();
    let dpop = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop.jkt}}), None);
    let proof = dpop_proof(
        &dpop,
        &access_token,
        "GET",
        "https://api.example/orders",
        "unavailable-replay-store",
        None,
        None,
    );
    let service = ProtectedResourceAuthorizationService::new(
        fixture.verifier,
        DpopProofVerifier::new(DpopProofVerifierConfig::default()),
        TestRevocations::returning(Ok(false)),
        AtomicReplayStore::replay_unavailable(),
    );

    let error = service
        .authorize(
            request(&access_token, AccessTokenScheme::Dpop, Some(&proof)),
            context(None),
        )
        .await
        .expect_err("unavailable replay protection must fail closed");
    assert_eq!(
        error,
        ProtectedResourceAuthorizationError::DependencyUnavailable(
            ProtectedResourceDependencyError::DpopReplayStoreUnavailable
        )
    );
}

#[test]
fn missing_tenant_boundary_is_rejected_before_revocation_lookup() {
    block_on(missing_tenant_boundary_is_rejected_before_revocation_lookup_async());
}

async fn missing_tenant_boundary_is_rejected_before_revocation_lookup_async() {
    let fixture = fixture();
    let access_token = token(&fixture, json!({"tenant_id": null}), None);
    let service = ProtectedResourceAuthorizationService::new(
        fixture.verifier,
        DpopProofVerifier::new(DpopProofVerifierConfig::default()),
        TestRevocations::returning(Err(
            ProtectedResourceDependencyError::RevocationLookupUnavailable,
        )),
        AtomicReplayStore::default(),
    );

    let error = service
        .authorize(
            request(&access_token, AccessTokenScheme::Bearer, None),
            context(None),
        )
        .await
        .expect_err("tenant-less token must fail locally");
    assert_eq!(
        error,
        ProtectedResourceAuthorizationError::InvalidTenantBoundary
    );
}
