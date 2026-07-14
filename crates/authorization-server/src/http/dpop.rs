use actix_web::HttpRequest;
use nazo_auth::{
    DpopNoncePolicy, DpopProofRequest, DpopStateStorePort, issue_authorization_server_dpop_nonce,
    validate_authorization_server_dpop,
};
use serde_json::json;

pub(crate) use nazo_auth::DpopError;
pub(crate) use nazo_http_actix::{DpopErrorContext, dpop_error_response};

use crate::adapters::audit::{audit_event, audit_fields};

pub(crate) fn dpop_proof_present(request: &HttpRequest) -> bool {
    nazo_http_actix::dpop_proof_present(request.headers())
}

pub(crate) async fn validate_dpop_proof_with_store<S>(
    store: &S,
    issuer: &str,
    mtls_endpoint_base_url: &str,
    nonce_policy: DpopNoncePolicy,
    request: &HttpRequest,
    token_for_ath: Option<&str>,
    expected_jkt: Option<&str>,
) -> Result<Option<String>, DpopError>
where
    S: DpopStateStorePort + ?Sized,
{
    validate_dpop_proof(
        store,
        issuer,
        mtls_endpoint_base_url,
        nonce_policy,
        request,
        token_for_ath,
        expected_jkt,
    )
    .await
}

pub(crate) async fn validate_dpop_proof_with_authorization_service<S>(
    service: &S,
    issuer: &str,
    mtls_endpoint_base_url: &str,
    nonce_policy: DpopNoncePolicy,
    request: &HttpRequest,
    token_for_ath: Option<&str>,
    expected_jkt: Option<&str>,
) -> Result<Option<String>, DpopError>
where
    S: DpopStateStorePort + ?Sized,
{
    validate_dpop_proof(
        service,
        issuer,
        mtls_endpoint_base_url,
        nonce_policy,
        request,
        token_for_ath,
        expected_jkt,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn validate_dpop_proof<S>(
    store: &S,
    issuer: &str,
    mtls_endpoint_base_url: &str,
    nonce_policy: DpopNoncePolicy,
    request: &HttpRequest,
    token_for_ath: Option<&str>,
    expected_jkt: Option<&str>,
) -> Result<Option<String>, DpopError>
where
    S: DpopStateStorePort + ?Sized,
{
    let proof = nazo_http_actix::dpop_proof_header(request.headers())?;
    let target_uris =
        nazo_http_actix::dpop_target_uris(issuer, mtls_endpoint_base_url, request.uri().path());
    let target_uri_refs = [target_uris[0].as_str(), target_uris[1].as_str()];
    let result = validate_authorization_server_dpop(
        store,
        DpopProofRequest {
            proof,
            method: request.method().as_str(),
            target_uris: &target_uri_refs,
            access_token: token_for_ath,
            expected_jkt,
        },
        nonce_policy,
    )
    .await;
    if let Err(DpopError::ReplayDetected(event)) = &result {
        audit_event(
            "dpop_replay_detected",
            audit_fields(&[
                ("jti_hash", json!(event.jti_hash)),
                ("kid", json!(event.key_id)),
            ]),
        );
    }
    result
}

pub(crate) async fn issue_dpop_nonce_with_store<S>(store: &S) -> Result<String, DpopError>
where
    S: DpopStateStorePort + ?Sized,
{
    issue_authorization_server_dpop_nonce(store).await
}

pub(crate) async fn issue_dpop_nonce_with_authorization_service<S>(
    service: &S,
) -> Result<String, DpopError>
where
    S: DpopStateStorePort + ?Sized,
{
    issue_authorization_server_dpop_nonce(service).await
}
