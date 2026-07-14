use std::{future::Future, pin::Pin};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;

use crate::{
    DpopProofVerifier, DpopProofVerifierError, ResourceServerVerifier, ResourceServerVerifierError,
    VerifiedAccessToken, VerifiedSenderConstraintProof,
};

/// Boxed future used only at the two infrastructure dependency boundaries.
pub type ResourceServerPortFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessTokenScheme {
    Bearer,
    Dpop,
}

#[derive(Clone, Copy, Debug)]
pub struct ProtectedResourceAuthorizationRequest<'a> {
    pub access_token: &'a str,
    pub scheme: AccessTokenScheme,
    pub dpop_proof: Option<&'a str>,
}

/// Transport-verified request information. Certificate thumbprints must only
/// be populated after the deployment's trusted-proxy or TLS boundary has
/// authenticated the certificate source.
#[derive(Clone, Copy, Debug)]
pub struct ProtectedResourceAuthorizationContext<'a> {
    pub method: &'a str,
    /// Accepted request targets after the transport has constructed their
    /// externally visible scheme, authority, and path. A DPoP proof is
    /// verified once and may match any one target; callers must never retry
    /// authorization because replay consumption is stateful.
    pub target_uris: &'a [&'a str],
    pub mtls_x5t_s256: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedResourceAuthorizationResult {
    pub token: VerifiedAccessToken,
    pub sender_constraint: VerifiedSenderConstraintProof,
}

#[derive(Clone, Copy, Debug)]
pub struct RevocationLookupKey<'a> {
    pub tenant_id: &'a str,
    pub jti: &'a str,
}

/// External token-state lookup. The resource-server core remains independent
/// from the database representation and transaction implementation.
pub trait AccessTokenRevocationLookup: Send + Sync {
    fn is_revoked<'a>(
        &'a self,
        key: RevocationLookupKey<'a>,
    ) -> ResourceServerPortFuture<'a, Result<bool, ProtectedResourceDependencyError>>;
}

#[derive(Clone, Copy, Debug)]
pub struct DpopReplayKey<'a> {
    pub jkt: &'a str,
    pub jti: &'a str,
    pub expires_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpopReplayConsumptionResult {
    Accepted,
    Replay,
}

/// Atomic DPoP replay-marker consumption. Implementations must perform one
/// atomic insert-if-absent operation that expires no earlier than `expires_at`.
pub trait DpopReplayConsumption: Send + Sync {
    fn consume<'a>(
        &'a self,
        key: DpopReplayKey<'a>,
    ) -> ResourceServerPortFuture<
        'a,
        Result<DpopReplayConsumptionResult, ProtectedResourceDependencyError>,
    >;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpopNoncePolicy {
    Optional,
    Required,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpopNonceConsumptionResult {
    Accepted,
    Unknown,
}

/// Atomic one-time nonce state used by protected-resource DPoP validation.
/// Implementations must publish a nonce until at least `expires_at` and must
/// consume it with one atomic take operation.
pub trait DpopNonceStorage: Send + Sync {
    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a str,
        expires_at: i64,
    ) -> ResourceServerPortFuture<'a, Result<(), ProtectedResourceDependencyError>>;

    fn consume_nonce<'a>(
        &'a self,
        nonce: &'a str,
    ) -> ResourceServerPortFuture<
        'a,
        Result<DpopNonceConsumptionResult, ProtectedResourceDependencyError>,
    >;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectedResourceDependencyError {
    InvalidTenantBoundary,
    RevocationLookupUnavailable,
    DpopReplayStoreUnavailable,
    DpopNonceStoreUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtectedResourceAuthorizationError {
    InvalidToken(ResourceServerVerifierError),
    InvalidTenantBoundary,
    Revoked,
    MissingSenderConstraint,
    TokenNotDpopBound,
    InvalidDpopProof(DpopProofVerifierError),
    DpopBindingMismatch,
    MtlsBindingMismatch,
    ReplayDetected,
    UseDpopNonce(String),
    DependencyUnavailable(ProtectedResourceDependencyError),
}

/// Framework-independent protected-resource authorization chain.
///
/// Cryptographic token and proof validation stays local. Only revocation and
/// atomic replay consumption cross infrastructure boundaries.
pub struct ProtectedResourceAuthorizationService<R, P> {
    verifier: ResourceServerVerifier,
    dpop_verifier: DpopProofVerifier,
    revocations: R,
    replay: P,
    dpop_nonce_policy: DpopNoncePolicy,
}

impl<R, P> ProtectedResourceAuthorizationService<R, P>
where
    R: AccessTokenRevocationLookup,
    P: DpopReplayConsumption + DpopNonceStorage,
{
    pub fn new(
        verifier: ResourceServerVerifier,
        dpop_verifier: DpopProofVerifier,
        revocations: R,
        replay: P,
    ) -> Self {
        Self {
            verifier,
            dpop_verifier,
            revocations,
            replay,
            dpop_nonce_policy: DpopNoncePolicy::Optional,
        }
    }

    #[must_use]
    pub fn with_dpop_nonce_policy(mut self, policy: DpopNoncePolicy) -> Self {
        self.dpop_nonce_policy = policy;
        self
    }

    pub async fn authorize(
        &self,
        request: ProtectedResourceAuthorizationRequest<'_>,
        context: ProtectedResourceAuthorizationContext<'_>,
    ) -> Result<ProtectedResourceAuthorizationResult, ProtectedResourceAuthorizationError> {
        self.authorize_at(request, context, Utc::now().timestamp())
            .await
    }

    /// Identical to [`Self::authorize`], with an explicit clock value for
    /// deterministic policy tests and controlled embedding environments.
    pub async fn authorize_at(
        &self,
        request: ProtectedResourceAuthorizationRequest<'_>,
        context: ProtectedResourceAuthorizationContext<'_>,
        now: i64,
    ) -> Result<ProtectedResourceAuthorizationResult, ProtectedResourceAuthorizationError> {
        let token = self
            .verifier
            .verify_at(request.access_token, now)
            .map_err(ProtectedResourceAuthorizationError::InvalidToken)?;
        let tenant_id = token
            .tenant_id
            .as_deref()
            .filter(|tenant_id| !tenant_id.trim().is_empty())
            .ok_or(ProtectedResourceAuthorizationError::InvalidTenantBoundary)?;

        let sender_constraint = match request.scheme {
            AccessTokenScheme::Bearer => verify_bearer_constraint(&token, context)?,
            AccessTokenScheme::Dpop => {
                let expected_jkt = token
                    .cnf
                    .as_ref()
                    .and_then(|claims| claims.jkt.as_deref())
                    .ok_or(ProtectedResourceAuthorizationError::TokenNotDpopBound)?;
                let proof_jwt = request
                    .dpop_proof
                    .filter(|proof| !proof.trim().is_empty())
                    .ok_or(ProtectedResourceAuthorizationError::MissingSenderConstraint)?;
                let verification = self
                    .dpop_verifier
                    .verify_without_replay_for_targets_at(
                        proof_jwt,
                        context.method,
                        context.target_uris,
                        request.access_token,
                        now,
                    )
                    .map_err(ProtectedResourceAuthorizationError::InvalidDpopProof)?;
                let actual_jkt = verification
                    .proof
                    .dpop_jkt
                    .as_deref()
                    .ok_or(ProtectedResourceAuthorizationError::MissingSenderConstraint)?;
                if !constant_time_eq(expected_jkt.as_bytes(), actual_jkt.as_bytes()) {
                    return Err(ProtectedResourceAuthorizationError::DpopBindingMismatch);
                }
                let proof = match self
                    .replay
                    .consume(DpopReplayKey {
                        jkt: actual_jkt,
                        jti: &verification.jti,
                        expires_at: verification.expires_at,
                    })
                    .await
                    .map_err(ProtectedResourceAuthorizationError::DependencyUnavailable)?
                {
                    DpopReplayConsumptionResult::Accepted => verification.proof,
                    DpopReplayConsumptionResult::Replay => {
                        return Err(ProtectedResourceAuthorizationError::ReplayDetected);
                    }
                };
                self.validate_dpop_nonce(verification.nonce.as_deref(), now)
                    .await?;
                proof
            }
        };

        let revoked = self
            .revocations
            .is_revoked(RevocationLookupKey {
                tenant_id,
                jti: &token.jti,
            })
            .await
            .map_err(|error| match error {
                ProtectedResourceDependencyError::InvalidTenantBoundary => {
                    ProtectedResourceAuthorizationError::InvalidTenantBoundary
                }
                error => ProtectedResourceAuthorizationError::DependencyUnavailable(error),
            })?;
        if revoked {
            return Err(ProtectedResourceAuthorizationError::Revoked);
        }

        Ok(ProtectedResourceAuthorizationResult {
            token,
            sender_constraint,
        })
    }

    async fn validate_dpop_nonce(
        &self,
        nonce: Option<&str>,
        now: i64,
    ) -> Result<(), ProtectedResourceAuthorizationError> {
        let Some(nonce) = nonce else {
            return if self.dpop_nonce_policy == DpopNoncePolicy::Required {
                Err(ProtectedResourceAuthorizationError::UseDpopNonce(
                    self.issue_dpop_nonce(now).await?,
                ))
            } else {
                Ok(())
            };
        };
        match self
            .replay
            .consume_nonce(nonce)
            .await
            .map_err(ProtectedResourceAuthorizationError::DependencyUnavailable)?
        {
            DpopNonceConsumptionResult::Accepted => Ok(()),
            DpopNonceConsumptionResult::Unknown => {
                Err(ProtectedResourceAuthorizationError::UseDpopNonce(
                    self.issue_dpop_nonce(now).await?,
                ))
            }
        }
    }

    async fn issue_dpop_nonce(
        &self,
        now: i64,
    ) -> Result<String, ProtectedResourceAuthorizationError> {
        const DPOP_NONCE_TTL_SECONDS: i64 = 300;

        let nonce = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        self.replay
            .issue_nonce(&nonce, now.saturating_add(DPOP_NONCE_TTL_SECONDS))
            .await
            .map_err(ProtectedResourceAuthorizationError::DependencyUnavailable)?;
        Ok(nonce)
    }
}

fn verify_bearer_constraint(
    token: &VerifiedAccessToken,
    context: ProtectedResourceAuthorizationContext<'_>,
) -> Result<VerifiedSenderConstraintProof, ProtectedResourceAuthorizationError> {
    let Some(confirmation) = token.cnf.as_ref() else {
        return Ok(VerifiedSenderConstraintProof::default());
    };
    if let Some(expected) = confirmation.x5t_s256.as_deref() {
        let actual = context
            .mtls_x5t_s256
            .ok_or(ProtectedResourceAuthorizationError::MissingSenderConstraint)?;
        if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
            return Err(ProtectedResourceAuthorizationError::MtlsBindingMismatch);
        }
        return Ok(VerifiedSenderConstraintProof {
            dpop_jkt: None,
            mtls_x5t_s256: Some(actual.to_owned()),
        });
    }
    Err(ProtectedResourceAuthorizationError::MissingSenderConstraint)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
#[path = "../tests/in_source/service.rs"]
mod tests;
