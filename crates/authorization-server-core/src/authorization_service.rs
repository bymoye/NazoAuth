use std::{future::Future, pin::Pin};

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    AuthorizationCodeState, AuthorizationRequestError, AuthorizationResponsePolicyError,
    ConsentPayload, JarmAuthorizationResponse, JwtBearerGrantError, NormalizedRequestObject,
    OAuthClient, PushedAuthorizationRequest, PushedAuthorizationRequestConsumeError,
    RequestObjectClaims, RequestObjectPolicy, SignedJarmAuthorizationResponse,
    ValidatedJwtBearerAssertion, authorization_details_empty, canonical_authorization_details,
    high_risk_authorization_details, normalize_request_object,
};

pub type AuthorizationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AuthorizationPortError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationPortError {
    Unavailable,
    Conflict,
    CorruptData,
    Unexpected,
}

impl std::fmt::Display for AuthorizationPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "authorization dependency unavailable",
            Self::Conflict => "authorization state conflict",
            Self::CorruptData => "authorization state contains corrupt data",
            Self::Unexpected => "unexpected authorization dependency failure",
        })
    }
}

impl std::error::Error for AuthorizationPortError {}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredAuthorizationGrant {
    pub scopes: Value,
    pub resource_indicators: Value,
    pub authorization_details: Value,
}

pub struct GrantWrite<'a> {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub scopes: &'a [String],
    pub resource_indicators: &'a [String],
    pub authorization_details: &'a Value,
}

#[derive(Clone, Debug)]
pub enum AuthorizationDecisionAdmissionError {
    ConsentMissing,
    ConsentMalformed,
    ConsentReadFailed(AuthorizationPortError),
    UserMismatch,
    PushedRequestMissing(Box<ConsentPayload>),
    PushedRequestMalformed(Box<ConsentPayload>),
    PushedRequestReadFailed {
        consent: Box<ConsentPayload>,
        source: AuthorizationPortError,
    },
}

impl std::fmt::Display for AuthorizationDecisionAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ConsentMissing => "authorization consent is missing or expired",
            Self::ConsentMalformed => "authorization consent is malformed",
            Self::ConsentReadFailed(_) => "authorization consent store is unavailable",
            Self::UserMismatch => "authorization consent belongs to another user",
            Self::PushedRequestMissing(_) => "pushed authorization request is missing or expired",
            Self::PushedRequestMalformed(_) => "pushed authorization request is malformed",
            Self::PushedRequestReadFailed { .. } => {
                "pushed authorization request store is unavailable"
            }
        })
    }
}

impl std::error::Error for AuthorizationDecisionAdmissionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationApprovalCommitError {
    CodeWrite(AuthorizationPortError),
    GrantWrite {
        source: AuthorizationPortError,
        cleanup: Option<AuthorizationPortError>,
    },
}

impl std::fmt::Display for AuthorizationApprovalCommitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CodeWrite(error) => write!(formatter, "authorization code write failed: {error}"),
            Self::GrantWrite {
                source,
                cleanup: None,
            } => write!(formatter, "authorization grant write failed: {source}"),
            Self::GrantWrite {
                source,
                cleanup: Some(cleanup),
            } => write!(
                formatter,
                "authorization grant write failed ({source}) and code cleanup failed ({cleanup})"
            ),
        }
    }
}

impl std::error::Error for AuthorizationApprovalCommitError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationApprovalError {
    ClientReadFailed(AuthorizationPortError),
    ClientUnavailable,
    Commit(AuthorizationApprovalCommitError),
}

impl std::fmt::Display for AuthorizationApprovalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientReadFailed(error) => {
                write!(formatter, "authorization client lookup failed: {error}")
            }
            Self::ClientUnavailable => {
                formatter.write_str("authorization client is missing, inactive, or cross-tenant")
            }
            Self::Commit(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AuthorizationApprovalError {}

pub struct AuthorizationApprovalInput<'a> {
    pub consent: &'a ConsentPayload,
    pub code_hash: &'a str,
    pub code_id: &'a str,
    pub issued_at: DateTime<Utc>,
    pub code_ttl_seconds: u64,
    pub tenant_id: Uuid,
}

pub fn pushed_authorization_request_digest(
    request: &PushedAuthorizationRequest,
) -> Result<String, AuthorizationPortError> {
    #[derive(serde::Serialize)]
    struct CanonicalPushedAuthorizationRequest<'a> {
        client_id: &'a str,
        params: std::collections::BTreeMap<&'a str, &'a str>,
        dpop_jkt: Option<&'a str>,
        mtls_x5t_s256: Option<&'a str>,
        issued_at: &'a DateTime<Utc>,
        expires_at: &'a DateTime<Utc>,
    }

    let canonical = CanonicalPushedAuthorizationRequest {
        client_id: &request.client_id,
        params: request
            .params
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect(),
        dpop_jkt: request.dpop_jkt.as_deref(),
        mtls_x5t_s256: request.mtls_x5t_s256.as_deref(),
        issued_at: &request.issued_at,
        expires_at: &request.expires_at,
    };
    serde_json::to_vec(&canonical)
        .map(|encoded| blake3::hash(&encoded).to_hex().to_string())
        .map_err(|_| AuthorizationPortError::Unexpected)
}

#[derive(Clone, Copy)]
pub struct AuthorizationResponseSignInput<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub code: Option<&'a str>,
    pub error: Option<&'a str>,
    pub state: Option<&'a str>,
    pub ttl: i64,
    pub signing_algorithm: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationRateDimension {
    Token,
    TokenManagement,
}

pub trait AuthorizationRepositoryPort: Send + Sync {
    fn client_by_id<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>>;
    fn active_mtls_candidates(&self, limit: usize) -> AuthorizationFuture<'_, Vec<OAuthClient>>;
    fn grant<'a>(
        &'a self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<StoredAuthorizationGrant>>;
    fn upsert_grant<'a>(&'a self, write: GrantWrite<'a>) -> AuthorizationFuture<'a, ()>;
    fn client_secret_salt<'a>(&'a self, client_id: Uuid)
    -> AuthorizationFuture<'a, Option<String>>;
    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> AuthorizationFuture<'a, bool>;
}

pub trait AuthorizationStateStorePort: Send + Sync {
    fn load_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>>;
    fn take_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>>;
    fn compare_and_delete_par<'a>(
        &'a self,
        request_uri: &'a str,
        expected: &'a PushedAuthorizationRequest,
    ) -> AuthorizationFuture<'a, bool>;
    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()>;
    fn load_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>>;
    fn take_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>>;
    fn compare_and_delete_consent<'a>(
        &'a self,
        request_id: &'a str,
        expected: &'a ConsentPayload,
    ) -> AuthorizationFuture<'a, bool>;
    fn store_consent<'a>(
        &'a self,
        request_id: &'a str,
        payload: &'a ConsentPayload,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()>;
    fn store_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()>;
    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> AuthorizationFuture<'a, ()>;
    fn take_reauth_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>>;
    fn store_reauth_nonce<'a>(
        &'a self,
        nonce: &'a str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()>;
    fn consume_jar<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool>;
    fn consume_private_key_jwt<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool>;
    fn consume_jwt_bearer<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool>;
    fn consume_ciba_request_object<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool>;
    fn consume_dpop<'a>(
        &'a self,
        thumbprint: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool>;
    fn issue_dpop_nonce<'a>(
        &'a self,
        nonce: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()>;
    fn validate_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool>;
    fn increment_rate<'a>(
        &'a self,
        dimension: AuthorizationRateDimension,
        subject: &'a str,
        window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64>;
}

pub trait AuthorizationResponseSignerPort: Send + Sync {
    fn sign_authorization_response<'a>(
        &'a self,
        input: AuthorizationResponseSignInput<'a>,
    ) -> AuthorizationFuture<'a, String>;
}

pub struct AuthorizationService<R, S, K> {
    repository: R,
    state: S,
    signer: K,
}

impl<R, S, K> AuthorizationService<R, S, K>
where
    R: AuthorizationRepositoryPort,
    S: AuthorizationStateStorePort,
    K: AuthorizationResponseSignerPort,
{
    pub const fn new(repository: R, state: S, signer: K) -> Self {
        Self {
            repository,
            state,
            signer,
        }
    }

    pub async fn client_by_id(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthClient>, AuthorizationPortError> {
        self.repository.client_by_id(client_id).await
    }

    pub async fn active_mtls_candidates(
        &self,
        limit: usize,
    ) -> Result<Vec<OAuthClient>, AuthorizationPortError> {
        self.repository.active_mtls_candidates(limit).await
    }

    pub async fn client_secret_salt(
        &self,
        client_id: Uuid,
    ) -> Result<Option<String>, AuthorizationPortError> {
        self.repository.client_secret_salt(client_id).await
    }

    pub async fn client_secret_digest_matches(
        &self,
        client_id: Uuid,
        candidate: &str,
    ) -> Result<bool, AuthorizationPortError> {
        self.repository
            .client_secret_digest_matches(client_id, candidate)
            .await
    }

    pub async fn grant_covers(
        &self,
        user_id: Uuid,
        client_id: Uuid,
        scopes: &[String],
        resources: &[String],
        details: &Value,
    ) -> Result<bool, AuthorizationPortError> {
        Ok(self
            .repository
            .grant(user_id, client_id)
            .await?
            .as_ref()
            .is_some_and(|stored| {
                stored_grant_covers_requested_authorization(stored, scopes, resources, details)
            }))
    }

    pub async fn approve(
        &self,
        code_hash: &str,
        code_state: &AuthorizationCodeState,
        code_ttl_seconds: u64,
        grant: GrantWrite<'_>,
    ) -> Result<(), AuthorizationApprovalCommitError> {
        self.state
            .store_authorization_code(code_hash, code_state, code_ttl_seconds)
            .await
            .map_err(AuthorizationApprovalCommitError::CodeWrite)?;
        if let Err(source) = self.repository.upsert_grant(grant).await {
            let cleanup = self.state.delete_authorization_code(code_hash).await.err();
            return Err(AuthorizationApprovalCommitError::GrantWrite { source, cleanup });
        }
        Ok(())
    }

    /// Atomically claims a consent transaction for the authenticated user and,
    /// when present, consumes its PAR handle before the caller can issue a code.
    ///
    /// The non-consuming read intentionally precedes the atomic take. It prevents
    /// a user who learns another user's opaque request id from invalidating that
    /// transaction. The compare-and-delete then claims only the exact observed
    /// payload, so a replacement between the read and claim remains intact.
    pub async fn admit_user_decision(
        &self,
        request_id: &str,
        user_id: Uuid,
    ) -> Result<ConsentPayload, AuthorizationDecisionAdmissionError> {
        let observed = match self.state.load_consent(request_id).await {
            Ok(Some(consent)) => consent,
            Ok(None) => return Err(AuthorizationDecisionAdmissionError::ConsentMissing),
            Err(AuthorizationPortError::CorruptData) => {
                return Err(AuthorizationDecisionAdmissionError::ConsentMalformed);
            }
            Err(error) => {
                return Err(AuthorizationDecisionAdmissionError::ConsentReadFailed(
                    error,
                ));
            }
        };
        if observed.user_id != user_id {
            return Err(AuthorizationDecisionAdmissionError::UserMismatch);
        }

        let consent = observed;
        match self
            .state
            .compare_and_delete_consent(request_id, &consent)
            .await
        {
            Ok(true) => {}
            Ok(false) => return Err(AuthorizationDecisionAdmissionError::ConsentMissing),
            Err(error) => {
                return Err(AuthorizationDecisionAdmissionError::ConsentReadFailed(
                    error,
                ));
            }
        }

        if let Some(request_uri) = consent.pushed_request_uri.as_deref() {
            let pushed = match self.state.load_par(request_uri).await {
                Ok(Some(pushed)) => pushed,
                Ok(None) => {
                    return Err(AuthorizationDecisionAdmissionError::PushedRequestMissing(
                        Box::new(consent),
                    ));
                }
                Err(AuthorizationPortError::CorruptData) => {
                    return Err(AuthorizationDecisionAdmissionError::PushedRequestMalformed(
                        Box::new(consent),
                    ));
                }
                Err(source) => {
                    return Err(
                        AuthorizationDecisionAdmissionError::PushedRequestReadFailed {
                            consent: Box::new(consent),
                            source,
                        },
                    );
                }
            };
            if let Some(expected_digest) = consent.pushed_request_digest.as_deref() {
                let actual_digest =
                    pushed_authorization_request_digest(&pushed).map_err(|source| {
                        AuthorizationDecisionAdmissionError::PushedRequestReadFailed {
                            consent: Box::new(consent.clone()),
                            source,
                        }
                    })?;
                if expected_digest != actual_digest {
                    return Err(AuthorizationDecisionAdmissionError::PushedRequestMissing(
                        Box::new(consent),
                    ));
                }
            }
            match self
                .state
                .compare_and_delete_par(request_uri, &pushed)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Err(AuthorizationDecisionAdmissionError::PushedRequestMissing(
                        Box::new(consent),
                    ));
                }
                Err(source) => {
                    return Err(
                        AuthorizationDecisionAdmissionError::PushedRequestReadFailed {
                            consent: Box::new(consent),
                            source,
                        },
                    );
                }
            }
        }
        Ok(consent)
    }

    /// Commits an approved consent using the existing cross-store ordering:
    /// publish the undisclosed authorization code, write the durable grant, and
    /// delete the code if the grant write fails.
    ///
    /// The code itself is generated by the composition provider and is never
    /// passed here, so a failed commit cannot disclose an orphaned code. A
    /// cleanup failure is returned explicitly instead of being silently lost.
    pub async fn approve_consent(
        &self,
        input: AuthorizationApprovalInput<'_>,
    ) -> Result<(), AuthorizationApprovalError> {
        let client = self
            .repository
            .client_by_id(&input.consent.client_id)
            .await
            .map_err(AuthorizationApprovalError::ClientReadFailed)?
            .filter(|client| client.is_active && client.tenant_id == input.tenant_id)
            .ok_or(AuthorizationApprovalError::ClientUnavailable)?;
        let consent = input.consent;
        let code_payload = crate::CodePayload {
            code_id: input.code_id.to_owned(),
            user_id: consent.user_id,
            client_id: consent.client_id.clone(),
            redirect_uri: consent.redirect_uri.clone(),
            redirect_uri_was_supplied: consent.redirect_uri_was_supplied,
            scopes: consent.scopes.clone(),
            resource_indicators: consent.resource_indicators.clone(),
            authorization_details: consent.authorization_details.clone(),
            nonce: consent.nonce.clone(),
            auth_time: consent.auth_time,
            amr: consent.amr.clone(),
            oidc_sid: consent.oidc_sid.clone(),
            acr: consent.acr.clone(),
            userinfo_claims: consent.userinfo_claims.clone(),
            userinfo_claim_requests: consent.userinfo_claim_requests.clone(),
            id_token_claims: consent.id_token_claims.clone(),
            id_token_claim_requests: consent.id_token_claim_requests.clone(),
            code_challenge: consent.code_challenge.clone(),
            code_challenge_method: consent.code_challenge_method.clone(),
            dpop_jkt: consent.dpop_jkt.clone(),
            mtls_x5t_s256: consent.mtls_x5t_s256.clone(),
            issued_at: input.issued_at,
            expires_at: input.issued_at
                + Duration::seconds(input.code_ttl_seconds.try_into().unwrap_or(i64::MAX)),
        };
        self.approve(
            input.code_hash,
            &AuthorizationCodeState::Pending {
                payload: code_payload,
            },
            input.code_ttl_seconds,
            GrantWrite {
                tenant_id: client.tenant_id,
                user_id: consent.user_id,
                client_id: client.id,
                scopes: &consent.scopes,
                resource_indicators: &consent.resource_indicators,
                authorization_details: &consent.authorization_details,
            },
        )
        .await
        .map_err(AuthorizationApprovalError::Commit)
    }

    pub async fn store_authorization_code(
        &self,
        hash: &str,
        state: &AuthorizationCodeState,
        ttl: u64,
    ) -> Result<(), AuthorizationPortError> {
        self.state.store_authorization_code(hash, state, ttl).await
    }

    pub async fn load_par(
        &self,
        uri: &str,
    ) -> Result<Option<PushedAuthorizationRequest>, AuthorizationPortError> {
        self.state.load_par(uri).await
    }
    pub async fn take_par(
        &self,
        uri: &str,
    ) -> Result<Option<PushedAuthorizationRequest>, AuthorizationPortError> {
        self.state.take_par(uri).await
    }
    pub async fn store_par(
        &self,
        uri: &str,
        payload: &PushedAuthorizationRequest,
        ttl: u64,
    ) -> Result<(), AuthorizationPortError> {
        self.state.store_par(uri, payload, ttl).await
    }
    pub async fn load_consent(
        &self,
        id: &str,
    ) -> Result<Option<ConsentPayload>, AuthorizationPortError> {
        self.state.load_consent(id).await
    }
    pub async fn take_consent(
        &self,
        id: &str,
    ) -> Result<Option<ConsentPayload>, AuthorizationPortError> {
        self.state.take_consent(id).await
    }
    pub async fn store_consent(
        &self,
        id: &str,
        payload: &ConsentPayload,
        ttl: u64,
    ) -> Result<(), AuthorizationPortError> {
        self.state.store_consent(id, payload, ttl).await
    }
    pub async fn take_reauth_nonce(
        &self,
        nonce: &str,
    ) -> Result<Option<i64>, AuthorizationPortError> {
        self.state.take_reauth_nonce(nonce).await
    }
    pub async fn store_reauth_nonce(
        &self,
        nonce: &str,
        started_at: i64,
        ttl: u64,
    ) -> Result<(), AuthorizationPortError> {
        self.state.store_reauth_nonce(nonce, started_at, ttl).await
    }
    pub async fn consume_jar(
        &self,
        client_id: &str,
        jti: &str,
        ttl: u64,
    ) -> Result<bool, AuthorizationPortError> {
        self.state.consume_jar(client_id, jti, ttl).await
    }

    /// Validates a verified request object and commits its replay marker only
    /// after all pure claim and outer-parameter policy has succeeded.
    pub async fn admit_request_object(
        &self,
        outer: &std::collections::HashMap<String, String>,
        claims: &RequestObjectClaims,
        policy: RequestObjectPolicy<'_>,
    ) -> Result<NormalizedRequestObject, AuthorizationRequestError> {
        let normalized = normalize_request_object(outer, claims, policy)?;
        if let Some(replay) = normalized.replay.as_ref() {
            super::authorization_request::classify_request_object_replay(
                self.state
                    .consume_jar(&replay.client_id, &replay.jti, replay.ttl_seconds)
                    .await,
            )?;
        }
        Ok(normalized)
    }

    /// Atomically consumes a PAR transaction and preserves malformed-state and
    /// dependency-failure categories for the transport presenter.
    pub async fn consume_pushed_authorization_request(
        &self,
        request_uri: &str,
    ) -> Result<PushedAuthorizationRequest, PushedAuthorizationRequestConsumeError> {
        match self.state.take_par(request_uri).await {
            Ok(Some(request)) => Ok(request),
            Ok(None) => Err(PushedAuthorizationRequestConsumeError::Missing),
            Err(AuthorizationPortError::CorruptData) => {
                Err(PushedAuthorizationRequestConsumeError::Malformed)
            }
            Err(error) => Err(PushedAuthorizationRequestConsumeError::Dependency(error)),
        }
    }
    pub async fn consume_private_key_jwt(
        &self,
        client_id: &str,
        jti: &str,
        ttl: u64,
    ) -> Result<bool, AuthorizationPortError> {
        self.state
            .consume_private_key_jwt(client_id, jti, ttl)
            .await
    }

    pub async fn consume_jwt_bearer(
        &self,
        client_id: &str,
        jti: &str,
        ttl: u64,
    ) -> Result<bool, AuthorizationPortError> {
        self.state.consume_jwt_bearer(client_id, jti, ttl).await
    }

    pub async fn consume_ciba_request_object(
        &self,
        client_id: &str,
        jti: &str,
        ttl: u64,
    ) -> Result<bool, AuthorizationPortError> {
        self.state
            .consume_ciba_request_object(client_id, jti, ttl)
            .await
    }

    pub async fn consume_jwt_bearer_assertion(
        &self,
        client_id: &str,
        assertion: &ValidatedJwtBearerAssertion,
    ) -> Result<(), JwtBearerGrantError> {
        super::extension_grants::classify_jwt_bearer_replay(
            self.state
                .consume_jwt_bearer(client_id, &assertion.jti, assertion.replay_ttl_seconds)
                .await,
        )
    }
    pub async fn consume_dpop(
        &self,
        thumbprint: &str,
        jti: &str,
        ttl: u64,
    ) -> Result<bool, AuthorizationPortError> {
        self.state.consume_dpop(thumbprint, jti, ttl).await
    }
    pub async fn issue_dpop_nonce(
        &self,
        nonce: &str,
        ttl: u64,
    ) -> Result<(), AuthorizationPortError> {
        self.state.issue_dpop_nonce(nonce, ttl).await
    }
    pub async fn validate_dpop_nonce(&self, nonce: &str) -> Result<bool, AuthorizationPortError> {
        self.state.validate_dpop_nonce(nonce).await
    }
    pub async fn increment_rate(
        &self,
        subject: &str,
        window: u64,
    ) -> Result<u64, AuthorizationPortError> {
        self.state
            .increment_rate(AuthorizationRateDimension::TokenManagement, subject, window)
            .await
    }

    pub async fn increment_token_rate(
        &self,
        subject: &str,
        window: u64,
    ) -> Result<u64, AuthorizationPortError> {
        self.state
            .increment_rate(AuthorizationRateDimension::Token, subject, window)
            .await
    }
    pub async fn sign_authorization_response(
        &self,
        input: AuthorizationResponseSignInput<'_>,
    ) -> Result<String, AuthorizationPortError> {
        self.signer.sign_authorization_response(input).await
    }

    pub async fn sign_jarm_authorization_response(
        &self,
        response: &JarmAuthorizationResponse,
        signing_algorithm: Option<&str>,
    ) -> Result<SignedJarmAuthorizationResponse, AuthorizationResponsePolicyError> {
        let signed = self
            .signer
            .sign_authorization_response(response.signing_input(signing_algorithm))
            .await
            .map_err(AuthorizationResponsePolicyError::Dependency)?;
        Ok(SignedJarmAuthorizationResponse {
            redirect_uri: response.redirect_uri.clone(),
            response: signed,
        })
    }
}

#[must_use]
pub fn stored_grant_covers_requested_authorization(
    stored: &StoredAuthorizationGrant,
    scopes: &[String],
    resources: &[String],
    details: &Value,
) -> bool {
    fn strings(value: &Value) -> std::collections::HashSet<&str> {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect()
    }
    let stored_scopes = strings(&stored.scopes);
    let stored_resources = strings(&stored.resource_indicators);
    if !scopes
        .iter()
        .all(|value| stored_scopes.contains(value.as_str()))
        || !resources
            .iter()
            .all(|value| stored_resources.contains(value.as_str()))
    {
        return false;
    }
    authorization_details_empty(details)
        || (!high_risk_authorization_details(details)
            && canonical_authorization_details(&stored.authorization_details).ok()
                == canonical_authorization_details(details).ok())
}

#[cfg(test)]
#[path = "../tests/unit/authorization_service.rs"]
mod tests;
