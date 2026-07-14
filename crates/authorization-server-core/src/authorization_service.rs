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
    fn consume_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool>;
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
    pub async fn consume_dpop_nonce(&self, nonce: &str) -> Result<bool, AuthorizationPortError> {
        self.state.consume_dpop_nonce(nonce).await
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
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use chrono::{Duration, TimeZone, Utc};
    use serde_json::json;
    use uuid::Uuid;

    use crate::{
        AuthorizationCodeState, ConsentPayload, OAuthClient, PushedAuthorizationRequest,
        ValidatedClientRegistration,
    };

    use super::{
        AuthorizationApprovalCommitError, AuthorizationApprovalError, AuthorizationApprovalInput,
        AuthorizationDecisionAdmissionError, AuthorizationFuture, AuthorizationPortError,
        AuthorizationRateDimension, AuthorizationRepositoryPort, AuthorizationResponseSignInput,
        AuthorizationResponseSignerPort, AuthorizationService, AuthorizationStateStorePort,
        GrantWrite, StoredAuthorizationGrant, stored_grant_covers_requested_authorization,
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

        fn active_mtls_candidates(
            &self,
            _limit: usize,
        ) -> AuthorizationFuture<'_, Vec<OAuthClient>> {
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

        fn delete_authorization_code<'a>(
            &'a self,
            _code_hash: &'a str,
        ) -> AuthorizationFuture<'a, ()> {
            self.0.code_deletes.fetch_add(1, Ordering::Relaxed);
            let error = self.0.delete_error.lock().unwrap().take();
            if error.is_none() {
                *self.0.stored_code.lock().unwrap() = None;
            }
            Box::pin(async move { error.map_or(Ok(()), Err) })
        }

        fn take_reauth_nonce<'a>(
            &'a self,
            _nonce: &'a str,
        ) -> AuthorizationFuture<'a, Option<i64>> {
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
            Box::pin(async { Ok(true) })
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

        fn consume_dpop_nonce<'a>(&'a self, _nonce: &'a str) -> AuthorizationFuture<'a, bool> {
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
            allow_authorization_code_without_pkce: false,
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
            jwks: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
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
        *store.0.replace_consent_after_load.lock().unwrap() =
            Some(consent(replacement_owner, None));
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
        futures_executor::block_on(
            grant_failure_deletes_the_undisclosed_authorization_code_async(),
        );
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
        futures_executor::block_on(
            successful_approval_preserves_nonce_and_sender_constraints_async(),
        );
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
}
