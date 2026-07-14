use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use nazo_identity::SubjectClaims;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    AuthorizationCodeState, Claims, CodePayload, ConsumedAuthorizationCode, NewRefreshToken,
    OAuthClient, OidcClaimRequest, RefreshToken, RefreshTokenPersistResult,
};

pub type TokenFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, TokenPortError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenPortError {
    Unavailable,
    Conflict,
    CorruptData,
    InvalidSenderConstraint,
    Unexpected,
}

impl std::fmt::Display for TokenPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "token dependency unavailable",
            Self::Conflict => "token state conflict",
            Self::CorruptData => "corrupt token state",
            Self::InvalidSenderConstraint => "multiple sender constraints are not allowed",
            Self::Unexpected => "unexpected token dependency failure",
        })
    }
}

impl std::error::Error for TokenPortError {}

#[derive(Clone, Debug)]
pub enum AuthorizationCodeBeginResult {
    Consuming(CodePayload),
    Busy,
    Consumed(AuthorizationCodeState),
    Failed,
    Missing,
    Malformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationCodeTransitionResult {
    Applied,
    Missing,
    Malformed,
    Pending,
    Consuming,
    Consumed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedAccessToken {
    pub token: String,
    pub jti: String,
    pub expires_at: i64,
}

pub struct AccessTokenSignInput<'a> {
    pub issuer: &'a str,
    pub tenant_id: Uuid,
    pub subject: &'a str,
    pub user_id: Option<Uuid>,
    pub subject_type: &'a str,
    pub client_id: &'a str,
    pub audiences: &'a [String],
    pub scopes: &'a [String],
    pub authorization_details: &'a Value,
    pub userinfo_claims: &'a [String],
    pub userinfo_claim_requests: &'a [OidcClaimRequest],
    pub ttl_seconds: i64,
    pub dpop_jkt: Option<&'a str>,
    pub mtls_x5t_s256: Option<&'a str>,
    pub actor: Option<&'a Value>,
}

pub struct IdTokenSignInput<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub client_id: &'a str,
    pub nonce: Option<&'a str>,
    pub auth_time: Option<i64>,
    pub amr: &'a [String],
    pub sid: Option<&'a str>,
    pub acr: Option<&'a str>,
    pub extra_claims: Option<&'a Value>,
    pub ttl_seconds: i64,
    pub signing_algorithm: Option<&'a str>,
}

pub struct IntrospectionSignInput<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub body: &'a Value,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TokenInspection {
    Inactive,
    ActiveAccess {
        scope: String,
        client_id: String,
        token_type: &'static str,
        expires_at: i64,
        issued_at: i64,
        not_before: i64,
        subject: String,
        audience: Value,
        issuer: String,
        jti: String,
    },
    ActiveRefresh {
        scope: String,
        client_id: String,
        expires_at: i64,
        issued_at: i64,
        subject: String,
    },
}

impl TokenInspection {
    /// Build the RFC 7662 response document without coupling protocol results to an HTTP stack.
    #[must_use]
    pub fn into_document(self) -> serde_json::Value {
        match self {
            Self::Inactive => serde_json::json!({"active": false}),
            Self::ActiveAccess {
                scope,
                client_id,
                token_type,
                expires_at,
                issued_at,
                not_before,
                subject,
                audience,
                issuer,
                jti,
            } => serde_json::json!({
                "active": true,
                "scope": scope,
                "client_id": client_id,
                "token_type": token_type,
                "exp": expires_at,
                "iat": issued_at,
                "nbf": not_before,
                "sub": subject,
                "aud": audience,
                "iss": issuer,
                "jti": jti,
            }),
            Self::ActiveRefresh {
                scope,
                client_id,
                expires_at,
                issued_at,
                subject,
            } => serde_json::json!({
                "active": true,
                "scope": scope,
                "client_id": client_id,
                "exp": expires_at,
                "iat": issued_at,
                "sub": subject,
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessTokenRevocation {
    pub jti: String,
    pub expires_at: DateTime<Utc>,
}

pub struct TokenRevocation<'a> {
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub raw_token: &'a str,
    pub access_token: Option<AccessTokenRevocation>,
}

pub struct IssuedAuthorizationCodeTokens<'a> {
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub code_hash: &'a str,
    pub access_token_jti: &'a str,
    pub access_token_expires_at: i64,
    pub refresh_token_family_id: Option<Uuid>,
    pub consumed_state_ttl_seconds: u64,
}

pub trait TokenRepositoryPort: Send + Sync {
    fn client_by_id(&self, client_id: Uuid) -> TokenFuture<'_, Option<OAuthClient>>;

    fn client_by_protocol_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> TokenFuture<'a, Option<OAuthClient>>;

    fn refresh_token<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
    ) -> TokenFuture<'a, Option<RefreshToken>>;

    fn lost_response_successor_or_compromise<'a>(
        &'a self,
        token: &'a RefreshToken,
        client_id: Uuid,
        retry_started_at: DateTime<Utc>,
    ) -> TokenFuture<'a, Option<RefreshToken>>;

    fn persist_refresh_token<'a>(
        &'a self,
        token: NewRefreshToken,
    ) -> TokenFuture<'a, RefreshTokenPersistResult>;

    fn active_subject_claims(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, Option<SubjectClaims>>;

    fn revoke_issued_tokens<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &'a str,
        access_token_expires_at: Option<DateTime<Utc>>,
        refresh_token_family_id: Option<Uuid>,
    ) -> TokenFuture<'a, ()>;

    fn access_token_revoked<'a>(&'a self, tenant_id: Uuid, jti: &'a str) -> TokenFuture<'a, bool>;

    fn refresh_family_active(
        &self,
        tenant_id: Uuid,
        family_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, bool>;

    fn revoke_token<'a>(&'a self, input: TokenRevocation<'a>) -> TokenFuture<'a, usize>;
}

pub trait TokenStateStorePort: Send + Sync {
    fn load_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
    ) -> TokenFuture<'a, Option<AuthorizationCodeState>>;

    fn begin_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        consuming_at: DateTime<Utc>,
    ) -> TokenFuture<'a, AuthorizationCodeBeginResult>;

    fn mark_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        replacement: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, AuthorizationCodeTransitionResult>;

    fn store_access_token_subject<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
        user_id: Uuid,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, ()>;

    fn load_access_token_subject<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
    ) -> TokenFuture<'a, Option<Uuid>>;

    fn increment_token_management_rate<'a>(
        &'a self,
        subject: &'a str,
        window_seconds: u64,
    ) -> TokenFuture<'a, u64>;

    fn store_native_sso<'a>(
        &'a self,
        secret: &'a str,
        value: &'a Value,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, ()>;

    fn load_native_sso<'a>(&'a self, secret: &'a str) -> TokenFuture<'a, Option<Value>>;
}

pub trait TokenSignerPort: Send + Sync {
    fn sign_access_token<'a>(
        &'a self,
        input: AccessTokenSignInput<'a>,
    ) -> TokenFuture<'a, IssuedAccessToken>;

    fn sign_id_token<'a>(&'a self, input: IdTokenSignInput<'a>) -> TokenFuture<'a, String>;

    fn decode_access_token<'a>(
        &'a self,
        issuer: &'a str,
        token: &'a str,
    ) -> TokenFuture<'a, Option<Claims>>;

    fn decode_id_token<'a>(
        &'a self,
        issuer: &'a str,
        token: &'a str,
    ) -> TokenFuture<'a, Option<Value>>;

    fn sign_introspection_response<'a>(
        &'a self,
        input: IntrospectionSignInput<'a>,
    ) -> TokenFuture<'a, String>;
}

pub struct TokenService<R, S, K> {
    repository: R,
    state: S,
    signer: K,
}

impl<R, S, K> TokenService<R, S, K>
where
    R: TokenRepositoryPort,
    S: TokenStateStorePort,
    K: TokenSignerPort,
{
    pub const fn new(repository: R, state: S, signer: K) -> Self {
        Self {
            repository,
            state,
            signer,
        }
    }

    pub async fn refresh_token(
        &self,
        tenant_id: Uuid,
        raw_token: &str,
    ) -> Result<Option<RefreshToken>, TokenPortError> {
        self.repository.refresh_token(tenant_id, raw_token).await
    }

    pub async fn client_by_id(
        &self,
        client_id: Uuid,
    ) -> Result<Option<OAuthClient>, TokenPortError> {
        self.repository.client_by_id(client_id).await
    }

    pub async fn client_by_protocol_id(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> Result<Option<OAuthClient>, TokenPortError> {
        self.repository
            .client_by_protocol_id(tenant_id, client_id)
            .await
    }

    pub async fn load_access_token_subject(
        &self,
        tenant_id: Uuid,
        jti: &str,
    ) -> Result<Option<Uuid>, TokenPortError> {
        self.state.load_access_token_subject(tenant_id, jti).await
    }

    pub async fn store_native_sso(
        &self,
        secret: &str,
        value: &Value,
        ttl_seconds: u64,
    ) -> Result<(), TokenPortError> {
        self.state
            .store_native_sso(secret, value, ttl_seconds)
            .await
    }

    pub async fn load_native_sso(&self, secret: &str) -> Result<Option<Value>, TokenPortError> {
        self.state.load_native_sso(secret).await
    }

    pub async fn recover_lost_refresh_response(
        &self,
        token: &RefreshToken,
        client_id: Uuid,
        retry_started_at: DateTime<Utc>,
    ) -> Result<Option<RefreshToken>, TokenPortError> {
        self.repository
            .lost_response_successor_or_compromise(token, client_id, retry_started_at)
            .await
    }

    pub async fn persist_refresh_token(
        &self,
        token: NewRefreshToken,
    ) -> Result<RefreshTokenPersistResult, TokenPortError> {
        self.repository.persist_refresh_token(token).await
    }

    pub async fn active_subject_claims(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SubjectClaims>, TokenPortError> {
        self.repository
            .active_subject_claims(tenant_id, user_id)
            .await
    }

    pub async fn refresh_family_active(
        &self,
        tenant_id: Uuid,
        family_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, TokenPortError> {
        self.repository
            .refresh_family_active(tenant_id, family_id, user_id)
            .await
    }

    pub async fn decode_id_token(
        &self,
        issuer: &str,
        token: &str,
    ) -> Result<Option<Value>, TokenPortError> {
        self.signer.decode_id_token(issuer, token).await
    }

    pub async fn revoke_issued_tokens(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &str,
        access_token_expires_at: Option<DateTime<Utc>>,
        refresh_token_family_id: Option<Uuid>,
    ) -> Result<(), TokenPortError> {
        self.repository
            .revoke_issued_tokens(
                tenant_id,
                client_id,
                access_token_jti,
                access_token_expires_at,
                refresh_token_family_id,
            )
            .await
    }

    pub async fn load_authorization_code(
        &self,
        code_hash: &str,
    ) -> Result<Option<AuthorizationCodeState>, TokenPortError> {
        self.state.load_authorization_code(code_hash).await
    }

    pub async fn begin_authorization_code(
        &self,
        code_hash: &str,
        consuming_at: DateTime<Utc>,
    ) -> Result<AuthorizationCodeBeginResult, TokenPortError> {
        self.state
            .begin_authorization_code(code_hash, consuming_at)
            .await
    }

    pub async fn mark_authorization_code_failed(
        &self,
        code_hash: &str,
        error: &str,
        ttl_seconds: u64,
    ) -> Result<AuthorizationCodeTransitionResult, TokenPortError> {
        self.state
            .mark_authorization_code(
                code_hash,
                &AuthorizationCodeState::Failed {
                    failed_at: Utc::now(),
                    error: error.to_owned(),
                },
                ttl_seconds,
            )
            .await
    }

    pub async fn finalize_authorization_code(
        &self,
        issued: IssuedAuthorizationCodeTokens<'_>,
    ) -> Result<(), TokenPortError> {
        let marker = AuthorizationCodeState::Consumed {
            marker: ConsumedAuthorizationCode {
                client_id: issued.client_id,
                access_token_jti: issued.access_token_jti.to_owned(),
                access_token_expires_at: issued.access_token_expires_at,
                refresh_token_family_id: issued.refresh_token_family_id,
                consumed_at: Utc::now(),
            },
        };
        let transition = self
            .state
            .mark_authorization_code(issued.code_hash, &marker, issued.consumed_state_ttl_seconds)
            .await;
        if matches!(transition, Ok(AuthorizationCodeTransitionResult::Applied)) {
            return Ok(());
        }

        let expiry = DateTime::<Utc>::from_timestamp(issued.access_token_expires_at, 0);
        self.repository
            .revoke_issued_tokens(
                issued.tenant_id,
                issued.client_id,
                issued.access_token_jti,
                expiry,
                issued.refresh_token_family_id,
            )
            .await?;
        Err(transition.err().unwrap_or(TokenPortError::Conflict))
    }

    pub async fn store_access_token_subject(
        &self,
        tenant_id: Uuid,
        jti: &str,
        user_id: Uuid,
        ttl_seconds: u64,
    ) -> Result<(), TokenPortError> {
        self.state
            .store_access_token_subject(tenant_id, jti, user_id, ttl_seconds)
            .await
    }

    pub async fn sign_access_token(
        &self,
        input: AccessTokenSignInput<'_>,
    ) -> Result<IssuedAccessToken, TokenPortError> {
        validate_sender_constraint(input.dpop_jkt, input.mtls_x5t_s256)?;
        self.signer.sign_access_token(input).await
    }

    pub async fn decode_access_token(
        &self,
        issuer: &str,
        raw_token: &str,
    ) -> Result<Option<Claims>, TokenPortError> {
        self.signer.decode_access_token(issuer, raw_token).await
    }

    pub async fn access_token_revoked(
        &self,
        tenant_id: Uuid,
        jti: &str,
    ) -> Result<bool, TokenPortError> {
        self.repository.access_token_revoked(tenant_id, jti).await
    }

    pub async fn sign_id_token(
        &self,
        input: IdTokenSignInput<'_>,
    ) -> Result<String, TokenPortError> {
        self.signer.sign_id_token(input).await
    }

    pub async fn increment_token_management_rate(
        &self,
        subject: &str,
        window_seconds: u64,
    ) -> Result<u64, TokenPortError> {
        self.state
            .increment_token_management_rate(subject, window_seconds)
            .await
    }

    pub async fn inspect_token(
        &self,
        issuer: &str,
        raw_token: &str,
        resource_server: &OAuthClient,
        now: DateTime<Utc>,
    ) -> Result<TokenInspection, TokenPortError> {
        if let Some(claims) = self.signer.decode_access_token(issuer, raw_token).await? {
            let audience_allowed = token_audiences(&claims.aud)
                .iter()
                .any(|audience| resource_server.allowed_audiences.contains(audience));
            if (claims.client_id != resource_server.client_id && !audience_allowed)
                || claims.tenant_id.parse::<Uuid>().ok() != Some(resource_server.tenant_id)
            {
                return Ok(TokenInspection::Inactive);
            }
            let revoked = self
                .repository
                .access_token_revoked(resource_server.tenant_id, &claims.jti)
                .await?;
            if revoked || claims.exp <= now.timestamp() {
                return Ok(TokenInspection::Inactive);
            }
            let token_type = access_token_type(&claims);
            return Ok(TokenInspection::ActiveAccess {
                scope: claims.scope,
                client_id: claims.client_id,
                token_type,
                expires_at: claims.exp,
                issued_at: claims.iat,
                not_before: claims.nbf,
                subject: claims.sub,
                audience: claims.aud,
                issuer: claims.iss,
                jti: claims.jti,
            });
        }

        let Some(token) = self
            .repository
            .refresh_token(resource_server.tenant_id, raw_token)
            .await?
        else {
            return Ok(TokenInspection::Inactive);
        };
        if token.client_id != resource_server.id
            || token.revoked_at.is_some()
            || token.expires_at <= now
        {
            return Ok(TokenInspection::Inactive);
        }
        Ok(TokenInspection::ActiveRefresh {
            scope: json_strings(&token.scopes).join(" "),
            client_id: resource_server.client_id.clone(),
            expires_at: token.expires_at.timestamp(),
            issued_at: token.issued_at.timestamp(),
            subject: token.subject,
        })
    }

    pub async fn revoke_token(
        &self,
        issuer: &str,
        raw_token: &str,
        client: &OAuthClient,
    ) -> Result<usize, TokenPortError> {
        let access_token = self
            .signer
            .decode_access_token(issuer, raw_token)
            .await?
            .filter(|claims| claims.client_id == client.client_id)
            .and_then(|claims| {
                Some(AccessTokenRevocation {
                    jti: claims.jti,
                    expires_at: DateTime::<Utc>::from_timestamp(claims.exp, 0)?,
                })
            });
        self.repository
            .revoke_token(TokenRevocation {
                tenant_id: client.tenant_id,
                client_id: client.id,
                raw_token,
                access_token,
            })
            .await
    }

    pub async fn sign_introspection_response(
        &self,
        input: IntrospectionSignInput<'_>,
    ) -> Result<String, TokenPortError> {
        self.signer.sign_introspection_response(input).await
    }
}

fn token_audiences(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

fn json_strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect()
}

fn access_token_type(claims: &Claims) -> &'static str {
    if claims
        .cnf
        .as_ref()
        .and_then(|confirmation| confirmation.jkt.as_ref())
        .is_some()
    {
        "DPoP"
    } else {
        "Bearer"
    }
}

pub fn validate_sender_constraint(
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
) -> Result<(), TokenPortError> {
    if dpop_jkt.is_some() && mtls_x5t_s256.is_some() {
        return Err(TokenPortError::InvalidSenderConstraint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{Claims, ConfirmationClaims};

    use super::{TokenInspection, TokenPortError, access_token_type, validate_sender_constraint};

    fn access_claims(confirmation: Option<ConfirmationClaims>) -> Claims {
        Claims {
            iss: "https://issuer.example".to_owned(),
            sub: "subject".to_owned(),
            tenant_id: uuid::Uuid::nil().to_string(),
            user_id: None,
            subject_type: "client".to_owned(),
            aud: json!("resource://default"),
            client_id: "client".to_owned(),
            scope: "openid".to_owned(),
            authorization_details: json!([]),
            token_use: "access".to_owned(),
            jti: "jti".to_owned(),
            iat: 1,
            nbf: 1,
            exp: 2,
            cnf: confirmation,
            act: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
        }
    }

    #[test]
    fn access_token_cannot_bind_two_sender_constraints() {
        assert_eq!(
            validate_sender_constraint(Some("dpop"), Some("mtls")),
            Err(TokenPortError::InvalidSenderConstraint)
        );
        assert!(validate_sender_constraint(Some("dpop"), None).is_ok());
        assert!(validate_sender_constraint(None, Some("mtls")).is_ok());
    }

    #[test]
    fn introspection_reports_dpop_only_for_dpop_bound_tokens() {
        assert_eq!(access_token_type(&access_claims(None)), "Bearer");
        assert_eq!(
            access_token_type(&access_claims(Some(ConfirmationClaims {
                jkt: Some("thumbprint".to_owned()),
                x5t_s256: None,
            }))),
            "DPoP"
        );
        assert_eq!(
            access_token_type(&access_claims(Some(ConfirmationClaims {
                jkt: None,
                x5t_s256: Some("certificate-thumbprint".to_owned()),
            }))),
            "Bearer"
        );
    }

    #[test]
    fn token_inspection_builds_exact_rfc7662_documents() {
        assert_eq!(
            TokenInspection::Inactive.into_document(),
            json!({"active": false})
        );
        assert_eq!(
            TokenInspection::ActiveRefresh {
                scope: "openid offline_access".to_owned(),
                client_id: "client".to_owned(),
                expires_at: 20,
                issued_at: 10,
                subject: "subject".to_owned(),
            }
            .into_document(),
            json!({
                "active": true,
                "scope": "openid offline_access",
                "client_id": "client",
                "exp": 20,
                "iat": 10,
                "sub": "subject",
            })
        );
    }
}
