use std::sync::Arc;

use actix_web::HttpRequest;
use nazo_auth::{Claims, OAuthClient, token_audience_contains};
use nazo_http_actix::{
    AccessTokenAuthScheme, UserinfoDpopError, UserinfoError, UserinfoFuture, UserinfoOperations,
    UserinfoRepresentation, UserinfoSuccess,
};
use nazo_key_management::{KeyManager, signing_algorithm_from_name};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::adapters::security::{access_token_tenant_id, blake3_hex, constant_time_eq};
use crate::domain::client_jwe::{JwePayloadKind, client_jwe_key, encrypt_compact_jwe};
use crate::domain::client_policy::parse_scope;
use crate::domain::oidc_claims::oidc_user_claims;
use crate::http::client_ip::IpCidr;
use crate::http::dpop::{DpopError, validate_dpop_proof_with_store};
use crate::http::mtls::request_mtls_thumbprint_from_trusted_proxy;
use crate::settings::{DpopNoncePolicy, Settings};

use crate::http::token::ServerTokenService;

#[derive(Clone)]
pub(crate) struct UserinfoConfig {
    issuer: Box<str>,
    default_audience: Box<str>,
    mtls_endpoint_base_url: Box<str>,
    dpop_nonce_policy: DpopNoncePolicy,
    trusted_proxy_cidrs: Box<[IpCidr]>,
}

impl From<&Settings> for UserinfoConfig {
    fn from(settings: &Settings) -> Self {
        Self {
            issuer: settings.endpoint.issuer.as_str().into(),
            default_audience: settings.protocol.default_audience.as_str().into(),
            mtls_endpoint_base_url: settings.endpoint.mtls_endpoint_base_url.as_str().into(),
            dpop_nonce_policy: settings.protocol.dpop_nonce_policy,
            trusted_proxy_cidrs: settings.endpoint.trusted_proxy_cidrs.clone().into(),
        }
    }
}

impl UserinfoConfig {
    pub(crate) fn audience_allowed(&self, audience: &Value) -> bool {
        let userinfo_url = format!("{}/userinfo", self.issuer.trim_end_matches('/'));
        token_audience_contains(audience, &self.default_audience)
            || token_audience_contains(audience, &userinfo_url)
    }
}

/// Non-storage dependencies for the UserInfo protected-resource endpoint.
///
/// Token, subject, revocation and client reads remain on `ServerTokenService`;
/// this handle only owns DPoP replay state, response signing, and focused policy.
#[derive(Clone)]
pub(crate) struct UserinfoHandles {
    replay: nazo_valkey::ReplayStore,
    keys: KeyManager,
    config: UserinfoConfig,
}

#[derive(Clone)]
pub(crate) struct ServerUserinfoOperations {
    token_service: Arc<ServerTokenService>,
    handles: UserinfoHandles,
}

impl ServerUserinfoOperations {
    pub(crate) fn new(token_service: Arc<ServerTokenService>, handles: UserinfoHandles) -> Self {
        Self {
            token_service,
            handles,
        }
    }

    async fn execute(
        &self,
        request: &HttpRequest,
        scheme: AccessTokenAuthScheme,
        token: String,
    ) -> Result<UserinfoSuccess, UserinfoError> {
        let claims = self
            .token_service
            .decode_access_token(self.handles.issuer(), &token)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "failed to decode userinfo access token");
                UserinfoError::QueryUnavailable
            })?
            .ok_or(UserinfoError::InvalidAccessToken)?;
        if !self.handles.audience_allowed(&claims.aud) {
            return Err(UserinfoError::InvalidAudience);
        }
        let tenant_id =
            access_token_tenant_id(&claims).ok_or(UserinfoError::InvalidTenantBoundary)?;
        let revoked = self
            .token_service
            .access_token_revoked(tenant_id, &claims.jti)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "failed to check userinfo token revocation");
                UserinfoError::QueryUnavailable
            })?;
        if revoked {
            return Err(UserinfoError::RevokedAccessToken);
        }

        let dpop_nonce = self
            .validate_sender_constraint(request, scheme, &token, &claims)
            .await?;
        if !claims
            .scope
            .split_whitespace()
            .any(|scope| scope == "openid")
            || claims.subject_type != "user"
        {
            return Err(UserinfoError::InsufficientScope);
        }

        let scopes = parse_scope(&claims.scope);
        let user_id = self.access_token_user_id(tenant_id, &claims).await?;
        if nazo_identity::TenantId::new(tenant_id).is_err()
            || nazo_identity::UserId::new(user_id).is_err()
        {
            return Err(UserinfoError::InactiveSubject);
        }
        let subject_claims = self
            .token_service
            .active_subject_claims(tenant_id, user_id)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "failed to load userinfo subject claims");
                UserinfoError::QueryUnavailable
            })?
            .ok_or(UserinfoError::InactiveSubject)?;
        let client = match self
            .token_service
            .client_by_protocol_id(tenant_id, &claims.client_id)
            .await
        {
            Ok(Some(client)) if client.is_active => client,
            Ok(_) => return Err(UserinfoError::ClientUnavailable),
            Err(error) => {
                tracing::warn!(%error, "failed to load userinfo client response policy");
                return Err(UserinfoError::QueryUnavailable);
            }
        };
        let response_claims = oidc_user_claims(
            &subject_claims,
            &scopes,
            &claims.sub,
            &claims.userinfo_claims,
            &claims.userinfo_claim_requests,
            None,
        );
        let representation = self
            .protect_response(&client, response_claims)
            .await
            .map_err(|error| {
                tracing::warn!(
                    %error,
                    client_id_hash = %blake3_hex(&client.client_id),
                    "failed to protect userinfo response"
                );
                UserinfoError::ResponseProtectionFailed
            })?;
        Ok(UserinfoSuccess {
            representation,
            dpop_nonce,
        })
    }

    async fn validate_sender_constraint(
        &self,
        request: &HttpRequest,
        scheme: AccessTokenAuthScheme,
        token: &str,
        claims: &Claims,
    ) -> Result<Option<String>, UserinfoError> {
        match (scheme, claims.cnf.as_ref()) {
            (AccessTokenAuthScheme::DPoP, Some(cnf)) if cnf.jkt.is_some() => {
                self.handles
                    .validate_dpop_proof(request, token, cnf.jkt.as_deref())
                    .await
                    .map_err(map_dpop_error)?;
                self.handles
                    .issue_dpop_nonce()
                    .await
                    .map(Some)
                    .map_err(map_dpop_error)
            }
            (AccessTokenAuthScheme::DPoP, _) => {
                Err(UserinfoError::Dpop(UserinfoDpopError::TokenNotBound))
            }
            (AccessTokenAuthScheme::Bearer, Some(cnf)) if cnf.x5t_s256.is_some() => {
                let expected = cnf.x5t_s256.as_deref().unwrap_or_default();
                let actual = self
                    .handles
                    .request_mtls_thumbprint(request)
                    .ok_or(UserinfoError::MissingMtlsCertificate)?;
                if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
                    return Err(UserinfoError::MtlsCertificateMismatch);
                }
                Ok(None)
            }
            (AccessTokenAuthScheme::Bearer, Some(_)) => {
                Err(UserinfoError::Dpop(UserinfoDpopError::MissingProof))
            }
            (AccessTokenAuthScheme::Bearer, None) => Ok(None),
        }
    }

    async fn access_token_user_id(
        &self,
        tenant_id: Uuid,
        claims: &Claims,
    ) -> Result<Uuid, UserinfoError> {
        if let Some(user_id) = claims
            .user_id
            .as_deref()
            .and_then(|value| Uuid::parse_str(value).ok())
        {
            return Ok(user_id);
        }
        self.token_service
            .load_access_token_subject(tenant_id, &claims.jti)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "failed to load access token subject mapping");
                UserinfoError::QueryUnavailable
            })?
            .ok_or(UserinfoError::InvalidSubject)
    }

    async fn protect_response(
        &self,
        client: &OAuthClient,
        mut claims: Value,
    ) -> anyhow::Result<UserinfoRepresentation> {
        let signing_alg = match client.userinfo_signed_response_alg.as_deref() {
            Some(value) => Some(
                signing_algorithm_from_name(value)
                    .ok_or_else(|| anyhow::anyhow!("unsupported UserInfo signing algorithm"))?,
            ),
            None => None,
        };
        let encryption_key = client_jwe_key(
            client.jwks.as_ref(),
            client.userinfo_encrypted_response_alg.as_deref(),
            client.userinfo_encrypted_response_enc.as_deref(),
            "userinfo",
        )?;
        if signing_alg.is_none() && encryption_key.is_none() {
            return Ok(UserinfoRepresentation::Claims(claims));
        }

        let body = if let Some(signing_alg) = signing_alg {
            let object = claims
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("UserInfo claims must be a JSON object"))?;
            object.insert("iss".to_owned(), json!(self.handles.issuer()));
            object.insert("aud".to_owned(), json!(client.client_id));
            let signed = self
                .handles
                .sign_response_jwt(
                    nazo_auth::SigningPurpose::IdToken,
                    &claims,
                    "JWT",
                    signing_alg,
                )
                .await?;
            match encryption_key {
                Some(key) => {
                    encrypt_compact_jwe(&key, signed.as_bytes(), JwePayloadKind::NestedJwt)?
                }
                None => signed,
            }
        } else {
            let key = encryption_key.expect("checked UserInfo encryption key is present");
            encrypt_compact_jwe(&key, &serde_json::to_vec(&claims)?, JwePayloadKind::Claims)?
        };
        Ok(UserinfoRepresentation::Jwt(body))
    }
}

impl UserinfoOperations for ServerUserinfoOperations {
    fn userinfo<'a>(
        &'a self,
        request: &'a HttpRequest,
        scheme: AccessTokenAuthScheme,
        token: String,
    ) -> UserinfoFuture<'a> {
        Box::pin(async move { self.execute(request, scheme, token).await })
    }
}

fn map_dpop_error(error: DpopError) -> UserinfoError {
    let error = match error {
        DpopError::MissingProof => UserinfoDpopError::MissingProof,
        DpopError::MalformedProof => UserinfoDpopError::MalformedProof,
        DpopError::InvalidProof => UserinfoDpopError::InvalidProof,
        DpopError::ReplayDetected(_) => UserinfoDpopError::ReplayDetected,
        DpopError::BindingMismatch => UserinfoDpopError::BindingMismatch,
        DpopError::TokenNotBound => UserinfoDpopError::TokenNotBound,
        DpopError::UseNonce(nonce) => UserinfoDpopError::UseNonce(nonce),
        DpopError::NonceStoreUnavailable => UserinfoDpopError::NonceStoreUnavailable,
    };
    UserinfoError::Dpop(error)
}

impl UserinfoHandles {
    pub(crate) fn new(
        replay: nazo_valkey::ReplayStore,
        keys: KeyManager,
        config: UserinfoConfig,
    ) -> Self {
        Self {
            replay,
            keys,
            config,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_state(state: &super::TestAppState) -> Self {
        Self::new(
            nazo_valkey::ReplayStore::new(&state.valkey_connection()),
            state.keyset.clone(),
            UserinfoConfig::from(state.settings.as_ref()),
        )
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.config.issuer
    }

    pub(crate) fn audience_allowed(&self, audience: &Value) -> bool {
        self.config.audience_allowed(audience)
    }

    pub(crate) async fn validate_dpop_proof(
        &self,
        req: &HttpRequest,
        token: &str,
        expected_jkt: Option<&str>,
    ) -> Result<Option<String>, DpopError> {
        validate_dpop_proof_with_store(
            &self.replay,
            self.issuer(),
            &self.config.mtls_endpoint_base_url,
            self.config.dpop_nonce_policy,
            req,
            Some(token),
            expected_jkt,
        )
        .await
    }

    pub(crate) async fn issue_dpop_nonce(&self) -> Result<String, DpopError> {
        crate::http::dpop::issue_dpop_nonce_with_store(&self.replay).await
    }

    pub(crate) fn request_mtls_thumbprint(&self, req: &HttpRequest) -> Option<String> {
        request_mtls_thumbprint_from_trusted_proxy(req, &self.config.trusted_proxy_cidrs)
    }

    pub(crate) async fn sign_response_jwt(
        &self,
        purpose: nazo_auth::SigningPurpose,
        claims: &Value,
        typ: &str,
        signing_alg: jsonwebtoken::Algorithm,
    ) -> jsonwebtoken::errors::Result<String> {
        let mut header = jsonwebtoken::Header::new(signing_alg);
        header.typ = Some(typ.to_owned());
        self.keys.encode_jwt(purpose, &header, claims).await
    }
}
