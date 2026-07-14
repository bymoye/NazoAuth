//! External OIDC, OAuth2-social, and trusted SAML-gateway federation.

use actix_web::http::StatusCode;
use actix_web::web::{Data, Json, Path, Query};
use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
use nazo_http_actix::{
    json_response, json_response_no_store, make_cookie, oauth_error, redirect_found,
    with_cookie_headers,
};
#[cfg(test)]
use nazo_identity::PublicAccount;
use nazo_identity::{FederationError, LoginSuccess, VerifiedExternalIdentity};
use serde::{Serialize, de::DeserializeOwned};
#[cfg(test)]
use serde_json::Value;
use serde_json::json;

use crate::bootstrap::LocalFederationService;
use crate::http::client_ip::{ClientIpConfig, client_ip_with_config};
use crate::settings::{
    ExternalLoginProvider, ExternalLoginProviderAdapter, FederationProviderRegistry,
    OidcFederationSettings, SamlGatewaySettings, SocialProviderSettings,
};
use crate::{adapters::email::normalize_email_address, http::rate_limit::AuthRequestLimiter};

mod oidc;
mod saml;
mod social;
use oidc::*;
use saml::*;
use social::*;

pub(crate) const FEDERATION_STATE_TTL_SECONDS: u64 = 300;
pub(crate) const SAML_REPLAY_TTL_SECONDS: u64 =
    (SAML_ASSERTION_MAX_TTL_SECONDS + SAML_ASSERTION_CLOCK_SKEW_SECONDS) as u64;
const MAX_FEDERATION_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct FederationHttpConfig {
    providers: FederationProviderRegistry,
    saml_gateway: Option<SamlGatewaySettings>,
    session_cookie_name: String,
    csrf_cookie_name: String,
    session_ttl_seconds: u64,
    cookie_secure: bool,
}

impl FederationHttpConfig {
    pub(crate) fn new(
        providers: FederationProviderRegistry,
        saml_gateway: Option<SamlGatewaySettings>,
        session_cookie_name: impl Into<String>,
        csrf_cookie_name: impl Into<String>,
        session_ttl_seconds: u64,
        cookie_secure: bool,
    ) -> Self {
        Self {
            providers,
            saml_gateway,
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            session_ttl_seconds,
            cookie_secure,
        }
    }
}

fn federation_http_client() -> anyhow::Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none());
    #[cfg(test)]
    let builder = builder.no_proxy();
    Ok(builder.build()?)
}

async fn federation_response_bytes(response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let mut response = response.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_FEDERATION_PROVIDER_RESPONSE_BYTES as u64)
    {
        anyhow::bail!("federation provider response is too large");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let length = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow::anyhow!("federation provider response length overflow"))?;
        if length > MAX_FEDERATION_PROVIDER_RESPONSE_BYTES {
            anyhow::bail!("federation provider response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn federation_json_response<T: DeserializeOwned>(
    response: reqwest::Response,
) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(
        &federation_response_bytes(response).await?,
    )?)
}

async fn federation_text_response(response: reqwest::Response) -> anyhow::Result<String> {
    Ok(String::from_utf8(
        federation_response_bytes(response).await?,
    )?)
}

#[derive(Serialize)]
struct FederationProviderView {
    provider_id: String,
    display_name: String,
    adapter_type: &'static str,
    icon: Option<String>,
    display_order: i32,
    start_url: String,
}

pub(crate) async fn federation_provider_list(config: Data<FederationHttpConfig>) -> HttpResponse {
    let providers = config
        .providers
        .enabled_public_providers()
        .map(provider_view)
        .collect::<Vec<_>>();
    json_response_no_store(json!({ "providers": providers }))
}

pub(crate) async fn federation_provider_start(
    limiter: Data<AuthRequestLimiter>,
    service: Data<LocalFederationService>,
    config: Data<FederationHttpConfig>,
    req: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    if let Err(response) = limiter.enforce(&req).await {
        return response;
    }
    let provider_id = path.into_inner();
    let Some(provider) = config.providers.enabled_provider(&provider_id) else {
        return unknown_provider_response();
    };
    match &provider.adapter {
        ExternalLoginProviderAdapter::Oidc(provider) => {
            match service
                .start_oidc(provider.provider_id.clone(), Utc::now())
                .await
            {
                Ok(start) => redirect_found(oidc_authorization_url(
                    provider,
                    &start.state,
                    &start.nonce,
                    &start.pkce_verifier,
                )),
                Err(error) => federation_state_error(error),
            }
        }
        ExternalLoginProviderAdapter::Social(provider) => {
            match service.start_social(provider_id, Utc::now()).await {
                Ok(start) => redirect_found(social_authorization_url(
                    provider,
                    &start.state,
                    &start.pkce_verifier,
                )),
                Err(error) => federation_state_error(error),
            }
        }
    }
}

pub(crate) async fn federation_provider_callback(
    limiter: Data<AuthRequestLimiter>,
    client_ip: Data<ClientIpConfig>,
    service: Data<LocalFederationService>,
    config: Data<FederationHttpConfig>,
    req: HttpRequest,
    path: Path<String>,
    Query(query): Query<OidcCallbackQuery>,
) -> HttpResponse {
    if let Err(response) = limiter.enforce(&req).await {
        return response;
    }
    let provider_id = path.into_inner();
    let Some(provider) = config.providers.enabled_provider(&provider_id).cloned() else {
        return unknown_provider_response();
    };
    match provider.adapter {
        ExternalLoginProviderAdapter::Oidc(provider) => {
            oidc_callback_after_rate_limit_for_provider(
                service, config, client_ip, req, query, provider,
            )
            .await
        }
        ExternalLoginProviderAdapter::Social(provider) => {
            social_callback_after_rate_limit(
                service,
                config,
                client_ip,
                req,
                query,
                provider_id,
                provider,
            )
            .await
        }
    }
}

async fn oidc_callback_after_rate_limit_for_provider(
    service: Data<LocalFederationService>,
    config: Data<FederationHttpConfig>,
    client_ip: Data<ClientIpConfig>,
    req: HttpRequest,
    query: OidcCallbackQuery,
    provider: OidcFederationSettings,
) -> HttpResponse {
    let input = match validate_oidc_callback_input(&query) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let stored = match service
        .consume_oidc(&input.state_token, &provider.provider_id, Utc::now())
        .await
    {
        Ok(stored) => stored,
        Err(error) => return federation_state_error(error),
    };
    let token = match exchange_oidc_code(&provider, &input.code, &stored.pkce_verifier).await {
        Ok(token) => token,
        Err(error) => {
            tracing::warn!(%error, provider_id = %provider.provider_id, "OIDC token exchange failed");
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "OIDC federation failed.",
            );
        }
    };
    let jwks = match fetch_oidc_jwks(&provider).await {
        Ok(jwks) => jwks,
        Err(error) => {
            tracing::warn!(%error, provider_id = %provider.provider_id, "OIDC JWKS fetch failed");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "OIDC federation unavailable.",
            );
        }
    };
    let claims = match verify_oidc_id_token(&provider, &jwks, &token.id_token, &stored.nonce) {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(%error, provider_id = %provider.provider_id, "OIDC ID Token verification failed");
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "OIDC federation failed.",
            );
        }
    };
    let email = match claims
        .email
        .as_deref()
        .and_then(|value| normalize_email_address(value).ok())
    {
        Some(email) => email,
        None => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "access_denied",
                "OIDC email claim required.",
            );
        }
    };
    if claims.email_verified != Some(true) {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "OIDC email must be verified.",
        );
    }
    complete_federation(
        service.get_ref(),
        config.get_ref(),
        VerifiedExternalIdentity {
            provider_type: "oidc".to_owned(),
            provider_id: provider.provider_id,
            subject: claims.sub.clone(),
            email: Some(email.clone()),
            display_name: claims.name.clone(),
            claims: json!({
                "iss": claims.iss,
                "sub": claims.sub,
                "email": email,
                "name": claims.name,
                "given_name": claims.given_name,
                "family_name": claims.family_name,
            }),
        },
        "oidc",
        client_ip_with_config(&req, client_ip.get_ref()),
        false,
    )
    .await
}

async fn social_callback_after_rate_limit(
    service: Data<LocalFederationService>,
    config: Data<FederationHttpConfig>,
    client_ip: Data<ClientIpConfig>,
    req: HttpRequest,
    query: OidcCallbackQuery,
    provider_id: String,
    provider: SocialProviderSettings,
) -> HttpResponse {
    let input = match validate_oidc_callback_input(&query) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let stored = match service
        .consume_social(&input.state_token, &provider_id, Utc::now())
        .await
    {
        Ok(stored) => stored,
        Err(error) => return federation_state_error(error),
    };
    let identity =
        match resolve_social_identity(&provider, &input.code, &stored.pkce_verifier).await {
            Ok(identity) => identity,
            Err(error) => {
                tracing::warn!(
                    %provider_id,
                    upstream_http_error = error.is::<reqwest::Error>(),
                    "OAuth2 social federation failed"
                );
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "access_denied",
                    "social federation failed.",
                );
            }
        };
    let existing_only = identity.email.is_none();
    complete_federation(
        service.get_ref(),
        config.get_ref(),
        VerifiedExternalIdentity {
            provider_type: "oauth2_social".to_owned(),
            provider_id,
            subject: identity.subject,
            email: identity.email,
            display_name: identity.display_name,
            claims: identity.claims,
        },
        "oauth2_social",
        client_ip_with_config(&req, client_ip.get_ref()),
        existing_only,
    )
    .await
}

pub(crate) async fn federation_saml_acs(
    limiter: Data<AuthRequestLimiter>,
    client_ip: Data<ClientIpConfig>,
    service: Data<LocalFederationService>,
    config: Data<FederationHttpConfig>,
    req: HttpRequest,
    Json(payload): Json<SamlGatewayAssertion>,
) -> HttpResponse {
    if let Err(response) = limiter.enforce(&req).await {
        return response;
    }
    let Some(settings) = config.saml_gateway.as_ref() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "SAML federation is not configured.",
        );
    };
    let email = match normalize_email_address(&payload.email) {
        Ok(email) => email,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "SAML email is invalid.",
            );
        }
    };
    if !valid_saml_gateway_assertion(settings, &payload, &email) {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "SAML federation failed.",
        );
    }
    if let Err(error) = service
        .consume_saml_assertion(&payload.signature, payload.exp, Utc::now())
        .await
    {
        return federation_saml_replay_error(error);
    }
    complete_federation(
        service.get_ref(),
        config.get_ref(),
        VerifiedExternalIdentity {
            provider_type: "saml".to_owned(),
            provider_id: settings.issuer.clone(),
            subject: payload.subject.clone(),
            email: Some(email.clone()),
            display_name: payload.name.clone(),
            claims: json!({
                "iss": payload.issuer,
                "aud": payload.audience,
                "sub": payload.subject,
                "email": email,
                "name": payload.name,
            }),
        },
        "saml",
        client_ip_with_config(&req, client_ip.get_ref()),
        false,
    )
    .await
}

async fn complete_federation(
    service: &LocalFederationService,
    config: &FederationHttpConfig,
    identity: VerifiedExternalIdentity,
    method: &str,
    source_ip: String,
    existing_only: bool,
) -> HttpResponse {
    let result = if existing_only {
        service
            .complete_existing_only(identity, method.to_owned(), source_ip)
            .await
    } else {
        service
            .complete_verified(identity, method.to_owned(), source_ip)
            .await
    };
    match result {
        Ok(success) => federation_session_response(config, success),
        Err(error) => federation_completion_error(error),
    }
}

fn federation_session_response(
    config: &FederationHttpConfig,
    success: LoginSuccess,
) -> HttpResponse {
    with_cookie_headers(
        json_response(json!({
            "expires_in": config.session_ttl_seconds,
            "csrf_token": success.csrf_token,
            "mfa_required": false
        })),
        &[
            make_cookie(
                &config.session_cookie_name,
                &success.session_id,
                true,
                config.session_ttl_seconds,
                config.cookie_secure,
            ),
            make_cookie(
                &config.csrf_cookie_name,
                &success.csrf_token,
                false,
                config.session_ttl_seconds,
                config.cookie_secure,
            ),
        ],
    )
}

#[derive(Debug, PartialEq, Eq)]
struct OidcCallbackInput {
    state_token: String,
    code: String,
}

fn validate_oidc_callback_input(
    query: &OidcCallbackQuery,
) -> Result<OidcCallbackInput, HttpResponse> {
    if query.error.is_some() {
        return Err(oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "OIDC federation failed.",
        ));
    }
    let state_token = query
        .state
        .as_deref()
        .and_then(nazo_identity::federation::normalize_federation_token)
        .ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid federation state.",
            )
        })?;
    let code = query
        .code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| value.len() <= 4096)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "authorization code required.",
            )
        })?;
    Ok(OidcCallbackInput { state_token, code })
}

fn provider_view(provider: &ExternalLoginProvider) -> FederationProviderView {
    FederationProviderView {
        provider_id: provider.provider_id.clone(),
        display_name: provider.display_name.clone(),
        adapter_type: provider.adapter_type(),
        icon: provider.icon.clone(),
        display_order: provider.display_order,
        start_url: format!("/auth/federation/{}/start", provider.provider_id),
    }
}

fn unknown_provider_response() -> HttpResponse {
    oauth_error(
        StatusCode::NOT_FOUND,
        "invalid_request",
        "federation provider is not configured.",
    )
}

fn federation_state_error(error: FederationError) -> HttpResponse {
    match error {
        FederationError::InvalidState => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid federation state.",
        ),
        FederationError::StateExpired | FederationError::ProviderMismatch => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "federation state expired.",
        ),
        error => {
            tracing::warn!(?error, "federation state operation failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation state failed.",
            )
        }
    }
}

fn federation_completion_error(error: FederationError) -> HttpResponse {
    match error {
        FederationError::VerifiedEmailRequired => oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "verified external email or existing link required.",
        ),
        FederationError::InactiveExistingLink => {
            oauth_error(StatusCode::UNAUTHORIZED, "access_denied", "当前账号已停用.")
        }
        FederationError::LoginFailed => oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "federation login failed.",
        ),
        FederationError::Session(_) | FederationError::SessionCollision => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "session write failed.",
        ),
        error => {
            tracing::warn!(?error, "federation identity resolution failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "federation login failed.",
            )
        }
    }
}

fn federation_saml_replay_error(error: FederationError) -> HttpResponse {
    match error {
        FederationError::SamlReplay => oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "SAML federation failed.",
        ),
        error => federation_state_error(error),
    }
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/auth/tests/federation.rs"]
mod tests;
