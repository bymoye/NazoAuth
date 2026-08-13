use crate::adapters::security::{blake3_hex, random_urlsafe_token};
use crate::domain::ClientRow;
use crate::domain::client_jwe::{JwePayloadKind, client_jwe_key, encrypt_compact_jwe};
use crate::http::views::append_query;
use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use nazo_auth::{
    AuthorizationResponsePlan, AuthorizationResponsePolicyError, AuthorizationResponsePolicyInput,
    issue_oidc_session_state, plan_authorization_response,
};
use nazo_http_actix::{
    OAuthJsonErrorFields, form_post_authorization_response, oauth_error, redirect_found,
};
use serde_json::Value;

use super::AuthorizationRequestContext;

pub(crate) struct AuthorizationResponseRedirect<'a> {
    pub(crate) redirect_uri: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) response_mode: Option<&'a str>,
    pub(crate) code: Option<&'a str>,
    pub(crate) error: Option<&'a str>,
    pub(crate) state: Option<&'a str>,
    pub(crate) oidc_sid: Option<&'a str>,
    pub(crate) client_policy: Option<AuthorizationResponseClientPolicy>,
}

#[derive(Clone, Copy)]
pub(crate) struct AuthorizationResponseClientPolicy {
    pub(crate) signed_response_required: bool,
    pub(crate) session_management_allowed: bool,
    pub(crate) ttl_seconds: u64,
}

pub(crate) async fn authorization_response_redirect_with_context(
    context: &AuthorizationRequestContext<'_>,
    input: AuthorizationResponseRedirect<'_>,
) -> HttpResponse {
    let mut client = None;
    let response_policy = if let Some(policy) = input.client_policy {
        policy
    } else {
        client = if input.client_id.is_empty() {
            None
        } else {
            match context.service.client_by_id(input.client_id).await {
                Ok(Some(client)) if client.is_active => Some(client),
                Ok(_) => None,
                Err(error) => {
                    tracing::warn!(%error, client_id_hash = %blake3_hex(input.client_id), "failed to load authorization response client policy");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "authorization response policy is unavailable.",
                    );
                }
            }
        };
        let client_policy = client.as_ref().map_or_else(
            || context.config.profile.legacy_client_policy(),
            |client| context.config.profile.effective_client_policy(client),
        );
        AuthorizationResponseClientPolicy {
            signed_response_required: client_policy.require_signed_authorization_response,
            session_management_allowed: client_policy.session_management,
            ttl_seconds: if client_policy.requires_fapi2_security() {
                context.config.auth_code_ttl_seconds.min(60)
            } else {
                context.config.auth_code_ttl_seconds
            },
        }
    };
    let jarm_available = crate::http::authorization::permits_existing_module_transaction(
        context,
        nazo_runtime_modules::ModuleId::Jarm,
    );
    let session_management_available = response_policy.session_management_allowed
        && crate::http::authorization::accepts_module(
            context,
            nazo_runtime_modules::ModuleId::SessionManagement,
        );
    let plan = match plan_authorization_response(AuthorizationResponsePolicyInput {
        issuer: context.config.issuer.as_ref(),
        redirect_uri: input.redirect_uri,
        client_id: input.client_id,
        response_mode: input.response_mode,
        code: input.code,
        error: input.error,
        state: input.state,
        ttl_seconds: response_policy.ttl_seconds as i64,
        signed_response_required: response_policy.signed_response_required,
        jarm_available,
        session_management_available,
    }) {
        Ok(plan) => plan,
        Err(AuthorizationResponsePolicyError::UnsupportedResponseMode) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_response_mode",
                "JWT-secured authorization responses are disabled.",
            );
        }
        Err(AuthorizationResponsePolicyError::MissingClientId) => {
            tracing::warn!("cannot build signed authorization response without client_id");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response signing failed.",
            );
        }
        Err(AuthorizationResponsePolicyError::Dependency(error)) => {
            tracing::warn!(?error, "authorization response policy dependency failed");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response protection failed.",
            );
        }
    };
    if matches!(plan, AuthorizationResponsePlan::Jarm(_)) {
        debug_assert!(jarm_available);
        let client = match client {
            Some(client) => Some(client),
            None if input.client_id.is_empty() => None,
            None => match context.service.client_by_id(input.client_id).await {
                Ok(Some(client)) if client.is_active => Some(client),
                Ok(_) => None,
                Err(error) => {
                    tracing::warn!(%error, client_id_hash = %blake3_hex(input.client_id), "failed to load JARM client");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "authorization response protection failed.",
                    );
                }
            },
        };
        let Some(client) = client else {
            tracing::warn!(client_id_hash = %blake3_hex(input.client_id), "JARM client is missing or inactive");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response protection failed.",
            );
        };
        let protection = AuthorizationResponseProtection::from(&client);
        return authorization_response_redirect_with_protection_context(
            context,
            input,
            protection,
            response_policy.ttl_seconds as i64,
        )
        .await;
    }
    let (plain, form_post) = match plan {
        AuthorizationResponsePlan::Plain(plain) => (plain, false),
        AuthorizationResponsePlan::FormPost(plain) => (plain, true),
        AuthorizationResponsePlan::Jarm(_) => unreachable!("JARM response returned above"),
    };
    let session_state = if plain.issue_session_state {
        input
            .oidc_sid
            .and_then(|sid| issue_oidc_session_state(input.client_id, input.redirect_uri, sid))
    } else {
        None
    };
    if form_post {
        return form_post_authorization_response(
            &plain.redirect_uri,
            &plain.parameters,
            session_state.as_deref(),
            &random_urlsafe_token(),
        );
    }
    redirect_found(nazo_auth::plain_authorization_response_uri(
        &plain,
        session_state.as_deref(),
    ))
}

#[derive(Clone, Copy, Default)]
pub(super) struct AuthorizationResponseProtection<'a> {
    pub(super) signing_alg: Option<&'a str>,
    pub(super) encryption_alg: Option<&'a str>,
    pub(super) encryption_enc: Option<&'a str>,
    pub(super) jwks: Option<&'a Value>,
}

impl<'a> From<&'a ClientRow> for AuthorizationResponseProtection<'a> {
    fn from(client: &'a ClientRow) -> Self {
        Self {
            signing_alg: client.authorization_signed_response_alg.as_deref(),
            encryption_alg: client.authorization_encrypted_response_alg.as_deref(),
            encryption_enc: client.authorization_encrypted_response_enc.as_deref(),
            jwks: client.jwks.as_ref(),
        }
    }
}

pub(super) async fn authorization_response_redirect_with_protection_context(
    context: &AuthorizationRequestContext<'_>,
    input: AuthorizationResponseRedirect<'_>,
    protection: AuthorizationResponseProtection<'_>,
    ttl_seconds: i64,
) -> HttpResponse {
    let result =
        protected_authorization_response_jwt(context, &input, protection, ttl_seconds).await;
    authorization_response_jwt_result(input.redirect_uri, result)
}

async fn protected_authorization_response_jwt(
    context: &AuthorizationRequestContext<'_>,
    input: &AuthorizationResponseRedirect<'_>,
    protection: AuthorizationResponseProtection<'_>,
    ttl_seconds: i64,
) -> anyhow::Result<String> {
    let signed = context
        .service
        .sign_authorization_response(nazo_auth::AuthorizationResponseSignInput {
            issuer: context.config.issuer.as_ref(),
            client_id: input.client_id,
            code: input.code,
            error: input.error,
            state: input.state,
            ttl: ttl_seconds,
            signing_algorithm: protection.signing_alg,
        })
        .await
        .map_err(|error| anyhow::anyhow!("authorization response signing failed: {error:?}"))?;
    match client_jwe_key(
        protection.jwks,
        protection.encryption_alg,
        protection.encryption_enc,
        "authorization response",
    )? {
        Some(key) => Ok(encrypt_compact_jwe(
            &key,
            signed.as_bytes(),
            JwePayloadKind::NestedJwt,
        )?),
        None => Ok(signed),
    }
}

pub(super) fn authorization_response_jwt_result(
    redirect_uri: &str,
    result: anyhow::Result<String>,
) -> HttpResponse {
    match result {
        Ok(response) => authorization_response_jwt_redirect(redirect_uri, &response),
        Err(error) => {
            tracing::warn!(%error, "failed to protect JARM authorization response");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response signing failed.",
            )
        }
    }
}

pub(super) fn authorization_response_jwt_redirect(
    redirect_uri: &str,
    response: &str,
) -> HttpResponse {
    redirect_found(append_query(redirect_uri, &[("response", response)]))
}

pub(super) fn oauth_json_error(response: &HttpResponse) -> Option<String> {
    let extensions = response.extensions();
    extensions
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}
