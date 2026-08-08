//! /token grant_type 分发入口。
use std::sync::Arc;

use crate::adapters::security::ClientCredentials;
use crate::http::client_attestation::client_attestation_headers;
use crate::http::dpop::dpop_proof_present;
use crate::http::mtls::request_mtls_client_certificate_from_trusted_proxy;
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{
    TokenClientAuthForm, oauth_token_error, parse_token_form_with_pre_authorized,
    token_client_auth_transport_facts,
};

mod client_auth;
mod errors;
mod pre_authorized;
mod rate_limit;

pub(crate) use self::client_auth::validate_token_request_profile_with_profile;
use self::client_auth::{
    attestation_client_id_matches_form_hint, missing_client_authorization_code_holder_error,
    mtls_client_credentials_without_client_id, validate_token_client_enabled,
};
use self::errors::{client_credentials_holder_missing_client_error, pre_authorized_token_error};
use self::pre_authorized::pre_authorized_parameters;
use self::rate_limit::enforce_token_rate_limit;

#[cfg(test)]
use super::TokenForm;
use super::ciba::{CibaTokenContext, CibaTokenHandles};
use super::client_auth::{
    ClientAuthConfig, TokenManagementClientAuthError, authenticate_client_with_dependencies,
    consume_token_client_assertion_with_authorization_service,
    perform_dummy_client_secret_verification,
};
use super::issue::{TokenIssuanceConfig, TokenIssuanceContext};
use super::{
    CIBA_GRANT_TYPE, DEVICE_CODE_GRANT_TYPE, JWT_BEARER_GRANT_TYPE, ServerTokenService,
    TOKEN_EXCHANGE_GRANT_TYPE, TokenFormError, client_auth_request_facts,
    token_authorization_code_with_service, token_ciba, token_client_credentials_with_service,
    token_device_code_with_service, token_exchange, token_jwt_bearer_with_service,
    token_refresh_with_service,
};
use crate::http::authorization::ServerAuthorizationService;
use crate::runtime_modules::ServerRuntimeModuleRegistry;
use nazo_auth::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, ClientAuthenticationContext,
    token_client_authentication_context, unverified_client_assertion_client_id,
};

pub(crate) struct TokenEndpointHandles {
    core: TokenCoreHandles,
    ciba: CibaTokenHandles,
    issuance_config: Data<TokenIssuanceConfig>,
    runtime_modules: Data<ServerRuntimeModuleRegistry>,
    remote_client_documents:
        Arc<crate::domain::remote_client_documents::RemoteClientDocumentResolver>,
    openid4vc: Openid4vcTokenHandles,
}

pub(crate) struct TokenCoreHandles {
    pub(crate) token_service: Data<ServerTokenService>,
    pub(crate) authorization_service: Data<ServerAuthorizationService>,
    pub(crate) device_service: Data<super::device::ServerDeviceGrantService>,
}

#[derive(Default)]
pub(crate) struct Openid4vcTokenHandles {
    pub(crate) credential_issuer: Option<Data<nazo_openid4vc_http_actix::CredentialIssuerEndpoint>>,
    pub(crate) client_attestation: Option<Arc<crate::domain::Openid4vcClientAttestationValidator>>,
}

impl TokenEndpointHandles {
    pub(crate) fn new(
        core: TokenCoreHandles,
        ciba: CibaTokenHandles,
        issuance_config: Data<TokenIssuanceConfig>,
        runtime_modules: Data<ServerRuntimeModuleRegistry>,
        remote_client_documents: Arc<
            crate::domain::remote_client_documents::RemoteClientDocumentResolver,
        >,
        openid4vc: Openid4vcTokenHandles,
    ) -> Self {
        Self {
            core,
            ciba,
            issuance_config,
            runtime_modules,
            remote_client_documents,
            openid4vc,
        }
    }
}

pub(crate) async fn token_with_service(
    handles: Data<TokenEndpointHandles>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let token_service = handles.core.token_service.get_ref();
    let authorization_service = handles.core.authorization_service.get_ref();
    let issuance_config = handles.issuance_config.get_ref();
    let device_service = handles.core.device_service.get_ref();
    let runtime_modules = handles.runtime_modules.get_ref();
    if let Err(response) =
        enforce_token_rate_limit(authorization_service, issuance_config, &req).await
    {
        return response;
    }

    let parsed_form = match parse_token_form_with_pre_authorized(&req, &body) {
        Ok(form) => form,
        Err(TokenFormError::InvalidContentType) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token 请求必须使用 application/x-www-form-urlencoded.",
                false,
            );
        }
        Err(TokenFormError::InvalidEncoding) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token 请求体必须使用 UTF-8 编码.",
                false,
            );
        }
        Err(TokenFormError::DuplicateParameter) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "OAuth 参数不能重复.",
                false,
            );
        }
        Err(TokenFormError::InvalidResourceParameter) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "resource must be an absolute URI without a fragment.",
                false,
            );
        }
        Err(TokenFormError::MissingGrantType) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "缺少 grant_type.",
                false,
            );
        }
    };
    let form = parsed_form.form;
    let mut pre_authorized = parsed_form.pre_authorized;
    if form.has_audience_param && form.grant_type != TOKEN_EXCHANGE_GRANT_TYPE {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "audience is only valid for OAuth token exchange; use RFC 8707 resource elsewhere.",
            false,
        );
    }

    let auth_facts = token_client_auth_transport_facts(
        &req,
        TokenClientAuthForm {
            client_id: form.client_id.as_deref(),
            client_secret: form.client_secret.as_deref(),
            client_assertion_type: form.client_assertion_type.as_deref(),
            client_assertion: form.client_assertion.as_deref(),
        },
    );
    let client_auth_context = match token_client_authentication_context(auth_facts.presentation()) {
        Ok(context) => context,
        Err(_) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "同一 token 请求不能同时使用多种客户端认证方式.",
                false,
            );
        }
    };
    let has_client_attestation_material = req.headers().contains_key("OAuth-Client-Attestation")
        || req.headers().contains_key("OAuth-Client-Attestation-PoP");
    let has_mtls_material = request_mtls_client_certificate_from_trusted_proxy(
        &req,
        issuance_config.trusted_proxy_cidrs(),
    )
    .is_some();

    if form.grant_type == nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT {
        let preauth_has_authenticated_client_material = client_auth_context
            .has_any_client_auth_material
            || has_client_attestation_material
            || has_mtls_material;
        if preauth_has_authenticated_client_material {
            // Authenticated OpenID4VCI pre-authorized-code clients must flow
            // through the shared token endpoint client-authentication path below
            // so private_key_jwt, mTLS, and client-attestation identities are
            // verified before they become the issuance client_id.
        } else {
            let Some(endpoint) = handles.openid4vc.credential_issuer.as_ref() else {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "unsupported_grant_type",
                    "OpenID4VCI pre-authorized issuance is not configured.",
                    false,
                );
            };
            let (pre_authorized_code, tx_code) =
                match pre_authorized_parameters(&mut pre_authorized) {
                    Ok(parameters) => parameters,
                    Err(response) => return response,
                };
            let response = endpoint
                .pre_authorized_token(nazo_openid4vc_http_actix::PreAuthorizedTokenRequest {
                    pre_authorized_code,
                    tx_code,
                    client_id: form.client_id.clone(),
                    dpop_proof: req
                        .headers()
                        .get("DPoP")
                        .and_then(|value| value.to_str().ok())
                        .map(ToOwned::to_owned),
                    client_attestation: req
                        .headers()
                        .get("OAuth-Client-Attestation")
                        .and_then(|value| value.to_str().ok())
                        .map(ToOwned::to_owned),
                    client_attestation_pop: req
                        .headers()
                        .get("OAuth-Client-Attestation-PoP")
                        .and_then(|value| value.to_str().ok())
                        .map(ToOwned::to_owned),
                    request_url: format!(
                        "{}{}",
                        issuance_config.issuer().trim_end_matches('/'),
                        req.uri()
                    ),
                })
                .await;
            return match response {
                Ok(response) => HttpResponse::Ok()
                    .insert_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
                    .json(response),
                Err(error) => pre_authorized_token_error(error),
            };
        }
    }

    if form.grant_type == "password" {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Resource owner password credentials are not supported.",
            false,
        );
    }
    let attestation_headers = match client_attestation_headers(req.headers()) {
        Ok(headers) => headers,
        Err(()) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Exactly one of each client attestation header is required.",
                false,
            );
        }
    };
    if attestation_headers.is_some()
        && (client_auth_context.http_basic
            || client_auth_context.has_assertion
            || form.client_secret.is_some())
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Client attestation cannot be combined with another client authentication method.",
            false,
        );
    }
    let has_basic = client_auth_context.http_basic;
    let has_client_auth_material = client_auth_context.has_any_client_auth_material;
    let assertion_client_id = auth_facts
        .client_assertion()
        .filter(|_| auth_facts.client_assertion_type() == Some(CLIENT_ASSERTION_TYPE_JWT_BEARER))
        .and_then(unverified_client_assertion_client_id);
    let form_mtls_client_id =
        if !has_basic && !client_auth_context.has_assertion && form.client_secret.is_none() {
            form.client_id
                .as_ref()
                .filter(|_| {
                    request_mtls_client_certificate_from_trusted_proxy(
                        &req,
                        issuance_config.trusted_proxy_cidrs(),
                    )
                    .is_some()
                })
                .cloned()
        } else {
            None
        };
    let mut credentials =
        auth_facts.presented_credentials(assertion_client_id, form_mtls_client_id);
    if let Some((attestation, _)) = attestation_headers {
        credentials = ClientCredentials {
            client_id: crate::domain::Openid4vcClientAttestationValidator::unverified_client_id(
                attestation,
            ),
            client_secret: None,
            client_assertion: None,
            method: "attest_jwt_client_auth".to_owned(),
        };
    }
    if credentials.client_id.is_none()
        && !has_basic
        && form.client_secret.is_none()
        && !client_auth_context.has_assertion
    {
        match mtls_client_credentials_without_client_id(
            authorization_service,
            issuance_config.trusted_proxy_cidrs(),
            &req,
        )
        .await
        {
            Ok(Some(mtls_credentials)) => credentials = mtls_credentials,
            Ok(None) => {}
            Err(response) => return response,
        }
    }
    let Some(client_id) = credentials.client_id.as_deref() else {
        if !has_client_auth_material {
            if let Some(response) =
                client_credentials_holder_missing_client_error(&form, dpop_proof_present(&req))
            {
                return response;
            }
            if let Some(response) = missing_client_authorization_code_holder_error(
                token_service,
                authorization_service,
                &form,
            )
            .await
            {
                return response;
            }
        }
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
            has_basic,
        );
    };
    let client = match authorization_service.client_by_id(client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            perform_dummy_client_secret_verification(
                &credentials,
                issuance_config.client_secret_pepper(),
            );
            return oauth_token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端不存在或已停用.",
                has_basic,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for token request");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
                false,
            );
        }
    };
    if form.grant_type == nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT {
        if !client.is_active {
            return oauth_token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端不存在或已停用.",
                has_basic,
            );
        }
    } else if let Err(response) = validate_token_client_enabled(&client, &form.grant_type) {
        return response;
    }
    let auth_request = client_auth_request_facts(&req, issuance_config.trusted_proxy_cidrs());
    let mut client_attestation_jkt = None;
    let client_assertion = if let Some((attestation, proof)) = attestation_headers {
        if client.token_endpoint_auth_method != "attest_jwt_client_auth" {
            return oauth_token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client_attestation",
                "Client attestation is not registered for this client.",
                false,
            );
        }
        let Some(validator) = handles.openid4vc.client_attestation.as_ref() else {
            return oauth_token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client_attestation",
                "Client attestation is not configured.",
                false,
            );
        };
        let validated = match validator
            .validate_for_client(
                attestation,
                proof,
                issuance_config.issuer(),
                chrono::Utc::now().timestamp(),
            )
            .await
        {
            Ok(validated) if validated.client_id == client.client_id => validated,
            _ => {
                return oauth_token_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client_attestation",
                    "Client attestation validation failed.",
                    false,
                );
            }
        };
        if !attestation_client_id_matches_form_hint(form.client_id.as_deref(), &validated.client_id)
        {
            return oauth_token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Token request client_id does not match the client attestation.",
                false,
            );
        }
        client_attestation_jkt = Some(validated.client_instance_key_thumbprint.clone());
        let replay_key = format!("client-attestation:{}", validated.client_id);
        match authorization_service
            .consume_private_key_jwt(
                &replay_key,
                &validated.replay_id,
                validated.replay_ttl_seconds,
            )
            .await
        {
            Ok(true) => None,
            Ok(false) => {
                return oauth_token_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client_attestation",
                    "Client attestation proof was replayed.",
                    false,
                );
            }
            Err(_) => {
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "Client attestation replay state is unavailable.",
                    false,
                );
            }
        }
    } else {
        match authenticate_client_with_dependencies(
            authorization_service,
            ClientAuthConfig::new(
                issuance_config.issuer(),
                issuance_config.client_secret_pepper(),
            )
            .with_remote_jwks(&handles.remote_client_documents),
            &auth_request,
            &client,
            &credentials,
            ClientAuthenticationContext::AllowPublicNone,
        )
        .await
        {
            Ok(assertion) => assertion,
            Err(TokenManagementClientAuthError::PublicClientCredentialsForbidden) => {
                return oauth_token_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "public 客户端不能使用 client_secret.",
                    has_basic,
                );
            }
            Err(TokenManagementClientAuthError::InvalidClient) => {
                return oauth_token_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "客户端认证失败.",
                    has_basic && credentials.method != "private_key_jwt",
                );
            }
            Err(TokenManagementClientAuthError::StoreUnavailable) => {
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "客户端认证状态不可用.",
                    false,
                );
            }
        }
    };
    if let Err(response) = validate_token_request_profile_with_profile(
        issuance_config.authorization_server_profile(),
        &client,
        client.token_endpoint_auth_method.as_str(),
    ) {
        return response;
    }
    let modules = runtime_modules.snapshot();
    let issuance = TokenIssuanceContext {
        config: issuance_config,
        modules: &modules,
        authorization: authorization_service,
    };
    match form.grant_type.as_str() {
        "authorization_code" => {
            token_authorization_code_with_service(
                token_service,
                &issuance,
                &req,
                &client,
                &form,
                client_assertion.as_ref(),
                client_attestation_jkt.as_deref(),
            )
            .await
        }
        "refresh_token" => {
            token_refresh_with_service(
                token_service,
                &issuance,
                &req,
                &client,
                &form,
                client_assertion.as_ref(),
                client_attestation_jkt.as_deref(),
            )
            .await
        }
        "client_credentials" => {
            token_client_credentials_with_service(
                token_service,
                authorization_service,
                &issuance,
                &req,
                &client,
                &form,
                client_assertion.as_ref(),
            )
            .await
        }
        JWT_BEARER_GRANT_TYPE => {
            token_jwt_bearer_with_service(
                token_service,
                &issuance,
                &req,
                &client,
                &form,
                client_assertion.as_ref(),
            )
            .await
        }
        DEVICE_CODE_GRANT_TYPE => {
            token_device_code_with_service(
                token_service,
                &issuance,
                device_service,
                &req,
                &client,
                &form,
                client_assertion.as_ref(),
            )
            .await
        }
        CIBA_GRANT_TYPE => {
            token_ciba(
                CibaTokenContext {
                    token_service,
                    issuance: &issuance,
                    handles: &handles.ciba,
                    request: &req,
                },
                &client,
                &form,
                client_assertion.as_ref(),
                client.token_endpoint_auth_method.as_str(),
            )
            .await
        }
        nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT => {
            let Some(endpoint) = handles.openid4vc.credential_issuer.as_ref() else {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "unsupported_grant_type",
                    "OpenID4VCI pre-authorized issuance is not configured.",
                    false,
                );
            };
            let (pre_authorized_code, tx_code) =
                match pre_authorized_parameters(&mut pre_authorized) {
                    Ok(parameters) => parameters,
                    Err(response) => return response,
                };
            if let Err(error) = consume_token_client_assertion_with_authorization_service(
                authorization_service,
                &client,
                client_assertion.as_ref(),
            )
            .await
            {
                return super::token_client_assertion_error(error);
            }
            match endpoint
                .pre_authorized_token(nazo_openid4vc_http_actix::PreAuthorizedTokenRequest {
                    pre_authorized_code,
                    tx_code,
                    client_id: Some(client.client_id.clone()),
                    dpop_proof: req
                        .headers()
                        .get("DPoP")
                        .and_then(|value| value.to_str().ok())
                        .map(ToOwned::to_owned),
                    client_attestation: req
                        .headers()
                        .get("OAuth-Client-Attestation")
                        .and_then(|value| value.to_str().ok())
                        .map(ToOwned::to_owned),
                    client_attestation_pop: req
                        .headers()
                        .get("OAuth-Client-Attestation-PoP")
                        .and_then(|value| value.to_str().ok())
                        .map(ToOwned::to_owned),
                    request_url: format!(
                        "{}{}",
                        issuance_config.issuer().trim_end_matches('/'),
                        req.uri()
                    ),
                })
                .await
            {
                Ok(response) => HttpResponse::Ok()
                    .insert_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
                    .json(response),
                Err(error) => pre_authorized_token_error(error),
            }
        }
        TOKEN_EXCHANGE_GRANT_TYPE => {
            token_exchange(
                token_service,
                authorization_service,
                &issuance,
                &req,
                &client,
                &form,
                client_assertion.as_ref(),
            )
            .await
        }
        _ => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "不支持的 grant_type.",
            false,
        ),
    }
}

pub(crate) use token_with_service as token;

#[cfg(test)]
use self::client_auth::mtls_client_credentials;
#[cfg(test)]
use self::errors::authorization_code_holder_missing_client_error;
#[cfg(test)]
use crate::adapters::security::blake3_hex;
#[cfg(test)]
use crate::domain::{AuthorizationCodeState, ClientRow};

#[cfg(test)]
#[path = "../../../../tests/unit/http/token/dispatch.rs"]
mod tests;
