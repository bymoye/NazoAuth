use super::super::{ServerTokenService, TokenForm};
use crate::adapters::security::{ClientCredentials, blake3_hex};
use crate::domain::{AuthorizationCodeState, ClientRow};
use crate::http::authorization::ServerAuthorizationService;
use crate::http::mtls::{
    client_mtls_certificate_matches, request_mtls_client_certificate_from_trusted_proxy,
};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
use nazo_auth::{
    ClientProfile, ProtocolErrorCode, SecurityProfile, SenderConstraintPolicy,
    validate_token_request_profile as validate_auth_token_request_profile,
};
use nazo_http_actix::oauth_token_error;

use super::errors::authorization_code_holder_missing_client_error;

pub(super) fn mtls_client_credentials(client_id: String) -> ClientCredentials {
    ClientCredentials {
        client_id: Some(client_id),
        client_secret: None,
        client_assertion: None,
        method: "tls_client_auth".to_owned(),
    }
}

pub(super) async fn mtls_client_credentials_without_client_id(
    service: &ServerAuthorizationService,
    trusted_proxy_cidrs: &[nazo_http_actix::IpCidr],
    req: &HttpRequest,
) -> Result<Option<ClientCredentials>, HttpResponse> {
    let Some(certificate) =
        request_mtls_client_certificate_from_trusted_proxy(req, trusted_proxy_cidrs)
    else {
        return Ok(None);
    };
    match service.active_mtls_candidates(1000).await {
        Ok(candidates) => {
            let clients = candidates
                .into_iter()
                .filter(|client| client_mtls_certificate_matches(client, &certificate))
                .take(2)
                .collect::<Vec<_>>();
            Ok(match clients.as_slice() {
                [client] => Some(mtls_client_credentials(client.client_id.clone())),
                _ => None,
            })
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query mTLS client by certificate identity");
            Err(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
                false,
            ))
        }
    }
}

pub(super) async fn missing_client_authorization_code_holder_error(
    token_service: &ServerTokenService,
    authorization_service: &ServerAuthorizationService,
    form: &TokenForm,
) -> Option<HttpResponse> {
    if form.grant_type != "authorization_code" {
        return None;
    }
    let code = form.code.as_deref()?;
    let stored = match token_service
        .load_authorization_code(&blake3_hex(code))
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "failed to read authorization code before client authentication");
            return Some(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            ));
        }
    };
    let payload = match stored {
        AuthorizationCodeState::Pending { payload } => payload,
        _ => return None,
    };
    if let Some(response) = authorization_code_holder_missing_client_error(
        payload.dpop_jkt.is_some(),
        payload.mtls_x5t_s256.is_some(),
    ) {
        return Some(response);
    }
    match authorization_service.client_by_id(&payload.client_id).await {
        Ok(Some(client))
            if client.require_dpop_bound_tokens || client.require_mtls_bound_tokens =>
        {
            authorization_code_holder_missing_client_error(
                client.require_dpop_bound_tokens,
                client.require_mtls_bound_tokens,
            )
        }
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(%error, "failed to query authorization code client before client authentication");
            Some(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
                false,
            ))
        }
    }
}

pub(super) fn attestation_client_id_matches_form_hint(
    form_client_id: Option<&str>,
    attested_client_id: &str,
) -> bool {
    form_client_id.is_none_or(|client_id| client_id == attested_client_id)
}

pub(super) fn validate_token_client_enabled(
    client: &ClientRow,
    grant_type: &str,
) -> Result<(), HttpResponse> {
    if !client.is_active || !client.grant_types.iter().any(|grant| grant == grant_type) {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用当前授权类型.",
            false,
        ));
    }
    Ok(())
}

pub(crate) fn validate_token_request_profile_with_profile(
    server_profile: crate::settings::AuthorizationServerProfile,
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    let profile = if server_profile
        .effective_client_policy(client)
        .requires_fapi2_security()
    {
        SecurityProfile::Fapi2Security
    } else {
        SecurityProfile::Baseline
    };
    let sender_constraint = match (
        client.require_dpop_bound_tokens,
        client.require_mtls_bound_tokens,
    ) {
        (false, false) => SenderConstraintPolicy::BearerAllowed,
        (true, false) => SenderConstraintPolicy::DpopRequired,
        (false, true) => SenderConstraintPolicy::MtlsRequired,
        (true, true) => SenderConstraintPolicy::DpopOrMtls,
    };
    validate_auth_token_request_profile(
        profile,
        ClientProfile {
            client_type: &client.client_type,
            authentication_method: auth_method,
            sender_constraint,
        },
    )
    .map_err(|error| {
        let status = if error.code == ProtocolErrorCode::InvalidClient {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::BAD_REQUEST
        };
        oauth_token_error(status, error.code.as_str(), error.description, false)
    })
}
