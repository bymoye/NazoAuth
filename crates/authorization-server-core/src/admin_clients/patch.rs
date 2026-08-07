use super::helpers::{all_same_host, sector_identifier_host_for_redirects, trim_optional_string};
use super::policy::{
    AdminClientPolicy, ClientSecurityPolicyContext, validate_composable_security_policy,
};
use super::validation::{ClientMetadata, validate_client_metadata};
use super::{
    AdminClientCryptoPort, AdminClientError, PatchClientRequest, SectorIdentifierResolverPort,
};
use crate::OAuthClient;

pub async fn prepare_client_patch<S, C>(
    mut client: OAuthClient,
    request: PatchClientRequest,
    policy: &AdminClientPolicy,
    sector_identifiers: &S,
    crypto: &C,
) -> Result<OAuthClient, AdminClientError>
where
    S: SectorIdentifierResolverPort + ?Sized,
    C: AdminClientCryptoPort + ?Sized,
{
    if let Some(security_policy) = request.security_policy.as_ref() {
        security_policy
            .validate()
            .map_err(|message| AdminClientError::InvalidRequest(message.to_owned()))?;
    }
    let redirect_uris_changed = request.redirect_uris.is_some();
    if let Some(value) = request.client_name {
        client.client_name = value;
    }
    if let Some(value) = request.redirect_uris {
        client.redirect_uris = value;
    }
    if let Some(value) = request.post_logout_redirect_uris {
        client.post_logout_redirect_uris = value;
    }
    if let Some(value) = request.scopes {
        client.scopes = value;
    }
    if let Some(value) = request.allowed_audiences {
        client.allowed_audiences = value;
    }
    if let Some(value) = request.grant_types {
        client.grant_types = value;
    }
    if let Some(value) = request.require_dpop_bound_tokens {
        client.require_dpop_bound_tokens = value;
    }
    if let Some(value) = request.require_mtls_bound_tokens {
        client.require_mtls_bound_tokens = value;
    }
    if let Some(value) = request.allow_client_assertion_audience_array {
        client.allow_client_assertion_audience_array = value;
    }
    if let Some(value) = request.allow_client_assertion_endpoint_audience {
        client.allow_client_assertion_endpoint_audience = value;
    }
    if let Some(value) = request.require_par_request_object {
        client.require_par_request_object = value;
    }
    if let Some(value) = request.backchannel_token_delivery_mode {
        client.backchannel_token_delivery_mode = value;
    }
    if let Some(value) = request.backchannel_client_notification_endpoint {
        client.backchannel_client_notification_endpoint = trim_optional_string(Some(value));
    }
    if let Some(value) = request.backchannel_authentication_request_signing_alg {
        client.backchannel_authentication_request_signing_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.backchannel_user_code_parameter {
        client.backchannel_user_code_parameter = value;
    }
    if let Some(value) = request.backchannel_logout_uri {
        client.backchannel_logout_uri = trim_optional_string(Some(value));
    }
    if let Some(value) = request.backchannel_logout_session_required {
        client.backchannel_logout_session_required = value;
    }
    if let Some(value) = request.frontchannel_logout_uri {
        client.frontchannel_logout_uri = trim_optional_string(Some(value));
    }
    if let Some(value) = request.frontchannel_logout_session_required {
        client.frontchannel_logout_session_required = value;
    }
    if let Some(value) = request.tls_client_auth_subject_dn {
        client.tls_client_auth_subject_dn = trim_optional_string(Some(value));
    }
    if let Some(value) = request.tls_client_auth_cert_sha256 {
        client.tls_client_auth_cert_sha256 = trim_optional_string(Some(value));
    }
    if let Some(value) = request.tls_client_auth_san_dns {
        client.tls_client_auth_san_dns = value;
    }
    if let Some(value) = request.tls_client_auth_san_uri {
        client.tls_client_auth_san_uri = value;
    }
    if let Some(value) = request.tls_client_auth_san_ip {
        client.tls_client_auth_san_ip = value;
    }
    if let Some(value) = request.tls_client_auth_san_email {
        client.tls_client_auth_san_email = value;
    }
    if let Some(value) = request.jwks {
        client.jwks = Some(value);
    }
    if let Some(value) = request.id_token_signed_response_alg {
        client.id_token_signed_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.id_token_encrypted_response_alg {
        client.id_token_encrypted_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.id_token_encrypted_response_enc {
        client.id_token_encrypted_response_enc = trim_optional_string(Some(value));
    }
    if let Some(value) = request.request_object_signing_alg {
        client.request_object_signing_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.request_object_encryption_alg {
        client.request_object_encryption_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.request_object_encryption_enc {
        client.request_object_encryption_enc = trim_optional_string(Some(value));
    }
    if let Some(value) = request.token_endpoint_auth_signing_alg {
        client.token_endpoint_auth_signing_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.introspection_signed_response_alg {
        client.introspection_signed_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.introspection_encrypted_response_alg {
        client.introspection_encrypted_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.introspection_encrypted_response_enc {
        client.introspection_encrypted_response_enc = trim_optional_string(Some(value));
    }
    if let Some(value) = request.userinfo_signed_response_alg {
        client.userinfo_signed_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.userinfo_encrypted_response_alg {
        client.userinfo_encrypted_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.userinfo_encrypted_response_enc {
        client.userinfo_encrypted_response_enc = trim_optional_string(Some(value));
    }
    if let Some(value) = request.authorization_signed_response_alg {
        client.authorization_signed_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.authorization_encrypted_response_alg {
        client.authorization_encrypted_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.authorization_encrypted_response_enc {
        client.authorization_encrypted_response_enc = trim_optional_string(Some(value));
    }
    if let Some(value) = request.security_policy {
        client.security_policy = Some(value);
    }
    if let Some(value) = request.is_active {
        client.is_active = value;
    }

    let new_subject_type = request
        .subject_type
        .unwrap_or_else(|| client.subject_type.clone());
    let requested_sector_identifier_uri = match request.sector_identifier_uri {
        Some(_) if client.sector_identifier_uri.is_some() => {
            return Err(AdminClientError::InvalidRequest(
                "已配置 pairwise 客户端的 sector_identifier_uri 不可修改".to_owned(),
            ));
        }
        Some(uri) => Some(uri),
        None => client.sector_identifier_uri.clone(),
    };
    if new_subject_type != "pairwise" {
        client.sector_identifier_uri = None;
        client.sector_identifier_host = None;
    } else {
        if policy.pairwise_subject_secret.is_none() {
            return Err(AdminClientError::InvalidRequest(
                "pairwise 主题类型需要配置 PAIRWISE_SUBJECT_SECRET".to_owned(),
            ));
        }
        let host = match &requested_sector_identifier_uri {
            Some(uri)
                if !redirect_uris_changed
                    && client.sector_identifier_uri.as_deref() == Some(uri.as_str())
                    && client.sector_identifier_host.is_some() =>
            {
                client.sector_identifier_host.clone().ok_or_else(|| {
                    AdminClientError::Consistency(
                        "pairwise 客户端缺少 sector_identifier_host".to_owned(),
                    )
                })?
            }
            Some(uri) => {
                let uris = sector_identifiers.resolve(uri).await.map_err(|error| {
                    AdminClientError::InvalidRequest(format!(
                        "sector_identifier_uri 获取失败: {error}"
                    ))
                })?;
                sector_identifier_host_for_redirects(uri, &client.redirect_uris, &uris)?
            }
            None => client
                .sector_identifier_host
                .clone()
                .or_else(|| all_same_host(&client.redirect_uris))
                .ok_or_else(|| {
                    AdminClientError::InvalidRequest(
                        "pairwise 主题需要 sector_identifier_uri 或所有 redirect_uri 使用同一 host"
                            .to_owned(),
                    )
                })?,
        };
        client.sector_identifier_uri = requested_sector_identifier_uri;
        client.sector_identifier_host = Some(host);
    }
    client.subject_type = new_subject_type;

    validate_client_metadata(
        ClientMetadata::from_client(&client),
        &crypto.id_token_signing_algorithms(),
        &crypto.response_signing_algorithms(),
        crypto,
    )?;
    if let Some(effective_policy) = client.security_policy.as_ref() {
        validate_composable_security_policy(
            effective_policy,
            ClientSecurityPolicyContext {
                client_type: &client.client_type,
                authentication_method: &client.token_endpoint_auth_method,
                require_dpop_bound_tokens: client.require_dpop_bound_tokens,
                require_mtls_bound_tokens: client.require_mtls_bound_tokens,
                jwks_uri: client.jwks_uri.as_deref(),
                jwks: client.jwks.as_ref(),
            },
            crypto,
        )?;
    }
    Ok(client)
}
