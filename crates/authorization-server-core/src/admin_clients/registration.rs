use uuid::Uuid;

use super::helpers::{sector_identifier_host_for_redirects, trim_optional_string, trim_string_vec};
use super::policy::{
    AdminClientPolicy, ClientSecurityPolicyContext, validate_composable_security_policy,
};
use super::validation::{ClientMetadata, validate_client_metadata};
use super::{
    AdminClientCryptoPort, AdminClientError, CreateClientRequest, PreparedClientRegistration,
    SectorIdentifierResolverPort,
};
use crate::ValidatedClientRegistration;

pub async fn prepare_client_registration<S, C>(
    request: CreateClientRequest,
    policy: &AdminClientPolicy,
    sector_identifiers: &S,
    crypto: &C,
) -> Result<PreparedClientRegistration, AdminClientError>
where
    S: SectorIdentifierResolverPort + ?Sized,
    C: AdminClientCryptoPort + ?Sized,
{
    request
        .security_policy
        .validate()
        .map_err(|message| AdminClientError::InvalidRequest(message.to_owned()))?;
    validate_client_metadata(
        ClientMetadata::from_create(&request),
        &crypto.id_token_signing_algorithms(),
        &crypto.response_signing_algorithms(),
        crypto,
    )?;
    validate_composable_security_policy(
        &request.security_policy,
        ClientSecurityPolicyContext {
            client_type: &request.client_type,
            authentication_method: &request.token_endpoint_auth_method,
            require_dpop_bound_tokens: request.require_dpop_bound_tokens,
            require_mtls_bound_tokens: request.require_mtls_bound_tokens,
            jwks_uri: request.jwks_uri.as_deref(),
            jwks: request.jwks.as_ref(),
        },
        crypto,
    )?;
    let (issued_secret, client_secret_hash) = if request.client_type == "confidential"
        && matches!(
            request.token_endpoint_auth_method.as_str(),
            "client_secret_basic" | "client_secret_post"
        ) {
        let (secret, digest) = crypto.issue_client_secret(&policy.client_secret_pepper);
        (Some(secret), Some(digest))
    } else {
        (None, None)
    };
    let subject_type = request.subject_type.unwrap_or_else(|| "public".to_owned());
    let redirect_uris = request.redirect_uris;
    let (sector_identifier_uri, sector_identifier_host) = pairwise_subject(
        &subject_type,
        request.sector_identifier_uri,
        &redirect_uris,
        policy.pairwise_subject_secret.as_deref(),
        sector_identifiers,
    )
    .await?;
    Ok(PreparedClientRegistration {
        tenant: policy.tenant,
        conformance_lease_id: request.conformance_lease_id,
        registration: ValidatedClientRegistration {
            client_id: format!("client-{}", Uuid::now_v7()),
            client_name: request.client_name,
            client_type: request.client_type,
            redirect_uris,
            post_logout_redirect_uris: trim_string_vec(request.post_logout_redirect_uris),
            scopes: request.scopes,
            allowed_audiences: request.allowed_audiences,
            grant_types: request.grant_types,
            token_endpoint_auth_method: request.token_endpoint_auth_method,
            subject_type,
            sector_identifier_uri,
            sector_identifier_host,
            require_dpop_bound_tokens: request.require_dpop_bound_tokens,
            allow_client_assertion_audience_array: request.allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience: request
                .allow_client_assertion_endpoint_audience,
            require_par_request_object: request.require_par_request_object,
            backchannel_token_delivery_mode: request.backchannel_token_delivery_mode,
            backchannel_client_notification_endpoint: trim_optional_string(
                request.backchannel_client_notification_endpoint,
            ),
            backchannel_authentication_request_signing_alg: trim_optional_string(
                request.backchannel_authentication_request_signing_alg,
            ),
            backchannel_user_code_parameter: request.backchannel_user_code_parameter,
            backchannel_logout_uri: trim_optional_string(request.backchannel_logout_uri),
            backchannel_logout_session_required: request.backchannel_logout_session_required,
            frontchannel_logout_uri: trim_optional_string(request.frontchannel_logout_uri),
            frontchannel_logout_session_required: request.frontchannel_logout_session_required,
            tls_client_auth_subject_dn: trim_optional_string(request.tls_client_auth_subject_dn),
            tls_client_auth_cert_sha256: trim_optional_string(request.tls_client_auth_cert_sha256),
            tls_client_auth_san_dns: trim_string_vec(request.tls_client_auth_san_dns),
            tls_client_auth_san_uri: trim_string_vec(request.tls_client_auth_san_uri),
            tls_client_auth_san_ip: trim_string_vec(request.tls_client_auth_san_ip),
            tls_client_auth_san_email: trim_string_vec(request.tls_client_auth_san_email),
            jwks_uri: trim_optional_string(request.jwks_uri),
            jwks: request.jwks,
            request_uris: trim_string_vec(request.request_uris),
            initiate_login_uri: trim_optional_string(request.initiate_login_uri),
            presentation: request.presentation,
            id_token_signed_response_alg: trim_optional_string(
                request.id_token_signed_response_alg,
            ),
            id_token_encrypted_response_alg: trim_optional_string(
                request.id_token_encrypted_response_alg,
            ),
            id_token_encrypted_response_enc: trim_optional_string(
                request.id_token_encrypted_response_enc,
            ),
            request_object_signing_alg: trim_optional_string(request.request_object_signing_alg),
            request_object_encryption_alg: trim_optional_string(
                request.request_object_encryption_alg,
            ),
            request_object_encryption_enc: trim_optional_string(
                request.request_object_encryption_enc,
            ),
            token_endpoint_auth_signing_alg: trim_optional_string(
                request.token_endpoint_auth_signing_alg,
            ),
            introspection_signed_response_alg: trim_optional_string(
                request.introspection_signed_response_alg,
            ),
            introspection_encrypted_response_alg: trim_optional_string(
                request.introspection_encrypted_response_alg,
            ),
            introspection_encrypted_response_enc: trim_optional_string(
                request.introspection_encrypted_response_enc,
            ),
            userinfo_signed_response_alg: trim_optional_string(
                request.userinfo_signed_response_alg,
            ),
            userinfo_encrypted_response_alg: trim_optional_string(
                request.userinfo_encrypted_response_alg,
            ),
            userinfo_encrypted_response_enc: trim_optional_string(
                request.userinfo_encrypted_response_enc,
            ),
            authorization_signed_response_alg: trim_optional_string(
                request.authorization_signed_response_alg,
            ),
            authorization_encrypted_response_alg: trim_optional_string(
                request.authorization_encrypted_response_alg,
            ),
            authorization_encrypted_response_enc: trim_optional_string(
                request.authorization_encrypted_response_enc,
            ),
            security_policy: Some(request.security_policy),
        },
        require_mtls_bound_tokens: request.require_mtls_bound_tokens,
        issued_secret,
        client_secret_hash,
        registration_access_token_blake3: None,
    })
}

async fn pairwise_subject<S: SectorIdentifierResolverPort + ?Sized>(
    subject_type: &str,
    sector_identifier_uri: Option<String>,
    redirect_uris: &[String],
    pairwise_subject_secret: Option<&str>,
    resolver: &S,
) -> Result<(Option<String>, Option<String>), AdminClientError> {
    if subject_type != "pairwise" {
        return Ok((None, None));
    }
    if pairwise_subject_secret.is_none() {
        return Err(AdminClientError::InvalidRequest(
            "pairwise 主题类型需要配置 PAIRWISE_SUBJECT_SECRET".to_owned(),
        ));
    }
    let host = match sector_identifier_uri.as_deref() {
        Some(uri) => {
            let uris = resolver.resolve(uri).await.map_err(|error| {
                AdminClientError::InvalidRequest(format!("sector_identifier_uri 获取失败: {error}"))
            })?;
            sector_identifier_host_for_redirects(uri, redirect_uris, &uris)?
        }
        None => super::helpers::all_same_host(redirect_uris).ok_or_else(|| {
            AdminClientError::InvalidRequest(
                "pairwise 主题需要 sector_identifier_uri 或所有 redirect_uri 使用同一 host"
                    .to_owned(),
            )
        })?,
    };
    Ok((sector_identifier_uri, Some(host)))
}
