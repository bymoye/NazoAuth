//! 管理端客户端更新端点。
// PATCH 请求只覆盖显式提交的字段，其余字段保持数据库当前值。
use super::create::{
    all_same_host, sector_identifier_host_for_redirects, trim_optional_string,
    validate_pkce_compatibility_policy,
};
use crate::http::prelude::*;

#[derive(Deserialize)]
pub(crate) struct PatchClientRequest {
    client_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    post_logout_redirect_uris: Option<Vec<String>>,
    scopes: Option<Vec<String>>,
    allowed_audiences: Option<Vec<String>>,
    grant_types: Option<Vec<String>>,
    require_dpop_bound_tokens: Option<bool>,
    allow_client_assertion_audience_array: Option<bool>,
    allow_client_assertion_endpoint_audience: Option<bool>,
    require_par_request_object: Option<bool>,
    allow_authorization_code_without_pkce: Option<bool>,
    subject_type: Option<String>,
    sector_identifier_uri: Option<String>,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: Option<bool>,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: Option<bool>,
    tls_client_auth_subject_dn: Option<String>,
    tls_client_auth_cert_sha256: Option<String>,
    tls_client_auth_san_dns: Option<Vec<String>>,
    tls_client_auth_san_uri: Option<Vec<String>>,
    tls_client_auth_san_ip: Option<Vec<String>>,
    tls_client_auth_san_email: Option<Vec<String>>,
    jwks: Option<Value>,
    introspection_encrypted_response_alg: Option<String>,
    introspection_encrypted_response_enc: Option<String>,
    userinfo_signed_response_alg: Option<String>,
    userinfo_encrypted_response_alg: Option<String>,
    userinfo_encrypted_response_enc: Option<String>,
    authorization_signed_response_alg: Option<String>,
    authorization_encrypted_response_alg: Option<String>,
    authorization_encrypted_response_enc: Option<String>,
    is_active: Option<bool>,
}

struct PreparedClientPatch {
    client_name: String,
    redirect_uris: Value,
    post_logout_redirect_uris: Value,
    scopes: Value,
    allowed_audiences: Value,
    grant_types: Value,
    require_dpop_bound_tokens: bool,
    allow_client_assertion_audience_array: bool,
    allow_client_assertion_endpoint_audience: bool,
    require_par_request_object: bool,
    allow_authorization_code_without_pkce: bool,
    subject_type: String,
    sector_identifier_uri: Option<String>,
    sector_identifier_host: Option<String>,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: bool,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: bool,
    tls_client_auth_subject_dn: Option<String>,
    tls_client_auth_cert_sha256: Option<String>,
    tls_client_auth_san_dns: Value,
    tls_client_auth_san_uri: Value,
    tls_client_auth_san_ip: Value,
    tls_client_auth_san_email: Value,
    jwks: Option<Value>,
    introspection_encrypted_response_alg: Option<String>,
    introspection_encrypted_response_enc: Option<String>,
    userinfo_signed_response_alg: Option<String>,
    userinfo_encrypted_response_alg: Option<String>,
    userinfo_encrypted_response_enc: Option<String>,
    authorization_signed_response_alg: Option<String>,
    authorization_encrypted_response_alg: Option<String>,
    authorization_encrypted_response_enc: Option<String>,
    is_active: bool,
}

/// 局部更新 OAuth 客户端配置。
pub(crate) async fn admin_patch_client(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
    Json(payload): Json<PatchClientRequest>,
) -> HttpResponse {
    let client_id = path.into_inner();
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    if let Err(response) = require_admin_or_forbidden(&state, &req).await {
        return response;
    }

    let current = match find_client(&state.diesel_db, &client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该客户端.");
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for admin update");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };

    let response_signing_algorithms = state
        .keyset
        .snapshot()
        .response_signing_alg_values_supported();
    let prepared = match prepare_client_patch(
        &current,
        payload,
        state.settings.pairwise_subject_secret.as_deref(),
        &state.settings.issuer,
        &response_signing_algorithms,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("客户端更新失败: {error}"),
            );
        }
    };
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for client update");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端更新失败.",
            );
        }
    };
    let client = match diesel::update(
        oauth_clients::table.filter(oauth_clients::client_id.eq(&current.client_id)),
    )
    .set((
        oauth_clients::client_name.eq(prepared.client_name),
        oauth_clients::redirect_uris.eq(prepared.redirect_uris),
        oauth_clients::post_logout_redirect_uris.eq(prepared.post_logout_redirect_uris),
        oauth_clients::scopes.eq(prepared.scopes),
        oauth_clients::allowed_audiences.eq(prepared.allowed_audiences),
        oauth_clients::grant_types.eq(prepared.grant_types),
        oauth_clients::subject_type.eq(&prepared.subject_type),
        oauth_clients::sector_identifier_uri.eq(&prepared.sector_identifier_uri),
        oauth_clients::sector_identifier_host.eq(&prepared.sector_identifier_host),
        oauth_clients::require_dpop_bound_tokens.eq(prepared.require_dpop_bound_tokens),
        oauth_clients::allow_client_assertion_audience_array
            .eq(prepared.allow_client_assertion_audience_array),
        oauth_clients::allow_client_assertion_endpoint_audience
            .eq(prepared.allow_client_assertion_endpoint_audience),
        oauth_clients::require_par_request_object.eq(prepared.require_par_request_object),
        oauth_clients::allow_authorization_code_without_pkce
            .eq(prepared.allow_authorization_code_without_pkce),
        oauth_clients::backchannel_logout_uri.eq(prepared.backchannel_logout_uri),
        oauth_clients::backchannel_logout_session_required
            .eq(prepared.backchannel_logout_session_required),
        oauth_clients::frontchannel_logout_uri.eq(prepared.frontchannel_logout_uri),
        oauth_clients::frontchannel_logout_session_required
            .eq(prepared.frontchannel_logout_session_required),
        oauth_clients::tls_client_auth_subject_dn.eq(prepared.tls_client_auth_subject_dn),
        oauth_clients::tls_client_auth_cert_sha256.eq(prepared.tls_client_auth_cert_sha256),
        oauth_clients::tls_client_auth_san_dns.eq(prepared.tls_client_auth_san_dns),
        oauth_clients::tls_client_auth_san_uri.eq(prepared.tls_client_auth_san_uri),
        oauth_clients::tls_client_auth_san_ip.eq(prepared.tls_client_auth_san_ip),
        oauth_clients::tls_client_auth_san_email.eq(prepared.tls_client_auth_san_email),
        oauth_clients::jwks.eq(prepared.jwks),
        oauth_clients::introspection_encrypted_response_alg
            .eq(prepared.introspection_encrypted_response_alg),
        oauth_clients::introspection_encrypted_response_enc
            .eq(prepared.introspection_encrypted_response_enc),
        oauth_clients::userinfo_signed_response_alg.eq(prepared.userinfo_signed_response_alg),
        oauth_clients::userinfo_encrypted_response_alg.eq(prepared.userinfo_encrypted_response_alg),
        oauth_clients::userinfo_encrypted_response_enc.eq(prepared.userinfo_encrypted_response_enc),
        oauth_clients::authorization_signed_response_alg
            .eq(prepared.authorization_signed_response_alg),
        oauth_clients::authorization_encrypted_response_alg
            .eq(prepared.authorization_encrypted_response_alg),
        oauth_clients::authorization_encrypted_response_enc
            .eq(prepared.authorization_encrypted_response_enc),
        oauth_clients::is_active.eq(prepared.is_active),
        oauth_clients::updated_at.eq(diesel_now),
    ))
    .returning(ClientRow::as_returning())
    .get_result::<ClientRow>(&mut conn)
    .await
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(%error, "failed to update oauth client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端更新失败.",
            );
        }
    };

    audit_event(
        "client_updated",
        audit_fields(&[
            ("client_id", json!(client.client_id)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(&req, &state.settings))),
            ),
        ]),
    );
    json_response(client_json(client))
}

async fn prepare_client_patch(
    current: &ClientRow,
    payload: PatchClientRequest,
    pairwise_subject_secret: Option<&str>,
    _issuer: &str,
    response_signing_algorithms: &[&'static str],
) -> anyhow::Result<PreparedClientPatch> {
    let new_client_name = payload
        .client_name
        .unwrap_or_else(|| current.client_name.clone());
    let redirect_uris_changed = payload.redirect_uris.is_some();
    let new_redirect_uri_values = payload
        .redirect_uris
        .unwrap_or_else(|| json_array_to_strings(&current.redirect_uris));
    let new_post_logout_redirect_uri_values = payload
        .post_logout_redirect_uris
        .unwrap_or_else(|| json_array_to_strings(&current.post_logout_redirect_uris));
    let new_scope_values = payload
        .scopes
        .unwrap_or_else(|| json_array_to_strings(&current.scopes));
    let new_audience_values = payload
        .allowed_audiences
        .unwrap_or_else(|| json_array_to_strings(&current.allowed_audiences));
    let new_grant_type_values = payload
        .grant_types
        .unwrap_or_else(|| json_array_to_strings(&current.grant_types));
    let new_require_dpop_bound_tokens = payload
        .require_dpop_bound_tokens
        .unwrap_or(current.require_dpop_bound_tokens);
    let new_allow_client_assertion_audience_array = payload
        .allow_client_assertion_audience_array
        .unwrap_or(current.allow_client_assertion_audience_array);
    let new_allow_client_assertion_endpoint_audience = payload
        .allow_client_assertion_endpoint_audience
        .unwrap_or(current.allow_client_assertion_endpoint_audience);
    let new_require_par_request_object = payload
        .require_par_request_object
        .unwrap_or(current.require_par_request_object);
    let new_allow_authorization_code_without_pkce = payload
        .allow_authorization_code_without_pkce
        .unwrap_or(current.allow_authorization_code_without_pkce);
    let new_backchannel_logout_uri = payload
        .backchannel_logout_uri
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.backchannel_logout_uri.clone());
    let new_backchannel_logout_session_required = payload
        .backchannel_logout_session_required
        .unwrap_or(current.backchannel_logout_session_required);
    let new_frontchannel_logout_uri = payload
        .frontchannel_logout_uri
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.frontchannel_logout_uri.clone());
    let new_frontchannel_logout_session_required = payload
        .frontchannel_logout_session_required
        .unwrap_or(current.frontchannel_logout_session_required);
    let new_tls_client_auth_subject_dn = payload
        .tls_client_auth_subject_dn
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.tls_client_auth_subject_dn.clone());
    let new_tls_client_auth_cert_sha256 = payload
        .tls_client_auth_cert_sha256
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.tls_client_auth_cert_sha256.clone());
    let new_tls_client_auth_san_dns_values = payload
        .tls_client_auth_san_dns
        .unwrap_or_else(|| json_array_to_strings(&current.tls_client_auth_san_dns));
    let new_tls_client_auth_san_uri_values = payload
        .tls_client_auth_san_uri
        .unwrap_or_else(|| json_array_to_strings(&current.tls_client_auth_san_uri));
    let new_tls_client_auth_san_ip_values = payload
        .tls_client_auth_san_ip
        .unwrap_or_else(|| json_array_to_strings(&current.tls_client_auth_san_ip));
    let new_tls_client_auth_san_email_values = payload
        .tls_client_auth_san_email
        .unwrap_or_else(|| json_array_to_strings(&current.tls_client_auth_san_email));
    let new_jwks = payload.jwks.or_else(|| current.jwks.clone());
    let new_introspection_encrypted_response_alg = payload
        .introspection_encrypted_response_alg
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.introspection_encrypted_response_alg.clone());
    let new_introspection_encrypted_response_enc = payload
        .introspection_encrypted_response_enc
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.introspection_encrypted_response_enc.clone());
    let new_userinfo_signed_response_alg = payload
        .userinfo_signed_response_alg
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.userinfo_signed_response_alg.clone());
    let new_userinfo_encrypted_response_alg = payload
        .userinfo_encrypted_response_alg
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.userinfo_encrypted_response_alg.clone());
    let new_userinfo_encrypted_response_enc = payload
        .userinfo_encrypted_response_enc
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.userinfo_encrypted_response_enc.clone());
    let new_authorization_signed_response_alg = payload
        .authorization_signed_response_alg
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.authorization_signed_response_alg.clone());
    let new_authorization_encrypted_response_alg = payload
        .authorization_encrypted_response_alg
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.authorization_encrypted_response_alg.clone());
    let new_authorization_encrypted_response_enc = payload
        .authorization_encrypted_response_enc
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.authorization_encrypted_response_enc.clone());
    let new_is_active = payload.is_active.unwrap_or(current.is_active);

    let new_subject_type = payload
        .subject_type
        .unwrap_or_else(|| current.subject_type.clone());
    let requested_sector_identifier_uri = match payload.sector_identifier_uri {
        Some(_) if current.sector_identifier_uri.is_some() => {
            anyhow::bail!("已配置 pairwise 客户端的 sector_identifier_uri 不可修改");
        }
        Some(uri) => Some(uri),
        None => current.sector_identifier_uri.clone(),
    };
    let (new_sector_identifier_uri, new_sector_identifier_host) = if new_subject_type != "pairwise"
    {
        (None, None)
    } else {
        if pairwise_subject_secret.is_none() {
            anyhow::bail!("pairwise 主题类型需要配置 PAIRWISE_SUBJECT_SECRET");
        }
        let sector_identifier_host = match &requested_sector_identifier_uri {
            Some(uri)
                if !redirect_uris_changed
                    && current.sector_identifier_uri.as_deref() == Some(uri.as_str())
                    && current.sector_identifier_host.is_some() =>
            {
                current
                    .sector_identifier_host
                    .clone()
                    .expect("checked sector_identifier_host is present")
            }
            Some(uri) => {
                let uris = fetch_sector_identifier_uris(uri)
                    .await
                    .map_err(|e| anyhow::anyhow!("sector_identifier_uri 获取失败: {:?}", e))?;
                sector_identifier_host_for_redirects(uri, &new_redirect_uri_values, &uris)?
            }
            None => {
                if let Some(ref host) = current.sector_identifier_host {
                    host.clone()
                } else {
                    all_same_host(&new_redirect_uri_values).ok_or_else(|| {
                        anyhow::anyhow!(
                            "pairwise 主题需要 sector_identifier_uri 或所有 redirect_uri 使用同一 host"
                        )
                    })?
                }
            }
        };
        (
            requested_sector_identifier_uri,
            Some(sector_identifier_host),
        )
    };

    validate_pkce_compatibility_policy(
        new_allow_authorization_code_without_pkce,
        &current.client_type,
        new_require_dpop_bound_tokens,
    )
    .and_then(|()| {
        validate_client_metadata(ClientMetadata {
            client_type: &current.client_type,
            redirect_uris: &new_redirect_uri_values,
            post_logout_redirect_uris: &new_post_logout_redirect_uri_values,
            scopes: &new_scope_values,
            allowed_audiences: &new_audience_values,
            grant_types: &new_grant_type_values,
            token_endpoint_auth_method: &current.token_endpoint_auth_method,
            backchannel_logout_uri: new_backchannel_logout_uri.as_deref(),
            frontchannel_logout_uri: new_frontchannel_logout_uri.as_deref(),
            jwks: new_jwks.as_ref(),
            allow_jwks_without_kid: false,
            introspection_encrypted_response_alg: new_introspection_encrypted_response_alg
                .as_deref(),
            introspection_encrypted_response_enc: new_introspection_encrypted_response_enc
                .as_deref(),
            userinfo_signed_response_alg: new_userinfo_signed_response_alg.as_deref(),
            userinfo_encrypted_response_alg: new_userinfo_encrypted_response_alg.as_deref(),
            userinfo_encrypted_response_enc: new_userinfo_encrypted_response_enc.as_deref(),
            authorization_signed_response_alg: new_authorization_signed_response_alg.as_deref(),
            authorization_encrypted_response_alg: new_authorization_encrypted_response_alg
                .as_deref(),
            authorization_encrypted_response_enc: new_authorization_encrypted_response_enc
                .as_deref(),
            response_signing_algorithms,
            mtls_binding: Some(&ClientMtlsMetadata {
                tls_client_auth_subject_dn: new_tls_client_auth_subject_dn.clone(),
                tls_client_auth_cert_sha256: new_tls_client_auth_cert_sha256.clone(),
                tls_client_auth_san_dns: new_tls_client_auth_san_dns_values.clone(),
                tls_client_auth_san_uri: new_tls_client_auth_san_uri_values.clone(),
                tls_client_auth_san_ip: new_tls_client_auth_san_ip_values.clone(),
                tls_client_auth_san_email: new_tls_client_auth_san_email_values.clone(),
            }),
        })
    })?;
    Ok(PreparedClientPatch {
        client_name: new_client_name,
        redirect_uris: json!(new_redirect_uri_values),
        post_logout_redirect_uris: json!(new_post_logout_redirect_uri_values),
        scopes: json!(new_scope_values),
        allowed_audiences: json!(new_audience_values),
        grant_types: json!(new_grant_type_values),
        require_dpop_bound_tokens: new_require_dpop_bound_tokens,
        allow_client_assertion_audience_array: new_allow_client_assertion_audience_array,
        allow_client_assertion_endpoint_audience: new_allow_client_assertion_endpoint_audience,
        require_par_request_object: new_require_par_request_object,
        allow_authorization_code_without_pkce: new_allow_authorization_code_without_pkce,
        subject_type: new_subject_type,
        sector_identifier_uri: new_sector_identifier_uri,
        sector_identifier_host: new_sector_identifier_host,
        backchannel_logout_uri: new_backchannel_logout_uri,
        backchannel_logout_session_required: new_backchannel_logout_session_required,
        frontchannel_logout_uri: new_frontchannel_logout_uri,
        frontchannel_logout_session_required: new_frontchannel_logout_session_required,
        tls_client_auth_subject_dn: new_tls_client_auth_subject_dn,
        tls_client_auth_cert_sha256: new_tls_client_auth_cert_sha256,
        tls_client_auth_san_dns: json!(new_tls_client_auth_san_dns_values),
        tls_client_auth_san_uri: json!(new_tls_client_auth_san_uri_values),
        tls_client_auth_san_ip: json!(new_tls_client_auth_san_ip_values),
        tls_client_auth_san_email: json!(new_tls_client_auth_san_email_values),
        jwks: new_jwks,
        introspection_encrypted_response_alg: new_introspection_encrypted_response_alg,
        introspection_encrypted_response_enc: new_introspection_encrypted_response_enc,
        userinfo_signed_response_alg: new_userinfo_signed_response_alg,
        userinfo_encrypted_response_alg: new_userinfo_encrypted_response_alg,
        userinfo_encrypted_response_enc: new_userinfo_encrypted_response_enc,
        authorization_signed_response_alg: new_authorization_signed_response_alg,
        authorization_encrypted_response_alg: new_authorization_encrypted_response_alg,
        authorization_encrypted_response_enc: new_authorization_encrypted_response_enc,
        is_active: new_is_active,
    })
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/admin/clients/tests/update.rs"]
mod tests;
