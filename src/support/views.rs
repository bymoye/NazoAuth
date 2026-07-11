//! JSON view 组装函数。
// 将数据库行转换为前端和管理端直接消费的 JSON 形状。

use super::prelude::*;

pub(crate) async fn auth_me_json(state: &AppState, user: &UserRow) -> anyhow::Result<Value> {
    let count = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => {
            user_client_grants::table
                .filter(user_client_grants::user_id.eq(user.id))
                .select(count(user_client_grants::client_id).aggregate_distinct())
                .first::<i64>(&mut conn)
                .await?
        }
        Err(error) => return Err(error),
    };
    Ok(json!({
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
        "given_name": user.given_name,
        "family_name": user.family_name,
        "middle_name": user.middle_name,
        "nickname": user.nickname,
        "profile_url": user.profile_url,
        "website_url": user.website_url,
        "gender": user.gender,
        "birthdate": user.birthdate,
        "zoneinfo": user.zoneinfo,
        "locale": user.locale,
        "address_formatted": user.address_formatted,
        "address_street_address": user.address_street_address,
        "address_locality": user.address_locality,
        "address_region": user.address_region,
        "address_postal_code": user.address_postal_code,
        "address_country": user.address_country,
        "phone_number": user.phone_number,
        "phone_number_verified": user.phone_number_verified,
        "mfa_enabled": user.mfa_enabled,
        "role": user.role,
        "admin_level": user.admin_level,
        "authorized_app_count": count
    }))
}

pub(crate) fn is_cross_site_fetch(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().eq_ignore_ascii_case("cross-site"))
        .unwrap_or(false)
}

pub(crate) fn admin_user_json(user: UserRow) -> Value {
    json!({
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "given_name": user.given_name,
        "family_name": user.family_name,
        "middle_name": user.middle_name,
        "nickname": user.nickname,
        "profile_url": user.profile_url,
        "website_url": user.website_url,
        "gender": user.gender,
        "birthdate": user.birthdate,
        "zoneinfo": user.zoneinfo,
        "locale": user.locale,
        "address_formatted": user.address_formatted,
        "address_street_address": user.address_street_address,
        "address_locality": user.address_locality,
        "address_region": user.address_region,
        "address_postal_code": user.address_postal_code,
        "address_country": user.address_country,
        "phone_number": user.phone_number,
        "phone_number_verified": user.phone_number_verified,
        "mfa_enabled": user.mfa_enabled,
        "is_active": user.is_active,
        "role": user.role,
        "admin_level": user.admin_level,
        "created_at": user.created_at
    })
}

pub(crate) fn client_json(client: ClientRow) -> Value {
    json!({
        "client_id": client.client_id,
        "client_name": client.client_name,
        "client_type": client.client_type,
        "redirect_uris": json_array_to_strings(&client.redirect_uris),
        "post_logout_redirect_uris": json_array_to_strings(&client.post_logout_redirect_uris),
        "scopes": json_array_to_strings(&client.scopes),
        "allowed_audiences": json_array_to_strings(&client.allowed_audiences),
        "grant_types": json_array_to_strings(&client.grant_types),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "require_dpop_bound_tokens": client.require_dpop_bound_tokens,
        "subject_type": client.subject_type,
        "sector_identifier_uri": client.sector_identifier_uri,
        "sector_identifier_host": client.sector_identifier_host,
        "require_mtls_bound_tokens": client.require_mtls_bound_tokens,
        "tls_client_auth_subject_dn": client.tls_client_auth_subject_dn,
        "tls_client_auth_cert_sha256": client.tls_client_auth_cert_sha256,
        "tls_client_auth_san_dns": json_array_to_strings(&client.tls_client_auth_san_dns),
        "tls_client_auth_san_uri": json_array_to_strings(&client.tls_client_auth_san_uri),
        "tls_client_auth_san_ip": json_array_to_strings(&client.tls_client_auth_san_ip),
        "tls_client_auth_san_email": json_array_to_strings(&client.tls_client_auth_san_email),
        "allow_client_assertion_audience_array": client.allow_client_assertion_audience_array,
        "allow_client_assertion_endpoint_audience": client.allow_client_assertion_endpoint_audience,
        "require_par_request_object": client.require_par_request_object,
        "allow_authorization_code_without_pkce": client.allow_authorization_code_without_pkce,
        "backchannel_logout_uri": client.backchannel_logout_uri,
        "backchannel_logout_session_required": client.backchannel_logout_session_required,
        "frontchannel_logout_uri": client.frontchannel_logout_uri,
        "frontchannel_logout_session_required": client.frontchannel_logout_session_required,
        "is_active": client.is_active,
        "jwks": client.jwks,
        "introspection_encrypted_response_alg": client.introspection_encrypted_response_alg,
        "introspection_encrypted_response_enc": client.introspection_encrypted_response_enc,
        "userinfo_signed_response_alg": client.userinfo_signed_response_alg,
        "userinfo_encrypted_response_alg": client.userinfo_encrypted_response_alg,
        "userinfo_encrypted_response_enc": client.userinfo_encrypted_response_enc,
        "authorization_signed_response_alg": client.authorization_signed_response_alg,
        "authorization_encrypted_response_alg": client.authorization_encrypted_response_alg,
        "authorization_encrypted_response_enc": client.authorization_encrypted_response_enc
    })
}

pub(crate) fn pagination(q: &HashMap<String, String>) -> (i32, i32, i32) {
    let page = q
        .get("page")
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1);
    let page_size = q
        .get("page_size")
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(20)
        .min(100);
    let offset = (page - 1) * page_size;
    (page, page_size, offset)
}

pub(crate) fn append_query(base: &str, pairs: &[(&str, &str)]) -> String {
    let Ok(mut url) = url::Url::parse(base) else {
        return base.to_owned();
    };
    {
        let mut qp = url.query_pairs_mut();
        for (k, v) in pairs {
            if !v.is_empty() {
                qp.append_pair(k, v);
            }
        }
    }
    url.to_string()
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/views.rs"]
mod tests;
