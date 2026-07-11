//! token introspection 端点。
// 只处理 access/refresh token 活跃性查询。
use super::{
    TokenManagementClientAuthError, authenticate_introspection_client, parse_token_management_form,
    token_management_client_auth_error, token_management_form_error,
    token_management_has_conflicting_client_auth, token_management_oauth_error,
};
use crate::domain::Claims;
use crate::http::prelude::*;

const TOKEN_INTROSPECTION_JWT_MEDIA_TYPE: &str = "application/token-introspection+jwt";

pub(crate) async fn introspect(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }
    introspect_after_rate_limit(state, req, body).await
}

pub(crate) async fn introspect_after_rate_limit(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let form = match parse_token_management_form(&req, &body) {
        Ok(form) => form,
        Err(error) => return token_management_form_error(error),
    };

    let has_basic = has_basic_authorization_scheme(req.headers());
    if token_management_has_conflicting_client_auth(has_basic, &form) {
        return token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一请求不能同时使用多种客户端认证方式.",
        );
    }
    let credentials = extract_client_credentials(
        &req,
        &state.settings,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    let Some(client_id) = credentials.client_id.as_deref() else {
        return token_management_client_auth_error(
            TokenManagementClientAuthError::InvalidClient,
            has_basic,
        );
    };
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for token introspection client lookup");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    let client = match oauth_clients::table
        .filter(oauth_clients::tenant_id.eq(DEFAULT_TENANT_ID))
        .filter(oauth_clients::client_id.eq(client_id))
        .select(ClientRow::as_select())
        .first::<ClientRow>(&mut conn)
        .await
        .optional()
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return token_management_client_auth_error(
                TokenManagementClientAuthError::InvalidClient,
                has_basic,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for token introspection");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    drop(conn);
    if let Err(error) = authenticate_introspection_client(&state, &req, &client, &credentials).await
    {
        return token_management_client_auth_error(error, has_basic);
    }
    let use_signed_response = signed_introspection_requested(&req)
        && state
            .settings
            .authorization_server_profile
            .requires_signed_introspection();
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for token introspection state lookup");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "token 状态查询失败.",
            );
        }
    };
    if let Some(claims) = decode_access_claims(&state, &form.token) {
        if claims.client_id != client.client_id && !token_audience_allowed(&client, &claims.aud) {
            return introspection_response(
                &state,
                &client,
                json!({"active": false}),
                use_signed_response,
            )
            .await;
        }
        if access_token_tenant_id(&claims) != Some(client.tenant_id) {
            return introspection_response(
                &state,
                &client,
                json!({"active": false}),
                use_signed_response,
            )
            .await;
        }
        let revoked = match access_token_revocations::table
            .filter(access_token_revocations::tenant_id.eq(client.tenant_id))
            .filter(access_token_revocations::access_token_jti_blake3.eq(blake3_hex(&claims.jti)))
            .select(count_star())
            .first::<i64>(&mut conn)
            .await
        {
            Ok(count) => count > 0,
            Err(error) => {
                tracing::warn!(%error, "failed to query access token revocation state");
                return token_management_oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "token 状态查询失败.",
                );
            }
        };
        let active = !revoked && claims.exp > Utc::now().timestamp();
        if !active {
            return introspection_response(
                &state,
                &client,
                json!({"active": false}),
                use_signed_response,
            )
            .await;
        }
        return introspection_response(
            &state,
            &client,
            json!({
            "active": active,
            "scope": claims.scope,
            "client_id": claims.client_id,
            "token_type": introspection_access_token_type(&claims),
            "exp": claims.exp,
            "iat": claims.iat,
            "nbf": claims.nbf,
            "sub": claims.sub,
            "aud": claims.aud,
            "iss": claims.iss,
            "jti": claims.jti
            }),
            use_signed_response,
        )
        .await;
    }
    let hash = blake3_hex(&form.token);
    let token = match oauth_tokens::table
        .filter(oauth_tokens::tenant_id.eq(client.tenant_id))
        .filter(oauth_tokens::refresh_token_blake3.eq(hash))
        .select(TokenRow::as_select())
        .first::<TokenRow>(&mut conn)
        .await
        .optional()
    {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to query refresh token introspection state");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "token 状态查询失败.",
            );
        }
    };
    if let Some(token) = token {
        if token.client_id != client.id {
            return introspection_response(
                &state,
                &client,
                json!({"active": false}),
                use_signed_response,
            )
            .await;
        }
        let active = token.revoked_at.is_none() && token.expires_at > Utc::now();
        if !active {
            return introspection_response(
                &state,
                &client,
                json!({"active": false}),
                use_signed_response,
            )
            .await;
        }
        return introspection_response(
            &state,
            &client,
            active_refresh_token_introspection_body(&token, &client.client_id),
            use_signed_response,
        )
        .await;
    }
    introspection_response(
        &state,
        &client,
        json!({"active": false}),
        use_signed_response,
    )
    .await
}

fn signed_introspection_requested(req: &HttpRequest) -> bool {
    req.headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|part| {
                part.split(';').next().is_some_and(|media_type| {
                    media_type.trim() == TOKEN_INTROSPECTION_JWT_MEDIA_TYPE
                })
            })
        })
}

async fn introspection_response(
    state: &AppState,
    resource_server: &ClientRow,
    body: Value,
    signed: bool,
) -> HttpResponse {
    if !signed {
        return json_response_no_store(body);
    }
    match signed_introspection_response(state, resource_server, body).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "failed to build token introspection JWT response");
            token_management_oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "token introspection JWT response build failed.",
            )
        }
    }
}

async fn signed_introspection_response(
    state: &AppState,
    resource_server: &ClientRow,
    body: Value,
) -> anyhow::Result<HttpResponse> {
    let keyset = state.keyset.snapshot();
    let mut header = jsonwebtoken::Header::new(keyset.active_alg);
    header.typ = Some("token-introspection+jwt".to_owned());
    header.kid = Some(keyset.active_kid.clone());
    let claims = json!({
        "iss": state.settings.issuer,
        "aud": resource_server.client_id,
        "iat": Utc::now().timestamp(),
        "token_introspection": body
    });
    let token = keyset.sign_jwt(&header, &claims).await?;
    let token = match introspection_encryption_key(resource_server)? {
        Some(key) => encrypt_compact_jwe(&key, token.as_bytes(), JwePayloadKind::NestedJwt)?,
        None => token,
    };
    Ok(HttpResponse::Ok()
        .insert_header((
            header::CONTENT_TYPE,
            HeaderValue::from_static(TOKEN_INTROSPECTION_JWT_MEDIA_TYPE),
        ))
        .insert_header((header::CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .insert_header((header::PRAGMA, HeaderValue::from_static("no-cache")))
        .body(token))
}

fn introspection_encryption_key(
    resource_server: &ClientRow,
) -> anyhow::Result<Option<ClientJweKey<'_>>> {
    client_jwe_key(
        resource_server.jwks.as_ref(),
        resource_server
            .introspection_encrypted_response_alg
            .as_deref(),
        resource_server
            .introspection_encrypted_response_enc
            .as_deref(),
        "introspection",
    )
}

fn introspection_access_token_type(claims: &Claims) -> &'static str {
    if claims
        .cnf
        .as_ref()
        .and_then(|cnf| cnf.jkt.as_ref())
        .is_some()
    {
        "DPoP"
    } else {
        "Bearer"
    }
}

fn active_refresh_token_introspection_body(token: &TokenRow, client_id: &str) -> Value {
    json!({
        "active": true,
        "scope": json_array_to_strings(&token.scopes).join(" "),
        "client_id": client_id,
        "exp": token.expires_at.timestamp(),
        "iat": token.issued_at.timestamp(),
        "sub": token.subject
    })
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/introspect.rs"]
mod tests;
