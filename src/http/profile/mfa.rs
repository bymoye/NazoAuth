//! MFA enrollment, challenge, and step-up endpoints.
use crate::http::prelude::*;

#[derive(Deserialize)]
pub(crate) struct ConfirmTotpRequest {
    code: String,
}

#[derive(Deserialize)]
pub(crate) struct MfaChallengeRequest {
    code: String,
    remember_device: Option<bool>,
}

#[derive(Deserialize)]
pub(crate) struct MfaProtectedRequest {
    code: String,
}

#[derive(Queryable)]
struct TotpCredentialRow {
    id: Uuid,
    secret_base32: String,
    confirmed_at: Option<DateTime<Utc>>,
    last_used_step: Option<i64>,
}

pub(crate) async fn mfa_totp_begin(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(_) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "数据库连接失败.",
            );
        }
    };
    let existing = match load_totp_credential(&mut conn, &user).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to load TOTP credential");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 凭据查询失败.",
            );
        }
    };
    if existing
        .as_ref()
        .is_some_and(|credential| credential.confirmed_at.is_some())
    {
        return oauth_error(StatusCode::CONFLICT, "invalid_request", "TOTP MFA 已启用.");
    }

    let secret = generate_totp_secret_base32();
    let label = format!("{} ({})", user.email, state.settings.issuer);
    let result = if let Some(credential) = existing {
        diesel::update(user_totp_credentials::table.find(credential.id))
            .set((
                user_totp_credentials::secret_base32.eq(&secret),
                user_totp_credentials::label.eq(&label),
                user_totp_credentials::confirmed_at.eq::<Option<DateTime<Utc>>>(None),
                user_totp_credentials::last_used_step.eq::<Option<i64>>(None),
                user_totp_credentials::updated_at.eq(diesel_now),
            ))
            .execute(&mut conn)
            .await
    } else {
        diesel::insert_into(user_totp_credentials::table)
            .values((
                user_totp_credentials::tenant_id.eq(user.tenant_id),
                user_totp_credentials::user_id.eq(user.id),
                user_totp_credentials::secret_base32.eq(&secret),
                user_totp_credentials::label.eq(&label),
            ))
            .execute(&mut conn)
            .await
    };
    if let Err(error) = result {
        tracing::warn!(%error, "failed to store TOTP enrollment secret");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "MFA 凭据写入失败.",
        );
    }

    json_response(json!({
        "secret_base32": secret,
        "otpauth_uri": otpauth_uri(&state.settings.issuer, &user.email, &secret),
        "period": MFA_TOTP_PERIOD_SECONDS,
        "digits": MFA_TOTP_DIGITS
    }))
}

pub(crate) async fn mfa_totp_confirm(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<ConfirmTotpRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(_) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "数据库连接失败.",
            );
        }
    };
    let credential = match load_totp_credential(&mut conn, &user).await {
        Ok(Some(credential)) if credential.confirmed_at.is_none() => credential,
        Ok(Some(_)) => {
            return oauth_error(StatusCode::CONFLICT, "invalid_request", "TOTP MFA 已启用.");
        }
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "请先开始 TOTP MFA 注册.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load TOTP credential");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 凭据查询失败.",
            );
        }
    };
    let Some(step) = verified_totp_step(
        &credential.secret_base32,
        &payload.code,
        Utc::now().timestamp(),
        credential.last_used_step,
    ) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "MFA 验证码无效.");
    };
    let rotation =
        match step_up_current_session(&state, &req, MfaVerificationMethod::Totp.amr()).await {
            Ok(Some(rotation)) => rotation,
            Ok(None) => {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "login_required",
                    "当前会话已过期.",
                );
            }
            Err(error) => {
                tracing::warn!(%error, "failed to step up current session before TOTP enrollment");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "会话写入失败.",
                );
            }
        };
    let confirm_result = diesel::update(user_totp_credentials::table.find(credential.id))
        .set((
            user_totp_credentials::confirmed_at.eq(Utc::now()),
            user_totp_credentials::last_used_step.eq(step),
            user_totp_credentials::updated_at.eq(diesel_now),
        ))
        .execute(&mut conn)
        .await;
    if let Err(error) = confirm_result {
        tracing::warn!(%error, "failed to confirm TOTP credential");
        return with_rotated_session_cookies(
            &state,
            &rotation,
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 启用失败.",
            ),
        );
    }
    if let Err(error) = diesel::update(
        users::table
            .find(user.id)
            .filter(users::tenant_id.eq(user.tenant_id)),
    )
    .set((
        users::mfa_enabled.eq(true),
        users::updated_at.eq(diesel_now),
    ))
    .execute(&mut conn)
    .await
    {
        tracing::warn!(%error, "failed to enable MFA flag");
        return with_rotated_session_cookies(
            &state,
            &rotation,
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 启用失败.",
            ),
        );
    }
    let backup_codes = match replace_backup_codes(&state.diesel_db, &user).await {
        Ok(codes) => codes,
        Err(error) => {
            tracing::warn!(%error, "failed to generate backup codes");
            return with_rotated_session_cookies(
                &state,
                &rotation,
                oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "备份码生成失败.",
                ),
            );
        }
    };
    audit_event(
        "mfa_totp_enabled",
        audit_fields(&[("user_id", json!(user.id)), ("method", json!("totp"))]),
    );
    with_cookie_headers(
        json_response(json!({
            "mfa_enabled": true,
            "backup_codes": backup_codes
        })),
        &rotated_session_cookies(&state, &rotation),
    )
}

pub(crate) async fn mfa_verify(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<MfaChallengeRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let session = match current_pending_mfa_session(&state, &req).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "没有待完成的 MFA 登录挑战.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to resolve pending MFA session");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话查询失败.",
            );
        }
    };
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    let method = match verify_user_mfa_code(&state.diesel_db, &session.user, &payload.code).await {
        Ok(Some(method)) => method,
        Ok(None) => {
            audit_event(
                "mfa_challenge_failure",
                audit_fields(&[("user_id", json!(session.user.id))]),
            );
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "MFA 验证码无效.");
        }
        Err(error) => {
            tracing::warn!(%error, "failed to verify MFA challenge");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 验证失败.",
            );
        }
    };
    let mut cookies = Vec::new();
    if payload.remember_device.unwrap_or(false) {
        match remember_mfa_device(&state, &req, &session.user).await {
            Ok(token) => cookies.push(make_cookie(
                MFA_REMEMBERED_COOKIE_NAME,
                &token,
                true,
                MFA_REMEMBERED_TTL_SECONDS,
                state.settings.cookie_secure,
            )),
            Err(error) => {
                tracing::warn!(%error, "failed to remember MFA device");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "MFA 设备记住失败.",
                );
            }
        }
    }
    let rotation = match complete_mfa_session(&state, &req, method.amr()).await {
        Ok(Some(rotation)) => rotation,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "MFA 登录挑战已过期.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to complete MFA session");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话写入失败.",
            );
        }
    };
    cookies.extend(rotated_session_cookies(&state, &rotation));
    audit_event(
        "mfa_challenge_success",
        audit_fields(&[
            ("user_id", json!(session.user.id)),
            ("method", json!(method.amr())),
        ]),
    );
    with_cookie_headers(
        json_response(json!({
            "success": true,
            "method": method.amr()
        })),
        &cookies,
    )
}

pub(crate) async fn mfa_backup_codes_regenerate(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    if !user.mfa_enabled {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "MFA 未启用.");
    }
    let method = match verify_user_mfa_code(&state.diesel_db, &user, &payload.code).await {
        Ok(Some(method)) => method,
        Ok(None) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "MFA 验证码无效.");
        }
        Err(error) => {
            tracing::warn!(%error, "failed to verify MFA for backup code regeneration");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 验证失败.",
            );
        }
    };
    let rotation = match step_up_current_session(&state, &req, method.amr()).await {
        Ok(Some(rotation)) => rotation,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "当前会话已过期.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to step up session before backup code regeneration");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话写入失败.",
            );
        }
    };
    let backup_codes = match replace_backup_codes(&state.diesel_db, &user).await {
        Ok(codes) => codes,
        Err(error) => {
            tracing::warn!(%error, "failed to regenerate backup codes");
            return with_rotated_session_cookies(
                &state,
                &rotation,
                oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "备份码生成失败.",
                ),
            );
        }
    };
    audit_event(
        "mfa_backup_codes_regenerated",
        audit_fields(&[("user_id", json!(user.id)), ("method", json!(method.amr()))]),
    );
    with_cookie_headers(
        json_response(json!({ "backup_codes": backup_codes })),
        &rotated_session_cookies(&state, &rotation),
    )
}

fn rotated_session_cookies(
    state: &AppState,
    rotation: &SessionRotation,
) -> [actix_web::cookie::Cookie<'static>; 2] {
    [
        make_cookie(
            &state.settings.session_cookie_name,
            &rotation.session_id,
            true,
            state.settings.session_ttl_seconds,
            state.settings.cookie_secure,
        ),
        make_cookie(
            &state.settings.csrf_cookie_name,
            &rotation.csrf_token,
            false,
            state.settings.session_ttl_seconds,
            state.settings.cookie_secure,
        ),
    ]
}

fn with_rotated_session_cookies(
    state: &AppState,
    rotation: &SessionRotation,
    response: HttpResponse,
) -> HttpResponse {
    with_cookie_headers(response, &rotated_session_cookies(state, rotation))
}

pub(crate) async fn mfa_disable(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    if !user.mfa_enabled {
        return json_response(json!({ "mfa_enabled": false }));
    }
    match verify_user_mfa_code(&state.diesel_db, &user, &payload.code).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "MFA 验证码无效.");
        }
        Err(error) => {
            tracing::warn!(%error, "failed to verify MFA for disable");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 验证失败.",
            );
        }
    }
    if let Err(error) = clear_user_mfa_state(&state.diesel_db, &user).await {
        tracing::warn!(%error, "failed to disable MFA");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "MFA 禁用失败.",
        );
    }
    audit_event("mfa_disabled", audit_fields(&[("user_id", json!(user.id))]));
    with_cookie_headers(
        json_response(json!({ "mfa_enabled": false })),
        &[clear_cookie(
            MFA_REMEMBERED_COOKIE_NAME,
            state.settings.cookie_secure,
        )],
    )
}

async fn load_totp_credential(
    conn: &mut diesel_async::AsyncPgConnection,
    user: &UserRow,
) -> Result<Option<TotpCredentialRow>, diesel::result::Error> {
    user_totp_credentials::table
        .filter(user_totp_credentials::tenant_id.eq(user.tenant_id))
        .filter(user_totp_credentials::user_id.eq(user.id))
        .select((
            user_totp_credentials::id,
            user_totp_credentials::secret_base32,
            user_totp_credentials::confirmed_at,
            user_totp_credentials::last_used_step,
        ))
        .first::<TotpCredentialRow>(conn)
        .await
        .optional()
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/mfa.rs"]
mod tests;
