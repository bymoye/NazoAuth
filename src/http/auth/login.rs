//! 用户登录端点。
// 登录成功后同时写入服务端会话和双 cookie，其中 CSRF cookie 允许前端读取。
use crate::http::prelude::*;

#[derive(Deserialize)]
pub(crate) struct LoginRequest {
    email: String,
    password: String,
    next: Option<String>,
}

#[derive(Clone, Copy)]
enum LoginResponseMode {
    Json,
    Form,
}

/// 校验邮箱密码并创建会话。
pub(crate) async fn login(state: Data<AppState>, req: HttpRequest, body: Bytes) -> HttpResponse {
    let (payload, response_mode) = match parse_login_request(&req, &body) {
        Ok(value) => value,
        Err(response) => return response,
    };

    if matches!(response_mode, LoginResponseMode::Form)
        && !form_login_origin_is_allowed(&state.settings, &req)
    {
        return oauth_error(StatusCode::FORBIDDEN, "access_denied", "登录来源无效.");
    }

    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }

    let email = payload.email.trim().to_lowercase();
    if let Err(response) = enforce_login_failure_throttle(&state, &req, &email).await {
        return response;
    }

    let user = match find_user_by_email(&state.diesel_db, &email).await {
        Ok(user) => user,
        Err(error) => {
            tracing::warn!(%error, "failed to query user for login");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户查询失败.",
            );
        }
    };
    let authenticatable = user.as_ref().is_some_and(|user| user.is_active);
    let password_hash = if authenticatable {
        user.as_ref()
            .expect("authenticatable users must exist")
            .password_hash
            .clone()
    } else {
        match dummy_password_hash() {
            Ok(hash) => hash,
            Err(error) => {
                tracing::error!(%error, "dummy password hash is unavailable");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "密码校验失败.",
                );
            }
        }
    };
    let password_valid =
        match verify_password_blocking_limited(payload.password.clone(), password_hash).await {
            Ok(valid) => valid,
            Err(PasswordVerificationError::Saturated) => {
                tracing::warn!("password verification concurrency limit reached");
                let mut response = oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "登录服务繁忙，请稍后重试.",
                );
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                return response;
            }
            Err(PasswordVerificationError::WorkerFailed) => {
                tracing::warn!("password verification worker failed");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "密码校验失败.",
                );
            }
        };
    if !authenticatable || !password_valid {
        if let Err(response) = record_login_failure(&state, &req, &email).await {
            return response;
        }
        let mut fields = vec![
            ("email_hash", json!(blake3_hex(&email))),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(&req, &state.settings))),
            ),
        ];
        if let Some(user) = &user {
            fields.push(("user_id", json!(user.id)));
        }
        audit_event("login_failure", audit_fields(&fields));
        return oauth_error(StatusCode::UNAUTHORIZED, "access_denied", "邮箱或密码错误.");
    }
    let user = user.expect("successful authentication requires an active user");
    clear_login_failures(&state, &req, &email).await;

    let session_id = random_urlsafe_token();
    let csrf_token = random_urlsafe_token();
    let key = format!("oauth:session:{session_id}");
    let remembered_mfa = if user.mfa_enabled {
        match remembered_mfa_device_valid(&state, &req, &user).await {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "failed to check remembered MFA device");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "MFA 状态查询失败.",
                );
            }
        }
    } else {
        false
    };
    let mut amr = vec!["password".to_owned()];
    if remembered_mfa {
        amr.push("remembered_mfa".to_owned());
        amr.push("mfa".to_owned());
    }
    let session = SessionPayload {
        user_id: user.id,
        auth_time: Utc::now().timestamp(),
        amr,
        pending_mfa: user.mfa_enabled && !remembered_mfa,
        oidc_sid: Some(random_urlsafe_token()),
    };
    let session_body = match serde_json::to_string(&session) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize session");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话写入失败.",
            );
        }
    };
    if valkey_set_ex(
        &state.valkey,
        key,
        session_body,
        state.settings.session_ttl_seconds,
    )
    .await
    .is_err()
    {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "会话写入失败.",
        );
    }

    audit_event(
        "login_success",
        audit_fields(&[
            ("user_id", json!(user.id)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(&req, &state.settings))),
            ),
            ("amr", json!(session.amr)),
        ]),
    );

    let cookies = [
        make_cookie(
            &state.settings.session_cookie_name,
            &session_id,
            true,
            state.settings.session_ttl_seconds,
            state.settings.cookie_secure,
        ),
        make_cookie(
            &state.settings.csrf_cookie_name,
            &csrf_token,
            false,
            state.settings.session_ttl_seconds,
            state.settings.cookie_secure,
        ),
    ];

    if matches!(response_mode, LoginResponseMode::Form) {
        let location = safe_form_login_next(&state, &req, payload.next.as_deref());
        let mut response = HttpResponse::SeeOther();
        if let Ok(value) = HeaderValue::from_str(&location) {
            response.insert_header((header::LOCATION, value));
        }
        return with_cookie_headers(response.finish(), &cookies);
    }

    let response_body = json!({
        "expires_in": state.settings.session_ttl_seconds,
        "csrf_token": csrf_token,
        "mfa_required": session.pending_mfa
    });
    with_cookie_headers(json_response(response_body), &cookies)
}

fn parse_login_request(
    req: &HttpRequest,
    body: &Bytes,
) -> Result<(LoginRequest, LoginResponseMode), HttpResponse> {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or_default();

    if content_type.eq_ignore_ascii_case("application/json") {
        let payload = serde_json::from_slice::<LoginRequest>(body).map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "login request body must be valid JSON.",
            )
        })?;
        return Ok((payload, LoginResponseMode::Json));
    }

    if content_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        let raw = std::str::from_utf8(body).map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "login form body must be valid UTF-8.",
            )
        })?;
        return parse_login_form(raw).map(|payload| (payload, LoginResponseMode::Form));
    }

    Err(oauth_error(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "invalid_request",
        "login request must use JSON or form encoding.",
    ))
}

fn parse_login_form(raw: &str) -> Result<LoginRequest, HttpResponse> {
    let mut email: Option<String> = None;
    let mut password: Option<String> = None;
    let mut next: Option<String> = None;

    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        match key.as_ref() {
            "email" => assign_once(&mut email, value.into_owned())?,
            "password" => assign_once(&mut password, value.into_owned())?,
            "next" => assign_once(&mut next, value.into_owned())?,
            _ => {}
        }
    }

    let Some(email) = email else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "email is required.",
        ));
    };
    let Some(password) = password else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "password is required.",
        ));
    };

    Ok(LoginRequest {
        email,
        password,
        next,
    })
}

fn assign_once(slot: &mut Option<String>, value: String) -> Result<(), HttpResponse> {
    if slot.is_some() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "duplicate login form parameter.",
        ));
    }
    *slot = Some(value);
    Ok(())
}

fn form_login_origin_is_allowed(settings: &Settings, req: &HttpRequest) -> bool {
    let mut origin_headers = req.headers().get_all(header::ORIGIN);
    let Some(origin_header) = origin_headers.next() else {
        return false;
    };
    if origin_headers.next().is_some() {
        return false;
    }
    let Ok(origin_header) = origin_header.to_str() else {
        return false;
    };
    let Some(request_origin) = strict_request_origin(origin_header) else {
        return false;
    };

    [&settings.issuer, &settings.frontend_base_url]
        .into_iter()
        .filter_map(|trusted_url| normalized_url_origin(trusted_url))
        .any(|trusted_origin| trusted_origin == request_origin)
}

fn strict_request_origin(value: &str) -> Option<String> {
    if value == "null" || value != value.trim() {
        return None;
    }
    let parsed = url::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

fn normalized_url_origin(value: &str) -> Option<String> {
    let parsed = url::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

fn safe_form_login_next(state: &AppState, req: &HttpRequest, submitted: Option<&str>) -> String {
    let default_next = format!(
        "{}/profile",
        state.settings.frontend_base_url.trim_end_matches('/')
    );
    submitted
        .and_then(safe_relative_next)
        .or_else(|| referer_login_next(req))
        .unwrap_or(default_next)
}

fn safe_relative_next(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') || trimmed.starts_with("//") {
        return None;
    }
    let path = trimmed
        .split_once(['?', '#'])
        .map(|(path, _)| path)
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    if path != "/authorize" {
        return None;
    }
    Some(trimmed.to_owned())
}

fn referer_login_next(req: &HttpRequest) -> Option<String> {
    let header = req.headers().get(header::REFERER)?.to_str().ok()?;
    let referer = url::Url::parse(header).ok()?;
    let next = referer.query_pairs().find_map(|(key, value)| {
        if key == "next" {
            Some(value.into_owned())
        } else {
            None
        }
    })?;
    safe_relative_next(&next)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/auth/tests/login.rs"]
mod tests;
