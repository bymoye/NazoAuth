use super::*;

pub(crate) async fn parse_backchannel_authentication_form(
    req: &HttpRequest,
    payload: &mut Payload,
) -> Result<BackchannelAuthenticationForm, HttpResponse> {
    if !request_uses_form_urlencoded(req) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA request must use application/x-www-form-urlencoded.",
        ));
    }
    let mut body = Vec::with_capacity(16 * 1024);
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA body is invalid.",
            )
        })?;
        if body.len().saturating_add(chunk.len()) > 16 * 1024 {
            return Err(oauth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "CIBA body is too large.",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let mut form = BackchannelAuthenticationForm::default();
    let mut seen = HashSet::new();
    for (key, value) in url::form_urlencoded::parse(&body) {
        let value = value.into_owned();
        let key = key.into_owned();
        if !seen.insert(key.clone()) {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA parameters must not repeat.",
            ));
        }
        match key.as_str() {
            "request" => form.request = non_empty(value),
            "scope" => form.scope = non_empty(value),
            "login_hint" => form.login_hint = non_empty(value),
            "id_token_hint" => form.id_token_hint = non_empty(value),
            "login_hint_token" => form.login_hint_token = non_empty(value),
            "binding_message" => form.binding_message = non_empty(value),
            "client_notification_token" => form.client_notification_token = non_empty(value),
            "acr_values" => form.acr_values = non_empty(value),
            "requested_expiry" => {
                form.requested_expiry_seconds = parse_requested_expiry_string(&value)
            }
            "client_id" => form.client_id = non_empty(value),
            "client_secret" => form.client_secret = non_empty(value),
            "client_assertion_type" => form.client_assertion_type = non_empty(value),
            "client_assertion" => form.client_assertion = non_empty(value),
            _ => {}
        }
    }
    Ok(form)
}

pub(crate) fn validate_and_apply_ciba_request_object_claims_with_config(
    config: &CibaHttpConfig,
    client: &ClientRow,
    form: &mut BackchannelAuthenticationForm,
) -> Result<Option<CibaRequestObjectReplay>, HttpResponse> {
    let Some(request_object) = form.request.as_deref() else {
        return Ok(None);
    };
    let claims = signed_ciba_request_object_claims(request_object, client)?;
    let now = Utc::now().timestamp();
    if claims.iss.as_deref() != Some(client.client_id.as_str())
        || !ciba_request_object_audience_valid(&claims, &config.issuer)
        || !ciba_request_object_times_valid(&claims, now)
        || !ciba_request_object_jti_valid(claims.jti.as_deref())
        || ciba_request_object_hint_count(&claims) != 1
        || claims.login_hint.as_deref().is_none_or(str::is_empty)
    {
        return Err(ciba_invalid_request(
            "CIBA request object claims are invalid.",
        ));
    }
    let replay = CibaRequestObjectReplay {
        jti: claims
            .jti
            .clone()
            .expect("validated CIBA request object has jti"),
        ttl_seconds: claims
            .exp
            .expect("validated CIBA request object has exp")
            .saturating_sub(now)
            .clamp(1, CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS) as u64,
    };
    if let Some(binding_message) = claims.binding_message.as_deref()
        && !ciba_binding_message_is_supported(binding_message)
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_binding_message",
            "CIBA binding_message is unsupported.",
        ));
    }
    merge_request_object_string(
        &mut form.scope,
        claims.scope,
        "CIBA request object scope conflicts with outer parameter.",
    )?;
    merge_request_object_string(
        &mut form.login_hint,
        claims.login_hint,
        "CIBA request object login_hint conflicts with outer parameter.",
    )?;
    merge_request_object_string(
        &mut form.id_token_hint,
        claims.id_token_hint,
        "CIBA request object id_token_hint conflicts with outer parameter.",
    )?;
    merge_request_object_string(
        &mut form.login_hint_token,
        claims.login_hint_token,
        "CIBA request object login_hint_token conflicts with outer parameter.",
    )?;
    merge_request_object_string(
        &mut form.binding_message,
        claims.binding_message,
        "CIBA request object binding_message conflicts with outer parameter.",
    )?;
    merge_request_object_string(
        &mut form.acr_values,
        claims.acr_values,
        "CIBA request object acr_values conflicts with outer parameter.",
    )?;
    merge_request_object_string(
        &mut form.client_notification_token,
        claims.client_notification_token,
        "CIBA request object client_notification_token conflicts with outer parameter.",
    )?;
    if let Some(requested_expiry) = claims.requested_expiry {
        let Some(seconds) = ciba_requested_expiry_seconds(&requested_expiry) else {
            return Err(ciba_invalid_request(
                "CIBA request object requested_expiry is invalid.",
            ));
        };
        if let Some(outer) = form.requested_expiry_seconds
            && outer != seconds
        {
            return Err(ciba_invalid_request(
                "CIBA request object requested_expiry conflicts with outer parameter.",
            ));
        }
        form.requested_expiry_seconds = Some(seconds);
    }
    Ok(Some(replay))
}

pub(crate) fn signed_ciba_request_object_claims(
    request_object: &str,
    client: &ClientRow,
) -> Result<CibaAuthenticationRequestClaims, HttpResponse> {
    let Some((header_part, _payload_part, signature_part)) = split_compact_jwt(request_object)
    else {
        return Err(ciba_invalid_request(
            "CIBA request object is not a compact JWT.",
        ));
    };
    if signature_part.is_empty() {
        return Err(ciba_invalid_request("CIBA request object must be signed."));
    }
    let header_value = decode_jwt_header_value(header_part)?;
    if header_value.get("alg").and_then(Value::as_str) == Some("none") {
        return Err(ciba_invalid_request("CIBA request object must be signed."));
    }
    let header = jsonwebtoken::decode_header(request_object)
        .map_err(|_| ciba_invalid_request("CIBA request object header is invalid."))?;
    if !ciba_jwt_signing_algorithm_supported(header.alg) {
        return Err(ciba_invalid_request(
            "CIBA request object signing algorithm is unsupported.",
        ));
    }
    if let Some(expected) = client
        .backchannel_authentication_request_signing_alg
        .as_deref()
        && ciba_algorithm_name(header.alg) != Some(expected)
    {
        return Err(ciba_invalid_request(
            "CIBA request object signing algorithm does not match client registration.",
        ));
    }
    let Some(kid) = header.kid.as_deref() else {
        return Err(ciba_invalid_request("CIBA request object is missing kid."));
    };
    let Some(decoding_key) = client_jwt_decoding_key(client, kid, header.alg) else {
        return Err(ciba_invalid_request(
            "CIBA request object signing key is invalid.",
        ));
    };
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_required_spec_claims::<&str>(&[]);
    validation.set_issuer(&[client.client_id.as_str()]);
    jsonwebtoken::decode::<CibaAuthenticationRequestClaims>(
        request_object,
        &decoding_key,
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|_| ciba_invalid_request("CIBA request object signature is invalid."))
}

pub(crate) fn apply_ciba_request_object_client_id_hint(
    form: &mut BackchannelAuthenticationForm,
    has_basic: bool,
    has_assertion: bool,
) {
    if form.client_id.is_some() || has_basic || has_assertion {
        return;
    }
    if let Some(client_id) = form
        .request
        .as_deref()
        .and_then(unverified_signed_ciba_request_object_client_id)
    {
        form.client_id = Some(client_id);
    }
}

pub(crate) fn unverified_signed_ciba_request_object_client_id(
    request_object: &str,
) -> Option<String> {
    let (header_part, payload_part, signature_part) = split_compact_jwt(request_object)?;
    if signature_part.is_empty() {
        return None;
    }
    let header_value = decode_jwt_header_value(header_part).ok()?;
    if header_value.get("alg").and_then(Value::as_str) == Some("none") {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload_part).ok()?;
    let claims: UnverifiedCibaAuthenticationRequestClaims = serde_json::from_slice(&bytes).ok()?;
    let issuer = claims.iss?.trim().to_owned();
    if issuer.is_empty() {
        return None;
    }
    let subject_matches = claims
        .sub
        .as_deref()
        .is_none_or(|subject| subject == issuer);
    subject_matches.then_some(issuer)
}

pub(crate) fn split_compact_jwt(token: &str) -> Option<(&str, &str, &str)> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    parts
        .next()
        .is_none()
        .then_some((header, payload, signature))
}

pub(crate) fn decode_jwt_header_value(header: &str) -> Result<Value, HttpResponse> {
    let bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| ciba_invalid_request("CIBA request object header is invalid."))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ciba_invalid_request("CIBA request object header is invalid."))
}

pub(crate) fn ciba_request_object_audience_valid(
    claims: &CibaAuthenticationRequestClaims,
    issuer: &str,
) -> bool {
    let Some(aud) = claims.aud.as_ref() else {
        return false;
    };
    let endpoint = format!("{issuer}/bc-authorize");
    match aud {
        Value::String(value) => value == issuer || value == &endpoint,
        Value::Array(values) => values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| value == issuer || value == endpoint)
        }),
        _ => false,
    }
}

pub(crate) fn ciba_request_object_times_valid(
    claims: &CibaAuthenticationRequestClaims,
    now: i64,
) -> bool {
    let Some(exp) = claims.exp else {
        return false;
    };
    let Some(nbf) = claims.nbf else {
        return false;
    };
    let Some(iat) = claims.iat else {
        return false;
    };
    if exp <= now || nbf > now.saturating_add(CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS) {
        return false;
    }
    if now.saturating_sub(nbf) > CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS {
        return false;
    }
    if exp <= nbf
        || exp.saturating_sub(nbf)
            > CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS
                .saturating_add(CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
    {
        return false;
    }
    if iat > now.saturating_add(CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
        || now.saturating_sub(iat) > CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS
    {
        return false;
    }
    true
}

pub(crate) fn ciba_request_object_jti_valid(jti: Option<&str>) -> bool {
    let Some(jti) = jti else {
        return false;
    };
    let trimmed = jti.trim();
    !trimmed.is_empty() && trimmed.len() <= 128
}

pub(crate) fn ciba_request_object_hint_count(claims: &CibaAuthenticationRequestClaims) -> usize {
    [
        claims.login_hint.as_deref(),
        claims.id_token_hint.as_deref(),
        claims.login_hint_token.as_deref(),
    ]
    .into_iter()
    .filter(|value| value.is_some_and(|value| !value.trim().is_empty()))
    .count()
}

pub(crate) fn ciba_hint_count(form: &BackchannelAuthenticationForm) -> usize {
    [
        form.login_hint.as_deref(),
        form.id_token_hint.as_deref(),
        form.login_hint_token.as_deref(),
    ]
    .into_iter()
    .filter(|value| value.is_some_and(|value| !value.trim().is_empty()))
    .count()
}

pub(crate) fn ciba_selected_acr(acr_values: Option<&str>) -> Option<String> {
    acr_values?
        .split_ascii_whitespace()
        .find(|value| *value == "1")
        .map(ToOwned::to_owned)
}

pub(crate) fn ciba_binding_message_is_supported(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.chars().count() <= CIBA_BINDING_MESSAGE_MAX_CHARS
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii() && !ch.is_ascii_control())
}

pub(crate) fn merge_request_object_string(
    target: &mut Option<String>,
    value: Option<String>,
    conflict_description: &str,
) -> Result<(), HttpResponse> {
    let Some(value) = value.map(|value| value.trim().to_owned()) else {
        return Ok(());
    };
    if value.is_empty() {
        return Err(ciba_invalid_request(
            "CIBA request object parameter is empty.",
        ));
    }
    if let Some(existing) = target.as_deref()
        && existing != value
    {
        return Err(ciba_invalid_request(conflict_description));
    }
    *target = Some(value);
    Ok(())
}

pub(crate) fn ciba_requested_expiry_seconds(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(value) => parse_requested_expiry_string(value),
        _ => None,
    }
    .filter(|seconds| *seconds > 0)
}

pub(crate) fn parse_requested_expiry_string(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
}
