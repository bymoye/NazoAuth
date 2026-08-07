use super::*;
use crate::adapters::audit::{audit_event_required, ensure_audit_storage};

enum GuardedCibaCreation {
    Created(String),
    ClientAuthentication(TokenManagementClientAuthError),
    RequestObjectReplay,
    RequestObjectStore,
    State(CibaCreateFailure),
    LeaseExpired,
}

// Actix supplies each dependency as an independent extractor at this route
// boundary. The handler keeps that explicit transport contract; its creation
// logic is already isolated below the extraction/authentication phase.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn backchannel_authentication(
    authorization_service: Data<ServerAuthorizationService>,
    ciba_service: Data<ServerCibaService>,
    conformance_leases: Data<nazo_postgres::ConformanceLeaseRepository>,
    users: Data<nazo_postgres::UserRepository>,
    config: Data<CibaHttpConfig>,
    runtime: Data<ServerRuntimeModuleRegistry>,
    req: HttpRequest,
    mut payload: Payload,
) -> HttpResponse {
    if !ciba_module_admissible(&runtime, nazo_auth::CapabilityAdmission::NewRequest) {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut form = match parse_backchannel_authentication_form(&req, &mut payload).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    let has_basic = has_basic_authorization_scheme(req.headers());
    let has_assertion = form.client_assertion_type.is_some() || form.client_assertion.is_some();
    if has_basic && (form.client_id.is_some() || form.client_secret.is_some() || has_assertion)
        || has_assertion && form.client_secret.is_some()
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA request cannot mix client authentication methods.",
        );
    }
    apply_ciba_request_object_client_id_hint(&mut form, has_basic, has_assertion);
    let credentials = extract_client_credentials_with_trusted_proxies(
        &req,
        &config.trusted_proxy_cidrs,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    let Some(client_id) = credentials.client_id.as_deref() else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    };
    let client = match authorization_service.client_by_id(client_id).await {
        Ok(Some(client)) if client.is_active => client,
        Ok(_) => {
            super::super::client_auth::perform_dummy_client_secret_verification(
                &credentials,
                &config.client_secret_pepper,
            );
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query CIBA client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
            );
        }
    };
    let auth_request = client_auth_request_facts(&req, &config.trusted_proxy_cidrs);
    let assertion = match authenticate_client_with_dependencies(
        &authorization_service,
        ClientAuthConfig::new(&config.issuer, &config.client_secret_pepper),
        &auth_request,
        &client,
        &credentials,
        ClientAuthenticationContext::ConfidentialOnly,
    )
    .await
    {
        Ok(assertion) => assertion,
        Err(error) => return token_management_auth_error(error),
    };
    if !ciba_client_assertion_algorithm_supported(assertion.as_ref()) {
        return token_management_auth_error(TokenManagementClientAuthError::InvalidClient);
    }
    if !client_supports_grant(&client, CIBA_GRANT_TYPE) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用 CIBA 授权类型.",
        );
    }
    if !config
        .authorization_server_profile
        .effective_client_policy(&client)
        .allow_cross_device_flows
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未授权使用跨设备流程.",
        );
    }
    if let Err(response) = validate_ciba_token_request_profile(
        &config,
        &client,
        client.token_endpoint_auth_method.as_str(),
    ) {
        return response;
    }
    if let Err(response) = validate_ciba_security_profile_client_with_config(
        &config,
        &client,
        client.token_endpoint_auth_method.as_str(),
    ) {
        return response;
    }
    if let Err(response) =
        validate_ciba_request_object_presence_with_config(&config, &client, &form)
    {
        return response;
    }
    let request_object_replay = match validate_and_apply_ciba_request_object_claims_with_config(
        &config, &client, &mut form,
    ) {
        Ok(replay) => replay,
        Err(response) => return response,
    };
    if let Err(response) = validate_ciba_delivery_request(&client, &form) {
        return response;
    }
    let scopes = parse_scope(form.scope.as_deref().unwrap_or(""));
    if !scopes.iter().any(|scope| scope == "openid") || !is_subset(&scopes, &client.scopes) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "CIBA requires an allowed openid scope.",
        );
    }
    if ciba_hint_count(&form) != 1 || form.login_hint.is_none() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA requires exactly one supported user hint.",
        );
    }
    let Some(login_hint) = form
        .login_hint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA requires login_hint.",
        );
    };
    let user = match users
        .public_account_by_email(
            nazo_identity::TenantId::new(DEFAULT_TENANT_ID).expect("default tenant ID is non-nil"),
            login_hint,
        )
        .await
    {
        Ok(Some(user)) if user.principal.active => user,
        Ok(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unknown_user_id",
                "CIBA login_hint does not identify an active user.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query CIBA login_hint user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
            );
        }
    };
    let expires_in = form
        .requested_expiry_seconds
        .unwrap_or(config.auth_req_id_ttl_seconds)
        .min(config.auth_req_id_ttl_seconds);
    let acr = match ciba_selected_acr(form.acr_values.as_deref()) {
        Some(acr) => Some(acr),
        None if form.acr_values.is_some() => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA acr_values is unsupported.",
            );
        }
        None => None,
    };
    let now = Utc::now().timestamp();
    let expires_at = now.saturating_add(expires_in.min(i64::MAX as u64) as i64);
    let state_payload = CibaRequestState {
        client_id: client.client_id.clone(),
        user_id: user.id(),
        scopes,
        audiences: vec![config.default_audience.to_string()],
        acr,
        authentication_context: None,
        binding_message: form.binding_message,
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: config.poll_interval_seconds,
        expires_at,
        retention_expires_at: ciba_retention_deadline(expires_at),
        last_poll_at: None,
        ping_notification: if client.backchannel_token_delivery_mode == "ping" {
            Some(CibaPingNotification {
                auth_req_id: None,
                endpoint: client
                    .backchannel_client_notification_endpoint
                    .clone()
                    .expect("validated ping clients have a notification endpoint"),
                client_notification_token: form.client_notification_token,
                status: CibaPingNotificationStatus::AwaitingDecision,
                attempts: 0,
                next_attempt_at: None,
            })
        } else {
            None
        },
    };
    if let Err(error) = ensure_audit_storage().await {
        tracing::error!(%error, "CIBA authorization-start audit preflight failed");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA audit storage unavailable.",
        );
    }
    if let Err(error) = audit_event_required(
        "ciba_authorization_intent",
        audit_fields(&[
            ("client_id", json!(state_payload.client_id)),
            ("user_id", json!(state_payload.user_id)),
            ("scope", json!(state_payload.scopes.join(" "))),
            ("audience", json!(state_payload.audiences)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip_with_context(
                    &req,
                    config.client_ip_header_mode,
                    &config.trusted_proxy_cidrs,
                ))),
            ),
        ]),
    )
    .await
    {
        tracing::error!(%error, "CIBA authorization-start audit intent failed");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA authorization audit unavailable.",
        );
    }
    let audit_state = state_payload.clone();
    let client_id = client.client_id.clone();
    let lease_client_id = client_id.clone();
    let client_for_creation = client.clone();
    let authorization_service_for_creation = authorization_service.clone();
    let ciba_service_for_creation = ciba_service.clone();
    let auth_req_id = match conformance_leases
        .with_active_ciba_decision(
            config.tenant_id,
            &lease_client_id,
            None,
            |lease_expires_at| async move {
                if lease_expires_at.is_some_and(|deadline| Utc::now().timestamp() >= deadline) {
                    return GuardedCibaCreation::LeaseExpired;
                }
                if let Err(error) =
                    consume_token_management_client_assertion_with_authorization_service(
                        &authorization_service_for_creation,
                        &client_for_creation,
                        assertion.as_ref(),
                    )
                    .await
                {
                    return GuardedCibaCreation::ClientAuthentication(error);
                }
                if let Some(replay) = request_object_replay {
                    if lease_expires_at
                        .is_some_and(|deadline| Utc::now().timestamp() >= deadline)
                    {
                        return GuardedCibaCreation::LeaseExpired;
                    }
                    match authorization_service_for_creation
                        .consume_ciba_request_object(
                            &client_id,
                            &replay.jti,
                            replay.ttl_seconds,
                        )
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => return GuardedCibaCreation::RequestObjectReplay,
                        Err(error) => {
                            tracing::warn!(%error, "failed to persist CIBA request object replay state");
                            return GuardedCibaCreation::RequestObjectStore;
                        }
                    }
                }
                if lease_expires_at.is_some_and(|deadline| Utc::now().timestamp() >= deadline) {
                    return GuardedCibaCreation::LeaseExpired;
                }
                match ciba_service_for_creation
                    .create_unique_with_lease_deadline(
                        &state_payload,
                        lease_expires_at,
                        random_urlsafe_token,
                    )
                    .await
                {
                    Ok(auth_req_id) => GuardedCibaCreation::Created(auth_req_id),
                    Err(error) => GuardedCibaCreation::State(error),
                }
            },
        )
        .await
    {
        Ok(Some(GuardedCibaCreation::Created(auth_req_id))) => auth_req_id,
        Ok(Some(GuardedCibaCreation::ClientAuthentication(error))) => {
            return token_management_auth_error(error);
        }
        Ok(Some(GuardedCibaCreation::RequestObjectReplay)) => {
            return ciba_invalid_request("CIBA request object has already been used.");
        }
        Ok(Some(GuardedCibaCreation::RequestObjectStore)) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
            );
        }
        Ok(Some(GuardedCibaCreation::LeaseExpired)) | Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            );
        }
        Ok(Some(GuardedCibaCreation::State(error))) => {
            tracing::warn!(%error, "failed to create CIBA auth_req_id");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to acquire CIBA creation lease guard");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
            );
        }
    };
    audit_event(
        "ciba_authorization_started",
        ciba_start_audit_fields(
            &audit_state,
            &auth_req_id,
            Some(blake3_hex(&client_ip_with_context(
                &req,
                config.client_ip_header_mode,
                &config.trusted_proxy_cidrs,
            ))),
        ),
    );
    json_response_no_store(json!({
        "auth_req_id": auth_req_id,
        "expires_in": expires_in,
        "interval": config.poll_interval_seconds
    }))
}
