use super::decision::ciba_poll_failure_response;
use super::*;

pub(crate) async fn token_ciba(
    context: CibaTokenContext<'_, '_>,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
    auth_method: &str,
) -> HttpResponse {
    let CibaTokenContext {
        token_service,
        issuance,
        handles,
        request: req,
    } = context;
    let config = handles.config.get_ref();
    let ciba_service = handles.service.get_ref();
    let users = handles.users.get_ref();
    if !issuance.permits(nazo_runtime_modules::ModuleId::Ciba) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "CIBA is not enabled.",
            false,
        );
    }
    if !issuance
        .config
        .authorization_server_profile()
        .effective_client_policy(client)
        .allow_cross_device_flows
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "This client is not authorized for cross-device flows.",
            false,
        );
    }
    let Some(auth_req_id) = form.auth_req_id.as_deref() else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA token request requires auth_req_id.",
            false,
        );
    };
    if !ciba_client_assertion_algorithm_supported(client_assertion) {
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "CIBA private_key_jwt signing algorithm is unsupported.",
            false,
        );
    }
    if let Err(response) =
        validate_ciba_security_profile_client_with_config(config, client, auth_method)
    {
        return response;
    }
    let initial = match ciba_service.load(auth_req_id).await {
        Ok(value) => value,
        Err(error) => return ciba_poll_failure_response(CibaPollFailure::Storage(error)),
    };
    if let Some(initial) = initial.as_ref()
        && let Some(response) = ciba_auth_req_id_client_error(initial.state(), client)
    {
        return response;
    }
    let (dpop_jkt, mtls_x5t_s256) = match ciba_issue_binding(issuance, req, client).await {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    let ciba_grant_key = ciba_grant_key(auth_req_id, dpop_jkt.as_deref(), mtls_x5t_s256.as_deref());
    let Some(initial) = initial else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA auth_req_id is expired.",
            false,
        );
    };
    if let Err(error) = consume_token_client_assertion_with_authorization_service(
        issuance.authorization,
        client,
        client_assertion,
    )
    .await
    {
        return super::super::token_client_assertion_error(error);
    }
    let ciba = match ciba_service
        .poll(auth_req_id, &client.client_id, initial, || {
            Utc::now().timestamp()
        })
        .await
    {
        Ok(CibaPollCommit::AuthorizationPending) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "authorization_pending",
                "CIBA authorization is pending.",
                false,
            );
        }
        Ok(CibaPollCommit::SlowDown) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "slow_down",
                "CIBA polling too fast.",
                false,
            );
        }
        Ok(CibaPollCommit::Denied) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "CIBA authorization was denied.",
                false,
            );
        }
        Ok(CibaPollCommit::Expired) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "expired_token",
                "CIBA auth_req_id is expired.",
                false,
            );
        }
        Ok(CibaPollCommit::Approved(ciba)) => ciba,
        Err(failure) => return ciba_poll_failure_response(failure),
    };
    let user = match users
        .public_account_by_id(
            nazo_identity::TenantId::new(DEFAULT_TENANT_ID).expect("default tenant ID is non-nil"),
            nazo_identity::UserId::new(ciba.user_id).expect("persisted CIBA user ID is non-nil"),
        )
        .await
    {
        Ok(Some(user)) if user.principal.active => user,
        Ok(_) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "CIBA user is unavailable.",
                false,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load CIBA user");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
                false,
            );
        }
    };
    let subject = match ciba_subject_for_client(issuance.config, ciba.user_id, client) {
        Ok(subject) => subject,
        Err(error) => {
            tracing::warn!(%error, "failed to compute CIBA subject");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
                false,
            );
        }
    };
    let issue = ciba_token_issue(user.id(), subject, *ciba, dpop_jkt, mtls_x5t_s256);
    issue_token_response_with_service_and_grant(
        issuance,
        token_service,
        client,
        Some(&ciba_grant_key),
        issue,
    )
    .await
}

pub(super) fn ciba_auth_req_id_client_error(
    ciba: &CibaRequestState,
    client: &ClientRow,
) -> Option<HttpResponse> {
    (ciba.client_id != client.client_id).then(|| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA auth_req_id was not issued to this client.",
            false,
        )
    })
}

pub(super) fn ciba_token_issue(
    user_id: Uuid,
    subject: String,
    ciba: CibaRequestState,
    dpop_jkt: Option<String>,
    mtls_x5t_s256: Option<String>,
) -> TokenIssue {
    TokenIssue {
        user_id: Some(user_id),
        subject,
        scopes: ciba.scopes,
        authorization_details: json!([]),
        audiences: ciba.audiences,
        nonce: None,
        auth_time: Some(
            ciba.authentication_context
                .as_ref()
                .map_or(ciba.issued_at, |context| context.auth_time),
        ),
        amr: ciba.authentication_context.as_ref().map_or_else(
            || vec!["ciba_automation".to_owned()],
            |context| context.amr.clone(),
        ),
        oidc_sid: ciba
            .authentication_context
            .as_ref()
            .and_then(|context| context.oidc_sid.clone()),
        acr: ciba.acr,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        refresh_id_token_sid: None,
        include_refresh: true,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: dpop_jkt.clone(),
        refresh_token_dpop_jkt: dpop_jkt,
        mtls_x5t_s256: mtls_x5t_s256.clone(),
        refresh_token_mtls_x5t_s256: mtls_x5t_s256,
        refresh_token_client_attestation_jkt: None,
        refresh_token_scopes: None,
        authorization_code_hash: None,
        actor: None,
        issued_token_type: None,
        native_sso: None,
    }
}

async fn ciba_issue_binding(
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
) -> Result<(Option<String>, Option<String>), HttpResponse> {
    if client.require_dpop_bound_tokens {
        let dpop_jkt = validate_dpop_proof_with_authorization_service(
            issuance.authorization,
            issuance.config.issuer(),
            issuance.config.mtls_endpoint_base_url(),
            issuance.config.dpop_nonce_policy(),
            req,
            None,
            None,
        )
        .await
        .map_err(|error| dpop_error_response(error, DpopErrorContext::TokenEndpoint))?;
        if dpop_jkt.is_none() {
            return Err(dpop_error_response(
                DpopError::MissingProof,
                DpopErrorContext::TokenEndpoint,
            ));
        }
        return Ok((dpop_jkt, None));
    }
    if client.require_mtls_bound_tokens {
        let Some(x5t_s256) =
            request_mtls_thumbprint_from_trusted_proxy(req, issuance.config.trusted_proxy_cidrs())
        else {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "CIBA requires mTLS sender constraint.",
                false,
            ));
        };
        return Ok((None, Some(x5t_s256)));
    }
    Ok((None, None))
}

fn ciba_subject_for_client(
    config: &TokenIssuanceConfig,
    user_id: Uuid,
    client: &ClientRow,
) -> anyhow::Result<String> {
    let redirect_uri = client.redirect_uris.first().map_or("", String::as_str);
    Ok(nazo_auth::oidc_subject_for_client(
        config.issuer(),
        config.pairwise_subject_secret(),
        user_id,
        &client.subject_type,
        client.sector_identifier_host.as_deref(),
        redirect_uri,
    )?)
}

pub(super) async fn load_ciba_request_payload(
    ciba_service: &ServerCibaService,
    auth_req_id: &str,
) -> Result<Option<CibaRequestState>, HttpResponse> {
    ciba_service
        .load(auth_req_id)
        .await
        .map(|stored| stored.map(|stored| stored.into_state()))
        .map_err(ciba_state_error_response)
}

pub(super) fn ciba_state_error_response(error: CibaStatePortError) -> HttpResponse {
    tracing::warn!(%error, "failed to load CIBA state");
    ciba_error_no_store(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "CIBA state unavailable.",
    )
}

pub(super) fn ciba_error_no_store(
    status: StatusCode,
    error: &str,
    description: &str,
) -> HttpResponse {
    let mut response = oauth_error(status, error, description);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
