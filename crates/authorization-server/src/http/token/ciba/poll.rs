use super::decision::ciba_poll_failure_response;
use super::*;
use crate::http::dpop::{DpopErrorContext, dpop_error_response};
use crate::http::token::{
    SenderConstraintValidationError, sender_constraint_multiple_error,
    validate_token_sender_constraints,
};
use actix_web::body::MessageBody;
use nazo_http_actix::OAuthJsonErrorFields;

/// `HttpResponse<BoxBody>` is intentionally not `Send`, while the database
/// lease transaction must return a `Send` value.  Materialize the small JSON
/// response while the lease lock is held and rebuild the Actix response after
/// the transaction commits.
struct SendCibaResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    oauth_error: Option<OAuthJsonErrorFields>,
}

impl SendCibaResponse {
    fn into_http_response(self) -> HttpResponse {
        let mut response = HttpResponse::build(self.status);
        for (name, value) in &self.headers {
            response.append_header((name.clone(), value.clone()));
        }
        if let Some(fields) = self.oauth_error {
            response.extensions_mut().insert(fields);
        }
        response.body(self.body)
    }
}

fn materialize_ciba_response(response: HttpResponse) -> SendCibaResponse {
    let (head, body) = response.into_parts();
    let status = head.status();
    let headers = head.headers().clone();
    let oauth_error = head.extensions().get::<OAuthJsonErrorFields>().cloned();
    let body = body.try_into_bytes().unwrap_or_else(|_| {
        Bytes::from_static(
            br#"{"error":"server_error","error_description":"CIBA response body unavailable."}"#,
        )
    });
    SendCibaResponse {
        status,
        headers,
        body,
        oauth_error,
    }
}

struct CibaPollIssueRequest<'a, 'issuance> {
    ciba_service: &'a ServerCibaService,
    users: &'a nazo_postgres::UserRepository,
    token_service: &'a ServerTokenService,
    issuance: &'a TokenIssuanceContext<'issuance>,
    client: &'a ClientRow,
    auth_req_id: &'a str,
    initial: nazo_auth::CibaStoredRequest<nazo_valkey::StoredCibaRequest>,
    ciba_grant_key: String,
    dpop_jkt: Option<String>,
    mtls_x5t_s256: Option<String>,
    client_assertion: Option<ValidatedClientAssertion>,
    lease_expires_at: Option<i64>,
}

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
    // The assertion replay marker is a mutation too.  Move it into the same
    // lease guard as the CIBA CAS and token issuance so revocation cannot
    // linearize between authentication consumption and the grant transition.
    let client_assertion = client_assertion.cloned();
    match handles
        .conformance_leases
        .with_active_ciba_decision(
            config.tenant_id,
            &client.client_id,
            None,
            |lease_expires_at| async move {
                poll_and_issue_ciba(CibaPollIssueRequest {
                    ciba_service,
                    users,
                    token_service,
                    issuance,
                    client,
                    auth_req_id,
                    initial,
                    ciba_grant_key,
                    dpop_jkt,
                    mtls_x5t_s256,
                    client_assertion,
                    lease_expires_at,
                })
                .await
            },
        )
        .await
    {
        Ok(Some(response)) => response.into_http_response(),
        Ok(None) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA client or conformance lease is no longer active.",
            false,
        ),
        Err(error) => {
            tracing::warn!(%error, "failed to acquire CIBA token lease guard");
            oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
                false,
            )
        }
    }
}

async fn poll_and_issue_ciba(request: CibaPollIssueRequest<'_, '_>) -> SendCibaResponse {
    let CibaPollIssueRequest {
        ciba_service,
        users,
        token_service,
        issuance,
        client,
        auth_req_id,
        initial,
        ciba_grant_key,
        dpop_jkt,
        mtls_x5t_s256,
        client_assertion,
        lease_expires_at,
    } = request;
    if let Err(error) = consume_token_client_assertion_with_authorization_service(
        issuance.authorization,
        client,
        client_assertion.as_ref(),
    )
    .await
    {
        return materialize_ciba_response(super::super::token_client_assertion_error(error));
    }
    let ciba = match ciba_service
        .poll_with_lease_deadline(
            auth_req_id,
            &client.client_id,
            initial,
            lease_expires_at,
            || Utc::now().timestamp(),
        )
        .await
    {
        Ok(CibaPollCommit::AuthorizationPending) => {
            return materialize_ciba_response(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "authorization_pending",
                "CIBA authorization is pending.",
                false,
            ));
        }
        Ok(CibaPollCommit::SlowDown) => {
            return materialize_ciba_response(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "slow_down",
                "CIBA polling too fast.",
                false,
            ));
        }
        Ok(CibaPollCommit::Denied) => {
            return materialize_ciba_response(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "CIBA authorization was denied.",
                false,
            ));
        }
        Ok(CibaPollCommit::Expired) => {
            return materialize_ciba_response(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "expired_token",
                "CIBA auth_req_id is expired.",
                false,
            ));
        }
        Ok(CibaPollCommit::Approved(ciba)) => ciba,
        Err(failure) => return materialize_ciba_response(ciba_poll_failure_response(failure)),
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
            return materialize_ciba_response(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "CIBA user is unavailable.",
                false,
            ));
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load CIBA user");
            return materialize_ciba_response(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
                false,
            ));
        }
    };
    let subject = match ciba_subject_for_client(issuance.config, ciba.user_id, client) {
        Ok(subject) => subject,
        Err(error) => {
            tracing::warn!(%error, "failed to compute CIBA subject");
            return materialize_ciba_response(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA failed.",
                false,
            ));
        }
    };
    if lease_expires_at.is_some_and(|deadline| Utc::now().timestamp() >= deadline) {
        return materialize_ciba_response(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "CIBA conformance lease is expired.",
            false,
        ));
    }
    let issue = ciba_token_issue(user.id(), subject, *ciba, dpop_jkt, mtls_x5t_s256);
    let response = issue_token_response_with_service_and_grant(
        issuance,
        token_service,
        client,
        Some(&ciba_grant_key),
        issue,
    )
    .await;
    materialize_ciba_response(response)
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
    let sender = validate_token_sender_constraints(issuance, req, client, None, None, None)
        .await
        .map_err(|error| match error {
            SenderConstraintValidationError::Dpop(error) => {
                dpop_error_response(error, DpopErrorContext::TokenEndpoint)
            }
            SenderConstraintValidationError::MissingMtls => oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "CIBA requires mTLS sender constraint.",
                false,
            ),
            SenderConstraintValidationError::Multiple => sender_constraint_multiple_error(),
        })?;
    Ok((sender.dpop_jkt, sender.mtls_x5t_s256))
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
