use crate::adapters::audit::{audit_event_required, audit_fields, ensure_audit_storage};

use super::poll::{ciba_error_no_store, ciba_state_error_response, load_ciba_request_payload};
use super::*;

pub(crate) async fn ciba_verification_page(
    config: Data<CibaHttpConfig>,
    runtime: Data<ServerRuntimeModuleRegistry>,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    if !ciba_module_admissible(
        &runtime,
        nazo_auth::CapabilityAdmission::ExistingTransaction,
    ) {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let location = format!(
        "{}/ciba/{}",
        config.frontend_base_url.trim_end_matches('/'),
        urlencoding::encode(&path.into_inner())
    );
    HttpResponse::Found()
        .insert_header((header::LOCATION, location))
        .insert_header((header::CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .insert_header((header::PRAGMA, HeaderValue::from_static("no-cache")))
        .finish()
}

pub(crate) async fn ciba_verification(
    authorization_service: Data<ServerAuthorizationService>,
    ciba_service: Data<ServerCibaService>,
    sessions: Data<AdminSessionHandles>,
    config: Data<CibaHttpConfig>,
    runtime: Data<ServerRuntimeModuleRegistry>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    if !ciba_module_admissible(
        &runtime,
        nazo_auth::CapabilityAdmission::ExistingTransaction,
    ) {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let session = match sessions.current_session_or_login_required(&req).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let auth_req_id = path.into_inner();
    let state_payload = match load_ciba_request_payload(&ciba_service, &auth_req_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return oauth_error(
                StatusCode::NOT_FOUND,
                "invalid_request",
                "CIBA request expired.",
            );
        }
        Err(response) => return response,
    };
    if state_payload.user_id != session.user.id() {
        return oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "CIBA request user mismatch.",
        );
    }
    let request = if state_payload.status == CibaStatus::Pending
        && state_payload.expires_at > Utc::now().timestamp()
    {
        match ciba_authorization_request_view(&authorization_service, &state_payload).await {
            Ok(value) => value,
            Err(response) => return response,
        }
    } else {
        None
    };
    json_response_no_store(CibaVerificationView {
        auth_req_id,
        csrf_token: cookie_value(&req, &config.csrf_cookie_name),
        request,
    })
}

/// The Actix route boundary intentionally receives independent extractors and
/// shared application handles. Keep that transport signature explicit; the
/// business helpers below use focused command values instead.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn ciba_decision(
    ciba_service: Data<ServerCibaService>,
    sessions: Data<AdminSessionHandles>,
    config: Data<CibaHttpConfig>,
    runtime: Data<ServerRuntimeModuleRegistry>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
    Json(payload): Json<CibaDecisionRequest>,
) -> HttpResponse {
    if !ciba_module_admissible(
        &runtime,
        nazo_auth::CapabilityAdmission::ExistingTransaction,
    ) {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let session_http = sessions.http_config();
    if !has_valid_csrf_token_for_cookies(
        &req,
        payload.csrf_token.as_deref(),
        session_http.session_cookie_name(),
        session_http.csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    let session = match sessions.current_session_or_login_required(&req).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let auth_req_id = path.into_inner();
    if !matches!(payload.decision.as_str(), "approve" | "deny") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA decision is invalid.",
        );
    }
    let decision = if payload.decision == "approve" {
        CibaDecision::Approve(CibaAuthenticationContext {
            auth_time: session.auth_time,
            amr: session.amr.clone(),
            oidc_sid: Some(session.oidc_sid.clone()),
        })
    } else {
        CibaDecision::Deny
    };
    set_ciba_request_decision(
        &ciba_service,
        CibaDecisionCommand {
            auth_req_id,
            decision,
            expected_user_id: Some(session.user.id()),
            source: CibaDecisionSource::User,
            source_ip_hash: Some(blake3_hex(&client_ip_with_context(
                &req,
                config.client_ip_header_mode,
                &config.trusted_proxy_cidrs,
            ))),
        },
    )
    .await
}

struct CibaDecisionCommand {
    auth_req_id: String,
    decision: CibaDecision,
    expected_user_id: Option<Uuid>,
    source: CibaDecisionSource,
    source_ip_hash: Option<String>,
}

async fn prepare_ciba_decision_intent(
    ciba_service: &ServerCibaService,
    command: &CibaDecisionCommand,
) -> Result<(), HttpResponse> {
    let state = match load_ciba_request_payload(ciba_service, &command.auth_req_id).await {
        Ok(Some(state)) => state,
        Ok(None) => {
            return Err(ciba_error_no_store(
                StatusCode::NOT_FOUND,
                "invalid_request",
                "CIBA request expired.",
            ));
        }
        Err(response) => return Err(response),
    };
    if let Err(error) = ensure_audit_storage().await {
        tracing::error!(%error, "CIBA decision audit preflight failed");
        return Err(ciba_error_no_store(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA decision audit storage unavailable.",
        ));
    }
    let decision_name = match &command.decision {
        CibaDecision::Approve(_) => "approve",
        CibaDecision::Deny => "deny",
    };
    let mut fields = audit_fields(&[
        ("client_id", json!(state.client_id)),
        ("user_id", json!(state.user_id)),
        ("auth_req_id_hash", json!(blake3_hex(&command.auth_req_id))),
        ("decision", json!(decision_name)),
        ("decision_source", json!(command.source.as_str())),
        ("scope", json!(state.scopes.join(" "))),
        ("audience", json!(state.audiences)),
    ]);
    if let Some(source_ip_hash) = command.source_ip_hash.as_deref() {
        fields.insert("source_ip_hash".to_owned(), json!(source_ip_hash));
    }
    if let Some(expected_user_id) = command.expected_user_id {
        fields.insert("expected_user_id".to_owned(), json!(expected_user_id));
    }
    audit_event_required("ciba_decision_intent", fields)
        .await
        .map_err(|error| {
            tracing::error!(%error, "CIBA decision audit intent failed");
            ciba_error_no_store(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA decision audit could not be persisted.",
            )
        })
}

async fn set_ciba_request_decision(
    ciba_service: &ServerCibaService,
    command: CibaDecisionCommand,
) -> HttpResponse {
    if let Err(response) = prepare_ciba_decision_intent(ciba_service, &command).await {
        return response;
    }
    let CibaDecisionCommand {
        auth_req_id,
        decision,
        expected_user_id,
        source,
        source_ip_hash,
    } = command;
    let result = ciba_service
        .decide(&auth_req_id, decision, expected_user_id, || {
            Utc::now().timestamp()
        })
        .await;
    complete_ciba_decision(result, &auth_req_id, source, source_ip_hash)
}

pub(super) fn complete_ciba_decision(
    result: Result<CibaCommittedDecision, CibaDecisionFailure>,
    auth_req_id: &str,
    source: CibaDecisionSource,
    source_ip_hash: Option<String>,
) -> HttpResponse {
    match result {
        Ok(committed) => {
            let event = match &committed.decision {
                CibaDecision::Approve(_) => "ciba_authorization_approved",
                CibaDecision::Deny => "ciba_authorization_denied",
            };
            let decision_name = match &committed.decision {
                CibaDecision::Approve(_) => "approve",
                CibaDecision::Deny => "deny",
            };
            let mut fields = audit_fields(&[
                ("client_id", json!(committed.state.client_id)),
                ("user_id", json!(committed.state.user_id)),
                ("auth_req_id_hash", json!(blake3_hex(auth_req_id))),
                ("decision", json!(decision_name)),
                ("decision_source", json!(source.as_str())),
            ]);
            if let Some(source_ip_hash) = source_ip_hash {
                fields.insert("source_ip_hash".to_owned(), json!(source_ip_hash));
            }
            audit_event(event, fields);
            json_response_no_store(json!({"success": true}))
        }
        Err(CibaDecisionFailure::Missing | CibaDecisionFailure::Expired) => ciba_error_no_store(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "CIBA request expired.",
        ),
        Err(CibaDecisionFailure::UserMismatch) => ciba_error_no_store(
            StatusCode::FORBIDDEN,
            "access_denied",
            "CIBA request user mismatch.",
        ),
        Err(CibaDecisionFailure::AlreadyHandled) => ciba_error_no_store(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA request was already handled.",
        ),
        Err(CibaDecisionFailure::InvalidAuthenticationContext) => ciba_error_no_store(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA authentication context is invalid.",
        ),
        Err(CibaDecisionFailure::Storage(error)) => ciba_state_error_response(error),
        Err(CibaDecisionFailure::Contended) => ciba_error_no_store(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA state is busy.",
        ),
    }
}

async fn ciba_authorization_request_view(
    authorization_service: &ServerAuthorizationService,
    payload: &CibaRequestState,
) -> Result<Option<CibaAuthorizationRequestView>, HttpResponse> {
    let client = match authorization_service.client_by_id(&payload.client_id).await {
        Ok(Some(client)) if client.is_active => client,
        Ok(_) => return Ok(None),
        Err(error) => {
            tracing::warn!(%error, "failed to load CIBA client for verification page");
            return Err(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA client unavailable.",
            ));
        }
    };
    Ok(Some(CibaAuthorizationRequestView {
        client_id: payload.client_id.clone(),
        client_name: client.client_name.clone(),
        scopes: payload.scopes.clone(),
        audiences: payload.audiences.clone(),
        binding_message: payload.binding_message.clone(),
        interval_seconds: payload.interval_seconds,
        issued_at: DateTime::<Utc>::from_timestamp(payload.issued_at, 0).unwrap_or_else(Utc::now),
        expires_at: DateTime::<Utc>::from_timestamp(payload.expires_at, 0).unwrap_or_else(Utc::now),
    }))
}

pub(super) fn ciba_poll_failure_response(failure: CibaPollFailure) -> HttpResponse {
    match failure {
        CibaPollFailure::Missing => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA auth_req_id is expired or consumed.",
            false,
        ),
        CibaPollFailure::ClientMismatch => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "CIBA auth_req_id was not issued to this client.",
            false,
        ),
        CibaPollFailure::Storage(error) => {
            tracing::warn!(%error, "CIBA poll state operation failed");
            oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA state unavailable.",
                false,
            )
        }
        CibaPollFailure::Contended => oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA state is busy.",
            false,
        ),
    }
}
