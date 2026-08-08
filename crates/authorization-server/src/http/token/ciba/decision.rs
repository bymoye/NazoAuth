use crate::adapters::{
    audit::{audit_event_required, audit_fields, ensure_audit_storage},
    security::constant_time_eq,
};

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

pub(crate) async fn ciba_automated_decision(
    ciba_service: Data<ServerCibaService>,
    conformance_leases: Option<Data<nazo_postgres::ConformanceLeaseRepository>>,
    config: Data<CibaHttpConfig>,
    runtime: Data<ServerRuntimeModuleRegistry>,
    req: HttpRequest,
    Query(query): Query<CibaAutomatedDecisionQuery>,
) -> HttpResponse {
    if !ciba_module_admissible(
        &runtime,
        nazo_auth::CapabilityAdmission::ExistingTransaction,
    ) {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let (auth_req_id, lease_binding) = match config.automated_decision_mode {
        CibaAutomatedDecisionMode::Disabled => {
            let Some(actual_token) = ciba_automated_decision_request_token(&config, &req, &query)
            else {
                return empty_response(StatusCode::NOT_FOUND);
            };
            let actual_token_sha256 = sha256_hex(actual_token.as_bytes());
            let Some(conformance_leases) = conformance_leases else {
                // The production composition root always installs this repository;
                // a missing dependency must fail closed rather than opening every
                // CIBA transaction when the default mode is disabled.
                return empty_response(StatusCode::NOT_FOUND);
            };
            let lease_id = match conformance_leases
                .active_ciba_automated_decision_lease_id(
                    config.tenant_id,
                    CIBA_AUTOMATED_DECISION_PROFILE,
                    &actual_token_sha256,
                )
                .await
            {
                Ok(Some(lease_id)) => lease_id,
                Ok(None) => return empty_response(StatusCode::NOT_FOUND),
                Err(_error) => {
                    tracing::warn!(
                        "failed to query CIBA automated-decision conformance lease token"
                    );
                    return ciba_error_no_store(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "CIBA automated decision unavailable.",
                    );
                }
            };
            let auth_req_id = match ciba_automated_decision_auth_req_id(&query) {
                Ok(auth_req_id) => auth_req_id,
                Err(response) => return response,
            };
            let state_payload = match load_ciba_request_payload(&ciba_service, auth_req_id).await {
                Ok(Some(value)) => value,
                Ok(None) => return empty_response(StatusCode::NOT_FOUND),
                Err(response) => return response,
            };
            (
                auth_req_id,
                Some((
                    lease_id,
                    state_payload.client_id.clone(),
                    conformance_leases,
                )),
            )
        }
        CibaAutomatedDecisionMode::Header | CibaAutomatedDecisionMode::QueryParameter => {
            let Some(expected_token) = config.automated_decision_token.as_deref() else {
                return empty_response(StatusCode::NOT_FOUND);
            };
            let Some(actual_token) = ciba_automated_decision_request_token(&config, &req, &query)
            else {
                return empty_response(StatusCode::NOT_FOUND);
            };
            if !constant_time_eq(expected_token.as_bytes(), actual_token.as_bytes()) {
                return empty_response(StatusCode::NOT_FOUND);
            }
            let auth_req_id = match ciba_automated_decision_auth_req_id(&query) {
                Ok(auth_req_id) => auth_req_id,
                Err(response) => return response,
            };
            let Some(conformance_leases) = conformance_leases else {
                return empty_response(StatusCode::NOT_FOUND);
            };
            let state_payload = match load_ciba_request_payload(&ciba_service, auth_req_id).await {
                Ok(Some(value)) => value,
                Ok(None) => return empty_response(StatusCode::NOT_FOUND),
                Err(response) => return response,
            };
            let lease_id = match conformance_leases
                .active_lease_id_for_client(
                    config.tenant_id,
                    &state_payload.client_id,
                    CIBA_AUTOMATED_DECISION_PROFILE,
                )
                .await
            {
                Ok(Some(lease_id)) => lease_id,
                Ok(None) => return empty_response(StatusCode::NOT_FOUND),
                Err(error) => {
                    tracing::warn!(%error, "failed to query CIBA automated-decision client lease");
                    return ciba_error_no_store(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "CIBA automated decision unavailable.",
                    );
                }
            };
            (
                auth_req_id,
                Some((lease_id, state_payload.client_id, conformance_leases)),
            )
        }
    };
    let decision = match query
        .action
        .as_deref()
        .or(query.r#type.as_deref())
        .map(str::trim)
    {
        Some("allow" | "approve") => CibaDecision::Approve,
        Some("deny") => CibaDecision::Deny,
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA automated decision is invalid.",
            );
        }
    };
    let source_ip_hash = Some(blake3_hex(&client_ip_with_context(
        &req,
        config.client_ip_header_mode,
        &config.trusted_proxy_cidrs,
    )));
    let Some((lease_id, client_id, conformance_leases)) = lease_binding else {
        // Every enabled automated-decision transport is lease-bound.  The
        // branches above return an opaque response when the lease repository
        // or active lease is unavailable, so an unguarded decision path must
        // never be reachable here.
        return empty_response(StatusCode::NOT_FOUND);
    };
    set_ciba_request_decision_with_lease(
        &ciba_service,
        &conformance_leases,
        CibaDecisionLease {
            tenant_id: config.tenant_id,
            client_id,
            expected_lease_id: Some(lease_id),
        },
        CibaDecisionCommand {
            auth_req_id: auth_req_id.to_owned(),
            decision,
            expected_user_id: None,
            source: CibaDecisionSource::Automation,
            authentication_context: None,
            source_ip_hash,
        },
    )
    .await
}

pub(super) fn ciba_automated_decision_auth_req_id(
    query: &CibaAutomatedDecisionQuery,
) -> Result<&str, HttpResponse> {
    query
        .auth_req_id
        .as_deref()
        .or(query.token.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA auth_req_id is required.",
            )
        })
}

pub(super) fn sha256_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
            output
        })
}

pub(super) fn ciba_automated_decision_request_token(
    config: &CibaHttpConfig,
    req: &HttpRequest,
    query: &CibaAutomatedDecisionQuery,
) -> Option<String> {
    match config.automated_decision_mode {
        CibaAutomatedDecisionMode::Disabled => {
            if req.method() != actix_web::http::Method::POST {
                return None;
            }
            query.decision_token.clone()
        }
        CibaAutomatedDecisionMode::QueryParameter => {
            if req.method() != actix_web::http::Method::GET {
                return None;
            }
            query.decision_token.clone()
        }
        CibaAutomatedDecisionMode::Header => {
            if req.method() != actix_web::http::Method::POST || query.decision_token.is_some() {
                return None;
            }
            match nazo_http_actix::authorization_access_token(req.headers()) {
                Some((nazo_http_actix::AccessTokenAuthScheme::Bearer, token)) => Some(token),
                _ => None,
            }
        }
    }
}

/// The Actix route boundary intentionally receives independent extractors and
/// shared application handles. Keep that transport signature explicit; the
/// business helpers below use focused command values instead.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn ciba_decision(
    ciba_service: Data<ServerCibaService>,
    conformance_leases: Option<Data<nazo_postgres::ConformanceLeaseRepository>>,
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
        CibaDecision::Approve
    } else {
        CibaDecision::Deny
    };
    let state_payload = match load_ciba_request_payload(&ciba_service, &auth_req_id).await {
        Ok(Some(value)) => value,
        Ok(None) => return empty_response(StatusCode::NOT_FOUND),
        Err(response) => return response,
    };
    let Some(conformance_leases) = conformance_leases else {
        // The composition root always installs the repository. A missing
        // guard must fail closed instead of allowing a browser decision to
        // race a conformance-lease revocation.
        return ciba_error_no_store(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA decision unavailable.",
        );
    };
    set_ciba_request_decision_with_lease(
        &ciba_service,
        &conformance_leases,
        CibaDecisionLease {
            tenant_id: config.tenant_id,
            client_id: state_payload.client_id,
            expected_lease_id: None,
        },
        CibaDecisionCommand {
            auth_req_id,
            decision,
            expected_user_id: Some(session.user.id()),
            source: CibaDecisionSource::User,
            authentication_context: Some(CibaAuthenticationContext {
                auth_time: session.auth_time,
                amr: session.amr.clone(),
                oidc_sid: Some(session.oidc_sid.clone()),
            }),
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
    authentication_context: Option<CibaAuthenticationContext>,
    source_ip_hash: Option<String>,
}

struct CibaDecisionLease {
    tenant_id: Uuid,
    client_id: String,
    expected_lease_id: Option<Uuid>,
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
    let decision_name = match command.decision {
        CibaDecision::Approve => "approve",
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

async fn set_ciba_request_decision_with_lease(
    ciba_service: &ServerCibaService,
    conformance_leases: &nazo_postgres::ConformanceLeaseRepository,
    lease: CibaDecisionLease,
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
        authentication_context,
        source_ip_hash,
    } = command;
    let operation_auth_req_id = auth_req_id.clone();
    let result = match conformance_leases
        .with_active_ciba_decision(
            lease.tenant_id,
            &lease.client_id,
            lease.expected_lease_id,
            |lease_expires_at| async move {
                ciba_service
                    .decide_with_authentication_context_and_lease_deadline(
                        &operation_auth_req_id,
                        decision,
                        expected_user_id,
                        authentication_context,
                        lease_expires_at,
                        || Utc::now().timestamp(),
                    )
                    .await
            },
        )
        .await
    {
        Ok(Some(result)) => result,
        Ok(None) => {
            // A per-run credential is deliberately indistinguishable
            // from an unknown transaction or an already revoked lease.  Do
            // not return a protocol body that would let the caller probe the
            // client/lease binding; the disabled production route is an
            // opaque, temporary conformance boundary.
            if lease.expected_lease_id.is_some() {
                return empty_response(StatusCode::NOT_FOUND);
            }
            return complete_ciba_decision(
                Err(CibaDecisionFailure::Missing),
                &auth_req_id,
                source,
                source_ip_hash,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to acquire CIBA conformance lease decision guard");
            return ciba_error_no_store(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA decision unavailable.",
            );
        }
    };
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
            let event = match committed.decision {
                CibaDecision::Approve => "ciba_authorization_approved",
                CibaDecision::Deny => "ciba_authorization_denied",
            };
            let decision_name = match committed.decision {
                CibaDecision::Approve => "approve",
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
