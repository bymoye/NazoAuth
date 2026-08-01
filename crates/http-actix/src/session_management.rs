use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Data, Query},
};
use nazo_auth::{OidcSessionStatus, check_oidc_session_state};
use serde::Deserialize;
use serde_json::json;

use crate::{cookie_value, empty_response, json_response_no_store};

pub type SessionManagementFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<String>, SessionManagementError>> + Send + 'a>>;
pub type SessionManagementOriginFuture<'a> =
    Pin<Box<dyn Future<Output = Result<bool, SessionManagementError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionManagementAvailability {
    Disabled,
    Enabled,
    Draining,
}

impl SessionManagementAvailability {
    const fn permits_existing_transaction(self) -> bool {
        matches!(self, Self::Enabled | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionManagementError {
    SessionLookupUnavailable,
}

/// Storage and runtime-module boundary required by the session-management transport.
pub trait SessionManagementOperations: Send + Sync {
    fn availability(&self) -> SessionManagementAvailability;

    fn is_origin_allowed<'a>(
        &'a self,
        client_id: &'a str,
        origin: &'a str,
    ) -> SessionManagementOriginFuture<'a>;

    fn op_browser_state<'a>(&'a self, session_id: &'a str) -> SessionManagementFuture<'a>;
}

#[derive(Clone)]
pub struct SessionManagementConfig {
    issuer: Box<str>,
    session_cookie_name: Box<str>,
}

impl SessionManagementConfig {
    #[must_use]
    pub fn new(issuer: impl Into<Box<str>>, session_cookie_name: impl Into<Box<str>>) -> Self {
        Self {
            issuer: issuer.into(),
            session_cookie_name: session_cookie_name.into(),
        }
    }
}

#[derive(Clone)]
pub struct SessionManagementEndpoint {
    operations: Arc<dyn SessionManagementOperations>,
    config: SessionManagementConfig,
}

impl SessionManagementEndpoint {
    #[must_use]
    pub fn new(
        operations: Arc<dyn SessionManagementOperations>,
        config: SessionManagementConfig,
    ) -> Self {
        Self { operations, config }
    }
}

pub async fn check_session_iframe(endpoint: Data<SessionManagementEndpoint>) -> HttpResponse {
    if !endpoint
        .operations
        .availability()
        .permits_existing_transaction()
    {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let status_endpoint = format!("{}/check_session/status", endpoint.config.issuer);
    HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::PRAGMA, "no-cache"))
        .content_type("text/html; charset=utf-8")
        .body(session_management_iframe_document(&status_endpoint))
}

#[derive(Deserialize)]
pub struct CheckSessionStatusQuery {
    client_id: String,
    origin: String,
    session_state: String,
}

pub async fn check_session_status(
    endpoint: Data<SessionManagementEndpoint>,
    request: HttpRequest,
    Query(query): Query<CheckSessionStatusQuery>,
) -> HttpResponse {
    if !endpoint
        .operations
        .availability()
        .permits_existing_transaction()
    {
        return empty_response(StatusCode::NOT_FOUND);
    }

    // Preserve the protocol distinction between malformed state and a missing
    // OP session without performing a storage lookup for malformed input.
    if check_oidc_session_state(&query.client_id, &query.origin, &query.session_state, None)
        == OidcSessionStatus::Error
    {
        return status_response(OidcSessionStatus::Error);
    }

    match endpoint
        .operations
        .is_origin_allowed(&query.client_id, &query.origin)
        .await
    {
        Ok(true) => {}
        Ok(false) | Err(SessionManagementError::SessionLookupUnavailable) => {
            return status_response(OidcSessionStatus::Error);
        }
    }

    let Some(session_id) = cookie_value(&request, &endpoint.config.session_cookie_name) else {
        return status_response(OidcSessionStatus::Changed);
    };
    let op_browser_state = match endpoint.operations.op_browser_state(&session_id).await {
        Ok(state) => state,
        Err(SessionManagementError::SessionLookupUnavailable) => {
            return status_response(OidcSessionStatus::Error);
        }
    };
    status_response(check_oidc_session_state(
        &query.client_id,
        &query.origin,
        &query.session_state,
        op_browser_state.as_deref(),
    ))
}

fn status_response(status: OidcSessionStatus) -> HttpResponse {
    let status = match status {
        OidcSessionStatus::Unchanged => "unchanged",
        OidcSessionStatus::Changed => "changed",
        OidcSessionStatus::Error => "error",
    };
    json_response_no_store(json!({ "status": status }))
}

fn session_management_iframe_document(status_endpoint: &str) -> String {
    let head = include_str!("session_management_iframe.head.html").trim_end_matches(['\r', '\n']);
    format!(
        "{}{}{}{}",
        head,
        escape_js_string(status_endpoint),
        include_str!("session_management_iframe.tail.html"),
        ""
    )
}

fn escape_js_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\'', "\\'")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

#[cfg(test)]
#[path = "../tests/unit/session_management.rs"]
mod tests;
