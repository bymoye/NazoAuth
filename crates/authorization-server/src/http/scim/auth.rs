use super::ScimEndpoint;
use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::constant_time_eq;
use crate::domain::tenancy::default_tenant_context;
use crate::http::client_ip::client_ip_with_config;
use crate::http::scim::schema::scim_error;
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse};
use nazo_identity::ports::ScimCredentialUse;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;

pub(super) const SCIM_SCOPE_READ: &str = "scim:read";
pub(super) const SCIM_SCOPE_WRITE: &str = "scim:write";
pub(super) const SCIM_SCOPE_ALL: &str = "scim:*";

#[derive(Clone)]
pub(super) struct ScimCredential {
    pub(super) token_id: Option<Uuid>,
    pub(super) tenant_id: Uuid,
    pub(super) scopes: Vec<String>,
    pub(super) source: &'static str,
}

#[derive(Clone, Copy)]
pub(super) enum ScimRequiredScope {
    Read,
    Write,
}

impl ScimRequiredScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => SCIM_SCOPE_READ,
            Self::Write => SCIM_SCOPE_WRITE,
        }
    }
}

pub(super) async fn require_scim_bearer(
    endpoint: &ScimEndpoint,
    req: &HttpRequest,
    required_scope: ScimRequiredScope,
) -> Result<ScimCredential, HttpResponse> {
    if !endpoint.admission.accepts_new_requests() {
        return Err(scim_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "SCIM is disabled",
        ));
    }
    let Some(actual) = bearer_token(req) else {
        audit_scim_token_denied(endpoint, req, required_scope, "missing_bearer", None);
        return Err(scim_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing bearer token",
        ));
    };
    let token_hash = blake3_hex(actual);
    match load_scim_credential(endpoint, &token_hash).await {
        Ok(Some(credential)) => {
            return authorize_scim_credential(endpoint, req, required_scope, credential).await;
        }
        Ok(None) => {}
        Err(response) => {
            if let Some(credential) = legacy_scim_credential(endpoint, actual) {
                return authorize_scim_credential(endpoint, req, required_scope, credential).await;
            }
            return Err(response);
        }
    }
    if let Some(credential) = legacy_scim_credential(endpoint, actual) {
        return authorize_scim_credential(endpoint, req, required_scope, credential).await;
    }
    audit_scim_token_denied(endpoint, req, required_scope, "invalid_token", None);
    Err(scim_error(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "invalid bearer token",
    ))
}

async fn load_scim_credential(
    endpoint: &ScimEndpoint,
    token_hash: &str,
) -> Result<Option<ScimCredential>, HttpResponse> {
    match endpoint.service.active_credential(token_hash).await {
        Ok(Some(credential)) => Ok(Some(ScimCredential {
            token_id: Some(credential.id),
            tenant_id: credential.tenant_id,
            scopes: credential.scopes,
            source: "database",
        })),
        Ok(None) => Ok(None),
        Err(error) => {
            tracing::warn!(%error, "failed to query SCIM token");
            Err(scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            ))
        }
    }
}

fn legacy_scim_credential(endpoint: &ScimEndpoint, actual: &str) -> Option<ScimCredential> {
    let expected = endpoint.config.legacy_bearer_token.as_deref()?;
    constant_time_eq(expected.as_bytes(), actual.as_bytes()).then(|| {
        let tenant = default_tenant_context();
        ScimCredential {
            token_id: None,
            tenant_id: tenant.tenant_id,
            scopes: vec![SCIM_SCOPE_READ.to_owned(), SCIM_SCOPE_WRITE.to_owned()],
            source: "legacy-env",
        }
    })
}

async fn authorize_scim_credential(
    endpoint: &ScimEndpoint,
    req: &HttpRequest,
    required_scope: ScimRequiredScope,
    credential: ScimCredential,
) -> Result<ScimCredential, HttpResponse> {
    if !scim_credential_allows(&credential, required_scope) {
        audit_scim_token_denied(
            endpoint,
            req,
            required_scope,
            "insufficient_scope",
            credential.token_id,
        );
        return Err(scim_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "SCIM token lacks the required scope",
        ));
    }
    if !scim_credential_targets_served_tenant(&credential) {
        audit_scim_token_denied(
            endpoint,
            req,
            required_scope,
            "tenant_mismatch",
            credential.token_id,
        );
        return Err(scim_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "SCIM token is not valid for this tenant",
        ));
    }
    record_scim_token_use(endpoint, req, required_scope, &credential).await;
    audit_event(
        "scim_token_used",
        audit_fields(&[
            ("token_id", json!(credential.token_id)),
            ("tenant_id", json!(credential.tenant_id)),
            ("scope", json!(required_scope.as_str())),
            ("source", json!(credential.source)),
            (
                "ip_hash",
                json!(blake3_hex(&client_ip_with_config(
                    req,
                    &endpoint.config.client_ip
                ))),
            ),
        ]),
    );
    Ok(credential)
}

pub(super) fn scim_credential_targets_served_tenant(credential: &ScimCredential) -> bool {
    default_tenant_context().same_tenant(credential.tenant_id)
}

pub(super) fn scim_credential_allows(
    credential: &ScimCredential,
    required_scope: ScimRequiredScope,
) -> bool {
    credential
        .scopes
        .iter()
        .any(|scope| scope == SCIM_SCOPE_ALL || scope == required_scope.as_str())
}

#[cfg(test)]
pub(super) fn scim_scope_values(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(str::trim))
        .filter(|scope| !scope.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

async fn record_scim_token_use(
    endpoint: &ScimEndpoint,
    req: &HttpRequest,
    required_scope: ScimRequiredScope,
    credential: &ScimCredential,
) {
    let Some(token_id) = credential.token_id else {
        return;
    };
    let user_agent_hash = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(blake3_hex);
    if let Err(error) = endpoint
        .service
        .record_credential_use(ScimCredentialUse {
            token_id,
            tenant_id: credential.tenant_id,
            scopes: vec![required_scope.as_str().to_owned()],
            ip_hash: Some(blake3_hex(&client_ip_with_config(
                req,
                &endpoint.config.client_ip,
            ))),
            user_agent_hash,
        })
        .await
    {
        tracing::warn!(%error, token_id = %token_id, "failed to insert SCIM token audit event");
    }
}

fn audit_scim_token_denied(
    endpoint: &ScimEndpoint,
    req: &HttpRequest,
    required_scope: ScimRequiredScope,
    reason: &str,
    token_id: Option<Uuid>,
) {
    audit_event(
        "scim_token_denied",
        audit_fields(&[
            ("token_id", json!(token_id)),
            ("scope", json!(required_scope.as_str())),
            ("reason", json!(reason)),
            (
                "ip_hash",
                json!(blake3_hex(&client_ip_with_config(
                    req,
                    &endpoint.config.client_ip
                ))),
            ),
        ]),
    );
}

pub(super) fn bearer_token(req: &HttpRequest) -> Option<&str> {
    let raw = req
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim();
    let (scheme, token) = raw.split_once(char::is_whitespace)?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("Bearer")
        && !token.is_empty()
        && !token.contains(char::is_whitespace))
    .then_some(token)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/scim/tests/auth.rs"]
mod tests;
