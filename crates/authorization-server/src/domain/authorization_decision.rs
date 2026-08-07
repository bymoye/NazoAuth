use std::sync::Arc;

use chrono::Utc;
use nazo_auth::{
    AuthorizationApprovalInput, AuthorizationDecisionAdmissionError, AuthorizationResponsePlan,
    AuthorizationResponsePolicyError, AuthorizationResponsePolicyInput, CapabilityAdmission,
    SignedJarmAuthorizationResponse, UserAuthorizationDecision, module_admissible,
    plain_authorization_response_uri, plan_authorization_response,
    signed_jarm_authorization_response_uri,
};
use nazo_http_actix::{
    AuthorizationDecisionCommand, AuthorizationDecisionError, AuthorizationDecisionFuture,
    AuthorizationDecisionOperations, AuthorizationDecisionResponse,
};
use nazo_identity::{SessionResolution, SessionService};
use nazo_runtime_modules::ModuleId;
use serde_json::json;
use uuid::Uuid;

use crate::{
    adapters::{
        audit::{audit_event, audit_event_required, audit_fields, ensure_audit_storage},
        security::{blake3_hex, random_urlsafe_token},
    },
    domain::{
        client_jwe::{JwePayloadKind, client_jwe_key, encrypt_compact_jwe},
        tenancy::default_tenant_context,
    },
    http::authorization::{AuthorizationHttpConfig, ServerAuthorizationService},
    runtime_modules::ServerRuntimeModuleRegistry,
};

#[derive(Clone)]
pub(crate) struct ServerAuthorizationDecisionOperations {
    service: Arc<ServerAuthorizationService>,
    sessions: SessionService,
    config: Arc<AuthorizationHttpConfig>,
    runtime_modules: Arc<ServerRuntimeModuleRegistry>,
}

impl ServerAuthorizationDecisionOperations {
    pub(crate) fn new(
        service: Arc<ServerAuthorizationService>,
        sessions: SessionService,
        config: Arc<AuthorizationHttpConfig>,
        runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    ) -> Self {
        Self {
            service,
            sessions,
            config,
            runtime_modules,
        }
    }

    async fn decide_inner(
        &self,
        command: AuthorizationDecisionCommand,
    ) -> Result<AuthorizationDecisionResponse, AuthorizationDecisionError> {
        let session = match self
            .sessions
            .current(&command.session_id, Utc::now().timestamp())
            .await
            .map_err(|error| {
                tracing::warn!(%error, "failed to resolve authorization decision session");
                AuthorizationDecisionError::SessionLookupUnavailable
            })? {
            SessionResolution::Present(session) => session,
            SessionResolution::Missing | SessionResolution::Invalidated => {
                return Err(AuthorizationDecisionError::LoginRequired);
            }
        };

        ensure_audit_storage().await.map_err(|error| {
            tracing::error!(%error, "authorization decision audit preflight failed");
            AuthorizationDecisionError::AuditUnavailable
        })?;
        let decision = match command.decision {
            UserAuthorizationDecision::Approve => "approve",
            UserAuthorizationDecision::Deny => "deny",
        };
        audit_event_required(
            "authorization_decision_intent",
            audit_fields(&[
                ("request_id_hash", json!(blake3_hex(&command.request_id))),
                ("user_id", json!(session.user().id())),
                ("decision", json!(decision)),
                ("source_ip_hash", json!(blake3_hex(&command.source_ip))),
            ]),
        )
        .await
        .map_err(|error| {
            tracing::error!(%error, "authorization decision audit intent failed");
            AuthorizationDecisionError::AuditUnavailable
        })?;

        let payload = match self
            .service
            .admit_user_decision(&command.request_id, session.user().id())
            .await
        {
            Ok(payload) => payload,
            Err(
                AuthorizationDecisionAdmissionError::ConsentMissing
                | AuthorizationDecisionAdmissionError::ConsentMalformed,
            ) => return Err(AuthorizationDecisionError::ConsentInvalid),
            Err(AuthorizationDecisionAdmissionError::ConsentReadFailed(error)) => {
                tracing::warn!(%error, "failed to claim authorization consent state");
                return Err(AuthorizationDecisionError::ConsentReadUnavailable);
            }
            Err(AuthorizationDecisionAdmissionError::UserMismatch) => {
                return Err(AuthorizationDecisionError::UserMismatch);
            }
            Err(AuthorizationDecisionAdmissionError::PushedRequestMissing(consent)) => {
                return self
                    .response_location(&consent, None, Some("invalid_request_uri"), None)
                    .await;
            }
            Err(AuthorizationDecisionAdmissionError::PushedRequestMalformed(consent)) => {
                tracing::warn!("PAR payload is malformed while claiming authorization consent");
                return self
                    .response_location(&consent, None, Some("server_error"), None)
                    .await;
            }
            Err(AuthorizationDecisionAdmissionError::PushedRequestReadFailed {
                consent,
                source,
            }) => {
                tracing::warn!(%source, "failed to claim consent-bound PAR state");
                return self
                    .response_location(&consent, None, Some("server_error"), None)
                    .await;
            }
        };

        // The intent above is the fail-closed evidence boundary. The outcome
        // remains best-effort because consent/PAR state and the audit ledger
        // are separate stores and cannot commit atomically here.
        if command.decision == UserAuthorizationDecision::Deny {
            record_decision_audit("authorization_denied", &payload, &command.source_ip);
            return self
                .response_location(&payload, None, Some("access_denied"), None)
                .await;
        }

        let establishes_oidc_login = payload.scopes.iter().any(|scope| scope == "openid");
        if establishes_oidc_login && payload.oidc_sid.as_deref() != Some(session.oidc_sid()) {
            tracing::warn!("authorization consent is not bound to the current OP browser session");
            return Err(AuthorizationDecisionError::ConsentInvalid);
        }

        let now = Utc::now();
        let code = random_urlsafe_token();
        let code_id = Uuid::now_v7().to_string();
        let code_hash = blake3_hex(&code);
        if let Err(error) = self
            .service
            .approve_consent(AuthorizationApprovalInput {
                consent: &payload,
                code_hash: &code_hash,
                code_id: &code_id,
                issued_at: now,
                code_ttl_seconds: payload
                    .authorization_code_ttl_seconds
                    .unwrap_or(self.config.auth_code_ttl_seconds),
                tenant_id: default_tenant_context().tenant_id,
            })
            .await
        {
            tracing::warn!(%error, "failed to persist user client grant");
            return Err(AuthorizationDecisionError::ApprovalUnavailable);
        }

        if establishes_oidc_login
            && !self
                .sessions
                .bind_client(&command.session_id, &payload.client_id)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "failed to bind logged-in RP to OP browser session");
                    AuthorizationDecisionError::SessionLookupUnavailable
                })?
        {
            tracing::warn!("OP browser session disappeared while binding logged-in RP");
            return Err(AuthorizationDecisionError::LoginRequired);
        }

        record_decision_audit("authorization_approved", &payload, &command.source_ip);
        self.response_location(&payload, Some(&code), None, payload.oidc_sid.as_deref())
            .await
    }

    async fn response_location(
        &self,
        payload: &nazo_auth::ConsentPayload,
        code: Option<&str>,
        error: Option<&str>,
        oidc_sid: Option<&str>,
    ) -> Result<AuthorizationDecisionResponse, AuthorizationDecisionError> {
        let modules = self.runtime_modules.snapshot();
        let plan = plan_authorization_response(AuthorizationResponsePolicyInput {
            issuer: &self.config.issuer,
            redirect_uri: &payload.redirect_uri,
            client_id: &payload.client_id,
            response_mode: payload.response_mode.as_deref(),
            code,
            error,
            state: payload.state.as_deref(),
            ttl_seconds: payload
                .authorization_code_ttl_seconds
                .unwrap_or(self.config.auth_code_ttl_seconds) as i64,
            signed_response_required: payload
                .signed_authorization_response_required
                .unwrap_or_else(|| self.config.profile.requires_signed_authorization_response()),
            jarm_available: module_admissible(
                &modules,
                ModuleId::Jarm,
                CapabilityAdmission::ExistingTransaction,
            ),
            session_management_available: payload.session_management_allowed.unwrap_or(true)
                && module_admissible(
                    &modules,
                    ModuleId::SessionManagement,
                    CapabilityAdmission::NewRequest,
                ),
        })
        .map_err(map_response_policy_error)?;

        let response = match plan {
            AuthorizationResponsePlan::Plain(plain) => {
                let session_state = if plain.issue_session_state {
                    oidc_sid.and_then(|sid| {
                        nazo_auth::issue_oidc_session_state(
                            &payload.client_id,
                            &payload.redirect_uri,
                            sid,
                        )
                    })
                } else {
                    None
                };
                AuthorizationDecisionResponse::Redirect {
                    location: plain_authorization_response_uri(&plain, session_state.as_deref()),
                }
            }
            AuthorizationResponsePlan::FormPost(plain) => {
                let session_state = if plain.issue_session_state {
                    oidc_sid.and_then(|sid| {
                        nazo_auth::issue_oidc_session_state(
                            &payload.client_id,
                            &payload.redirect_uri,
                            sid,
                        )
                    })
                } else {
                    None
                };
                AuthorizationDecisionResponse::FormPost {
                    action: plain.redirect_uri,
                    parameters: plain.parameters,
                    session_state,
                    csp_nonce: random_urlsafe_token(),
                }
            }
            AuthorizationResponsePlan::Jarm(jarm) => {
                let client = self
                    .service
                    .client_by_id(&payload.client_id)
                    .await
                    .map_err(|error| {
                        tracing::warn!(%error, client_id_hash = %blake3_hex(&payload.client_id), "failed to load JARM client response policy");
                        AuthorizationDecisionError::ResponseProtectionUnavailable
                    })?
                    .filter(|client| client.is_active)
                    .ok_or_else(|| {
                        tracing::warn!(client_id_hash = %blake3_hex(&payload.client_id), "JARM client is missing or inactive");
                        AuthorizationDecisionError::ResponseProtectionUnavailable
                    })?;
                let signed = self
                    .service
                    .sign_authorization_response(
                        jarm.signing_input(client.authorization_signed_response_alg.as_deref()),
                    )
                    .await
                    .map_err(|error| {
                        tracing::warn!(?error, "failed to sign JARM authorization response");
                        AuthorizationDecisionError::ResponseSigningUnavailable
                    })?;
                let response = match client_jwe_key(
                    client.jwks.as_ref(),
                    client.authorization_encrypted_response_alg.as_deref(),
                    client.authorization_encrypted_response_enc.as_deref(),
                    "authorization response",
                )
                .map_err(|error| {
                    tracing::warn!(%error, "failed to select JARM encryption key");
                    AuthorizationDecisionError::ResponseSigningUnavailable
                })? {
                    Some(key) => encrypt_compact_jwe(
                        &key,
                        signed.as_bytes(),
                        JwePayloadKind::NestedJwt,
                    )
                    .map_err(|error| {
                        tracing::warn!(%error, "failed to encrypt JARM authorization response");
                        AuthorizationDecisionError::ResponseSigningUnavailable
                    })?,
                    None => signed,
                };
                AuthorizationDecisionResponse::Redirect {
                    location: signed_jarm_authorization_response_uri(
                        &SignedJarmAuthorizationResponse {
                            redirect_uri: jarm.redirect_uri,
                            response,
                        },
                    ),
                }
            }
        };
        Ok(response)
    }
}

impl AuthorizationDecisionOperations for ServerAuthorizationDecisionOperations {
    fn decide(&self, command: AuthorizationDecisionCommand) -> AuthorizationDecisionFuture<'_> {
        Box::pin(self.decide_inner(command))
    }
}

fn map_response_policy_error(
    error: AuthorizationResponsePolicyError,
) -> AuthorizationDecisionError {
    match error {
        AuthorizationResponsePolicyError::UnsupportedResponseMode => {
            AuthorizationDecisionError::UnsupportedResponseMode
        }
        AuthorizationResponsePolicyError::MissingClientId => {
            AuthorizationDecisionError::ResponseSigningUnavailable
        }
        AuthorizationResponsePolicyError::Dependency(error) => {
            tracing::warn!(?error, "authorization response policy dependency failed");
            AuthorizationDecisionError::ResponseProtectionUnavailable
        }
    }
}

fn record_decision_audit(event: &str, payload: &nazo_auth::ConsentPayload, source_ip: &str) {
    audit_event(
        event,
        audit_fields(&[
            ("user_id", json!(payload.user_id)),
            ("client_id", json!(payload.client_id)),
            ("request_id_hash", json!(blake3_hex(&payload.request_id))),
            ("scope", json!(payload.scopes.join(" "))),
            ("source_ip_hash", json!(blake3_hex(source_ip))),
        ]),
    );
}

#[cfg(test)]
#[path = "../../tests/unit/domain/authorization_decision.rs"]
mod tests;
