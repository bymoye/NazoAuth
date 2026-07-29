use std::sync::Arc;

use nazo_auth::{CapabilityAdmission, module_admissible};
use nazo_http_actix::{
    SessionManagementAvailability, SessionManagementError, SessionManagementFuture,
    SessionManagementOperations, SessionManagementOriginFuture,
};
use nazo_postgres::OAuthClientRepository;
use nazo_runtime_modules::ModuleId;

use crate::http::sessions::SessionProfileHandles;
use crate::runtime_modules::ServerRuntimeModuleRegistry;

/// Minimal composition-root provider for OIDC Session Management.
///
/// It reads only the immutable module snapshot and the focused session resolver.
/// The resolver deliberately preserves account revocation, pending-MFA, and
/// malformed-session checks before an OP browser-state can be reported live.
#[derive(Clone)]
pub(crate) struct ServerSessionManagementOperations {
    sessions: SessionProfileHandles,
    clients: OAuthClientRepository,
    runtime_modules: Arc<ServerRuntimeModuleRegistry>,
}

impl ServerSessionManagementOperations {
    pub(crate) fn new(
        sessions: SessionProfileHandles,
        clients: OAuthClientRepository,
        runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    ) -> Self {
        Self {
            sessions,
            clients,
            runtime_modules,
        }
    }
}

impl SessionManagementOperations for ServerSessionManagementOperations {
    fn availability(&self) -> SessionManagementAvailability {
        let snapshot = self.runtime_modules.snapshot();
        if module_admissible(
            &snapshot,
            ModuleId::SessionManagement,
            CapabilityAdmission::NewRequest,
        ) {
            SessionManagementAvailability::Enabled
        } else if module_admissible(
            &snapshot,
            ModuleId::SessionManagement,
            CapabilityAdmission::ExistingTransaction,
        ) {
            SessionManagementAvailability::Draining
        } else {
            SessionManagementAvailability::Disabled
        }
    }

    fn op_browser_state<'a>(&'a self, session_id: &'a str) -> SessionManagementFuture<'a> {
        Box::pin(async move {
            self.sessions
                .current_session_by_id(session_id)
                .await
                .map(|session| session.map(|current| current.oidc_sid))
                .map_err(|error| {
                    tracing::warn!(%error, "failed to resolve oidc session-management state");
                    SessionManagementError::SessionLookupUnavailable
                })
        })
    }

    fn is_origin_allowed<'a>(
        &'a self,
        client_id: &'a str,
        origin: &'a str,
    ) -> SessionManagementOriginFuture<'a> {
        Box::pin(async move {
            let client = self
                .clients
                .by_client_id(crate::domain::tenancy::DEFAULT_TENANT_ID, client_id)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "failed to resolve oidc session-management client");
                    SessionManagementError::SessionLookupUnavailable
                })?;
            Ok(client.is_some_and(|client| {
                client
                    .security_policy
                    .as_ref()
                    .is_none_or(|policy| policy.session_management)
                    && client_allows_origin(client.is_active, &client.redirect_uris, origin)
            }))
        })
    }
}

fn client_allows_origin(is_active: bool, redirect_uris: &[String], origin: &str) -> bool {
    is_active
        && redirect_uris.iter().any(|redirect_uri| {
            nazo_auth::oidc_redirect_uri_origin(redirect_uri).as_deref() == Some(origin)
        })
}

#[cfg(test)]
#[path = "../../tests/unit/domain/session_management.rs"]
mod tests;
