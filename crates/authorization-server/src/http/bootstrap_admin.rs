use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use actix_web::{
    HttpResponse,
    http::StatusCode,
    web::{Data, Json},
};
use nazo_identity::{email::normalize_email_address, ports::SecretHashPort as _};
use nazo_persistence::{
    InitialAdminBootstrapState, InitialAdminBootstrapStore, InitialAdminClaimOutcome,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::{
    adapters::security::constant_time_eq, bootstrap::RegistrationSecretHasher,
    config::read_or_create_runtime_secret,
};

#[derive(Clone)]
pub(crate) struct InitialAdminBootstrapEndpoint {
    repository: Arc<dyn InitialAdminBootstrapStore>,
    expected_token_hash: Arc<RwLock<Option<String>>>,
    token_path: PathBuf,
    /// Persistent deployment identity from control discovery. Every bootstrap
    /// claim must name exactly this deployment.
    expected_deployment_id: String,
}

impl InitialAdminBootstrapEndpoint {
    pub(crate) async fn initialize(
        repository: Arc<dyn InitialAdminBootstrapStore>,
        data_dir: &std::path::Path,
        issuer: &str,
        deployment_id: &str,
    ) -> anyhow::Result<Self> {
        let (token_path, token) =
            read_or_create_runtime_secret(data_dir, "bootstrap/initial-admin-token")?;
        if !valid_initial_admin_token(&token) {
            anyhow::bail!(
                "initial administrator token is malformed; restore or remove the private bootstrap state"
            );
        }
        let token_hash = hash_token(&token);
        let state = repository.load_state().await?;
        let expected_token_hash = bootstrap_token_state(state, &token_path, issuer, token_hash);
        Ok(Self {
            repository,
            expected_token_hash: Arc::new(RwLock::new(expected_token_hash)),
            token_path,
            expected_deployment_id: deployment_id.to_owned(),
        })
    }

    fn expected_token_hash(&self) -> Option<String> {
        self.expected_token_hash
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn deployment_id_matches(&self, presented: &str) -> bool {
        // Exact bytes: a deployment identity is an identifier, not free text,
        // and the binding must not be loosened by incidental whitespace.
        constant_time_eq(self.expected_deployment_id.as_bytes(), presented.as_bytes())
    }

    fn close(&self) {
        *self
            .expected_token_hash
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

fn bootstrap_token_state(
    state: InitialAdminBootstrapState,
    token_path: &std::path::Path,
    issuer: &str,
    token_hash: String,
) -> Option<String> {
    match state {
        InitialAdminBootstrapState::Closed => {
            remove_consumed_token(token_path);
            None
        }
        InitialAdminBootstrapState::Ready => {
            tracing::warn!(
                issuer = %issuer.trim_end_matches('/'),
                token_file = %token_path.display(),
                "initial administrator setup is required; use the operator workflow to read the private runtime-owned token file"
            );
            Some(token_hash)
        }
        InitialAdminBootstrapState::Claimed {
            expected_token_hash,
        } => {
            if expected_token_hash != token_hash {
                remove_consumed_token(token_path);
            }
            tracing::warn!(
                issuer = %issuer.trim_end_matches('/'),
                token_file = %token_path.display(),
                "initial administrator claim is committed; retain the private token until the controller verifies its idempotent receipt"
            );
            Some(expected_token_hash)
        }
    }
}

fn valid_initial_admin_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_bootstrap_request_id(request_id: &str) -> bool {
    request_id.len() == 48
        && request_id
            .strip_prefix("bootstrap-admin-")
            .is_some_and(|suffix| {
                suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitialAdminClaimRequest {
    request_id: String,
    token: String,
    /// Deployment identity the caller believes it is claiming against. Must
    /// equal the persistent control-discovery deployment identity.
    deployment_id: String,
    email: String,
    password: String,
}

pub(crate) async fn claim_initial_admin(
    endpoint: Data<InitialAdminBootstrapEndpoint>,
    Json(payload): Json<InitialAdminClaimRequest>,
) -> HttpResponse {
    let Some(expected_hash) = endpoint.expected_token_hash() else {
        return bootstrap_error(StatusCode::GONE, "bootstrap_closed");
    };
    if !valid_bootstrap_request_id(&payload.request_id) {
        return bootstrap_error(StatusCode::BAD_REQUEST, "invalid_request_id");
    }
    if !valid_initial_admin_token(&payload.token) {
        return bootstrap_error(StatusCode::NOT_FOUND, "invalid_bootstrap_token");
    }
    let token_hash = hash_token(&payload.token);
    if !constant_time_eq(expected_hash.as_bytes(), token_hash.as_bytes()) {
        return bootstrap_error(StatusCode::NOT_FOUND, "invalid_bootstrap_token");
    }
    if !endpoint.deployment_id_matches(&payload.deployment_id) {
        return bootstrap_error(StatusCode::BAD_REQUEST, "deployment_mismatch");
    }
    let Ok(email) = normalize_email_address(&payload.email) else {
        return bootstrap_error(StatusCode::BAD_REQUEST, "invalid_email");
    };
    if !(12..=1024).contains(&payload.password.chars().count()) {
        return bootstrap_error(StatusCode::BAD_REQUEST, "invalid_password");
    }
    let password_hash = match RegistrationSecretHasher.hash_secret(payload.password).await {
        Ok(password_hash) => password_hash,
        Err(error) => {
            tracing::warn!(%error, "initial administrator password hashing failed");
            return bootstrap_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        }
    };
    match endpoint
        .repository
        .claim(&payload.request_id, &token_hash, &email, password_hash)
        .await
    {
        Ok(outcome) => claim_outcome_response(&endpoint, outcome),
        Err(error) => {
            tracing::error!(%error, "initial administrator claim failed");
            bootstrap_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
    }
}

fn claim_outcome_response(
    endpoint: &InitialAdminBootstrapEndpoint,
    outcome: InitialAdminClaimOutcome,
) -> HttpResponse {
    match outcome {
        InitialAdminClaimOutcome::Created {
            request_id,
            id,
            email,
        } => HttpResponse::Created().json(json!({
            "request_id": request_id,
            "id": id,
            "email": email,
            "role": "admin",
            "next": "/ui/auth"
        })),
        InitialAdminClaimOutcome::Closed => {
            endpoint.close();
            remove_consumed_token(&endpoint.token_path);
            bootstrap_error(StatusCode::GONE, "bootstrap_closed")
        }
        InitialAdminClaimOutcome::EmailConflict => {
            bootstrap_error(StatusCode::CONFLICT, "email_conflict")
        }
        InitialAdminClaimOutcome::IdempotencyConflict => {
            bootstrap_error(StatusCode::CONFLICT, "bootstrap_request_conflict")
        }
    }
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn remove_consumed_token(path: &std::path::Path) {
    if let Err(error) = std::fs::remove_file(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(%error, path = %path.display(), "failed to remove consumed bootstrap token");
    }
}

fn bootstrap_error(status: StatusCode, code: &str) -> HttpResponse {
    HttpResponse::build(status).json(json!({"error": code}))
}

#[cfg(test)]
#[path = "../../tests/unit/http/bootstrap_admin.rs"]
mod tests;
