use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use actix_web::{
    HttpResponse,
    http::{StatusCode, header},
    web::{Data, Form, Query},
};
use chrono::{Duration, Utc};
use nazo_identity::{email::normalize_email_address, ports::SecretHashPort as _};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::{
    adapters::security::constant_time_eq, bootstrap::RegistrationSecretHasher,
    config::read_or_create_runtime_secret,
};

const INITIAL_ADMIN_CLAIM_TTL_MINUTES: i64 = 30;

#[derive(Clone)]
pub(crate) struct InitialAdminBootstrapEndpoint {
    repository: nazo_postgres::InitialAdminBootstrapRepository,
    expected_token_hash: Arc<RwLock<Option<String>>>,
    token_path: PathBuf,
}

impl InitialAdminBootstrapEndpoint {
    pub(crate) async fn initialize(
        pool: nazo_postgres::DbPool,
        data_dir: &std::path::Path,
        issuer: &str,
    ) -> anyhow::Result<Self> {
        let (token_path, token) =
            read_or_create_runtime_secret(data_dir, "bootstrap/initial-admin-token")?;
        let token_hash = hash_token(&token);
        let repository = nazo_postgres::InitialAdminBootstrapRepository::new(pool);
        let state = repository
            .ensure_claim(
                &token_hash,
                Utc::now() + Duration::minutes(INITIAL_ADMIN_CLAIM_TTL_MINUTES),
            )
            .await?;
        let expected_token_hash = bootstrap_token_state(state, &token_path, issuer, token_hash);
        Ok(Self {
            repository,
            expected_token_hash: Arc::new(RwLock::new(expected_token_hash)),
            token_path,
        })
    }

    fn expected_token_hash(&self) -> Option<String> {
        self.expected_token_hash
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn close(&self) {
        *self
            .expected_token_hash
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

fn bootstrap_token_state(
    state: nazo_postgres::InitialAdminBootstrapState,
    token_path: &std::path::Path,
    issuer: &str,
    token_hash: String,
) -> Option<String> {
    match state {
        nazo_postgres::InitialAdminBootstrapState::Closed => {
            remove_consumed_token(token_path);
            None
        }
        nazo_postgres::InitialAdminBootstrapState::OwnedByAnotherInstance { expires_at } => {
            remove_consumed_token(token_path);
            tracing::warn!(
                %expires_at,
                "initial administrator setup is owned by another instance; share DATA_DIR across replicas"
            );
            None
        }
        nazo_postgres::InitialAdminBootstrapState::Ready { expires_at } => {
            tracing::warn!(
                issuer = %issuer.trim_end_matches('/'),
                %expires_at,
                token_file = %token_path.display(),
                "initial administrator setup is required; read the root-owned token file through the operator workflow"
            );
            Some(token_hash)
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct SetupQuery {
    token: String,
}

#[derive(Deserialize)]
pub(crate) struct InitialAdminClaimRequest {
    token: String,
    email: String,
    password: String,
}

pub(crate) async fn initial_admin_setup_page(
    endpoint: Data<InitialAdminBootstrapEndpoint>,
    Query(query): Query<SetupQuery>,
) -> HttpResponse {
    if !endpoint
        .expected_token_hash()
        .as_deref()
        .is_some_and(|expected| {
            constant_time_eq(expected.as_bytes(), hash_token(&query.token).as_bytes())
        })
    {
        return HttpResponse::NotFound().finish();
    }
    let token = html_escape(&query.token);
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header((header::REFERRER_POLICY, "no-referrer"))
        .body(format!(
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>NazoAuth 初始管理员</title></head><body><main><h1>创建初始管理员</h1><form method=\"post\" action=\"/auth/bootstrap-admin\"><input type=\"hidden\" name=\"token\" value=\"{token}\"><label>邮箱 <input required type=\"email\" name=\"email\" autocomplete=\"email\"></label><label>密码 <input required minlength=\"12\" type=\"password\" name=\"password\" autocomplete=\"new-password\"></label><button type=\"submit\">创建管理员</button></form></main></body></html>"
        ))
}

pub(crate) async fn claim_initial_admin(
    endpoint: Data<InitialAdminBootstrapEndpoint>,
    Form(payload): Form<InitialAdminClaimRequest>,
) -> HttpResponse {
    let Some(expected_hash) = endpoint.expected_token_hash() else {
        return bootstrap_error(StatusCode::GONE, "bootstrap_closed");
    };
    let token_hash = hash_token(&payload.token);
    if !constant_time_eq(expected_hash.as_bytes(), token_hash.as_bytes()) {
        return bootstrap_error(StatusCode::NOT_FOUND, "invalid_bootstrap_token");
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
        .claim(&token_hash, &email, password_hash)
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
    outcome: nazo_postgres::InitialAdminClaimOutcome,
) -> HttpResponse {
    match outcome {
        nazo_postgres::InitialAdminClaimOutcome::Created { id, email } => {
            endpoint.close();
            remove_consumed_token(&endpoint.token_path);
            HttpResponse::Created().json(json!({
                "id": id,
                "email": email,
                "role": "admin",
                "next": "/ui/login"
            }))
        }
        nazo_postgres::InitialAdminClaimOutcome::Closed => {
            endpoint.close();
            remove_consumed_token(&endpoint.token_path);
            bootstrap_error(StatusCode::GONE, "bootstrap_closed")
        }
        nazo_postgres::InitialAdminClaimOutcome::InvalidOrExpired => {
            bootstrap_error(StatusCode::NOT_FOUND, "invalid_bootstrap_token")
        }
        nazo_postgres::InitialAdminClaimOutcome::EmailConflict => {
            bootstrap_error(StatusCode::CONFLICT, "email_conflict")
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

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
#[path = "../../tests/unit/http/bootstrap_admin.rs"]
mod tests;
