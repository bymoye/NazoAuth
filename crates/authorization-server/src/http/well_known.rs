use std::sync::Arc;

use actix_web::{
    HttpResponse,
    http::StatusCode,
    web::{Data, Json},
};
use nazo_persistence::DatabaseHealthPort;
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Clone)]
pub(crate) struct ReadinessDependencies {
    database: Arc<dyn DatabaseHealthPort>,
    transient_state: Arc<dyn crate::bootstrap::TransientStateHealthPort>,
    keyset: nazo_key_management::KeyManager,
}

impl ReadinessDependencies {
    pub(crate) fn new(
        database: Arc<dyn DatabaseHealthPort>,
        transient_state: Arc<dyn crate::bootstrap::TransientStateHealthPort>,
        keyset: nazo_key_management::KeyManager,
    ) -> Self {
        Self {
            database,
            transient_state,
            keyset,
        }
    }
}

#[derive(Serialize)]
struct DependencyCheck {
    status: &'static str,
}

#[derive(Serialize)]
struct ReadinessResponse {
    status: &'static str,
    checks: ReadinessChecks,
}

#[derive(Serialize)]
struct ReadinessChecks {
    database: DependencyCheck,
    transient_state: DependencyCheck,
    signing_keys: DependencyCheck,
}

pub(crate) async fn live() -> Json<Value> {
    Json(json!({"status": "live"}))
}

pub(crate) async fn startup() -> Json<Value> {
    // The listener is bound only after migrations, dependency connections,
    // runtime-module initialization, and signing-key loading have completed.
    Json(json!({"status": "started"}))
}

pub(crate) async fn ready(dependencies: Data<ReadinessDependencies>) -> HttpResponse {
    let (database, transient_state) = tokio::join!(
        dependencies.database.check(),
        dependencies.transient_state.check()
    );
    let database_up = database.is_ok();
    let transient_state_up = transient_state.is_ok();
    let signing_keys_up = dependencies.keyset.is_healthy();
    if let Err(error) = database {
        tracing::warn!(%error, "readiness database probe failed");
    }
    if let Err(error) = transient_state {
        tracing::warn!(%error, "readiness transient-state probe failed");
    }
    if !signing_keys_up {
        tracing::warn!("readiness signing-key lifecycle is unhealthy");
    }
    readiness_response(database_up, transient_state_up, signing_keys_up)
}

fn readiness_response(
    database_up: bool,
    transient_state_up: bool,
    signing_keys_up: bool,
) -> HttpResponse {
    let ready = database_up && transient_state_up && signing_keys_up;
    HttpResponse::build(if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    })
    .json(ReadinessResponse {
        status: if ready { "ready" } else { "not_ready" },
        checks: ReadinessChecks {
            database: DependencyCheck {
                status: if database_up { "up" } else { "down" },
            },
            transient_state: DependencyCheck {
                status: if transient_state_up { "up" } else { "down" },
            },
            signing_keys: DependencyCheck {
                status: if signing_keys_up { "up" } else { "down" },
            },
        },
    })
}

pub(crate) async fn captcha_config() -> Json<Value> {
    Json(json!({
        "turnstile_enabled": false,
        "turnstile_site_key": null,
        "registration_enabled": true
    }))
}

#[cfg(test)]
#[path = "../../tests/unit/http/well_known.rs"]
mod tests;
