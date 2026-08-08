use actix_web::{
    HttpResponse,
    http::StatusCode,
    web::{Data, Json},
};
use nazo_postgres::DbPool;
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Clone)]
pub(crate) struct ReadinessDependencies {
    database: DbPool,
    valkey: nazo_valkey::ValkeyConnection,
    keyset: nazo_key_management::KeyManager,
}

impl ReadinessDependencies {
    pub(crate) fn new(
        database: DbPool,
        valkey: nazo_valkey::ValkeyConnection,
        keyset: nazo_key_management::KeyManager,
    ) -> Self {
        Self {
            database,
            valkey,
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
    postgresql: DependencyCheck,
    valkey: DependencyCheck,
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
    let (postgresql, valkey) = tokio::join!(
        nazo_postgres::health_check(&dependencies.database),
        dependencies.valkey.health_check()
    );
    let postgresql_up = postgresql.is_ok();
    let valkey_up = valkey.is_ok();
    let signing_keys_up = dependencies.keyset.is_healthy();
    if let Err(error) = postgresql {
        tracing::warn!(%error, "readiness PostgreSQL probe failed");
    }
    if let Err(error) = valkey {
        tracing::warn!(%error, "readiness Valkey probe failed");
    }
    if !signing_keys_up {
        tracing::warn!("readiness signing-key lifecycle is unhealthy");
    }
    readiness_response(postgresql_up, valkey_up, signing_keys_up)
}

fn readiness_response(postgresql_up: bool, valkey_up: bool, signing_keys_up: bool) -> HttpResponse {
    let ready = postgresql_up && valkey_up && signing_keys_up;
    HttpResponse::build(if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    })
    .json(ReadinessResponse {
        status: if ready { "ready" } else { "not_ready" },
        checks: ReadinessChecks {
            postgresql: DependencyCheck {
                status: if postgresql_up { "up" } else { "down" },
            },
            valkey: DependencyCheck {
                status: if valkey_up { "up" } else { "down" },
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
