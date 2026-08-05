use std::time::Duration;

use anyhow::Context as _;
use nazo_operator_protocol::{ConformanceLeaseSummary, Openid4vcConformanceTrust, TaskResult};
use nazo_postgres::{ConformanceLease, ConformanceLeaseRepository, ConformanceLeaseTokenDigests};
use uuid::Uuid;

use crate::{
    config::{ConfigSource, database_url},
    domain::tenancy::DEFAULT_TENANT_ID,
};

pub(crate) async fn operator_create(
    profile: &str,
    material_sha256: &str,
    dynamic_registration_initial_access_token_sha256: Option<&str>,
    ciba_automated_decision_token_sha256: Option<&str>,
    public_material: Option<Openid4vcConformanceTrust>,
    ttl_seconds: u64,
) -> anyhow::Result<TaskResult> {
    let ttl_seconds = i64::try_from(ttl_seconds).context("conformance lease ttl is too large")?;
    if (dynamic_registration_initial_access_token_sha256.is_some()
        || ciba_automated_decision_token_sha256.is_some())
        && profile != "oidc-fapi-ciba"
    {
        anyhow::bail!("conformance token bindings are only allowed for the oidc-fapi-ciba profile");
    }
    for (digest, purpose) in [
        (
            dynamic_registration_initial_access_token_sha256,
            "dynamic registration initial-access-token",
        ),
        (
            ciba_automated_decision_token_sha256,
            "CIBA automated-decision token",
        ),
    ] {
        let Some(digest) = digest else {
            continue;
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            anyhow::bail!("{purpose} binding must be a lowercase SHA-256 digest");
        }
    }
    if let Some(material) = public_material.as_ref() {
        crate::domain::parse_conformance_credential_trust_anchor(
            &material.credential_trust_anchor_pem,
        )
        .context("invalid OpenID4VC conformance credential trust anchor")?;
    }
    let repository = repository()?;
    let lease = repository
        .create(
            DEFAULT_TENANT_ID,
            profile,
            material_sha256,
            ConformanceLeaseTokenDigests {
                dynamic_registration_initial_access_token_sha256,
                ciba_automated_decision_token_sha256,
            },
            public_material.map(|material| {
                serde_json::to_value(material).expect("serialize conformance trust")
            }),
            ttl_seconds,
        )
        .await?;
    Ok(TaskResult::ConformanceLeaseCreated {
        lease: summary(lease),
    })
}

pub(crate) async fn operator_list() -> anyhow::Result<TaskResult> {
    let leases = repository()?
        .list(DEFAULT_TENANT_ID)
        .await?
        .into_iter()
        .map(summary)
        .collect();
    Ok(TaskResult::ConformanceLeaseList { leases })
}

pub(crate) async fn operator_revoke(lease_id: &str) -> anyhow::Result<TaskResult> {
    let lease_id = Uuid::parse_str(lease_id).context("conformance lease id is not a UUID")?;
    let deactivated_clients = repository()?.revoke(DEFAULT_TENANT_ID, lease_id).await?;
    Ok(TaskResult::ConformanceLeaseRevoked {
        lease_id: lease_id.to_string(),
        deactivated_clients: u64::try_from(deactivated_clients)
            .context("negative conformance client count")?,
    })
}

pub(crate) async fn operator_cleanup() -> anyhow::Result<TaskResult> {
    let result = repository()?.cleanup().await?;
    Ok(TaskResult::ConformanceLeaseCleaned {
        cleaned_leases: u64::try_from(result.cleaned_leases)
            .context("negative conformance lease cleanup count")?,
        deleted_clients: u64::try_from(result.deleted_clients)
            .context("negative conformance client cleanup count")?,
    })
}

fn repository() -> anyhow::Result<ConformanceLeaseRepository> {
    let config = ConfigSource::load_for_migrations()?;
    let pool = nazo_postgres::create_pool(database_url(&config), 1)?;
    Ok(ConformanceLeaseRepository::new(pool))
}

fn summary(lease: ConformanceLease) -> ConformanceLeaseSummary {
    ConformanceLeaseSummary {
        lease_id: lease.id.to_string(),
        profile: lease.profile,
        material_sha256: lease.material_sha256,
        created_at: lease.created_at.timestamp(),
        expires_at: lease.expires_at.timestamp(),
        revoked_at: lease.revoked_at.map(|value| value.timestamp()),
        cleaned_at: lease.cleaned_at.map(|value| value.timestamp()),
    }
}

pub(crate) fn spawn_cleanup(pool: nazo_postgres::DbPool) {
    tokio::spawn(async move {
        let repository = ConformanceLeaseRepository::new(pool);
        loop {
            match repository.cleanup().await {
                Ok(result) if result.cleaned_leases > 0 => tracing::info!(
                    cleaned_leases = result.cleaned_leases,
                    deleted_clients = result.deleted_clients,
                    "cleaned expired conformance leases"
                ),
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    error = %error,
                    "failed to clean expired conformance leases; will retry"
                ),
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

#[cfg(test)]
#[path = "../tests/unit/conformance_lease.rs"]
mod tests;
