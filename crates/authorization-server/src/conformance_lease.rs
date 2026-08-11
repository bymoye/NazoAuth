use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    future::Future,
    io::{Read as _, Write as _},
    path::Path,
    pin::Pin,
    time::Duration,
};

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

#[cfg(unix)]
use rustix::fs::{Mode, OFlags};

use anyhow::{Context as _, bail};
use chrono::{DateTime, Utc};
use nazo_operator_protocol::{
    ConformanceLeaseSummary, ConformanceMatrixDescriptor, ConformanceOnboardingSummary,
    MAX_CONFORMANCE_ONBOARDING_CLIENTS, Openid4vcConformanceTrust, TaskResult,
    validate_conformance_matrix_descriptor,
};
use nazo_postgres::{ConformanceLease, ConformanceLeaseRepository, ConformanceLeaseTokenDigests};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    config::{ConfigSource, database_url},
    domain::tenancy::DEFAULT_TENANT_ID,
};

const CONFORMANCE_BUNDLE_PATH: &str = "/run/nazoauth-operator/conformance-bundle.json";
const CONFORMANCE_CLIENT_SECRET_PEPPER_PATH: &str = "/run/nazoauth-operator/client-secret-pepper";
const CONFORMANCE_PAIRWISE_SUBJECT_SECRET_PATH: &str =
    "/run/nazoauth-operator/pairwise-subject-secret";
const CONFORMANCE_OUTPUT_DIRECTORY: &str = "/run/nazoauth-operator-output";
const MAX_CONFORMANCE_BUNDLE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONFORMANCE_CLIENT_REQUEST_BYTES: usize = 256 * 1024;
const CONFORMANCE_MATRIX_BYTES: &[u8] =
    include_bytes!("../resources/nazoauth-conformance-matrix-v1.json");

/// The non-secret, already validated input passed to the persistence port.
///
/// This type deliberately lives in the authorization-server domain.  The
/// persistence crate must adapt it to its own transaction input instead of
/// making the operator protocol or server depend on a storage implementation.
pub(crate) struct ConformanceOnboardingRequest {
    pub tenant_id: Uuid,
    pub task_jti: String,
    pub profile: String,
    pub bundle_schema: u32,
    pub bundle_sha256: String,
    pub matrix_sha256: String,
    pub dynamic_registration_initial_access_token_sha256: Option<String>,
    pub ciba_automated_decision_token_sha256: Option<String>,
    pub client_count: u32,
    pub ttl_seconds: u64,
    pub applicant: ConformanceOnboardingApplicant,
    pub clients: Vec<ConformanceOnboardingClient>,
    pub mtls_trust_anchors: Vec<ConformanceOnboardingMtlsTrustAnchor>,
}

pub(crate) struct ConformanceOnboardingMtlsTrustAnchor {
    pub logical_client_id: String,
    pub certificate_pem: String,
    pub certificate_sha256: String,
    pub subject_dn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

pub(crate) struct ConformanceOnboardingApplicant {
    pub username: String,
    pub email: String,
    pub password_hash: nazo_identity::ports::PasswordHashInput,
    pub email_verified: bool,
}

pub(crate) struct ConformanceOnboardingClient {
    pub logical_client_id: String,
    pub prepared: nazo_auth::PreparedClientRegistration,
}

#[derive(Clone, Debug)]
pub(crate) struct ConformanceOnboardingResult {
    pub lease_id: Uuid,
    pub request_jti: String,
    pub applicant_id: String,
    pub client_mappings: Vec<(String, String)>,
    pub client_count: u32,
    pub matrix_sha256: String,
    pub bundle_sha256: String,
    pub expires_at: i64,
    pub idempotent_replay: bool,
}

pub(crate) type OnboardingFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<ConformanceOnboardingResult>> + Send + 'a>>;

/// Persistence boundary for the atomic lease + applicant + client transaction.
pub(crate) trait ConformanceOnboardingRepository: Send + Sync {
    fn apply_onboarding(&self, request: ConformanceOnboardingRequest) -> OnboardingFuture<'_>;
}

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
        crate::domain::parse_conformance_credential_trust_anchors(
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

/// Reads and validates the deployment-owned matrix descriptor. The operator
/// receipt supplies the signature; this function only enforces the closed,
/// non-secret schema before returning it.
pub(crate) async fn operator_matrix_describe() -> anyhow::Result<TaskResult> {
    let descriptor = load_matrix_descriptor()?;
    let sha256 = digest_hex(CONFORMANCE_MATRIX_BYTES);
    write_matrix_output(CONFORMANCE_MATRIX_BYTES)?;
    Ok(TaskResult::ConformanceMatrix {
        summary: nazo_operator_protocol::ConformanceMatrixSummary {
            schema: descriptor.schema,
            sha256,
            size: u64::try_from(CONFORMANCE_MATRIX_BYTES.len())
                .context("conformance matrix descriptor size overflow")?,
            group_count: u32::try_from(descriptor.groups.len())
                .context("conformance matrix group count overflow")?,
            plan_count: u32::try_from(
                descriptor
                    .groups
                    .iter()
                    .map(|group| group.plans.len())
                    .sum::<usize>(),
            )
            .context("conformance matrix plan count overflow")?,
            source_release: descriptor.source.release,
        },
    })
}

fn load_matrix_descriptor() -> anyhow::Result<ConformanceMatrixDescriptor> {
    if CONFORMANCE_MATRIX_BYTES.len() > 8 * 1024 * 1024 {
        bail!("conformance matrix descriptor exceeds the size limit");
    }
    let descriptor: ConformanceMatrixDescriptor = serde_json::from_slice(CONFORMANCE_MATRIX_BYTES)
        .map_err(|_| anyhow::anyhow!("conformance matrix descriptor is invalid"))?;
    validate_conformance_matrix_descriptor(&descriptor)
        .map_err(|_| anyhow::anyhow!("conformance matrix descriptor violates protocol policy"))?;
    Ok(descriptor)
}

/// Applies one atomic conformance onboarding request through the persistence
/// port. The JTI is supplied by the signed task and is never accepted from
/// the secret bundle.
pub(crate) async fn operator_onboarding_apply(
    task_jti: &str,
    profile: &str,
    bundle_schema: u32,
    expected_bundle_sha256: &str,
    expected_matrix_sha256: &str,
    expected_client_count: u32,
    ttl_seconds: u64,
) -> anyhow::Result<TaskResult> {
    let bundle_bytes =
        read_fixed_material(&conformance_bundle_path()?, MAX_CONFORMANCE_BUNDLE_BYTES)
            .context("conformance onboarding bundle is unavailable")?;
    let actual_bundle_sha256 = digest_hex(&bundle_bytes);
    if actual_bundle_sha256 != expected_bundle_sha256 {
        bail!("conformance onboarding bundle digest mismatch");
    }
    load_matrix_descriptor()?;
    if digest_hex(CONFORMANCE_MATRIX_BYTES) != expected_matrix_sha256 {
        bail!("conformance matrix digest mismatch");
    }
    let bundle: ConformanceOnboardingBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|_| anyhow::anyhow!("conformance onboarding bundle is invalid"))?;
    let request = validate_bundle(
        SignedOnboardingClaims {
            task_jti,
            profile,
            bundle_schema,
            bundle_sha256: expected_bundle_sha256,
            matrix_sha256: expected_matrix_sha256,
            client_count: expected_client_count,
            ttl_seconds,
        },
        bundle,
    )
    .await?;
    let repository = PostgresOnboardingRepository::new(
        repository()
            .map_err(|_| anyhow::anyhow!("conformance onboarding repository is unavailable"))?,
    );
    let result = repository.apply_onboarding(request).await?;
    let client_count = result.client_count;
    if client_count != expected_client_count
        || result.client_mappings.len() != usize::try_from(client_count).unwrap_or(usize::MAX)
        || result.bundle_sha256 != expected_bundle_sha256
        || result.matrix_sha256 != expected_matrix_sha256
    {
        bail!("persistence returned an inconsistent conformance onboarding result");
    }
    let summary = ConformanceOnboardingSummary {
        lease_id: result.lease_id.to_string(),
        request_jti: result.request_jti,
        applicant_id: result.applicant_id,
        client_mappings: result
            .client_mappings
            .into_iter()
            .map(|(logical_client_id, client_id)| {
                nazo_operator_protocol::ConformanceClientIdMapping {
                    logical_client_id,
                    client_id,
                }
            })
            .collect(),
        client_count,
        matrix_sha256: result.matrix_sha256,
        bundle_sha256: result.bundle_sha256,
        expires_at: result.expires_at,
        idempotent_replay: result.idempotent_replay,
    };
    write_onboarding_output(&summary)?;
    Ok(TaskResult::ConformanceOnboardingApplied {
        onboarding: summary,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConformanceOnboardingBundle {
    schema: u32,
    request_jti: String,
    matrix_sha256: String,
    profile: String,
    target_issuer: String,
    suite_base_url: String,
    applicant: ConformanceApplicantBundle,
    #[serde(default)]
    dynamic_registration_initial_access_token: Option<SecretText>,
    #[serde(default)]
    ciba_automated_decision_token: Option<SecretText>,
    clients: Vec<ConformanceClientBundle>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConformanceApplicantBundle {
    email: String,
    password: SecretText,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConformanceClientBundle {
    logical_client_id: String,
    request: Value,
    #[serde(default)]
    client_secret: Option<SecretText>,
    #[serde(default)]
    mtls_trust_anchor_pem: Option<String>,
}

struct SecretText(String);

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

impl SecretText {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        wipe_secret_string(&mut self.0);
    }
}

fn wipe_secret_string(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    bytes.fill(0);
}

struct SignedOnboardingClaims<'a> {
    task_jti: &'a str,
    profile: &'a str,
    bundle_schema: u32,
    bundle_sha256: &'a str,
    matrix_sha256: &'a str,
    client_count: u32,
    ttl_seconds: u64,
}

async fn validate_bundle(
    claims: SignedOnboardingClaims<'_>,
    bundle: ConformanceOnboardingBundle,
) -> anyhow::Result<ConformanceOnboardingRequest> {
    let SignedOnboardingClaims {
        task_jti,
        profile,
        bundle_schema,
        bundle_sha256: expected_bundle_sha256,
        matrix_sha256: expected_matrix_sha256,
        client_count: expected_client_count,
        ttl_seconds,
    } = claims;
    let canonical_jti = task_jti.strip_prefix("request-").unwrap_or_default();
    if canonical_jti.len() != 32
        || !canonical_jti
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("operator task idempotency binding is invalid");
    }
    if bundle.schema != bundle_schema || bundle.schema != 2 {
        bail!("conformance onboarding bundle schema does not match the signed task");
    }
    if bundle.request_jti != task_jti {
        bail!("conformance onboarding bundle task binding does not match the signed task");
    }
    if bundle.matrix_sha256 != expected_matrix_sha256 {
        bail!("conformance onboarding bundle matrix digest does not match the signed task");
    }
    if bundle.profile != profile {
        bail!("conformance onboarding bundle profile does not match the signed task");
    }
    if profile != "nazoauth-full" {
        bail!("conformance onboarding profile is not supported");
    }
    if profile.is_empty() || profile.len() > 64 || !is_identifier(profile) {
        bail!("conformance onboarding profile is invalid");
    }
    if !is_lower_hex(expected_bundle_sha256, 64) {
        bail!("conformance onboarding bundle digest is invalid");
    }
    if !is_lower_hex(expected_matrix_sha256, 64) {
        bail!("conformance matrix digest is invalid");
    }
    if !(60..=86_400).contains(&ttl_seconds) {
        bail!("conformance onboarding ttl is out of bounds");
    }
    let expected_client_count = usize::try_from(expected_client_count)
        .context("conformance onboarding client count is invalid")?;
    if expected_client_count == 0
        || expected_client_count > usize::try_from(MAX_CONFORMANCE_ONBOARDING_CLIENTS).unwrap()
        || bundle.clients.len() != expected_client_count
    {
        bail!("conformance onboarding client count does not match the bundle");
    }
    let target_issuer = validate_target_issuer(&bundle.target_issuer)?;
    let configured_issuer = configured_issuer().map_err(|_| {
        anyhow::anyhow!("conformance deployment issuer configuration is unavailable")
    })?;
    if target_issuer != configured_issuer {
        bail!("conformance onboarding target issuer does not match this deployment");
    }
    let applicant_email = validate_email(&bundle.applicant.email)?;
    let applicant_password = validate_secret_text(
        bundle.applicant.password.as_str(),
        "applicant password",
        512,
    )?;
    let dynamic_registration_initial_access_token = bundle
        .dynamic_registration_initial_access_token
        .as_ref()
        .map(|value| validate_secret_text(value.as_str(), "dynamic registration token", 4096))
        .transpose()?;
    let ciba_automated_decision_token = bundle
        .ciba_automated_decision_token
        .as_ref()
        .map(|value| validate_secret_text(value.as_str(), "CIBA decision token", 4096))
        .transpose()?;
    if (dynamic_registration_initial_access_token.is_some()
        || ciba_automated_decision_token.is_some())
        && profile != "nazoauth-full"
    {
        bail!("conformance token bindings are only valid for the nazoauth-full profile");
    }
    let descriptor = load_matrix_descriptor()?;
    let mut expected_logical_ids = BTreeSet::new();
    for group in &descriptor.groups {
        for plan in &group.plans {
            for role in group.required_roles.iter().chain(&plan.required_roles) {
                if role.registration_template.is_some() {
                    expected_logical_ids.insert(
                        role.logical_client_id
                            .as_deref()
                            .unwrap_or(&role.role)
                            .to_owned(),
                    );
                }
            }
        }
    }
    let requires_dynamic_token = descriptor_requires_reference(
        &descriptor,
        "deployment.dynamic_registration_initial_access_token",
    );
    // The CIBA secret is embedded in the generated decision URL, rather than
    // exposed as a second independent Matrix value. Both forms are protocol
    // references to the same lease-bound secret.
    let requires_ciba_token =
        descriptor_requires_reference(&descriptor, "deployment.ciba_automated_decision_token")
            || descriptor_requires_reference(&descriptor, "target.ciba_automated_decision_url");
    if dynamic_registration_initial_access_token.is_some() != requires_dynamic_token
        || ciba_automated_decision_token.is_some() != requires_ciba_token
    {
        bail!("conformance token material does not match the deployment matrix");
    }
    let dynamic_registration_initial_access_token_sha256 =
        dynamic_registration_initial_access_token.map(|value| digest_hex(value.as_bytes()));
    let ciba_automated_decision_token_sha256 =
        ciba_automated_decision_token.map(|value| digest_hex(value.as_bytes()));

    let mut logical_ids = BTreeSet::new();
    let mut raw_clients = Vec::with_capacity(bundle.clients.len());
    let mut mtls_trust_anchors = Vec::new();
    for client in bundle.clients {
        if client.logical_client_id.is_empty()
            || client.logical_client_id.len() > 128
            || !is_file_identifier(&client.logical_client_id)
            || !logical_ids.insert(client.logical_client_id.clone())
        {
            bail!("conformance onboarding client logical id is invalid");
        }
        validate_client_request(&client.request)?;
        let auth_method = client
            .request
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .context("conformance client auth method is missing")?;
        let requires_supplied_secret =
            matches!(auth_method, "client_secret_basic" | "client_secret_post");
        if requires_supplied_secret != client.client_secret.is_some() {
            bail!("conformance client secret binding does not match auth method");
        }
        let requires_mtls_anchor = registration_requires_mtls_anchor(&client.request);
        if requires_mtls_anchor != client.mtls_trust_anchor_pem.is_some() {
            bail!("conformance mTLS trust anchor binding does not match client registration");
        }
        if let Some(anchor) = &client.mtls_trust_anchor_pem {
            if anchor.len() > 64 * 1024
                || !anchor.starts_with("-----BEGIN CERTIFICATE-----")
                || !anchor.ends_with("-----END CERTIFICATE-----\n")
                || anchor.contains("PRIVATE KEY")
            {
                bail!("conformance onboarding mTLS trust anchor is invalid");
            }
            let validated =
                nazo_key_management::validate_mtls_trust_anchor(anchor).map_err(|_| {
                    anyhow::anyhow!("conformance onboarding mTLS trust anchor is invalid")
                })?;
            mtls_trust_anchors.push(ConformanceOnboardingMtlsTrustAnchor {
                logical_client_id: client.logical_client_id.clone(),
                certificate_pem: validated.certificate_pem,
                certificate_sha256: validated.certificate_sha256,
                subject_dn: validated.subject_dn,
                not_before: validated.not_before,
                not_after: validated.not_after,
            });
        }
        if let Some(secret) = &client.client_secret {
            validate_secret_text(secret.as_str(), "client secret", 512)?;
        }
        raw_clients.push(client);
    }
    if logical_ids != expected_logical_ids {
        bail!("conformance onboarding client set does not match the deployment matrix");
    }

    let applicant_password_hash = hash_applicant_password(applicant_password).await?;
    validate_suite_origin(&bundle.suite_base_url, &target_issuer)?;
    let clients = prepare_client_registrations(raw_clients).await?;

    Ok(ConformanceOnboardingRequest {
        tenant_id: DEFAULT_TENANT_ID,
        task_jti: task_jti.to_owned(),
        profile: profile.to_owned(),
        bundle_schema,
        bundle_sha256: expected_bundle_sha256.to_owned(),
        matrix_sha256: expected_matrix_sha256.to_owned(),
        dynamic_registration_initial_access_token_sha256,
        ciba_automated_decision_token_sha256,
        client_count: u32::try_from(expected_client_count)?,
        ttl_seconds,
        applicant: ConformanceOnboardingApplicant {
            username: format!("conformance-{}", &task_jti[..task_jti.len().min(32)]),
            email: applicant_email,
            password_hash: applicant_password_hash,
            email_verified: true,
        },
        clients,
        mtls_trust_anchors,
    })
}

fn registration_requires_mtls_anchor(request: &Value) -> bool {
    request
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .is_some_and(|method| matches!(method, "tls_client_auth" | "self_signed_tls_client_auth"))
        || request
            .get("require_mtls_bound_tokens")
            .and_then(Value::as_bool)
            == Some(true)
        || ["tls_client_auth_subject_dn", "tls_client_auth_cert_sha256"]
            .iter()
            .any(|field| {
                request
                    .get(*field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
            })
        || [
            "tls_client_auth_san_dns",
            "tls_client_auth_san_uri",
            "tls_client_auth_san_ip",
            "tls_client_auth_san_email",
        ]
        .iter()
        .any(|field| {
            request
                .get(*field)
                .and_then(Value::as_array)
                .is_some_and(|values| !values.is_empty())
        })
}

async fn hash_applicant_password(
    password: &str,
) -> anyhow::Result<nazo_identity::ports::PasswordHashInput> {
    let config = ConfigSource::load_without_secret_values()
        .map_err(|_| anyhow::anyhow!("conformance password hash configuration is unavailable"))?;
    let max_concurrency = config
        .parse(
            "PASSWORD_HASH_MAX_CONCURRENCY",
            crate::adapters::security::default_password_hash_max_concurrency(),
        )
        .map_err(|_| anyhow::anyhow!("conformance password hash concurrency limit is invalid"))?;
    let queue_timeout_ms = config
        .parse(
            "PASSWORD_HASH_QUEUE_TIMEOUT_MS",
            crate::adapters::security::default_password_hash_queue_timeout_ms(),
        )
        .map_err(|_| anyhow::anyhow!("conformance password hash queue timeout is invalid"))?;
    if let Err(error) =
        crate::adapters::security::configure_password_hash_limits(max_concurrency, queue_timeout_ms)
    {
        // A long-lived server process may already have initialized the shared
        // limiter. The operator subprocess normally configures it here.
        if error.to_string()
            != "password hash limits must be configured before password verification"
        {
            bail!("conformance password hash limiter configuration failed");
        }
    }
    let hash = crate::adapters::security::hash_password_blocking_limited(password.to_owned())
        .await
        .map_err(|error| match error {
            crate::adapters::security::PasswordHashingError::Saturated => {
                anyhow::anyhow!("conformance password hash capacity is saturated")
            }
            crate::adapters::security::PasswordHashingError::WorkerFailed => {
                anyhow::anyhow!("conformance password hash worker failed")
            }
            crate::adapters::security::PasswordHashingError::HashFailed => {
                anyhow::anyhow!("conformance password hashing failed")
            }
        })?;
    nazo_identity::ports::PasswordHashInput::new(hash)
        .map_err(|_| anyhow::anyhow!("generated conformance applicant password hash is invalid"))
}

async fn prepare_client_registrations(
    raw_clients: Vec<ConformanceClientBundle>,
) -> anyhow::Result<Vec<ConformanceOnboardingClient>> {
    let config = ConfigSource::load_for_migrations()
        .map_err(|_| anyhow::anyhow!("conformance client policy configuration is unavailable"))?;
    let pool = nazo_postgres::create_pool(crate::config::database_url(&config), 1)
        .map_err(|_| anyhow::anyhow!("conformance client policy storage is unavailable"))?;
    let client_secret_pepper = read_fixed_secret_string(
        &conformance_policy_secret_path(
            "NAZOAUTH_OPERATOR_CLIENT_SECRET_PEPPER_FILE",
            CONFORMANCE_CLIENT_SECRET_PEPPER_PATH,
            "client-secret-pepper",
        )?,
        "conformance client secret pepper",
    )?;
    let pairwise_subject_secret = if config
        .string("SUBJECT_TYPE", "public")
        .eq_ignore_ascii_case("pairwise")
    {
        Some(read_fixed_secret_string(
            &conformance_policy_secret_path(
                "NAZOAUTH_OPERATOR_PAIRWISE_SUBJECT_SECRET_FILE",
                CONFORMANCE_PAIRWISE_SUBJECT_SECRET_PATH,
                "pairwise-subject-secret",
            )?,
            "conformance pairwise subject secret",
        )?)
    } else {
        None
    };
    let service = crate::http::admin::clients::ServerAdminClientService::new(
        nazo_postgres::OAuthClientRepository::new(pool),
        crate::http::admin::clients::ServerSectorIdentifierResolver,
        crate::http::admin::clients::ServerAdminClientCrypto::for_policy_validation(),
        nazo_auth::AdminClientPolicy {
            tenant: nazo_identity::TenantContext::default_system(),
            pairwise_subject_secret,
            client_secret_pepper,
        },
    );
    let mut clients = Vec::with_capacity(raw_clients.len());
    for client in raw_clients {
        let mut request = client.request.clone();
        canonicalize_conformance_registration_sets(&mut request)?;
        let request: nazo_auth::CreateClientRequest = serde_json::from_value(request)
            .map_err(|_| anyhow::anyhow!("conformance client request is invalid"))?;
        let prepared = if let Some(secret) = client.client_secret {
            let secret = nazo_auth::SuppliedClientSecret::new(secret.as_str().as_bytes())
                .map_err(|_| anyhow::anyhow!("conformance client secret is invalid"))?;
            service
                .prepare_registration_with_secret(request, secret)
                .await
                .map_err(|_| {
                    anyhow::anyhow!("conformance client request failed policy validation")
                })?
        } else {
            service.prepare_registration(request).await.map_err(|_| {
                anyhow::anyhow!("conformance client request failed policy validation")
            })?
        };
        clients.push(ConformanceOnboardingClient {
            logical_client_id: client.logical_client_id.clone(),
            prepared,
        });
    }
    Ok(clients)
}

fn canonicalize_conformance_registration_sets(request: &mut Value) -> anyhow::Result<()> {
    let object = request
        .as_object_mut()
        .context("conformance client request is not an object")?;
    for field in [
        "redirect_uris",
        "post_logout_redirect_uris",
        "scopes",
        "allowed_audiences",
        "grant_types",
        "tls_client_auth_san_dns",
        "tls_client_auth_san_uri",
        "tls_client_auth_san_ip",
        "tls_client_auth_san_email",
        "request_uris",
    ] {
        let Some(value) = object.get_mut(field) else {
            continue;
        };
        let values = value
            .as_array_mut()
            .with_context(|| format!("conformance client {field} is not an array"))?;
        if values.iter().any(|value| !value.is_string()) {
            bail!("conformance client {field} contains a non-string value");
        }
        let mut seen = BTreeSet::new();
        values.retain(|value| {
            value
                .as_str()
                .is_some_and(|value| seen.insert(value.to_owned()))
        });
    }
    Ok(())
}

/// Temporary adapter seam. The persistence crate provides the transaction
/// operation; this local wrapper is the only place where that concrete type is
/// coupled to the domain port.
struct PostgresOnboardingRepository {
    inner: ConformanceLeaseRepository,
}

fn map_persistence_client_mappings(
    mappings: Vec<nazo_postgres::ConformanceClientMapping>,
) -> Vec<(String, String)> {
    mappings
        .into_iter()
        .map(|mapping| (mapping.logical_client_id, mapping.client_id))
        .collect()
}

impl PostgresOnboardingRepository {
    fn new(inner: ConformanceLeaseRepository) -> Self {
        Self { inner }
    }
}

impl ConformanceOnboardingRepository for PostgresOnboardingRepository {
    fn apply_onboarding(&self, request: ConformanceOnboardingRequest) -> OnboardingFuture<'_> {
        let tenant = nazo_identity::TenantContext::default_system();
        if request.tenant_id != tenant.tenant_id.as_uuid() {
            return Box::pin(async { bail!("conformance onboarding tenant binding is invalid") });
        }
        let bundle_schema = match i32::try_from(request.bundle_schema) {
            Ok(value) => value,
            Err(_) => {
                return Box::pin(async {
                    bail!("conformance onboarding bundle schema is invalid")
                });
            }
        };
        let ttl_seconds = match i64::try_from(request.ttl_seconds) {
            Ok(value) => value,
            Err(_) => {
                return Box::pin(async { bail!("conformance onboarding ttl is invalid") });
            }
        };
        let ConformanceOnboardingRequest {
            task_jti,
            profile,
            matrix_sha256,
            bundle_sha256,
            dynamic_registration_initial_access_token_sha256,
            ciba_automated_decision_token_sha256,
            client_count,
            applicant,
            clients,
            mtls_trust_anchors,
            ..
        } = request;
        let task_jti_for_result = task_jti.clone();
        let requested_logical_ids = clients
            .iter()
            .map(|client| client.logical_client_id.clone())
            .collect::<BTreeSet<_>>();
        let persistence_client_count = match i32::try_from(client_count) {
            Ok(value) => value,
            Err(_) => {
                return Box::pin(async { bail!("conformance client count is invalid") });
            }
        };
        let matrix_sha256_for_result = matrix_sha256.clone();
        let persistence_request = nazo_postgres::ConformanceOnboardingRequest {
            tenant,
            task_jti,
            profile,
            bundle_schema,
            material_sha256: matrix_sha256,
            bundle_sha256,
            dynamic_registration_initial_access_token_sha256,
            ciba_automated_decision_token_sha256,
            client_count: persistence_client_count,
            ttl_seconds,
            applicant: nazo_postgres::ConformanceApplicant {
                username: applicant.username,
                email: applicant.email,
                password_hash: applicant.password_hash,
                email_verified: applicant.email_verified,
            },
            clients: clients
                .into_iter()
                .map(|client| nazo_postgres::ConformanceClient {
                    logical_client_id: client.logical_client_id,
                    prepared: client.prepared,
                })
                .collect(),
            mtls_trust_anchors: mtls_trust_anchors
                .into_iter()
                .map(|anchor| nazo_postgres::ConformanceMtlsTrustAnchor {
                    logical_client_id: anchor.logical_client_id,
                    certificate_pem: anchor.certificate_pem,
                    certificate_sha256: anchor.certificate_sha256,
                    subject_dn: anchor.subject_dn,
                    not_before: anchor.not_before,
                    not_after: anchor.not_after,
                })
                .collect(),
        };
        let repository = self.inner.clone();
        Box::pin(async move {
            let result =
                repository
                    .onboard(persistence_request)
                    .await
                    .map_err(|error| match error {
                        nazo_identity::ports::RepositoryError::Conflict
                        | nazo_identity::ports::RepositoryError::AlreadyProcessed => {
                            anyhow::anyhow!("conformance onboarding transaction conflicted")
                        }
                    nazo_identity::ports::RepositoryError::Consistency(message) => {
                        // This port is fed only by the bounded onboarding
                        // repository, whose consistency messages are static
                        // invariant names and never contain SQL, credentials,
                        // applicant data, or client material. Preserve that
                        // safe stage so an operator can repair the invariant
                        // instead of receiving an opaque transaction failure.
                        anyhow::anyhow!(
                            "conformance onboarding transaction failed consistency checks: {message}"
                        )
                        }
                        nazo_identity::ports::RepositoryError::Unavailable => {
                            anyhow::anyhow!("conformance onboarding storage is unavailable")
                        }
                        nazo_identity::ports::RepositoryError::NotFound => {
                            anyhow::anyhow!("conformance onboarding dependency was not found")
                        }
                        nazo_identity::ports::RepositoryError::Unexpected(_) => {
                            anyhow::anyhow!("conformance onboarding storage operation failed")
                        }
                    })?;
            let applicant_id = result
                .applicant_user_id
                .ok_or_else(|| anyhow::anyhow!("conformance onboarding result is incomplete"))?;
            let client_count = usize::try_from(result.client_count)
                .map_err(|_| anyhow::anyhow!("conformance onboarding result is invalid"))?;
            if client_count != result.client_mappings.len() {
                bail!("conformance onboarding result is inconsistent");
            }
            let returned_logical_ids = result
                .client_mappings
                .iter()
                .map(|mapping| mapping.logical_client_id.clone())
                .collect::<BTreeSet<_>>();
            if returned_logical_ids != requested_logical_ids {
                bail!("conformance onboarding result is inconsistent");
            }
            Ok(ConformanceOnboardingResult {
                lease_id: result.lease_id,
                request_jti: task_jti_for_result,
                applicant_id: applicant_id.to_string(),
                client_mappings: map_persistence_client_mappings(result.client_mappings),
                client_count: u32::try_from(client_count)
                    .map_err(|_| anyhow::anyhow!("conformance onboarding result is invalid"))?,
                matrix_sha256: matrix_sha256_for_result,
                bundle_sha256: result.bundle_sha256,
                expires_at: result.expires_at.timestamp(),
                idempotent_replay: result.idempotent_replay,
            })
        })
    }
}

fn read_fixed_material(path: &Path, maximum: usize) -> anyhow::Result<Vec<u8>> {
    read_fixed_material_with_policy(path, maximum, false)
}

fn read_fixed_secret_string(path: &Path, label: &str) -> anyhow::Result<String> {
    let bytes = read_fixed_material_with_policy(path, 4096, true)
        .with_context(|| format!("{label} is unavailable"))?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("{label} is not UTF-8"))?
        .trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        bail!("{label} is invalid");
    }
    Ok(value.to_owned())
}

fn read_fixed_material_with_policy(
    path: &Path,
    maximum: usize,
    #[cfg_attr(not(unix), allow(unused_variables))] allow_owner_write: bool,
) -> anyhow::Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect secure material {}", path.display()))?;
    if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
        bail!("secure conformance material is not a regular file");
    }
    #[cfg(unix)]
    let mut file = File::from(
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("failed to open secure material {}", path.display()))?,
    );
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("failed to open secure material {}", path.display()))?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        bail!("secure conformance material is not a regular file");
    }
    #[cfg(unix)]
    {
        validate_secure_material_metadata(&opened, allow_owner_write)?;
        if path_metadata.dev() != opened.dev() || path_metadata.ino() != opened.ino() {
            bail!("secure conformance material changed while opening");
        }
    }
    if opened.len() == 0 || opened.len() > u64::try_from(maximum).unwrap_or(u64::MAX) {
        bail!("secure conformance material size is out of bounds");
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(maximum));
    (&mut file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        bail!("secure conformance material size is out of bounds");
    }
    #[cfg(unix)]
    {
        let after = file.metadata()?;
        validate_secure_material_metadata(&after, allow_owner_write)?;
        if opened.dev() != after.dev() || opened.ino() != after.ino() || opened.len() != after.len()
        {
            bail!("secure conformance material changed while reading");
        }
    }
    Ok(bytes)
}

#[cfg(unix)]
fn validate_secure_material_metadata(
    metadata: &fs::Metadata,
    allow_owner_write: bool,
) -> anyhow::Result<()> {
    if !metadata.is_file() || metadata.nlink() != 1 {
        bail!("secure conformance material is not a single-link regular file");
    }
    let effective_uid = rustix::process::geteuid().as_raw();
    let effective_gid = rustix::process::getegid().as_raw();
    let owner_is_trusted = metadata.uid() == 0 || metadata.uid() == effective_uid;
    let mode = metadata.mode() & 0o777;
    let permissions_are_bound = match mode {
        0o400 => owner_is_trusted,
        0o440 => owner_is_trusted && metadata.gid() == effective_gid,
        0o600 => allow_owner_write && metadata.uid() == effective_uid,
        _ => false,
    };
    if !permissions_are_bound {
        bail!(
            "secure conformance material permissions are not owner-bound or service-group-bound read-only"
        );
    }
    Ok(())
}

fn conformance_policy_secret_path(
    environment_key: &str,
    fixed_path: &str,
    credential_name: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let value = std::env::var_os(environment_key)
        .with_context(|| format!("{environment_key} is unavailable"))?;
    let path = std::path::PathBuf::from(value);
    if path == Path::new(fixed_path) {
        return Ok(path);
    }
    let is_systemd_credential = path.is_absolute()
        && path.file_name().is_some_and(|name| name == credential_name)
        && path.parent().is_some_and(|parent| {
            parent.starts_with("/run/credentials") || parent.starts_with("/run/systemd/credentials")
        });
    if !is_systemd_credential {
        bail!("conformance policy secret path is not a controller-owned fixed mapping");
    }
    Ok(path)
}

fn conformance_bundle_path() -> anyhow::Result<std::path::PathBuf> {
    let Some(value) = std::env::var_os("NAZOAUTH_OPERATOR_CONFORMANCE_BUNDLE_FILE") else {
        return Ok(Path::new(CONFORMANCE_BUNDLE_PATH).to_owned());
    };
    let path = std::path::PathBuf::from(value);
    if path == Path::new(CONFORMANCE_BUNDLE_PATH) {
        return Ok(path);
    }
    let is_systemd_credential = path.is_absolute()
        && path
            .file_name()
            .is_some_and(|name| name == "conformance-bundle")
        && path.parent().is_some_and(|parent| {
            parent.starts_with("/run/credentials") || parent.starts_with("/run/systemd/credentials")
        });
    if !is_systemd_credential {
        bail!("conformance bundle path is not a controller-owned fixed mapping");
    }
    Ok(path)
}

fn conformance_output_directory() -> anyhow::Result<std::path::PathBuf> {
    let Some(value) = std::env::var_os("NAZOAUTH_OPERATOR_OUTPUT_DIRECTORY") else {
        return Ok(Path::new(CONFORMANCE_OUTPUT_DIRECTORY).to_owned());
    };
    let path = std::path::PathBuf::from(value);
    if path == Path::new(CONFORMANCE_OUTPUT_DIRECTORY) {
        return Ok(path);
    }
    if !path.is_absolute()
        || !path.starts_with("/run/")
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("conformance output path is not an absolute private directory");
    }
    let metadata = fs::symlink_metadata(&path)
        .context("controller-owned conformance output directory is unavailable")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("controller-owned conformance output path is not a directory");
    }
    #[cfg(unix)]
    {
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("controller-owned conformance output directory is not private");
        }
    }
    Ok(path)
}

fn write_matrix_output(bytes: &[u8]) -> anyhow::Result<()> {
    let directory = conformance_output_directory()?;
    if let Ok(metadata) = fs::symlink_metadata(&directory) {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("conformance output directory is not a real directory");
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("conformance output directory permissions are too broad");
        }
    } else {
        fs::create_dir_all(&directory).context("failed to create conformance output directory")?;
        #[cfg(unix)]
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    if bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 {
        bail!("conformance matrix descriptor size is out of bounds");
    }
    let path = directory.join("conformance-matrix.json");
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("conformance matrix output is not a regular file");
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o777 != 0o600 {
            bail!("conformance matrix output permissions are not 0600");
        }
        let existing = fs::read(&path).context("failed to read existing matrix output")?;
        if existing != bytes {
            bail!("conformance matrix output is bound to another descriptor");
        }
        return Ok(());
    }
    let temporary = directory.join(format!(".conformance-matrix-{}.tmp", Uuid::now_v7()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &path)?;
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn write_onboarding_output(summary: &ConformanceOnboardingSummary) -> anyhow::Result<()> {
    let directory = conformance_output_directory()?;
    if let Ok(metadata) = fs::symlink_metadata(&directory) {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("conformance onboarding output directory is not a real directory");
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("conformance onboarding output directory permissions are too broad");
        }
    } else {
        fs::create_dir_all(&directory)
            .context("failed to create conformance onboarding output directory")?;
        #[cfg(unix)]
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    let encoded = serde_json::to_vec(summary).context("failed to encode onboarding output")?;
    let path = directory.join("conformance-onboarding.json");
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("conformance onboarding output is not a regular file");
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o777 != 0o600 {
            bail!("conformance onboarding output permissions are not 0600");
        }
    }
    if let Ok(existing) = fs::read(&path) {
        let prior: ConformanceOnboardingSummary = serde_json::from_slice(&existing)
            .context("existing conformance onboarding output is invalid")?;
        if prior != *summary {
            bail!("conformance onboarding output is bound to another transaction");
        }
        return Ok(());
    }
    let temporary = directory.join(format!(".conformance-onboarding-{}.tmp", Uuid::now_v7()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &path)?;
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn configured_issuer() -> anyhow::Result<String> {
    let config = ConfigSource::load_without_secret_values()?;
    let public_base_url = config.string("PUBLIC_BASE_URL", "http://127.0.0.1:8000");
    let issuer = config.string("ISSUER", &public_base_url);
    validate_target_issuer(&issuer)
}

fn validate_target_issuer(value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    let url = url::Url::parse(value).map_err(|_| anyhow::anyhow!("target issuer is invalid"))?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("target issuer must not contain credentials, query, or fragment");
    }
    let host = url
        .host_str()
        .context("target issuer host is unavailable")?;
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback) {
        bail!("target issuer must use HTTPS or loopback HTTP");
    }
    Ok(value.trim_end_matches('/').to_owned())
}

fn validate_suite_origin(value: &str, target_issuer: &str) -> anyhow::Result<String> {
    let value = value.trim();
    let url = url::Url::parse(value).map_err(|_| anyhow::anyhow!("suite origin is invalid"))?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("suite origin must be an HTTPS origin without credentials or query");
    }
    let origin = format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().context("suite origin host is unavailable")?,
        url.port()
            .map_or_else(String::new, |port| format!(":{port}")),
    );
    if origin == target_issuer {
        bail!("suite origin must differ from target issuer");
    }
    Ok(origin)
}

fn validate_email(value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 320
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.matches('@').count() != 1
    {
        bail!("conformance applicant email is invalid");
    }
    let (local, domain) = value.split_once('@').unwrap();
    if local.is_empty() || domain.is_empty() || domain.starts_with('.') || domain.ends_with('.') {
        bail!("conformance applicant email is invalid");
    }
    Ok(value.to_owned())
}

fn validate_secret_text<'a>(
    value: &'a str,
    label: &str,
    maximum: usize,
) -> anyhow::Result<&'a str> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        bail!("conformance {label} is invalid");
    }
    Ok(value)
}

fn validate_client_request(request: &Value) -> anyhow::Result<()> {
    let object = request
        .as_object()
        .context("conformance client request must be an object")?;
    let encoded = serde_json::to_vec(request)?;
    if encoded.is_empty() || encoded.len() > MAX_CONFORMANCE_CLIENT_REQUEST_BYTES {
        bail!("conformance client request size is out of bounds");
    }
    const REQUIRED: &[&str] = &[
        "client_name",
        "client_type",
        "redirect_uris",
        "scopes",
        "allowed_audiences",
        "grant_types",
        "token_endpoint_auth_method",
    ];
    const ALLOWED: &[&str] = &[
        "client_name",
        "client_type",
        "redirect_uris",
        "post_logout_redirect_uris",
        "scopes",
        "allowed_audiences",
        "grant_types",
        "token_endpoint_auth_method",
        "subject_type",
        "sector_identifier_uri",
        "require_dpop_bound_tokens",
        "require_mtls_bound_tokens",
        "allow_client_assertion_audience_array",
        "allow_client_assertion_endpoint_audience",
        "require_par_request_object",
        "backchannel_token_delivery_mode",
        "backchannel_client_notification_endpoint",
        "backchannel_authentication_request_signing_alg",
        "backchannel_user_code_parameter",
        "backchannel_logout_uri",
        "backchannel_logout_session_required",
        "frontchannel_logout_uri",
        "frontchannel_logout_session_required",
        "tls_client_auth_subject_dn",
        "tls_client_auth_cert_sha256",
        "tls_client_auth_san_dns",
        "tls_client_auth_san_uri",
        "tls_client_auth_san_ip",
        "tls_client_auth_san_email",
        "jwks",
        "id_token_signed_response_alg",
        "id_token_encrypted_response_alg",
        "id_token_encrypted_response_enc",
        "request_object_signing_alg",
        "request_object_encryption_alg",
        "request_object_encryption_enc",
        "token_endpoint_auth_signing_alg",
        "introspection_signed_response_alg",
        "introspection_encrypted_response_alg",
        "introspection_encrypted_response_enc",
        "userinfo_signed_response_alg",
        "userinfo_encrypted_response_alg",
        "userinfo_encrypted_response_enc",
        "authorization_signed_response_alg",
        "authorization_encrypted_response_alg",
        "authorization_encrypted_response_enc",
        "security_policy",
    ];
    if REQUIRED.iter().any(|key| !object.contains_key(*key))
        || object.keys().any(|key| !ALLOWED.contains(&key.as_str()))
        || contains_secret_field(request)
    {
        bail!("conformance client request contains unsupported fields");
    }
    if object.get("client_type").and_then(Value::as_str) != Some("confidential") {
        bail!("conformance client request must be confidential");
    }
    if let Some(digest) = object
        .get("tls_client_auth_cert_sha256")
        .and_then(Value::as_str)
        && !is_lower_hex(digest, 64)
    {
        bail!("conformance client mTLS certificate digest is invalid");
    }
    for field in [
        "tls_client_auth_subject_dn",
        "tls_client_auth_san_dns",
        "tls_client_auth_san_uri",
        "tls_client_auth_san_ip",
        "tls_client_auth_san_email",
    ] {
        if let Some(value) = object.get(field)
            && serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > 4096)
        {
            bail!("conformance client mTLS identity metadata is too large");
        }
    }
    Ok(())
}

fn contains_secret_field(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "client_secret"
                    | "password"
                    | "token"
                    | "access_token"
                    | "refresh_token"
                    | "password_hash"
                    | "private_key"
                    | "private_jwk"
                    | "private_jwks"
                    | "d"
                    | "p"
                    | "q"
                    | "dp"
                    | "dq"
                    | "qi"
                    | "oth"
                    | "k"
            ) || contains_secret_field(value)
        }),
        Value::Array(values) => values.iter().any(contains_secret_field),
        _ => false,
    }
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_/@+-".contains(character))
}

fn is_file_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_+-".contains(character))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

fn value_contains_reference(value: &Value, reference: &str) -> bool {
    match value {
        Value::Array(values) => values
            .iter()
            .any(|child| value_contains_reference(child, reference)),
        Value::Object(values) => values
            .values()
            .any(|child| value_contains_reference(child, reference)),
        Value::String(text) => text == &format!("{{{{{reference}}}}}"),
        _ => false,
    }
}

fn descriptor_requires_reference(
    descriptor: &ConformanceMatrixDescriptor,
    reference: &str,
) -> bool {
    descriptor.groups.iter().any(|group| {
        group
            .plans
            .iter()
            .any(|plan| value_contains_reference(&plan.config_template, reference))
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
